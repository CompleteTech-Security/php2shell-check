"""Synthetic-only external-profile transport/admission regressions."""

import gzip
import io
import json
import os
from email.message import Message
import socket
import socketserver
import subprocess
import sys
import threading
import time
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock
from urllib.request import Request

from integrations.worker import admission, network, network_dns
from integrations.worker.profiles import PROFILE_SHA256


SERVICES = [{"scheme": "http", "port": 80}, {"scheme": "https", "port": 443}]
TARGET = "http://fixture.example/"
PUBLIC_ANSWERS = [[socket.AF_INET, socket.SOCK_STREAM, 6, "", ["93.184.216.34", 80]]]


class Guard:
    kind = "external"

    def __init__(self):
        self.kinds = []
        self.finished = 0

    def admit(self, *, kind):
        self.kinds.append(kind)

    def ensure_fresh(self):
        pass

    def done(self):
        self.finished += 1


class Response:
    def __init__(self, body=b"safe", status=200, headers=None):
        self.status = status
        self.headers = Message()
        for name, value in (headers or {}).items():
            self.headers[name] = value
        self.data = io.BytesIO(body)
        self.closed = False
        self.reads = 0

    def read(self, amount=-1):
        self.reads += 1
        return self.data.read(amount)

    def close(self):
        self.closed = True


class Connection:
    def __init__(self, response):
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, *args, **kwargs):
        self.requests.append((args, kwargs))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def opener(*, guard=None, meter=None, **kwargs):
    scope, _ = network.ProfileScope.from_target(TARGET, SERVICES)
    return network.ExternalPinnedOpener(scope, guard or Guard(), profile_sha256=PROFILE_SHA256,
                                        meter=meter or network.ProfileMeter(), **kwargs)


class ProfileScopeTests(unittest.TestCase):
    def test_explicit_services_and_safe_paths_only(self):
        scope, canonical = network.ProfileScope.from_target(TARGET, SERVICES)
        self.assertEqual(canonical, TARGET)
        self.assertEqual(scope.validate_request("https://fixture.example/robots.txt"),
                         ("https", 443, "fixture.example", "/robots.txt"))
        for target in ("https://www.fixture.example/", "https://fixture.example:444/",
                       "https://fixture.example/wp-config.php", "https://fixture.example/%2f",
                       "https://fixture.example/?x=1", "https://fixture.example/#token",
                       "https://u:p@fixture.example/"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                scope.validate_request(target)

    def test_invalid_services_and_binding_are_refused(self):
        for value in ([], list(reversed(SERVICES)), SERVICES + SERVICES, [{"scheme": [], "port": 80}],
                      [{"scheme": "http", "port": True}], [{"scheme": "http", "port": 81}]):
            with self.assertRaises(ValueError):
                network.ProfileScope.from_target(TARGET, value)
        scope, _ = network.ProfileScope.from_target(TARGET, SERVICES)
        with self.assertRaises(ValueError):
            network.ExternalPinnedOpener(scope, Guard(), profile_sha256="0" * 64,
                                          meter=network.ProfileMeter())

    def test_shared_meter_cannot_change_scope(self):
        meter = network.ProfileMeter()
        opener(meter=meter)
        other, _ = network.ProfileScope.from_target("http://other.example/", SERVICES)
        with self.assertRaises(network.BoundaryViolation):
            network.ExternalPinnedOpener(other, Guard(), profile_sha256=PROFILE_SHA256, meter=meter)


class BodyAndHeaderTests(unittest.TestCase):
    def raw_response(self, payload):
        raw = io.BytesIO(payload)
        response = network._BoundedHTTPResponse(SimpleNamespace(makefile=lambda _mode: raw))
        response.begin()
        return response

    def use(self, response, *, request=None, **kwargs):
        transport = opener(**kwargs)
        connection = Connection(response)
        patcher = mock.patch.object(transport, "_connection", return_value=connection)
        patcher.start()
        self.addCleanup(patcher.stop)
        return transport, connection, transport.open(request or Request(TARGET))

    def test_header_parser_enforces_aggregate_limit_before_allocation(self):
        raw = io.BytesIO(b"HTTP/1.1 200 OK\r\nX-Big: " + b"a" * 40000 + b"\r\n\r\n")
        sock = SimpleNamespace(makefile=lambda _mode: raw)
        response = network._BoundedHTTPResponse(sock)
        with self.assertRaises(network.BoundaryViolation):
            response.begin()
        self.assertLessEqual(raw.tell(), 32769)

    def test_gzip_is_decoded_bounded_and_headers_normalized(self):
        response = Response(gzip.compress(b"User-agent: *\nAllow: /\n"),
                            headers={"Content-Encoding": "gzip", "Content-Length": "42"})
        transport, connection, stream = self.use(response)
        with stream:
            self.assertEqual(stream.read(4) + stream.read(), b"User-agent: *\nAllow: /\n")
            self.assertEqual(stream.headers["Content-Encoding"], "identity")
            self.assertIsNone(stream.headers["Content-Length"])
        self.assertTrue(response.closed and connection.closed)
        self.assertFalse(transport.meter.inflight)

    def test_gzip_headers_are_normalized_before_the_first_read(self):
        response = Response(gzip.compress(b"safe"), headers={"Content-Encoding": "gzip"})
        _transport, _connection, stream = self.use(response)
        self.assertEqual(stream.headers["Content-Encoding"], "identity")
        self.assertEqual(response.reads, 0)
        with stream:
            self.assertEqual(stream.read(), b"safe")

    def test_chunk_metadata_and_trailers_are_bounded_and_counted(self):
        payload = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nsafe\r\n0\r\nX-End: yes\r\n\r\n"
        transport, _connection, stream = self.use(self.raw_response(payload))
        with stream:
            self.assertEqual(stream.read(), b"safe")
        self.assertEqual(transport.meter.wire_used, len(payload.split(b"\r\n\r\n", 1)[1]))
        for suffix in (b"1;" + b"x" * 40000 + b"\r\na\r\n0\r\n\r\n",
                       b"1\r\na\r\n0\r\nX-End: " + b"x" * 40000 + b"\r\n\r\n"):
            transport, connection, stream = self.use(self.raw_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + suffix))
            with self.assertRaises(network.BoundaryViolation):
                stream.read(1)
            self.assertTrue(connection.closed)
            self.assertIsNone(stream._buffer)
            self.assertIsNotNone(transport.meter.failure)

    def test_ambiguous_or_truncated_framing_never_returns_a_prefix(self):
        for payload in (
                b"Content-Length: 10\r\n\r\nsafe",
                b"Content-Length: 4\r\nContent-Length: 4\r\n\r\nsafe",
                b"Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n4\r\nsafe\r\n0\r\n\r\n",
                b"Transfer-Encoding: chunked\r\n\r\n4\r\nsafe\r\n0\r\n"):
            transport, connection, stream = self.use(self.raw_response(b"HTTP/1.1 200 OK\r\n" + payload))
            with self.assertRaises(network.BoundaryViolation):
                stream.read(1)
            self.assertTrue(connection.closed)
            self.assertIsNone(stream._buffer)
            self.assertIsNotNone(transport.meter.failure)

    def test_gzip_bomb_and_extra_member_never_return_prefix(self):
        for body in (gzip.compress(b"x" * 262145), gzip.compress(b"safe") + gzip.compress(b"hidden")):
            transport, connection, stream = self.use(Response(body, headers={"Content-Encoding": "gzip"}))
            with self.assertRaises(network.BoundaryViolation):
                stream.read(1)
            self.assertTrue(connection.closed)
            self.assertIsNone(stream._buffer)
            self.assertIsNotNone(transport.meter.failure)

    def test_body_limit_and_cumulative_budget_are_enforced(self):
        for body, meter in ((b"a" * 262145, network.ProfileMeter()), (b"abc", network.ProfileMeter())):
            if len(body) == 3:
                meter.body_used = 5242880 - 2
            transport, connection, stream = self.use(Response(body), meter=meter)
            with self.assertRaises(network.BoundaryViolation):
                stream.read()
            self.assertTrue(connection.closed)

    def test_head_never_reads_unsolicited_body(self):
        response = Response(b"-----BEGIN PRIVATE KEY-----secret")
        transport, connection, stream = self.use(response, request=Request(TARGET, method="HEAD"))
        with stream:
            self.assertEqual(stream.read(), b"")
        self.assertEqual(response.reads, 0)

    def test_default_sensitive_guard_cannot_be_replaced(self):
        transport, connection, stream = self.use(Response(b"-----BEGIN PRIVATE KEY-----PRIVATE"),
                                                  body_validator=lambda *_args: None)
        with self.assertRaisesRegex(network.BoundaryViolation, "possible_sensitive_indicator"):
            stream.read()
        self.assertIsNone(stream._buffer)

    def test_validator_stop_categories_are_fixed_and_never_echo_unknown_reasons(self):
        class Stop(Exception):
            def __init__(self, reason): self.reason = reason
        for reason in ("possible_sensitive_indicator", "possible_compromise_indicator", "private-target-value", []):
            def validate(_body, _headers): raise Stop(reason)
            transport, connection, stream = self.use(Response(b"safe"), body_validator=validate)
            with self.assertRaises(network.BoundaryViolation) as refused:
                stream.read(1)
            self.assertEqual(refused.exception.reason,
                             reason if type(reason) is str and reason.startswith("possible_") else "profile_response_failed")
            self.assertTrue(connection.closed)
            self.assertIsNone(stream._buffer)

    def test_header_indicator_and_access_restrictions_stop_without_body(self):
        for response in (Response(b"body", headers={"X-Notice": "-----BEGIN PRIVATE KEY-----"}),
                         Response(b"body", status=403), Response(b"body", status=429), Response(b"body", status=503)):
            transport, connection, stream = self.use(response)
            with self.assertRaises(network.BoundaryViolation):
                stream.read()
            if response.status != 200:
                self.assertEqual(response.reads, 0)

    def test_no_credentials_or_proxy_headers_are_forwarded(self):
        request = Request(TARGET, headers={"Authorization": "sentinel", "Cookie": "sentinel",
                                          "Host": "other.example", "Proxy-Authorization": "sentinel"})
        _transport, connection, stream = self.use(Response(), request=request)
        stream.close()
        sent = connection.requests[0][1]["headers"]
        self.assertEqual(set(sent), {"Connection", "Accept-Encoding"})

    def test_unsafe_dns_prevents_connection(self):
        transport = opener()
        for addresses in ([[socket.AF_INET, socket.SOCK_STREAM, 6, "", ["127.0.0.1", 80]]],
                          PUBLIC_ANSWERS + [[socket.AF_INET, socket.SOCK_STREAM, 6, "", ["10.0.0.1", 80]]]):
            with mock.patch.object(network_dns, "resolve_answers", return_value=addresses), \
                    mock.patch.object(network, "_ProfileHTTPConnection") as connection:
                with self.assertRaises(network.BoundaryViolation):
                    transport.open(Request(TARGET))
                connection.assert_not_called()
            # A refused attempt poisons its job; a second scenario uses a fresh job.
            transport = opener()


class AdmissionTests(unittest.TestCase):
    def grant(self, sequence, kind):
        return {"ok": True, "admitted": True, "sequence": sequence, "valid_ms": 1000,
                "timeout_ms": 10000, "http_remaining": 99, "kind": kind,
                "profile_sha256": PROFILE_SHA256, "tls_remaining": 20 if kind == "http" else 19,
                "body_bytes_remaining": 4980736, "active_ms_remaining": 600000 - sequence * 10000}

    def claim(self):
        return SimpleNamespace(profile_id="external-web-v1", profile_sha256=PROFILE_SHA256,
                               services=(("http", 80), ("https", 443)),
                               expires_at=datetime.fromtimestamp(time.time() + 300, timezone.utc))

    def test_external_strict_schema_and_profile_binding(self):
        valid = self.grant(1, "http")
        self.assertEqual(admission.parse_external_grant(valid, kind="http", profile_sha256=PROFILE_SHA256).sequence, 1)
        for changed in ({**valid, "profile_sha256": "0" * 64}, {**valid, "kind": "tls"},
                        {**valid, "http_remaining": True}, {**valid, "timeout_ms": 10001},
                        {**valid, "body_bytes_remaining": -1}, {**valid, "extra": 1}):
            with self.assertRaises(admission.AdmissionDenied):
                admission.parse_external_grant(changed, kind="http", profile_sha256=PROFILE_SHA256)

    def test_one_gate_carries_both_kinds_and_rejects_replay(self):
        responses = [self.grant(1, "http"), self.grant(2, "tls"), self.grant(2, "tls")]
        calls = []
        api = SimpleNamespace(admit=lambda claim, kind: calls.append(kind) or responses.pop(0))
        gate = admission.AdmissionGate(api, self.claim(), kind="external")
        gate.admit(kind="http")
        gate.admit(kind="tls")
        with self.assertRaisesRegex(admission.AdmissionDenied, "replayed"):
            gate.admit(kind="tls")
        self.assertEqual(calls, ["http", "tls", "tls"])

    def test_pump_uses_combined_sequence_and_one_inflight_slot(self):
        parent, child = socket.socketpair()
        self.addCleanup(parent.close)
        self.addCleanup(child.close)
        kinds = []
        gate = SimpleNamespace(kind="external", admit=lambda *, kind: kinds.append(kind) or
                               admission.Grant(len(kinds), 1, 10, 1, time.monotonic()))
        pump = admission.AdmissionPump(parent, gate, kind="external")
        self.assertIsNone(pump._handle(b'{"op":"admit","kind":"http","n":1}'))
        child.recv(1024)
        self.assertIsNone(pump._handle(b'{"op":"done","n":1}'))
        self.assertIsNone(pump._handle(b'{"op":"admit","kind":"tls","n":2}'))
        child.recv(1024)
        self.assertIn("protocol", pump._handle(b'{"op":"admit","kind":"http","n":3}'))
        self.assertEqual(kinds, ["http", "tls"])

    def test_malformed_kind_is_a_refusal_not_an_exception(self):
        parent, child = socket.socketpair()
        self.addCleanup(parent.close)
        self.addCleanup(child.close)
        pump = admission.AdmissionPump(parent, SimpleNamespace(kind="external"), kind="external")
        self.assertIn("protocol", pump._handle(b'{"op":"admit","kind":[],"n":1}'))


class DNSAndTLSBoundaryTests(unittest.TestCase):
    # The worker's runner/scanner refuse non-Linux execution. These exercise
    # its clean resolver environment and POSIX process/descriptor lifecycle,
    # unlike the portable pure admission, TLS metadata and budget tests below.
    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux worker resolver process isolation")
    def test_dns_timeout_kills_and_reaps_the_helper(self):
        processes = []
        real_popen = subprocess.Popen
        def start(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process
        started = time.monotonic()
        with mock.patch.object(network_dns, "_LOOKUP", "import time;time.sleep(30)"), \
                mock.patch.object(network_dns.subprocess, "Popen", side_effect=start):
            with self.assertRaisesRegex(network_dns.DNSFailure, "timeout"):
                network_dns.resolve_answers("localhost", 80, 0.1)
        self.assertLess(time.monotonic() - started, 1)
        self.assertIsNotNone(processes[0].returncode)
        if os.name == "posix":
            with self.assertRaises(ChildProcessError):
                os.waitpid(processes[0].pid, os.WNOHANG)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux worker resolver process isolation")
    def test_dns_helper_gets_no_parent_secrets_or_inherited_channel(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        os.set_inheritable(read_fd, True)
        script = ("import json,os;closed=False\n"
                  "try:os.fstat(" + str(read_fd) + ")\n"
                  "except OSError:closed=True\n"
                  "assert closed and 'CT_PRIVATE_SENTINEL' not in os.environ\n"
                  "print(json.dumps([[2,1,6,'',['127.0.0.1',80]]]))")
        with mock.patch.dict(os.environ, {"CT_PRIVATE_SENTINEL": "never-forward"}), \
                mock.patch.object(network_dns, "_LOOKUP", script):
            answers = network_dns.resolve_answers("localhost", 80, 1)
        self.assertEqual(answers[0][4], ["127.0.0.1", 80])

    def test_tls_only_never_sends_http_or_returns_raw_certificate(self):
        guard = Guard()
        transport = opener(guard=guard)
        tls_socket = SimpleNamespace(
            getpeercert=lambda: {"notAfter": "Nov 14 00:00:00 2030 GMT", "secret": "not-returned"},
            version=lambda: "TLSv1.3")
        connection = SimpleNamespace(sock=tls_socket, connect=mock.Mock(), close=mock.Mock(), request=mock.Mock())
        with mock.patch.object(transport, "_connection", return_value=connection):
            result = transport.inspect_tls("https://fixture.example/")
        self.assertEqual(result, {"verified": True, "protocol": "TLSv1.3", "not_after": "2030-11-14T00:00:00Z"})
        self.assertEqual(guard.kinds, ["tls"])
        connection.request.assert_not_called()
        connection.close.assert_called_once()
        self.assertFalse(transport.meter.inflight)

    def test_insecure_tls_context_refused_before_any_admission(self):
        import ssl
        context = ssl._create_unverified_context()
        guard = Guard()
        with self.assertRaisesRegex(ValueError, "verification"):
            opener(guard=guard, ssl_context=context)
        self.assertEqual(guard.kinds, [])

    def test_count_duration_and_redirect_ceilings_cannot_reset(self):
        class Clock:
            now = 0.0
            def __call__(self): return self.now
        for kind, maximum in (("http", 100), ("tls", 20)):
            clock = Clock()
            meter = network.ProfileMeter(monotonic=clock)
            for _ in range(maximum):
                meter.begin(kind)
                meter.done()
                clock.now += 1
            with self.assertRaises(network.BoundaryViolation):
                meter.begin(kind)
        clock = Clock()
        meter = network.ProfileMeter(monotonic=clock)
        clock.now = 600
        with self.assertRaises(network.BoundaryViolation):
            meter.begin("http")
        meter = network.ProfileMeter()
        for _ in range(3): meter.redirect()
        with self.assertRaisesRegex(network.BoundaryViolation, "redirect"):
            meter.redirect()


class TrickleTests(unittest.TestCase):
    def fixture(self, *, headers=False):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(4096)
                try:
                    if headers:
                        self.request.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                    else:
                        self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
                    for _ in range(100):
                        self.request.sendall(b"x")
                        time.sleep(0.02)
                except OSError:
                    pass
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        def connect(connection, deadline):
            # Owned loopback fixture only. Address-safety is separately tested;
            # production resolver/classifier code is never changed by this test.
            connection._before_connect()
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connection.sock = raw
            raw.settimeout(deadline.remaining())
            deadline.attach(raw)
            raw.connect(server.server_address)
            return raw
        return connect

    # Cross-thread shutdown of a duplicated socket enforces the Linux worker's
    # hard deadline. Preserve its strict bound on the supported runtime rather
    # than relaxing it to cover Windows socket cancellation behavior.
    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux worker hard socket deadline")
    def test_body_deadline_survives_connection_sock_handoff(self):
        transport = opener()
        started = time.monotonic()
        with mock.patch.object(network_dns, "resolve_answers", return_value=PUBLIC_ANSWERS), \
                mock.patch.object(network, "_profile_socket", self.fixture()):
            stream = transport.open(Request(TARGET), timeout=0.15)
            self.assertIsNone(stream._connection.sock)
            with self.assertRaises(network.BoundaryViolation):
                stream.read()
        self.assertLess(time.monotonic() - started, 0.8)
        self.assertFalse(transport.meter.inflight)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux worker hard socket deadline")
    def test_slow_header_has_total_not_inactivity_deadline(self):
        transport = opener()
        started = time.monotonic()
        with mock.patch.object(network_dns, "resolve_answers", return_value=PUBLIC_ANSWERS), \
                mock.patch.object(network, "_profile_socket", self.fixture(headers=True)):
            with self.assertRaises(network.BoundaryViolation):
                stream = transport.open(Request(TARGET), timeout=0.15)
                stream.read()
        self.assertLess(time.monotonic() - started, 0.8)
        self.assertFalse(transport.meter.inflight)

    def test_real_head_does_not_read_or_decompress_unexpected_body(self):
        completed = threading.Event()
        sent = []
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(4096)
                try:
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n")
                    time.sleep(0.05)
                    for _ in range(64):
                        self.request.sendall(b"x" * 16384)
                        sent.append(16384)
                        time.sleep(0.01)
                except OSError:
                    pass
                finally:
                    completed.set()
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        def connect(connection, deadline):
            connection._before_connect()
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connection.sock = raw
            deadline.attach(raw)
            raw.connect(server.server_address)
            return raw
        transport = opener()
        with mock.patch.object(network_dns, "resolve_answers", return_value=PUBLIC_ANSWERS), \
                mock.patch.object(network, "_profile_socket", connect), \
                mock.patch.object(network._BoundedHTTPResponse, "read", side_effect=AssertionError("HEAD body read")):
            with transport.open(Request(TARGET, method="HEAD"), timeout=0.5) as stream:
                self.assertEqual(stream.read(), b"")
        self.assertTrue(completed.wait(1))
        self.assertLess(sum(sent), 1048576)
        self.assertEqual(transport.meter.body_used, 0)


if __name__ == "__main__":
    unittest.main()
