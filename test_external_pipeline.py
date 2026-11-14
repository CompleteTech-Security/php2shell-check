"""Real external scanner/admission chain with in-memory target connections only.

This is a source integration regression, not a privileged worker, WordPress,
database, TLS-handshake or external-network acceptance test.
"""

from datetime import datetime, timezone
import hashlib
import io
import json
import select
import socket
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from integrations.worker import admission, network, network_dns, scanner
from integrations.worker.profiles import PROFILE_ID, PROFILE_SHA256
from integrations.worker.protocol import JobClaim, profile_fields
from integrations.worker.runner import SubprocessRunner


TARGET = "https://example.test/"
ROBOTS = b"User-agent: *\nAllow: /\n"
HOME = b'<html><meta name="generator" content="WordPress 6.8"></html>'


@unittest.skipUnless(sys.platform.startswith("linux"), "scanner entry requires Linux isolation")
class ExternalPipelineTests(unittest.TestCase):
    def run_scanner(self, *, home=HOME):
        expiry = datetime.fromtimestamp(time.time() + 300, timezone.utc)
        claim = JobClaim(1, TARGET, hashlib.sha256(TARGET.encode()).hexdigest(),
                         "a" * 64, expiry, "b" * 32, expiry,
                         PROFILE_ID, PROFILE_SHA256, (("http", 80), ("https", 443)))
        parent, child = socket.socketpair()
        self.addCleanup(parent.close)
        self.addCleanup(child.close)
        stopped = threading.Event()
        kinds, connections, openers, service_errors = [], [], [], []

        class API:
            def admit(self, _claim, kind):
                if kind == "probe":
                    return {"ok": True, "live": True}
                kinds.append(kind)
                http, tls = kinds.count("http"), kinds.count("tls")
                return {"ok": True, "admitted": True, "sequence": len(kinds),
                        "valid_ms": 1000, "timeout_ms": 10000,
                        "http_remaining": 100 - http, "kind": kind,
                        "profile_sha256": PROFILE_SHA256, "tls_remaining": 20 - tls,
                        "body_bytes_remaining": 5242880 - http * 262144,
                        "active_ms_remaining": 600000 - len(kinds) * 10000}

        gate = admission.AdmissionGate(API(), claim, kind="external")
        pump = admission.AdmissionPump(parent, gate, kind="external")

        def serve():
            try:
                while not stopped.is_set():
                    if select.select([parent], [], [], 0.02)[0] and pump.service():
                        return
                    if pump.tick():
                        return
            except BaseException as exc:
                service_errors.append(type(exc).__name__)

        service = threading.Thread(target=serve, daemon=True)
        service.start()

        class Connection:
            def __init__(self, scheme):
                self.scheme, self.method, self.path = scheme, None, None
                self.closed = False
                self.response = None
                self.sock = SimpleNamespace(
                    getpeercert=lambda: {"notAfter": "Nov 14 00:00:00 2030 GMT"},
                    version=lambda: "TLSv1.3")
                connections.append(self)

            def request(self, method, path, headers):
                self.method, self.path = method, path

            def getresponse(self):
                body = ROBOTS if self.path == "/robots.txt" else home
                payload = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                           b"X-Powered-By: PHP/8.3.36\r\nContent-Length: "
                           + str(len(body)).encode() + b"\r\n\r\n" + body)
                stream = io.BytesIO(payload)
                self.response = network._BoundedHTTPResponse(
                    SimpleNamespace(makefile=lambda _mode: stream), method=self.method)
                self.response.begin()
                return self.response

            def connect(self):
                pass

            def close(self):
                self.closed = True

        original_init = network.ExternalPinnedOpener.__init__

        def capture_opener(instance, *args, **kwargs):
            original_init(instance, *args, **kwargs)
            openers.append(instance)

        message = {"target": TARGET, **profile_fields(claim)}
        try:
            # Preserve the actual scanner, ChildAdmission socket protocol,
            # supervisor gate/pump, pinned opener, HTTP parser, meter, executor
            # and result validator. Replace only target connections and the
            # scanner's process-entry IO/identity/alarm setup.
            with patch.object(scanner.os, "geteuid", return_value=65534), \
                    patch.object(scanner.signal, "alarm"), \
                    patch.object(scanner.signal, "signal"), \
                    patch.object(scanner.sys, "stdin", Mock(buffer=io.BytesIO(json.dumps(message).encode()))), \
                    patch.object(scanner, "_admission_channel", return_value=child), \
                    patch.object(scanner, "_write", side_effect=lambda value, code: (value, code)), \
                    patch.object(network.ExternalPinnedOpener, "__init__", capture_opener), \
                    patch.object(network.ExternalPinnedOpener, "_connection",
                                 side_effect=lambda scheme, *_args: Connection(scheme)), \
                    patch.object(network_dns, "resolve_answers", side_effect=AssertionError("unexpected target DNS")), \
                    patch.object(network, "_public_addresses", side_effect=AssertionError("unexpected target DNS")), \
                    patch.object(network, "_profile_socket", side_effect=AssertionError("unexpected target connection")):
                value, code = scanner.main()
            until = time.monotonic() + 1
            while pump.inflight and time.monotonic() < until:
                stopped.wait(0.005)
            self.assertFalse(pump.inflight)
            self.assertIsNone(pump.fatal)
            self.assertEqual(service_errors, [])
            self.assertEqual(len(openers), 1)
            self.assertTrue(all(connection.closed for connection in connections))
            self.assertTrue(all(connection.response is None or connection.response.isclosed()
                                for connection in connections))
            self.assertFalse(openers[0].meter.inflight)
            self.assertEqual(pump.grants, len(kinds))
            self.assertEqual(pump._last_n, len(kinds))
            return value, code, claim, kinds, connections, openers[0].meter
        finally:
            stopped.set()
            service.join(1)
            self.assertFalse(service.is_alive(), "admission fixture thread must stop")
            pump.wait_probe(1)

    def test_real_chain_shares_budget_and_sequences_across_both_services_and_tls(self):
        value, code, claim, kinds, connections, meter = self.run_scanner()
        self.assertEqual(code, 0)
        self.assertIs(value["ok"], True)
        SubprocessRunner.validate_result(value["result"], TARGET,
                                        network.RequestOrigin.from_target(TARGET)[0], claim=claim)
        self.assertEqual(kinds, ["http"] * 6 + ["tls"])
        self.assertEqual((meter.http_used, meter.tls_used), (6, 1))
        self.assertEqual([(item.scheme, item.method, item.path) for item in connections], [
            ("http", "GET", "/robots.txt"), ("http", "GET", "/"), ("http", "HEAD", "/"),
            ("https", "GET", "/robots.txt"), ("https", "GET", "/"), ("https", "HEAD", "/"),
            ("https", None, None)])
        self.assertEqual(meter.body_used, 2 * (len(ROBOTS) + len(HOME)))
        self.assertEqual(meter.wire_used, meter.body_used)
        self.assertIsNone(meter.failure)

    def test_sensitive_body_stops_real_chain_without_later_service_or_tls_admission(self):
        value, code, _claim, kinds, connections, meter = self.run_scanner(
            home=b"-----BEGIN PRIVATE KEY-----synthetic-do-not-return")
        self.assertEqual((value, code), ({"ok": False, "error": "possible_sensitive_indicator"}, 2))
        self.assertEqual(kinds, ["http", "http"])
        self.assertEqual(len(connections), 2)
        self.assertEqual((meter.http_used, meter.tls_used), (2, 0))
        self.assertEqual(meter.failure, "possible_sensitive_indicator")


if __name__ == "__main__":
    unittest.main()
