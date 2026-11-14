"""Synthetic transport tests; no target, database or production requests."""

from dataclasses import fields
from email.message import Message
import json
import unittest
from unittest import mock

from wordpress_check import Result
from integrations.worker import external as E, profiles as P
from integrations.worker.network import RequestOrigin
from integrations.worker.runner import SubprocessRunner


TARGET = "https://example.test/"
HTTPS = [{"scheme": "https", "port": 443}]


class Clock:
    def __init__(self): self.value = 0.0
    def __call__(self): return self.value
    def sleep(self, value): self.value += value


class Response:
    def __init__(self, status=200, body=b"", headers=None, no_read=False):
        self.code, self.body, self.no_read = status, body, no_read
        self.headers = Message()
        for name, value in (headers or {}).items(): self.headers[name] = value
        self.closed, self.reads = False, 0
    def read(self, size=-1):
        self.reads += 1
        if self.no_read: raise AssertionError("metadata body was read")
        return self.body if size < 0 else self.body[:size]
    def close(self): self.closed = True
    def __enter__(self): return self
    def __exit__(self, *_args): self.close()


class Transport:
    def __init__(self, responses): self.responses, self.requests = list(responses), []
    def open(self, request, timeout=None):
        self.requests.append((request.get_method(), request.full_url, timeout))
        if not self.responses: raise AssertionError("unexpected additional request")
        return self.responses.pop(0)


def success_responses(version="8.3.36"):
    return [Response(body=b"User-agent: *\nAllow: /\n"),
            Response(body=b'<html><title>PRIVATE-TITLE-SENTINEL</title><meta name="generator" content="WordPress 6.8.3"></html>',
                     headers={"Content-Type": "text/html", "X-Powered-By": "PHP/" + version, "Server": "RAW-SERVER-SENTINEL"}),
            Response(headers={"Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "default-src 'self'"}, no_read=True)]


class ExecutorTests(unittest.TestCase):
    def run_profile(self, transport, *, services=None, target=TARGET, tls=None, clock=None, digest=P.PROFILE_SHA256):
        self.clock = clock or Clock()
        self.tls_calls = []
        def probe(service):
            self.tls_calls.append(service)
            if tls is not None: return tls(service)
            return {"verified": True, "protocol": "TLSv1.3", "not_after": "2099-01-01T00:00:00Z"}
        with mock.patch.object(E.time, "sleep", side_effect=self.clock.sleep):
            return E.execute_external(target, digest, services or HTTPS,
                                      transport_factory=lambda _service: transport, tls_probe=probe, clock=self.clock)

    def test_real_checker_result_compatible_and_raw_content_omitted(self):
        responses = success_responses()
        transport = Transport(responses)
        result = self.run_profile(transport)
        self.assertEqual([method for method, _url, _timeout in transport.requests], ["GET", "GET", "HEAD"])
        self.assertEqual(result["profile_id"], P.PROFILE_ID)
        self.assertEqual(result["php_version"], "8.3.36")
        self.assertEqual(result["php2shell_exploitability"], "not_tested")
        self.assertEqual(len(result["checks"]), 4)
        self.assertTrue(all(item["status"] == "not_assessed" for item in result["manual_remainder"]))
        text = json.dumps(result)
        for sentinel in ("PRIVATE-TITLE-SENTINEL", "RAW-SERVER-SENTINEL", "WordPress 6.8.3"):
            self.assertNotIn(sentinel, text)
        self.assertEqual(result["notes"], [])
        core = {field.name: result[field.name] for field in fields(Result)}
        self.assertEqual(SubprocessRunner.validate_result(core, TARGET, RequestOrigin.from_target(TARGET)[0]), core)
        self.assertTrue(all(response.closed for response in responses))
        self.assertEqual(responses[-1].reads, 0)

    def test_missing_binding_refuses_before_transport(self):
        transport = Transport([])
        with self.assertRaises(P.ProfileError): self.run_profile(transport, digest="0" * 64)
        self.assertEqual(transport.requests, [])

    def test_target_service_cannot_be_added_implicitly(self):
        transport = Transport([])
        with self.assertRaises(P.ProfileError):
            self.run_profile(transport, services=[{"scheme": "http", "port": 80}])
        self.assertEqual(transport.requests, [])

    def test_robots_denial_stops_all_remaining_connections(self):
        transport = Transport([Response(body=b"User-agent: *\nDisallow: /\n")])
        result = self.run_profile(transport)
        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(self.tls_calls, [])
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["checks"][0]["evidence"]["allowed"])

    def test_sensitive_body_stops_without_emitting_target_bytes(self):
        sentinel = b"-----BEGIN PRIVATE KEY-----\nPRIVATE-KEY-SENTINEL"
        transport = Transport([Response(body=b"User-agent: *\nAllow: /\n"), Response(body=sentinel)])
        with self.assertRaises(E.ProfileStopped) as caught: self.run_profile(transport)
        self.assertEqual(str(caught.exception), "possible_sensitive_indicator")
        self.assertNotIn("SENTINEL", str(caught.exception))
        self.assertEqual(len(transport.requests), 2)
        self.assertEqual(self.tls_calls, [])

    def test_decoded_accumulated_body_hook_detects_split_marker(self):
        E.check_sensitive_response(b"-----BEGIN PRI")
        with self.assertRaises(E.ProfileStopped): E.check_sensitive_response(b"-----BEGIN PRIVATE KEY-----")

    def test_possible_compromise_indicator_is_not_a_diagnosis(self):
        with self.assertRaises(E.ProfileStopped) as caught:
            E.check_sensitive_response(b"This page says Hacked by SYNTHETIC fixture")
        self.assertEqual(str(caught.exception), "possible_compromise_indicator")

    def test_header_limit_checked_before_body_and_response_closed(self):
        response = Response(headers={"X-Large": "A" * 32768}, no_read=True)
        transport = Transport([response])
        with self.assertRaises(E.ProfileStopped) as caught: self.run_profile(transport)
        self.assertEqual(str(caught.exception), "response_header_limit")
        self.assertTrue(response.closed)
        self.assertEqual(response.reads, 0)

    def test_body_limit_and_unsupported_compression_refuse(self):
        for response, reason in ((Response(body=b"A" * 262145), "response_body_limit"),
                                 (Response(body=b"GZIP-SENTINEL", headers={"Content-Encoding": "gzip"}, no_read=True), "content_encoding_unavailable")):
            with self.subTest(reason=reason), self.assertRaises(E.ProfileStopped) as caught:
                self.run_profile(Transport([response]))
            self.assertEqual(str(caught.exception), reason)
            self.assertTrue(response.closed)

    def test_access_denial_or_server_error_never_retries(self):
        for status in (401, 403, 407, 429, 451, 500, 503):
            transport = Transport([Response(status=status, no_read=True)])
            with self.subTest(status=status), self.assertRaises(E.ProfileStopped): self.run_profile(transport)
            self.assertEqual(len(transport.requests), 1)

    def test_secret_or_cross_scope_redirect_never_fetched(self):
        for location in ("/wp-config.php", "https://other.test/robots.txt", "/robots.txt?token=PRIVATE", "http://example.test/robots.txt"):
            transport = Transport([Response(status=302, headers={"Location": location}, no_read=True)])
            with self.subTest(location=location), self.assertRaises(E.ProfileStopped): self.run_profile(transport)
            self.assertEqual(len(transport.requests), 1)

    def test_http_only_does_not_probe_https(self):
        transport = Transport(success_responses())
        result = self.run_profile(transport, target="http://example.test/", services=[{"scheme": "http", "port": 80}])
        self.assertEqual(self.tls_calls, [])
        self.assertEqual(result["checks"][-1]["outcome"], "not_selected")
        self.assertTrue(all(url.startswith("http://") for _method, url, _timeout in transport.requests))

    def test_conflicting_services_preserve_version_uncertainty(self):
        transport = Transport(success_responses("8.3.35") + success_responses("8.3.36"))
        result = self.run_profile(transport, services=[{"scheme": "http", "port": 80}, {"scheme": "https", "port": 443}])
        self.assertEqual(result["php_version_candidates"], ["8.3.35", "8.3.36"])
        self.assertEqual(result["php2shell_status"], "unknown")
        self.assertEqual(len(result["checks"]), 8)

    def test_incomplete_selected_service_does_not_project_other_port_version(self):
        transport = Transport(success_responses() + [Response(status=404), Response(status=404)])
        result = self.run_profile(transport, services=[{"scheme": "http", "port": 80}, {"scheme": "https", "port": 443}])
        self.assertEqual(result["php_version_candidates"], [])
        self.assertEqual(result["php2shell_status"], "unknown")
        self.assertEqual(result["notes"], [])
        self.assertEqual(result["checks"][5]["outcome"], "unknown")
        self.assertEqual(self.tls_calls, [])
        core = {field.name: result[field.name] for field in fields(Result)}
        SubprocessRunner.validate_result(core, TARGET, RequestOrigin.from_target(TARGET)[0])

    def test_tls_evidence_cannot_include_raw_certificate_or_invalid_date(self):
        bad = [dict(verified=True, protocol="TLSv1.3", not_after="2099-02-30T00:00:00Z"),
               dict(verified=True, protocol="TLSv1.3", not_after="", raw_certificate="PRIVATE"),
               dict(verified=False, protocol="TLSv1.3", not_after="")]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(E.ProfileStopped):
                self.run_profile(Transport(success_responses()), tls=lambda _service: value)

    def test_deadline_after_transport_closes_before_body_read(self):
        clock, response = Clock(), Response(no_read=True)
        class Slow(Transport):
            def open(self, request, timeout=None):
                clock.value += 601
                return super().open(request, timeout)
        with self.assertRaises(E.ProfileStopped) as caught: self.run_profile(Slow([response]), clock=clock)
        self.assertEqual(str(caught.exception), "active_time_limit")
        self.assertTrue(response.closed)

    def test_aggregate_and_backward_clock_limits(self):
        clock = Clock()
        state = E._State(dict(P.profile_manifest()["limits"], aggregate_body_bytes=4), clock)
        state.consume(b"1234")
        with self.assertRaises(E.ProfileStopped): state.consume(b"5")
        clock.value = -1
        with self.assertRaises(E.ProfileStopped): state.remaining()


if __name__ == "__main__": unittest.main()
