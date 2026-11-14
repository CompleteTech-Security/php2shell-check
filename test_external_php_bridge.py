"""Actual executor -> runner -> callback -> PHP validator, injected transports only.

Run with CT_EXTERNAL_BRIDGE_PHP=/trusted/php python -m unittest -v
 test_external_php_bridge. PHP absence is an explicit optional-platform skip;
CI can make it mandatory by setting the executable path.
"""
from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import unittest
from unittest.mock import patch

from integrations.worker.external import ProfileStopped
from integrations.worker.network import RequestOrigin
from integrations.worker.profiles import PROFILE_ID, PROFILE_SHA256
from integrations.worker.protocol import profile_fields
from integrations.worker.runner import ScannerFailure, SubprocessRunner
from integrations.worker.service import WorkerService
import test_external_executor as fixtures
from test_external_executor import Transport, Response, success_responses
from test_scan_worker import _claim

PHP = os.environ.get("CT_EXTERNAL_BRIDGE_PHP") or shutil.which("php")
BRIDGE = Path(__file__).parent / "integrations/wordpress/standalone-tests/external-result-wire.php"
SERVICES = [{"scheme": "http", "port": 80}, {"scheme": "https", "port": 443}]
TARGET = "https://fixture.example.net/"
REVISION = "1" * 40


@unittest.skipUnless(PHP, "PHP is unavailable; set CT_EXTERNAL_BRIDGE_PHP for required bridge checks")
class ExternalPhpBridgeTests(unittest.TestCase):
    def setUp(self):
        # Every transport is injected. A future regression must never fall back
        # to real DNS, TCP or TLS while generating this fixture.
        self.no_network = patch.object(socket, "create_connection", side_effect=AssertionError("fixture attempted TCP"))
        self.no_dns = patch.object(socket, "getaddrinfo", side_effect=AssertionError("fixture attempted DNS"))
        self.no_network.start(); self.no_dns.start()
        self.addCleanup(self.no_network.stop); self.addCleanup(self.no_dns.stop)
        self.service = WorkerService(None, None, None, REVISION)

    def claim(self, target=TARGET, services=None):
        return replace(_claim(target=target), lease="a" * 64, profile_id=PROFILE_ID, profile_sha256=PROFILE_SHA256,
                       services=tuple((v["scheme"], v["port"]) for v in (services or [SERVICES[1]])))

    def execute(self, responses, *, claim=None, tls=None):
        claim = claim or self.claim()
        fixture = fixtures.ExecutorTests()
        transport = Transport(responses)
        result = fixture.run_profile(transport, target=claim.target, services=profile_fields(claim)["services"], tls=tls)
        scope = RequestOrigin.from_target(claim.target)[0]
        self.assertIs(SubprocessRunner.validate_result(result, claim.target, scope, claim=claim), result)
        self.assertFalse(transport.responses, "fixture left unused responses")
        return result

    def callback(self, claim, result=None, *, error=""):
        return json.loads(self.service._callback_body(claim.job_id, claim.lease, claim.scope_hash,
            "failed" if error else "completed", result, error, claim=claim))

    def php(self, claim, callback):
        wire = {"target": claim.target, "binding": profile_fields(claim), "callback": callback}
        proc = subprocess.run([PHP, str(BRIDGE)], input=json.dumps(wire, ensure_ascii=False),
                              capture_output=True, text=True, timeout=10, check=True)
        self.assertEqual(proc.stderr, "", "PHP emitted a warning or private fixture data")
        return json.loads(proc.stdout)

    def accepted(self, claim, result):
        callback = self.callback(claim, result)
        text = json.dumps(callback)
        for private in ("PRIVATE-TITLE-SENTINEL", "RAW-SERVER-SENTINEL", "PRIVATE-KEY-SENTINEL"):
            self.assertNotIn(private, text)
        self.assertEqual(self.php(claim, callback), {"accepted": True, "error": ""})

    def test_selected_service_variants(self):
        for services, target in (([SERVICES[0]], "http://fixture.example.net/"),
                                 ([SERVICES[1]], TARGET),
                                 (SERVICES, TARGET),
                                 (SERVICES, "http://fixture.example.net/")):
            with self.subTest(services=services, target=target):
                claim = self.claim(target, services)
                result = self.execute(success_responses() * len(services), claim=claim)
                self.accepted(claim, result)

    def test_reported_version_and_safe_unknown_variants(self):
        for version in ("8.3.35", "8.3.36", "8.4.27", "7.4.33", "8.3.36-vendor1", "8.3.36-rc1", "8.3"):
            with self.subTest(version=version):
                claim = self.claim(); self.accepted(claim, self.execute(success_responses(version), claim=claim))
        claim = self.claim()
        self.accepted(claim, self.execute([Response(body=b"User-agent: *\nAllow: /\n"),
            Response(body=b"<html>Public page without PHP metadata</html>"), Response(no_read=True)], claim=claim))
        self.accepted(claim, self.execute([Response(body=b"User-agent: *\nDisallow: /\n")], claim=claim))
        both = self.claim(services=SERVICES)
        self.accepted(both, self.execute(success_responses("8.3.35") + success_responses("8.3.36"), claim=both))
        self.accepted(both, self.execute(success_responses() + [Response(status=404), Response(status=404)], claim=both))
        def tls_failure(_service): raise OSError("SYNTHETIC PRIVATE TLS DETAIL")
        self.accepted(claim, self.execute(success_responses(), claim=claim, tls=tls_failure))

    def test_possible_indicator_stops_emit_only_safe_bound_failure(self):
        for body, reason in ((b"-----BEGIN PRIVATE KEY-----\nPRIVATE-KEY-SENTINEL", "possible_sensitive_indicator"),
                             (b"This page says Hacked by PRIVATE-COMPROMISE-SENTINEL", "possible_compromise_indicator")):
            with self.subTest(reason=reason):
                claim = self.claim()
                with self.assertRaises(ProfileStopped) as caught:
                    self.execute([Response(body=b"User-agent: *\nAllow: /\n"), Response(body=body)], claim=claim)
                self.assertEqual(str(caught.exception), reason)
                callback = self.callback(claim, error=reason)
                self.assertIsNone(callback["result"])
                self.assertNotIn("SENTINEL", json.dumps(callback))
                self.assertEqual(self.php(claim, callback), {"accepted": True, "error": ""})

    def test_actual_executor_result_tampering_refused_by_both_boundaries(self):
        claim = self.claim(); result = self.execute(success_responses(), claim=claim)
        for edit in (lambda r: r.update(title="PRIVATE-TITLE-SENTINEL"),
                     lambda r: r.update(profile_sha256="0" * 64),
                     lambda r: r["checks"][0]["evidence"].update(raw="PRIVATE"),
                     lambda r: r["checks"][0].update(service="http:80"),
                     lambda r: r["manual_remainder"].pop()):
            bad = deepcopy(result); edit(bad)
            with self.assertRaises(ScannerFailure):
                SubprocessRunner.validate_result(bad, claim.target, RequestOrigin.from_target(claim.target)[0], claim=claim)
            self.assertFalse(self.php(claim, self.callback(claim, bad))["accepted"])
        callback = self.callback(claim, result)
        callback.pop("profile_sha256")
        self.assertFalse(self.php(claim, callback)["accepted"])
        callback = self.callback(claim, result); callback["services"] = [SERVICES[0]]
        self.assertFalse(self.php(claim, callback)["accepted"])


if __name__ == "__main__":
    unittest.main()
