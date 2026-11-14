"""Offline frozen-profile claim, callback and recovery regressions."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import io
import json
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from integrations.worker.protocol import APIClient, APIError, profile_fields, validate_claim
from integrations.worker.profiles import PROFILE_ID, PROFILE_SHA256
from integrations.worker.runner import ScannerFailure, SubprocessRunner
from integrations.worker.service import WorkerService
from integrations.worker.spool import DurableSpool, SpoolError
from integrations.worker.network import RequestOrigin
from test_scan_worker import _claim, _result, _FakeAPI, NOW, REVISION, TARGET


def claim():
    return replace(_claim(), profile_id=PROFILE_ID, profile_sha256=PROFILE_SHA256,
                   services=(("https", 443),))


def result():
    value = _result()
    value.update(profile_fields(claim()))
    value["checks"] = [
        {"id": "robots_policy", "service": "https:443", "outcome": "observed", "evidence": {"http_status": 200, "allowed": True}},
        {"id": "public_header_triage", "service": "https:443", "outcome": "observed", "evidence": {"http_status": 200, "fetch_status": "ok"}},
        {"id": "security_header_presence", "service": "https:443", "outcome": "observed", "evidence": {"http_status": 200, "hsts": True, "csp": False, "frame_control": True, "mime_options": False}},
        {"id": "tls_certificate", "service": "https:443", "outcome": "observed", "evidence": {"verification": "verified", "protocol": "TLSv1.3", "not_after": "2027-01-01T00:00:00Z"}},
    ]
    value["manual_remainder"] = [{"id": key, "status": "not_assessed"} for key in (
        "runtime_and_backport_confirmation", "internal_configuration_review", "compromise_investigation")]
    return value


class ExternalWireTests(unittest.TestCase):
    def wire(self, value):
        return {"job": {"id": value.job_id, "target": value.target,
            "scope_hash": value.scope_hash, "terms_hash": value.terms_hash,
            "expires_at": int(value.expires_at.timestamp()), "lease": value.lease,
            "lease_until": int(value.lease_until.timestamp()), **profile_fields(value)}}

    def test_legacy_shape_and_external_binding(self):
        legacy = self.wire(_claim())
        self.assertEqual(len(legacy["job"]), 7)
        self.assertEqual(validate_claim(legacy, now=datetime.fromtimestamp(NOW, timezone.utc)), _claim())
        wire = self.wire(claim())
        self.assertEqual(len(wire["job"]), 10)
        self.assertEqual(validate_claim(wire, now=datetime.fromtimestamp(NOW, timezone.utc)), claim())

    def test_claim_refuses_unknown_partial_digest_reorder_or_primary_service(self):
        for edit in (
            lambda x: x.pop("profile_sha256"),
            lambda x: x.update(profile_id="unknown"),
            lambda x: x.update(profile_sha256="0" * 64),
            lambda x: x.update(services=[{"scheme": "http", "port": 80}]),
            lambda x: x.update(services=[{"scheme": "https", "port": 443}, {"scheme": "http", "port": 80}]),
            lambda x: x.update(services=[{"scheme": "https", "port": True}]),
            lambda x: x.update(extra=True),
        ):
            value = self.wire(claim())
            edit(value["job"])
            with self.assertRaises(APIError):
                validate_claim(value, now=datetime.fromtimestamp(NOW, timezone.utc))

    def test_result_typed_observations_and_no_raw_sensitive_fields(self):
        scope, _ = RequestOrigin.from_target(TARGET)
        value = result()
        self.assertIs(SubprocessRunner.validate_result(value, TARGET, scope, claim=claim()), value)
        edits = [
            lambda x: x.update(title="Private content"),
            lambda x: x.update(profile_sha256="0" * 64),
            lambda x: x["checks"].append(deepcopy(x["checks"][0])),
            lambda x: x["checks"][0]["evidence"].update(raw="Private content"),
            lambda x: x["checks"][0]["evidence"].update(allowed=1),
            lambda x: x["checks"][3]["evidence"].update(not_after="2027-02-31T00:00:00Z"),
            lambda x: x["manual_remainder"].pop(),
            lambda x: x["manual_remainder"][0].update(status="certified"),
            lambda x: x["checks"][0].update(service="http:80"),
            lambda x: x["checks"][0].update(outcome="unknown"),
            lambda x: x["checks"][1].update(outcome="blocked"),
            lambda x: x["checks"][2].update(evidence={"reason": "private_header_value"}, outcome="unknown"),
            lambda x: x["checks"][3].update(evidence={"reason": "service_not_assessed"}, outcome="observed"),
        ]
        for edit in edits:
            value = result()
            edit(value)
            with self.assertRaises(ScannerFailure):
                SubprocessRunner.validate_result(value, TARGET, scope, claim=claim())

    def test_real_executor_fixture_results_validate_for_all_selected_services(self):
        from test_external_executor import ExecutorTests, Transport, Response, success_responses
        fixture = ExecutorTests()
        cases = [
            ((("https", 443),), success_responses()),
            ((("http", 80),), success_responses()),
            ((("http", 80), ("https", 443)), success_responses("8.3.35") + success_responses()),
            ((("https", 443),), [Response(body=b"User-agent: *\nDisallow: /\n")]),
            ((("http", 80), ("https", 443)), success_responses() + [Response(status=404), Response(status=404)]),
        ]
        for selected, responses in cases:
            target = "http://example.test/" if len(selected) == 1 and selected[0][0] == "http" else TARGET
            current = replace(claim(), target=target, scope_hash=hashlib.sha256(target.encode()).hexdigest(), services=selected)
            value = fixture.run_profile(Transport(responses), target=target, services=profile_fields(current)["services"])
            with self.subTest(services=selected, status=value["status"]):
                SubprocessRunner.validate_result(value, target, RequestOrigin.from_target(target)[0], claim=current)

    def test_tls_admission_requires_pinned_external_claim(self):
        client = APIClient(b"x" * 32, transport=Mock())
        with patch.object(client, "post", return_value={"ok": True}) as post:
            with self.assertRaises(APIError):
                client.admit(_claim(), "tls")
            post.assert_not_called()
            client.admit(claim(), "tls")
            self.assertEqual(post.call_args.args[1]["kind"], "tls")
            with self.assertRaises(APIError):
                client.admit(claim(), "control")
            with self.assertRaises(APIError):
                client.admit(replace(claim(), profile_sha256="0" * 64), "tls")

    def test_running_recovery_posts_same_binding_without_scanner_or_claim(self):
        with tempfile.TemporaryDirectory() as root:
            spool = DurableSpool(root)
            spool.prepare()
            spool.save_running(claim(), REVISION, NOW - 181)
            api, runner = _FakeAPI(), Mock()
            service = WorkerService(api, spool, runner, REVISION, clock=lambda: NOW)
            self.assertEqual(service.process_once(), "callback_accepted")
            payload = json.loads(api.result_bodies[0])
            self.assertEqual(payload["outcome"], "failed")
            self.assertEqual(payload["error"], "scanner_interrupted")
            self.assertIsNone(payload["result"])
            for key, value in profile_fields(claim()).items():
                self.assertEqual(payload[key], value)
            runner.run.assert_not_called()
            self.assertEqual(api.claim_calls, 0)
            self.assertEqual(spool.active_uncertain(NOW), [])

    def test_callback_retry_exact_bytes_and_downgrade_refused(self):
        with tempfile.TemporaryDirectory() as root:
            spool = DurableSpool(root)
            spool.prepare()
            service = WorkerService(_FakeAPI(), spool, Mock(), REVISION, clock=lambda: NOW)
            body = service._callback_body(claim().job_id, claim().lease, claim().scope_hash,
                "completed", result(), "", claim=claim())
            path = spool.save_callback(claim(), body)
            self.assertEqual(spool.save_callback(claim(), body), path)
            self.assertEqual(spool.callback_records()[0][1]["body"].encode(), body)
            record = json.loads(path.read_text())
            payload = json.loads(record["body"])
            for key in profile_fields(claim()):
                payload.pop(key)
            record["body"] = json.dumps(payload)
            path.write_text(json.dumps(record))
            with self.assertRaises(SpoolError):
                spool.callback_records()

    def test_service_completes_with_bound_runner_and_additive_callback(self):
        with tempfile.TemporaryDirectory() as root:
            spool = DurableSpool(root)
            spool.prepare()
            runner = Mock()
            runner.run.return_value = result()
            api = _FakeAPI(claim())
            with patch("integrations.worker.service.AdmissionGate") as gate:
                service = WorkerService(api, spool, runner, REVISION, clock=lambda: NOW)
                self.assertEqual(service.process_once(), "callback_accepted")
                self.assertEqual(gate.call_args.kwargs["kind"], "external")
                self.assertEqual(runner.run.call_args.kwargs["claim"], claim())
                self.assertLessEqual(runner.run.call_args.kwargs["timeout"], 180)
            payload = json.loads(api.result_bodies[0])
            self.assertEqual(payload["outcome"], "completed")
            self.assertEqual(len(payload), 10)
            for key, value in profile_fields(claim()).items():
                self.assertEqual(payload[key], value)
                self.assertEqual(payload["result"][key], value)

    def test_service_failure_also_carries_profile_and_retry_never_rescans(self):
        with tempfile.TemporaryDirectory() as root:
            spool = DurableSpool(root)
            spool.prepare()
            runner = Mock()
            runner.run.side_effect = ScannerFailure("admission_refused")
            api = _FakeAPI(claim(), result_errors=[APIError("network"), None])
            with patch("integrations.worker.service.AdmissionGate"):
                service = WorkerService(api, spool, runner, REVISION, clock=lambda: NOW)
                self.assertEqual(service.process_once(), "callback_pending_network")
                self.assertEqual(service.process_once(), "callback_accepted")
            self.assertEqual(runner.run.call_count, 1)
            self.assertEqual(api.result_bodies[0], api.result_bodies[1])
            payload = json.loads(api.result_bodies[0])
            self.assertEqual(payload["outcome"], "failed")
            self.assertIsNone(payload["result"])
            self.assertEqual(payload["error"], "admission_refused")
            self.assertEqual(payload["profile_sha256"], PROFILE_SHA256)

    @unittest.skipUnless(sys.platform.startswith("linux"), "scanner entry requires Linux isolation")
    def test_scanner_dispatch_shares_one_meter_transport_and_admission_channel(self):
        from integrations.worker import scanner, network, external
        selected = replace(claim(), services=(("http", 80), ("https", 443)))
        message = {"target": TARGET, **profile_fields(selected)}
        scope, meter, opener, channel, guard = Mock(), Mock(), Mock(), Mock(), Mock()
        guard.kind = "external"
        opener.inspect_tls.return_value = {"verified": True, "protocol": "TLSv1.3", "not_after": ""}
        def execute(target, digest, services, *, transport_factory, tls_probe):
            self.assertEqual((target, digest, services), (TARGET, PROFILE_SHA256, message["services"]))
            self.assertIs(transport_factory(services[0]), opener)
            self.assertIs(transport_factory(services[1]), opener)
            self.assertEqual(tls_probe(services[1])["verified"], True)
            return result()
        class Boundary(Exception):
            pass
        with patch.object(scanner.os, "geteuid", return_value=65534), \
             patch.object(scanner.signal, "alarm"), \
             patch.object(scanner.sys, "stdin", Mock(buffer=io.BytesIO(json.dumps(message).encode()))), \
             patch.object(scanner, "_admission_channel", return_value=channel), \
             patch.object(scanner, "ChildAdmission", return_value=guard) as child, \
             patch.object(scanner, "_write", side_effect=lambda value, code: (value, code)), \
             patch.object(network, "ProfileScope", create=True) as scope_class, \
             patch.object(network, "ProfileMeter", return_value=meter, create=True) as meter_class, \
             patch.object(network, "ExternalPinnedOpener", return_value=opener, create=True) as opener_class, \
             patch.object(network, "BoundaryViolation", Boundary, create=True), \
             patch.object(external, "execute_external", side_effect=execute):
            scope_class.from_target.return_value = (scope, TARGET)
            value, code = scanner.main()
            self.assertEqual(code, 0)
            self.assertTrue(value["ok"])
            child.assert_called_once_with(channel, kind="external")
            meter_class.assert_called_once_with()
            self.assertEqual(opener_class.call_args.kwargs["profile_sha256"], PROFILE_SHA256)
            self.assertIs(opener_class.call_args.kwargs["meter"], meter)
            validator = opener_class.call_args.kwargs["body_validator"]
            with self.assertRaises(external.ProfileStopped):
                validator(b"-----BEGIN PRIVATE KEY-----", {})
            opener.inspect_tls.assert_called_once_with("https://example.test/")

    def test_start_marker_freezes_binding_before_ambiguous_start(self):
        with tempfile.TemporaryDirectory() as root:
            spool = DurableSpool(root)
            spool.prepare()
            runner = Mock()
            service = WorkerService(_FakeAPI(claim(), start_error=APIError("network")), spool,
                                    runner, REVISION, clock=lambda: NOW)
            self.assertEqual(service.process_once(), "start_uncertain")
            marker = spool.active_uncertain(NOW)[0]
            for key, value in profile_fields(claim()).items():
                self.assertEqual(marker[key], value)
            self.assertEqual(service.process_once(), "waiting_for_lease")
            runner.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
