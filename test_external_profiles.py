"""Local-only identity and scope refusal regressions for the worker profile."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from integrations.worker import profiles as P


class ProfileTests(unittest.TestCase):
    def test_pinned_bytes_and_canonical_identity(self):
        manifest = P.profile_manifest()
        self.assertEqual(P.canonical_json(manifest), P.MANIFEST_PATH.read_bytes())
        self.assertEqual(hashlib.sha256(P.canonical_json(manifest)).hexdigest(), P.profile_digest())
        self.assertEqual(manifest["limits"]["aggregate_body_bytes"], 5 * 1024 * 1024)
        self.assertEqual(manifest["limits"]["response_header_bytes"], 32768)
        self.assertEqual({c["method"] for c in manifest["checks"]}, {"GET", "HEAD", "TLS"})

    def test_returned_object_cannot_change_future_identity(self):
        manifest = P.profile_manifest()
        manifest["limits"]["http_transactions"] = 100000
        self.assertEqual(P.profile_manifest()["limits"]["http_transactions"], 100)

    def test_unknown_or_non_scalar_profile_refused(self):
        for value in ("r2-header-v1", "external-web-v2", "", None, True, [P.PROFILE_ID]):
            with self.subTest(value=value), self.assertRaises(P.ProfileError):
                P.profile_manifest(value)

    def test_missing_manifest_is_not_a_fallback(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(P.ProfileError):
            P.profile_manifest(path=Path(directory) / "absent")

    def test_changed_schema_limits_or_whitespace_refused(self):
        for change in ("schema", "limits", "extra", "space"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                value = P.profile_manifest()
                if change == "schema": value["schema_version"] = 2
                if change == "limits": value["limits"]["http_transactions"] = 101
                if change == "extra": value["unknown"] = True
                raw = P.canonical_json(value) if change != "space" else json.dumps(value).encode()
                path = Path(directory) / "manifest.json"
                path.write_bytes(raw)
                with self.assertRaises(P.ProfileError): P.profile_manifest(path=path)

    def test_symlink_or_hardlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_bytes(P.MANIFEST_PATH.read_bytes())
            hard = Path(directory) / "hard.json"
            os.link(path, hard)
            with self.assertRaises(P.ProfileError): P.profile_manifest(path=hard)
            hard.unlink()
            if hasattr(os, "O_NOFOLLOW"):
                link = Path(directory) / "link.json"
                link.symlink_to(path)
                with self.assertRaises(P.ProfileError): P.profile_manifest(path=link)

    def test_empty_or_oversize_source_refused(self):
        for raw in (b"", b"x" * (P.MAX_MANIFEST_BYTES + 1)):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "manifest.json"
                path.write_bytes(raw)
                with self.assertRaises(P.ProfileError): P.profile_manifest(path=path)

    def test_change_during_read_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_bytes(P.MANIFEST_PATH.read_bytes())
            original_read = os.read
            def change(descriptor, size):
                raw = original_read(descriptor, size)
                path.write_bytes(raw + b" ")
                return raw
            with mock.patch.object(P.os, "read", side_effect=change), self.assertRaises(P.ProfileError):
                P.profile_manifest(path=path)

    def test_exact_selected_services_are_not_expanded(self):
        https = [{"scheme": "https", "port": 443}]
        self.assertEqual(P.validate_binding(P.PROFILE_ID, P.PROFILE_SHA256, https), (("https", 443),))
        http = [{"scheme": "http", "port": 80}]
        self.assertEqual(P.validate_binding(P.PROFILE_ID, P.PROFILE_SHA256, http), (("http", 80),))

    def test_noncanonical_or_unapproved_services_refused(self):
        http, https = {"scheme": "http", "port": 80}, {"scheme": "https", "port": 443}
        for services in ([], [https, http], [http, http], [dict(http, hostname="other.test")],
                         [{"scheme": "https", "port": True}], [{"scheme": "HTTPS", "port": 443}],
                         [{"scheme": "https", "port": 8443}], (https,), ["https:443"]):
            with self.subTest(services=services), self.assertRaises(P.ProfileError):
                P.validate_services(services)

    def test_binding_digest_must_match_current_pinned_profile(self):
        for digest in ("0" * 64, P.PROFILE_SHA256.upper(), None, True):
            with self.subTest(digest=digest), self.assertRaises(P.ProfileError):
                P.validate_binding(P.PROFILE_ID, digest, [{"scheme": "https", "port": 443}])


if __name__ == "__main__":
    unittest.main()
