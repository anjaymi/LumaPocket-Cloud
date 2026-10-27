"""No real account, certificate, UDID or Apple network traffic is used here."""
import copy
import datetime as dt
import io
import json
import os
import tarfile
import tempfile
import unittest
import urllib.request
import zipfile
from pathlib import Path
from common import SigningError, private_env, run_private
from github_api import REPOSITORY_ID, SafeRedirect, trusted_run
from local_key import dpapi
from profile import UTC, ensure_extended, renewal_due, validate
from sign_ipa import check_zip
from storage import crypt, export_state, extract_state
from tool import safe_name
from apple import Apple
from profile import validate_local_inputs
from unittest import mock


class ProfileChecks(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 10, 27, tzinfo=UTC)
        self.identity = {"teamId": "TESTTEAM01", "bundleIdentifier": "io.lumapocket.client.testteam01",
                         "deviceUdid": "00000000-0000000000000000"}
        self.profile = {"CreationDate": self.now, "ExpirationDate": self.now + dt.timedelta(days=7),
                        "TeamIdentifier": ["TESTTEAM01"], "ProvisionedDevices": [self.identity["deviceUdid"]],
                        "DeveloperCertificates": [b"public-test-certificate"], "Entitlements": {
                            "application-identifier": "TESTTEAM01." + self.identity["bundleIdentifier"],
                            "com.apple.developer.team-identifier": "TESTTEAM01", "get-task-allow": True}}

    def verify(self):
        return validate(self.profile, self.identity, b"public-test-certificate", now=self.now)

    def test_expected_free_profile(self):
        self.assertEqual(self.verify(), self.now + dt.timedelta(days=7))

    def test_expired_profile(self):
        self.profile["ExpirationDate"] = self.now - dt.timedelta(seconds=1)
        self.assertRaisesRegex(SigningError, "expired", self.verify)

    def test_short_profile(self):
        self.profile["ExpirationDate"] = self.now + dt.timedelta(hours=1)
        self.assertRaisesRegex(SigningError, "too_short", self.verify)

    def test_wrong_team(self):
        self.profile["TeamIdentifier"] = ["OTHERTEAM1"]
        self.assertRaisesRegex(SigningError, "team_mismatch", self.verify)

    def test_wrong_device(self):
        self.profile["ProvisionedDevices"] = ["00000000-1111111111111111"]
        self.assertRaisesRegex(SigningError, "device_mismatch", self.verify)

    def test_wrong_app(self):
        self.profile["Entitlements"]["application-identifier"] = "TESTTEAM01.io.other.app"
        self.assertRaisesRegex(SigningError, "bundle_mismatch", self.verify)

    def test_wrong_certificate(self):
        self.profile["DeveloperCertificates"] = [b"different-certificate"]
        self.assertRaisesRegex(SigningError, "certificate_mismatch", self.verify)

    def test_distribution_rejected(self):
        self.profile["Entitlements"]["get-task-allow"] = False
        self.assertRaisesRegex(SigningError, "development_profile", self.verify)

    def test_enterprise_rejected(self):
        self.profile["ProvisionsAllDevices"] = True
        self.assertRaisesRegex(SigningError, "development_profile", self.verify)

    def test_future_creation_rejected(self):
        self.profile["CreationDate"] += dt.timedelta(hours=1)
        self.assertRaisesRegex(SigningError, "expired_or_too_short", self.verify)

    def test_nonfree_lifetime_rejected(self):
        self.profile["ExpirationDate"] += dt.timedelta(days=300)
        self.assertRaisesRegex(SigningError, "nonfree", self.verify)

    def test_missing_dates_rejected(self):
        del self.profile["CreationDate"]
        self.assertRaisesRegex(SigningError, "dates_missing", self.verify)

    def test_daily_due_window(self):
        self.assertTrue(renewal_due(self.now + dt.timedelta(hours=48), now=self.now))
        self.assertFalse(renewal_due(self.now + dt.timedelta(hours=49), now=self.now))

    def test_unchanged_expiring_profile_is_not_a_renewal(self):
        self.assertRaisesRegex(SigningError, "did_not_extend", ensure_extended, self.now, self.now, True)
        ensure_extended(self.now, self.now + dt.timedelta(days=7), True)


class ArchiveChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lumapocket-signing-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.assertTrue(self.root.is_relative_to(Path(tempfile.gettempdir()).resolve()))

    def archive(self, entries):
        archive_path = self.root / "state.tar"
        with tarfile.open(archive_path, "w") as archive:
            for name, content in entries:
                entry = tarfile.TarInfo(name)
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
        return archive_path

    def entries(self):
        return [("identity.json", b"{}"), ("session.dat", b"SS02fixture"),
                ("machine.dat", b"ADI1fixture"), ("certificate.p12", b"fixture")]

    def test_state_archive_traversal_rejected(self):
        archive = self.archive(self.entries() + [("../outside", b"test")])
        self.assertRaisesRegex(SigningError, "invalid_state", extract_state, archive, self.root / "out")

    def test_duplicate_state_rejected(self):
        archive = self.archive(self.entries() + [("session.dat", b"SS02other")])
        self.assertRaisesRegex(SigningError, "invalid_state", extract_state, archive, self.root / "out")

    def test_machine_bound_session_rejected(self):
        entries = [(name, b"SS01fixture" if name == "session.dat" else data) for name, data in self.entries()]
        self.assertRaisesRegex(SigningError, "portable_password", extract_state, self.archive(entries), self.root / "out")

    def test_missing_identity_rejected(self):
        self.assertRaisesRegex(SigningError, "incomplete", extract_state, self.archive(self.entries()[1:]), self.root / "out")

    def test_gpg_round_trip_and_wrong_key(self):
        source = self.root / "state"
        source.mkdir()
        for name, value in self.entries():
            (source / name).write_bytes(value)
        key = "fixture-passphrase-only-not-an-account-key-123456"
        encrypted = self.root / "state.gpg"
        export_state(source, encrypted, key, self.root)
        restored = self.root / "restored.tar.gz"
        crypt(encrypted, restored, key, self.root, decrypt=True)
        output = self.root / "restored"
        extract_state(restored, output)
        self.assertEqual((output / "session.dat").read_bytes(), b"SS02fixture")
        self.assertRaises(SigningError, crypt, encrypted, self.root / "wrong.tar", key + "wrong", self.root, True)

    def test_gpg_long_private_directory(self):
        root = self.root / ("long-" + "x" * 75)
        root.mkdir()
        source = root / "fixture.txt"
        source.write_bytes(b"public-offline-fixture")
        encrypted, restored = root / "fixture.gpg", root / "restored.txt"
        key = "fixture-passphrase-only-not-an-account-key-123456"
        try:
            crypt(source, encrypted, key, root)
            crypt(encrypted, restored, key, root, decrypt=True)
        except SigningError:
            # This test has only fixed public fixture data, never an account.
            self.fail("Offline GPG fixture failed: " + (root / "diagnostics.log").read_text(errors="replace"))
        self.assertEqual(source.read_bytes(), restored.read_bytes())

    def test_public_errors_do_not_echo_private_output(self):
        import sys
        secret = "TEST_PRIVATE_VALUE_NOT_A_REAL_TOKEN"
        with self.assertRaises(SigningError) as caught:
            run_private([sys.executable, "-c", "import sys; print('" + secret + "'); sys.exit(1)"], self.root, "fixture")
        self.assertEqual(str(caught.exception), "fixture_failed")
        self.assertIn(secret.encode(), (self.root / "diagnostics.log").read_bytes())

    def test_ipa_app_prefix_attack(self):
        path = self.root / "bad.ipa"
        with zipfile.ZipFile(path, "w") as package:
            package.writestr("Payload/Runner.app/Info.plist", b"fixture")
            package.writestr("Payload/Runner.app-evil/data", b"fixture")
        self.assertRaisesRegex(SigningError, "invalid_ipa", check_zip, path)

    def test_tool_path_attacks(self):
        for value in ["../secret", "/etc/passwd", "C:/secret", "dir\\file"]:
            with self.subTest(value=value):
                self.assertRaises(ValueError, safe_name, value)


class TrustChecks(unittest.TestCase):
    def setUp(self):
        self.run = {"status": "completed", "conclusion": "success", "head_branch": "main",
                    "workflow_id": 123, "head_repository": {"id": REPOSITORY_ID},
                    "actor": {"login": "anjaymi", "id": 129140237}, "event": "workflow_dispatch"}

    def test_owner_run_accepted(self):
        self.assertTrue(trusted_run(self.run, 123))

    def test_fork_run_rejected(self):
        self.run["head_repository"]["id"] = 7
        self.assertFalse(trusted_run(self.run, 123))

    def test_non_owner_rejected(self):
        self.run["actor"]["login"] = "someone-else"
        self.assertFalse(trusted_run(self.run, 123))

    def test_pr_event_rejected(self):
        self.run["event"] = "pull_request"
        self.assertFalse(trusted_run(self.run, 123))

    def test_wrong_workflow_rejected(self):
        self.assertFalse(trusted_run(self.run, 456))

    def test_failed_run_rejected(self):
        self.run["conclusion"] = "failure"
        self.assertFalse(trusted_run(self.run, 123))

    def test_bearer_token_not_forwarded_to_artifact_host(self):
        request = urllib.request.Request("https://api.github.com/test", headers={"Authorization": "Bearer fixture"})
        redirected = SafeRedirect().redirect_request(request, None, 302, "Found", {}, "https://example.org/artifact")
        self.assertIsNone(redirected.get_header("Authorization"))

    def test_insecure_redirect_rejected(self):
        request = urllib.request.Request("https://api.github.com/test")
        self.assertRaises(SigningError, SafeRedirect().redirect_request, request, None, 302, "Found", {}, "http://example.org/artifact")

    def test_child_does_not_inherit_signing_or_github_secrets(self):
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "fixture-token", "IOS_SIGNING_PASSPHRASE": "fixture-key"}):
            env = private_env(Path(tempfile.gettempdir()))
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("IOS_SIGNING_PASSPHRASE", env)

    def test_free_personal_team_is_required(self):
        apple = Apple("fixture", Path(tempfile.gettempdir()), {})
        apple.portal = lambda *args: " * Own (ID: TESTTEAM01, Type: 3)"
        self.assertEqual(apple.personal_team(), "TESTTEAM01")

    def test_multiple_teams_are_not_silently_selected(self):
        apple = Apple("fixture", Path(tempfile.gettempdir()), {})
        apple.portal = lambda *args: " * A (ID: TESTTEAM01, Type: 3)\n * B (ID: OTHERTEAM1, Type: 2)"
        self.assertRaisesRegex(SigningError, "single_personal_team", apple.personal_team)

    def test_account_team_change_is_rejected(self):
        apple = Apple("fixture", Path(tempfile.gettempdir()), {"teamId": "OTHERTEAM1"})
        apple.portal = lambda *args: " * Own (ID: TESTTEAM01, Type: 3)"
        self.assertRaisesRegex(SigningError, "team_changed", apple.personal_team)

    def test_udid_checked_before_login(self):
        self.assertRaisesRegex(SigningError, "invalid_device_udid", validate_local_inputs, "serial-not-udid", "https://example.org")

    def test_insecure_anisette_url_rejected(self):
        self.assertRaisesRegex(SigningError, "https_anisette", validate_local_inputs, "00000000-0000000000000000", "http://example.org")

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI")
    def test_windows_local_key_round_trip(self):
        value = b"fixture-not-an-account-password"
        encrypted = dpapi(value)
        self.assertNotEqual(encrypted, value)
        self.assertEqual(dpapi(encrypted, decrypt=True), value)


if __name__ == "__main__":
    unittest.main()
