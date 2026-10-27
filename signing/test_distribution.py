"""The shared release must contain a verified unsigned app and no Apple state."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock
import zipfile
from common import SigningError
from repository import UPSTREAM_OWNER_ID

source = Path(__file__).resolve().parents[1] / "ci/publish_unsigned.py"
spec = importlib.util.spec_from_file_location("unsigned_publisher", source)
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class DistributionChecks(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="lp-dist-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = {"applicationVersion": "1.0.0+1", "bundleIdentifier": "io.lumapocket.client"}
        self.info = {"CFBundleIdentifier": "io.lumapocket.client", "CFBundleShortVersionString": "1.0.0", "CFBundleVersion": "1"}
        self.run = {"id": 42, "head_sha": "f" * 40}

    def package(self, personal=False, extra=False, wrong_digest=False):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w") as ipa:
            ipa.writestr("Payload/Runner.app/Info.plist", plistlib.dumps(self.info))
            if personal:
                ipa.writestr("Payload/Runner.app/embedded.mobileprovision", b"fixture-private-profile")
        data = raw.getvalue()
        name = "LumaPocket_1.0.0+1_unsigned.ipa"
        report = {"sha256": "0" * 64 if wrong_digest else hashlib.sha256(data).hexdigest(), "bytes": len(data),
                  "version": "1.0.0+1", "architectures": "arm64", "bundleIdentifier": "io.lumapocket.client",
                  "requiresLocalSigning": True, "tokenizerSymbolsExported": True}
        package = self.root / "artifact.zip"
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr(name, data)
            archive.writestr(name + ".SHA256.txt", b"fixture")
            archive.writestr("build-report.json", json.dumps(report))
            if extra:
                archive.writestr("session.dat", b"fixture-private-session")
        return package

    def test_publication_accepts_only_unsigned_files(self):
        files = publisher.unpack(self.package(), self.root, self.run, self.config)
        self.assertEqual({path.name for path in files}, {"LumaPocket_1.0.0+1_unsigned.ipa", "unsigned-manifest.json"})

    def test_personal_profile_cannot_be_published(self):
        self.assertRaisesRegex(SigningError, "personal_or_mismatched", publisher.unpack, self.package(personal=True), self.root, self.run, self.config)

    def test_session_file_cannot_be_published(self):
        self.assertRaisesRegex(SigningError, "unexpected_unsigned_artifact", publisher.unpack, self.package(extra=True), self.root, self.run, self.config)

    def test_mismatched_build_report_cannot_be_published(self):
        self.assertRaisesRegex(SigningError, "report_mismatch", publisher.unpack, self.package(wrong_digest=True), self.root, self.run, self.config)

    def test_draft_is_found_before_its_tag_has_been_created(self):
        github = mock.Mock()
        github.get.side_effect = [None, [{"tag_name": "ios-unsigned-42", "draft": True, "id": 7}]]
        self.assertEqual(publisher.find_release(github, "ios-unsigned-42")["id"], 7)

    def test_foreign_build_actor_cannot_publish(self):
        github = mock.Mock()
        github.get.side_effect = [{"head_repository": {"id": 1435778522}, "actor": {"id": 123}}, {"id": 7}]
        self.assertRaisesRegex(SigningError, "trusted_upstream_build", publisher.verify_build, github, 42)


if __name__ == "__main__":
    unittest.main()
