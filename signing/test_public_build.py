"""Only a pinned upstream can supply the public, unsigned shared installation."""
import copy
import hashlib
import io
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock
import zipfile
from common import SigningError
from github_api import GitHub
from public_build import release_assets, unsigned, validate_manifest
from repository import Scope, UPSTREAM, UPSTREAM_ID, UPSTREAM_OWNER_ID, UPSTREAM_SCOPE


class PublicBuildChecks(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="lp-public-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w") as archive:
            archive.writestr("Payload/Runner.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "io.lumapocket.client"}))
        self.ipa = raw.getvalue()
        self.name, self.tag = "LumaPocket_1.0.0+1_unsigned.ipa", "ios-unsigned-42"
        self.manifest = {"schema": 1, "repository": UPSTREAM, "repositoryId": UPSTREAM_ID, "ownerId": UPSTREAM_OWNER_ID,
                         "runId": 42, "sourceRevision": "f" * 40, "filename": self.name,
                         "sha256": hashlib.sha256(self.ipa).hexdigest(), "bytes": len(self.ipa),
                         "build": {"applicationVersion": "1.0.0+1", "bundleIdentifier": "io.lumapocket.client"}}
        manifest_bytes = json.dumps(self.manifest).encode()
        self.data = {self.name: self.ipa, "unsigned-manifest.json": manifest_bytes}
        self.assets = {name: {"name": name, "digest": "sha256:" + hashlib.sha256(data).hexdigest(), "size": len(data),
                              "browser_download_url": "https://github.com/" + UPSTREAM + "/releases/download/" + self.tag + "/" + name}
                       for name, data in self.data.items()}
        self.release = {"draft": False, "prerelease": False, "tag_name": self.tag,
                        "author": {"id": UPSTREAM_OWNER_ID}, "assets": list(self.assets.values())}
        self.github = mock.Mock(scope=UPSTREAM_SCOPE)
        self.github.get.side_effect = lambda path: self.release if path else {
            "id": UPSTREAM_ID, "full_name": UPSTREAM, "private": False, "default_branch": "main",
            "owner": {"id": UPSTREAM_OWNER_ID, "login": "anjaymi", "type": "User"}}
        self.github.public_asset.side_effect = lambda item, tag: self.data[item["name"]]

    def test_shared_public_build_download_then_verified_cache(self):
        build, changed = unsigned(self.github, self.root)
        self.assertTrue(changed)
        self.assertEqual(build, self.manifest["build"])
        self.assertEqual((self.root / "unsigned.ipa").read_bytes(), self.ipa)
        self.github.public_asset.reset_mock()
        self.assertEqual(unsigned(self.github, self.root), (build, False))
        self.assertEqual(self.github.public_asset.call_count, 1)

    def test_wrong_upstream_repository_rejected_before_download(self):
        self.github.get.return_value = {}
        self.github.get.side_effect = lambda unused: {"id": 7, "full_name": UPSTREAM, "private": False, "default_branch": "main", "owner": {"id": UPSTREAM_OWNER_ID, "login": "anjaymi", "type": "User"}}
        self.assertRaisesRegex(SigningError, "trusted_unsigned_repository", unsigned, self.github, self.root)
        self.github.public_asset.assert_not_called()

    def test_personal_repository_cannot_be_a_shared_build_source(self):
        self.github.scope = Scope("alice/LumaPocket-Cloud", 1001, 101)
        self.assertRaisesRegex(SigningError, "trusted_unsigned_repository", unsigned, self.github, self.root)
        self.github.get.assert_not_called()

    def test_unapproved_release_author_and_draft_are_rejected(self):
        for key, value in [("author", {"id": 7}), ("draft", True), ("prerelease", True), ("tag_name", "anything")]:
            release = copy.deepcopy(self.release)
            release[key] = value
            with self.subTest(key=key), self.assertRaises(SigningError):
                release_assets(release)

    def test_manifest_wrong_scope_and_traversal_are_rejected(self):
        for key, value in [("repositoryId", 7), ("ownerId", 7), ("repository", "alice/LumaPocket-Cloud"),
                           ("filename", "../../private.ipa"), ("sha256", "0" * 64), ("runId", 41)]:
            manifest = copy.deepcopy(self.manifest)
            manifest[key] = value
            with self.subTest(key=key), self.assertRaises(SigningError):
                validate_manifest(manifest, self.tag, self.assets)

    def test_invalid_download_preserves_existing_package(self):
        original = self.root / "unsigned.ipa"
        original.write_bytes(b"previously-verified-fixture")
        self.data[self.name] = b"tampered-fixture"
        self.assertRaisesRegex(SigningError, "digest_mismatch", unsigned, self.github, self.root)
        self.assertEqual(original.read_bytes(), b"previously-verified-fixture")

    def test_network_outage_uses_only_verified_cached_package(self):
        build, _ = unsigned(self.github, self.root)
        self.github.get.side_effect = SigningError("github_download_unavailable")
        self.assertEqual(unsigned(self.github, self.root), (build, False))
        self.assertIn("using_verified_cache", (self.root / "unsigned-build.json").read_text())
        (self.root / "unsigned.ipa").write_bytes(b"corrupted")
        self.assertRaisesRegex(SigningError, "github_download_unavailable", unsigned, self.github, self.root)

    def test_invalid_source_is_never_hidden_by_a_valid_cache(self):
        unsigned(self.github, self.root)
        self.release["author"] = {"id": 7}
        self.assertRaisesRegex(SigningError, "trusted_unsigned_release", unsigned, self.github, self.root)

    def test_assets_cannot_contain_other_users_signing_state(self):
        self.release["assets"].append({"name": "session.dat"})
        self.assertRaisesRegex(SigningError, "incomplete_unsigned_release", release_assets, self.release)

    def test_public_asset_fetch_has_no_github_authorization(self):
        github = GitHub("fixture-private-token", UPSTREAM_SCOPE)
        github.request = mock.Mock(return_value=self.ipa)
        self.assertEqual(github.public_asset(self.assets[self.name], self.tag), self.ipa)
        request = github.request.call_args.args[0]
        self.assertIsNone(request.get_header("Authorization"))

    def test_external_asset_url_and_mismatched_hash_are_rejected(self):
        github = GitHub("fixture", UPSTREAM_SCOPE)
        github.request = mock.Mock(return_value=b"wrong")
        self.assertRaisesRegex(SigningError, "digest_mismatch", github.public_asset, self.assets[self.name], self.tag)
        item = dict(self.assets[self.name], browser_download_url="https://example.org/stolen.ipa")
        self.assertRaisesRegex(SigningError, "unexpected_public_release_asset_url", github.public_asset, item, self.tag)


if __name__ == "__main__":
    unittest.main()
