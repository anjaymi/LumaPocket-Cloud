"""Exercise two independent owners without using anyone's real credentials."""
import argparse
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile
from common import SigningError
from github_api import GitHub, trusted_run
from local_key import state_key
import local
import local_repositories as repos
from repository import Scope, account_binding, assert_identity_scope, assert_report_scope, bind_account
import ci_renew

ALICE = Scope("alice/LumaPocket-Cloud", 1001, 101)
BOB = Scope("bob/LumaPocket-Cloud", 2002, 202)


def metadata(scope):
    return {"full_name": scope.repository, "id": scope.repository_id, "private": False,
            "default_branch": "main", "owner": {"id": scope.owner_id, "login": scope.owner, "type": "User"},
            "permissions": {"admin": True}}


def environment(scope):
    return {"GITHUB_REPOSITORY": scope.repository, "GITHUB_REPOSITORY_ID": str(scope.repository_id),
            "GITHUB_REPOSITORY_OWNER_ID": str(scope.owner_id), "GITHUB_ACTOR": scope.owner,
            "GITHUB_ACTOR_ID": str(scope.owner_id), "GITHUB_REF": "refs/heads/main",
            "SIGNING_REPOSITORY_ID": str(scope.repository_id), "SIGNING_OWNER_ID": str(scope.owner_id)}


def identity(scope=ALICE):
    value = {"schema": 1, "teamId": "TESTTEAM01", "bundleIdentifier": "io.lumapocket.client.testteam01",
             "deviceUdid": "00000000-0000000000000000", "anisetteURL": "https://example.org",
             "sessionPassword": "fixture-session-" * 4, "machinePassword": "fixture-machine-" * 4,
             "p12Password": "fixture-p12-" * 4}
    bind_account(value, scope, "alice@example.invalid")
    return value


class ScopeChecks(unittest.TestCase):
    def test_two_owners_have_valid_independent_contexts(self):
        for scope in (ALICE, BOB):
            self.assertEqual(Scope.from_environment(environment(scope)), scope)
            self.assertEqual(Scope.from_metadata(metadata(scope), {"id": scope.owner_id, "login": scope.owner}), scope)

    def test_each_runner_context_field_is_enforced(self):
        for key, value in {"GITHUB_ACTOR": "outsider", "GITHUB_ACTOR_ID": "303",
                           "SIGNING_REPOSITORY_ID": "2002", "SIGNING_OWNER_ID": "202",
                           "GITHUB_REF": "refs/pull/1/merge"}.items():
            env = environment(ALICE)
            env[key] = value
            with self.subTest(key=key), self.assertRaises(SigningError):
                Scope.from_environment(env)

    def test_missing_initial_setup_is_rejected(self):
        env = environment(ALICE)
        del env["SIGNING_OWNER_ID"]
        self.assertRaisesRegex(SigningError, "setup", Scope.from_environment, env)

    def test_recreated_repository_with_same_name_is_different(self):
        self.assertRaisesRegex(SigningError, "another_repository", assert_identity_scope,
                               identity(), Scope(ALICE.repository, 9999, ALICE.owner_id))

    def test_copied_state_and_report_are_rejected_for_other_owner(self):
        self.assertRaisesRegex(SigningError, "another_repository", assert_identity_scope, identity(), BOB)
        self.assertRaisesRegex(SigningError, "another_repository", assert_report_scope,
                               {"repositoryScope": ALICE.as_dict()}, BOB)

    def test_unbound_legacy_state_is_not_implicitly_reassigned(self):
        value = identity()
        del value["repositoryScope"]
        self.assertRaisesRegex(SigningError, "binding_missing", assert_identity_scope, value, ALICE)

    def test_apple_account_switch_requires_new_repository(self):
        value = identity()
        self.assertRaisesRegex(SigningError, "different_apple_account", bind_account, value, ALICE, "bob@example.invalid")

    def test_normalized_same_apple_account_reuses_binding(self):
        value = identity()
        bind_account(value, ALICE, "  ALICE@example.invalid  ")
        self.assertEqual(value["accountBinding"], account_binding("alice@example.invalid"))
        self.assertNotIn("alice@example.invalid", json.dumps(value))

    def test_organization_private_and_non_admin_repositories_rejected(self):
        for field, replacement in [("private", True), ("default_branch", "develop"),
                                   ("owner", {"id": 101, "login": "alice", "type": "Organization"}),
                                   ("permissions", {"admin": False})]:
            value = metadata(ALICE)
            value[field] = replacement
            with self.subTest(field=field), self.assertRaises(SigningError):
                Scope.from_metadata(value, {"id": 101, "login": "alice"})

    def test_other_github_user_cannot_select_repository(self):
        self.assertRaisesRegex(SigningError, "must_own", Scope.from_metadata, metadata(ALICE), {"id": 202, "login": "bob"})

    def test_api_requests_target_the_selected_repository(self):
        for scope in (ALICE, BOB):
            github = GitHub("fixture-not-a-token", scope)
            github.request = mock.Mock(return_value={})
            github.get("actions/runs")
            request = github.request.call_args.args[0]
            self.assertEqual(request.full_url, "https://api.github.com/repos/" + scope.repository + "/actions/runs")

    def test_artifact_owner_and_repository_must_both_match(self):
        run = {"status": "completed", "conclusion": "success", "head_branch": "main", "workflow_id": 7,
               "head_repository": {"id": 1001}, "actor": {"login": "alice", "id": 101}, "event": "schedule"}
        self.assertTrue(trusted_run(run, 7, ALICE))
        self.assertFalse(trusted_run(run, 7, BOB))
        run["actor"]["id"] = 202
        self.assertFalse(trusted_run(run, 7, ALICE))


class LocalIsolationChecks(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="lp-isolation-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_profiles_and_encryption_keys_differ_by_repository(self):
        scopes = (ALICE, BOB, Scope("alice/Second-Apple-Account", 1003, 101))
        homes, keys = [], []
        for scope in scopes:
            home = repos.profile_home(self.root, scope)
            home.mkdir(parents=True)
            homes.append(home)
            keys.append(state_key(home, create=True))
        self.assertEqual(len(set(homes)), 3)
        self.assertEqual(len(set(keys)), 3)
        for home, key in zip(homes, keys):
            self.assertEqual(state_key(home), key)

    def test_concurrent_same_profile_is_refused_but_other_owner_can_work(self):
        alice_home, bob_home = repos.profile_home(self.root, ALICE), repos.profile_home(self.root, BOB)
        with repos.profile_lock(alice_home):
            with self.assertRaisesRegex(SigningError, "in_use"):
                with repos.profile_lock(alice_home):
                    pass
            with repos.profile_lock(bob_home):
                pass
        with repos.profile_lock(alice_home):
            pass

    def test_changing_github_login_does_not_select_previous_owner(self):
        repos.save_json(self.root / "active-101.json", ALICE.as_dict())
        with mock.patch.object(repos, "viewer", return_value={"id": 202, "login": "bob"}):
            self.assertRaisesRegex(SigningError, "setup_for_current", repos.selected, self.root)

    def test_setup_never_writes_another_owners_repository(self):
        with mock.patch.object(repos, "viewer", return_value={"id": 101, "login": "alice"}), mock.patch.object(repos, "gh") as gh:
            self.assertRaisesRegex(SigningError, "must_own", repos.setup, self.root, BOB.repository)
        gh.assert_not_called()

    def test_setup_configures_only_this_owner_without_apple_credentials(self):
        calls = []
        def gh(args, *unused, **kwargs):
            calls.append(args)
            if args[:2] == ["api", "repos/" + ALICE.repository]:
                return json.dumps(metadata(ALICE)).encode()
            if args[:2] == ["variable", "list"]:
                return b"[]"
            return b""
        import base64
        github = mock.Mock()
        github.get.return_value = {"content": base64.b64encode(b'{"schema":2,"upstream":"anjaymi/LumaPocket"}').decode()}
        with mock.patch.object(repos, "viewer", return_value={"id": 101, "login": "alice"}), mock.patch.object(repos, "gh", side_effect=gh), mock.patch.object(repos, "client", return_value=github):
            scope, home = repos.setup(self.root, ALICE.repository)
        self.assertEqual(scope, ALICE)
        self.assertEqual(json.loads((home / "repository.json").read_text()), ALICE.as_dict())
        writes = [args for args in calls if args[:2] == ["variable", "set"]]
        self.assertEqual(len(writes), 3)
        self.assertTrue(all(args[args.index("--repo") + 1] == ALICE.repository for args in writes))
        self.assertFalse(any(args[:2] == ["secret", "set"] for args in calls))

    def test_wrong_state_is_rejected_before_portal_or_public_build_access(self):
        state = self.root / "state"
        def extract(unused, target):
            target.mkdir()
            (target / "identity.json").write_text(json.dumps(identity(ALICE)))
        github = mock.Mock()
        github.get.return_value = metadata(BOB)
        github.restore_state.return_value = True
        with mock.patch.object(ci_renew, "GitHub", return_value=github), mock.patch.object(ci_renew, "crypt"), mock.patch.object(ci_renew, "extract_state", side_effect=extract), mock.patch.object(ci_renew, "Apple") as apple, mock.patch.dict(os.environ, {"GITHUB_TOKEN": "fixture", "RESET_SIGNING_STATE": "false"}):
            self.assertRaisesRegex(SigningError, "another_repository", ci_renew.renew, self.root, self.root, "fixture-only-" * 4, BOB)
        github.unsigned.assert_not_called()
        apple.assert_not_called()

    def test_both_owners_reach_missing_authorization_guard_without_network(self):
        for scope in (ALICE, BOB):
            root = self.root / str(scope.owner_id)
            root.mkdir()
            env = environment(scope)
            env.update(RUNNER_TEMP=str(root), GITHUB_OUTPUT=str(root / "output.txt"),
                       GITHUB_STEP_SUMMARY=str(root / "summary.md"))
            with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(io.StringIO()), mock.patch.object(ci_renew, "GitHub") as github:
                self.assertEqual(ci_renew.main(), 1)
            report = json.loads((root / "lumapocket-signing-out/signing-report.json").read_text())
            self.assertEqual(report["reason"], "initial_local_authorization_required")
            self.assertFalse((root / "lumapocket-signing-out/signing-state.tar.gz.gpg").exists())
            github.assert_not_called()

    def test_cross_owner_artifact_cannot_enable_daily_signing(self):
        package = self.root / "fixture.zip"
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("signing-report.json", json.dumps({"repositoryScope": ALICE.as_dict()}))
        github = mock.Mock()
        github.artifact.return_value = ({"id": 9}, {})
        github.download_artifact.side_effect = lambda unused, target: target.write_bytes(package.read_bytes())
        with mock.patch.object(local, "client", return_value=github), mock.patch.object(local, "repository_gh") as gh:
            self.assertRaisesRegex(SigningError, "another_repository", local.enable, self.root, BOB)
        gh.assert_not_called()

    def test_cached_github_token_is_verified_against_numeric_owner(self):
        with mock.patch.object(repos, "gh", side_effect=[b"fixture-not-a-token", b'{"id":202}']):
            self.assertRaisesRegex(SigningError, "another_owner", repos.client, ALICE)

    def test_cli_writes_use_frozen_owner_token_in_environment(self):
        result = mock.Mock(returncode=0, stdout=b"ok", stderr=b"")
        with mock.patch.object(repos.subprocess, "run", return_value=result) as run:
            repos.gh(["secret", "set", "fixture", "--repo", ALICE.repository], b"fixture-data", token="fixture-alice-token")
        self.assertEqual(run.call_args.kwargs["env"]["GH_TOKEN"], "fixture-alice-token")
        self.assertNotIn("fixture-alice-token", run.call_args.args[0])

    def test_network_retry_does_not_duplicate_dispatch(self):
        result = mock.Mock(returncode=1, stdout=b"", stderr=b"EOF")
        with mock.patch.object(repos.subprocess, "run", return_value=result) as run:
            self.assertRaises(SigningError, repos.gh, ["workflow", "run", "free-signing.yml", "--repo", ALICE.repository])
        self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
