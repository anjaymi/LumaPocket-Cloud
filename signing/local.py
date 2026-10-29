"""Interactive authorization stays on the owner's computer, outside CI logs."""
import argparse
import base64
import hashlib
import json
import os
import secrets
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from apple import Apple
from common import SigningError, run_private
from local_key import state_key
from local_repositories import client, profile_lock, repository_gh, selected, setup
from profile import identity_from, validate_local_inputs
from repository import assert_identity_scope, assert_report_scope, bind_account
from storage import crypt, export_state, extract_state
from tool import check, install
from local_pending import active_session, restore_pending, save_pending

HERE = Path(__file__).resolve().parent


def authorize(home, args, password, scope):
    # TemporaryDirectory is explicitly rooted beneath the private local state directory.
    with tempfile.TemporaryDirectory(prefix="authorize-", dir=home) as temporary:
        root = Path(temporary).resolve()
        if not root.is_relative_to(home.resolve()):
            raise SigningError("unexpected_local_work_directory")
        previous = home / "bootstrap-state.gpg"
        identity = restore_pending(root, home, password, scope)
        resuming = identity is not None
        if resuming:
            print("Signing phase: resume_session", flush=True)
            supplied_udid = args.udid or input('iPhone / iPad UDID (from Apple Devices/iTunes): ').strip()
            if supplied_udid.lower() != identity['deviceUdid'].lower():
                raise SigningError('checkpoint_device_mismatch')
        elif previous.exists():
            raw = root / "previous.tar.gz"
            crypt(previous, raw, password, root, decrypt=True)
            extract_state(raw, root)
            identity = identity_from(root / "identity.json")
            assert_identity_scope(identity, scope)
        else:
            session_password = secrets.token_urlsafe(48)
            identity = {"schema": 1, "sessionPassword": session_password,
                        "p12Password": session_password, "machinePassword": secrets.token_urlsafe(48),
                        "anisetteURL": args.anisette_url}
            identity["deviceUdid"] = args.udid or input("iPhone / iPad UDID (from Apple Devices/iTunes): ").strip()
        validate_local_inputs(identity["deviceUdid"], identity["anisetteURL"])
        apple_id = args.apple_id or input("Apple Account email: ").strip()
        bind_account(identity, scope, apple_id)
        tool = install(home / "tool")
        if not resuming or identity.pop('needsReauthentication', False):
            # Never let the CLI silently reuse an old explicit session when a
            # fresh password/code exchange has been requested.
            (root / 'session.dat').unlink(missing_ok=True)
            print("Enter your Apple password and verification code in the signing tool's local prompts.")
            run_private([str(tool), "dev", "login", "--apple-id", apple_id,
                     "--encrypt-password", identity["sessionPassword"],
                     "--session", str(root / "session.dat"),
                     "--machine-password", identity["machinePassword"],
                     "--machine-path", str(root / "machine.dat"),
                     "--server", identity["anisetteURL"], "--strict"], root, "local_apple_authorization",
                    timeout=900, interactive=True)
        print("Signing phase: save_session", flush=True)
        active = active_session(root)
        if active != root / 'session.dat':
            shutil.copy2(active, root / "session.dat")
        save_pending(root, home, password, identity)
        try:
            Apple(tool, root, identity).bootstrap()
        except Exception as error:
            # A portal/network failure must not throw away a successful login or
            # a newly created private key and force another verification code.
            try:
                if isinstance(error, SigningError) and str(error) == 'reauthorization_required':
                    identity['needsReauthentication'] = True
                save_pending(root, home, password, identity)
            except (SigningError, OSError):
                pass
            raise
        identity_from(root / "identity.json")
        print("Signing phase: encrypt_state", flush=True)
        save_pending(root, home, password, identity)
        export_state(root, home / "bootstrap-state.gpg", password, root)
        (home / 'pending-authorization.gpg').unlink(missing_ok=True)
    print("Authorized state saved locally with encryption. Apple password was not stored.")
    publish(home, password, scope)


def publish(home, password, scope):
    # Recheck decrypted ownership even when a user invokes publish separately.
    with tempfile.TemporaryDirectory(prefix="preflight-", dir=home) as temporary:
        root = Path(temporary)
        raw = root / "state.tar.gz"
        crypt(home / "bootstrap-state.gpg", raw, password, root, decrypt=True)
        extract_state(raw, root / "state")
        assert_identity_scope(identity_from(root / "state/identity.json"), scope)
    seed = base64.b64encode((home / "bootstrap-state.gpg").read_bytes())
    if len(seed) > 45000:
        raise SigningError("bootstrap_exceeds_github_secret_limit")
    github = client(scope)
    repository = scope.repository
    before = {run["id"] for run in github.get("actions/workflows/free-signing.yml/runs?event=workflow_dispatch&branch=main&per_page=20").get("workflow_runs", [])}
    repository_gh(github, ["variable", "set", "FREE_SIGNING_ENABLED", "--repo", repository, "--body", "false"])
    repository_gh(github, ["secret", "set", "IOS_SIGNING_PASSPHRASE", "--repo", repository], password.encode())
    repository_gh(github, ["secret", "set", "IOS_SIGNING_STATE_BASE64", "--repo", repository], seed)
    repository_gh(github, ["workflow", "run", "free-signing.yml", "--repo", repository,
        "-f", "mode=renew", "-f", "reset_state=true"])
    print("Manual signing run started: https://github.com/" + repository + "/actions")
    print("Waiting for the first verified cloud signature before enabling daily checks...")
    import time
    deadline = time.monotonic() + 1200
    target = None
    while time.monotonic() < deadline:
        if target is None:
            runs = github.get("actions/workflows/free-signing.yml/runs?event=workflow_dispatch&branch=main&per_page=20").get("workflow_runs", [])
            target = next((run["id"] for run in reversed(runs) if run["id"] not in before), None)
        if target is not None:
            run = github.get("actions/runs/" + str(target))
            if run.get("status") == "completed":
                if run.get("conclusion") != "success":
                    raise SigningError("first_manual_signing_failed_check_actions")
                enable(home, scope, expected_run=target)
                return
        time.sleep(20)
    raise SigningError("manual_run_still_pending_run_enable_after_success")


def signed_artifact(home, scope):
    github = client(scope)
    found = github.artifact("free-signing.yml", "LumaPocket-free-sign")
    if found is None:
        raise SigningError("successful_manual_signing_run_required")
    run, artifact = found
    package = home / "signed-artifact.zip"
    github.download_artifact(artifact, package)
    with zipfile.ZipFile(package) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or "signing-report.json" not in names or archive.getinfo("signing-report.json").file_size > 16384:
            raise SigningError("unexpected_signing_artifact")
        report = json.loads(archive.read("signing-report.json"))
        assert_report_scope(report, scope)
        if report.get("status") != "signed" or report.get("signatureChecksPassed") is not True or report.get("runId") != run["id"]:
            raise SigningError("successful_verified_signing_run_required")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+", report.get("version", "")) or not re.fullmatch(r"[0-9a-f]{64}", report.get("sha256", "")):
            raise SigningError("invalid_signed_app_report")
        bootstrap = home / "bootstrap-state.gpg"
        if not bootstrap.is_file() or hashlib.sha256(bootstrap.read_bytes()).hexdigest() != report.get("bootstrapStateSha256"):
            raise SigningError("current_authorization_not_verified")
        import datetime as dt
        try:
            expires = dt.datetime.fromisoformat(report["expiresAt"])
            if expires.tzinfo is None:
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise SigningError("invalid_signed_app_report") from None
        if expires <= dt.datetime.now(dt.timezone.utc):
            raise SigningError("fresh_verified_signing_run_required")
    return package, report


def enable(home, scope, expected_run=None):
    _, report = signed_artifact(home, scope)
    if expected_run is not None and report["runId"] != expected_run:
        raise SigningError("current_manual_run_not_verified")
    if hashlib.sha256((home / "bootstrap-state.gpg").read_bytes()).hexdigest() != report.get("bootstrapStateSha256"):
        raise SigningError("current_authorization_not_verified")
    import datetime as dt
    if dt.datetime.fromisoformat(report["expiresAt"]) <= dt.datetime.now(dt.timezone.utc):
        raise SigningError("fresh_verified_signing_run_required")
    github = client(scope)
    repository_gh(github, ["variable", "set", "FREE_SIGNING_ENABLED", "--repo", scope.repository, "--body", "true"])
    repository_gh(github, ["workflow", "enable", "free-signing.yml", "--repo", scope.repository])
    print("Daily expiry checks enabled (10:37 Hong Kong time, subject to GitHub scheduling).")


def download(home, password, scope):
    package, report = signed_artifact(home, scope)
    encrypted = home / "signed.ipa.gpg"
    with zipfile.ZipFile(package) as archive:
        encrypted.write_bytes(archive.read("LumaPocket_signed.ipa.gpg"))
    destination = home / ("LumaPocket_" + report["version"] + "_signed.ipa")
    crypt(encrypted, destination, password, home, decrypt=True)
    if hashlib.sha256(destination.read_bytes()).hexdigest() != report["sha256"]:
        raise SigningError("signed_ipa_digest_mismatch")
    print("Verified signed IPA: " + str(destination))
    print("Install/refresh on the registered iPhone / iPad. The cloud run does not install it remotely.")
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["onboard", "setup", "check", "authorize", "publish", "enable", "download", "disable"])
    parser.add_argument("--home", type=Path, default=HERE.parent / ".lumapocket-signing")
    parser.add_argument("--udid")
    parser.add_argument("--apple-id")
    parser.add_argument("--repo", help="Select a signing repository owned by the current GitHub account")
    parser.add_argument("--repo-name", default="LumaPocket-Cloud", help="Personal repository name for setup")
    parser.add_argument("--anisette-url", default="https://new.ani.sidestore.io")
    args = parser.parse_args()
    home = args.home.resolve()
    if home == HERE.parent or home == HERE:
        raise SigningError("private_subdirectory_required")
    if home.is_relative_to(HERE.parent) and not home.is_relative_to(HERE.parent / ".lumapocket-signing"):
        raise SigningError("use_ignored_private_state_directory")
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.command in ("setup", "onboard"):
        scope, personal_home = setup(home, args.repo, args.repo_name)
        if args.command == "onboard":
            with profile_lock(personal_home):
                password = state_key(personal_home, create=True)
                authorize(personal_home, args, password, scope)
    elif args.command == "check":
        print(json.dumps(check(home / "tool")))
    else:
        scope, home = selected(home, args.repo)
        with profile_lock(home):
            if args.command == "enable":
                enable(home, scope)
            elif args.command == "disable":
                repository_gh(client(scope), ["variable", "set", "FREE_SIGNING_ENABLED", "--repo", scope.repository, "--body", "false"])
                print("Daily signing disabled.")
            else:
                password = state_key(home, create=args.command == "authorize")
                if args.command == "authorize":
                    authorize(home, args, password, scope)
                elif args.command == "publish":
                    publish(home, password, scope)
                else:
                    download(home, password, scope)


if __name__ == "__main__":
    try:
        main()
    except SigningError as error:
        print("Signing helper stopped: " + str(error))
        sys.exit(1)
