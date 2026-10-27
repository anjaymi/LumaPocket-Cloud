"""Restore authorized state, refresh a free profile, sign, and publish ciphertext."""
import base64
import datetime as dt
import json
import hashlib
import os
import sys
from pathlib import Path
from apple import Apple
from common import SigningError
from github_api import GitHub
from profile import UTC, certificate_der, certificate_expiry, decode_profile, ensure_extended, identity_from, renewal_due, utc, validate
from repository import Scope, assert_identity_scope
from sign_ipa import sign
from storage import crypt, export_diagnostics, export_state, extract_state
from tool import install


def renew(root, out, password, scope):
    state = root / "state"
    encrypted = root / "restored-state.gpg"
    github = GitHub(os.environ["GITHUB_TOKEN"], scope)
    if Scope.from_metadata(github.get("")) != scope:
        raise SigningError("repository_identity_changed")
    reset = os.environ.get("RESET_SIGNING_STATE", "false") == "true"
    restored = not reset and github.restore_state(encrypted, root)
    if not restored:
        seed = os.environ.get("IOS_SIGNING_STATE_BASE64", "")
        if not seed:
            raise SigningError("initial_local_authorization_required")
        try:
            encrypted.write_bytes(base64.b64decode(seed, validate=True))
        except ValueError:
            raise SigningError("invalid_bootstrap_state") from None
    raw = root / "restored-state.tar.gz"
    crypt(encrypted, raw, password, root, decrypt=True)
    extract_state(raw, state)
    identity = identity_from(state / "identity.json")
    assert_identity_scope(identity, scope)
    build, changed = github.unsigned(state)
    certificate = certificate_der(state / "certificate.p12", identity["p12Password"], state)
    cert_expires = certificate_expiry(certificate, state)
    if renewal_due(cert_expires):
        raise SigningError("certificate_replacement_requires_local_authorization")
    previous = None
    profile = state / "profile.mobileprovision"
    if profile.is_file():
        parsed = decode_profile(profile, state)
        # Validate even expired profiles for identity/certificate, then handle expiry separately.
        created = parsed.get("CreationDate")
        if not isinstance(created, dt.datetime):
            raise SigningError("profile_dates_missing")
        previous = validate(parsed, identity, certificate, now=utc(created), minimum_hours=0)
    due = previous is None or renewal_due(previous)
    if not due and not changed and (state / "last-success.json").is_file():
        report = {"schema": 1, "status": "not_due", "expiresAt": previous.isoformat()}
        (out / "signing-report.json").write_text(json.dumps(report, indent=2))
        return report
    tool = install(root / "tool")
    apple = Apple(tool, state, identity)
    apple.personal_team()
    apple.ensure_registration()
    certificate = apple.certificate(create=False)
    fresh = apple.refresh_profile(certificate)
    ensure_extended(previous, fresh, due)
    report = sign(tool, state, identity, certificate, build)
    report.update(profileExtended=previous is None or fresh > previous,
                  runId=int(os.environ["GITHUB_RUN_ID"]), sourceRevision=os.environ["GITHUB_SHA"],
                  repositoryScope=scope.as_dict(),
                  unsignedBuildUpdateCheck=json.loads((state / "unsigned-build.json").read_text()).get("updateCheck", "current"),
                  bootstrapStateSha256=hashlib.sha256(base64.b64decode(os.environ["IOS_SIGNING_STATE_BASE64"], validate=True)).hexdigest())
    (state / "last-success.json").write_text(json.dumps(report))
    crypt(state / "signed.ipa", out / "LumaPocket_signed.ipa.gpg", password, root)
    export_state(state, out / "signing-state.tar.gz.gpg", password, root)
    (out / "signing-report.json").write_text(json.dumps(report, indent=2))
    return report


def main():
    scope = Scope.from_environment(os.environ)
    root = Path(os.environ["RUNNER_TEMP"]) / "lumapocket-private-signing"
    root.mkdir(mode=0o700, exist_ok=True)
    out = Path(os.environ["RUNNER_TEMP"]) / "lumapocket-signing-out"
    out.mkdir(exist_ok=True)
    password = os.environ.get("IOS_SIGNING_PASSPHRASE", "")
    try:
        if len(password) < 32 or not os.environ.get("IOS_SIGNING_STATE_BASE64"):
            raise SigningError("initial_local_authorization_required")
        report = renew(root, out, password, scope)
        print("Signing experiment: " + report["status"])
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write("Free-signing experiment: **" + report["status"] + "**.\n\n")
            summary.write("Expiry: " + report["expiresAt"] + ". Installation/refresh on your iPhone or iPad is still required.\n")
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, SigningError) else "unexpected_signing_failure"
        (out / "signing-report.json").write_text(json.dumps({"schema": 1, "status": "failed", "reason": code}))
        print("::error::Signing experiment stopped: " + code)
        return 1
    finally:
        publish = (out / "signing-state.tar.gz.gpg").is_file() or (out / "signing-report.json").is_file() and json.loads((out / "signing-report.json").read_text()).get("status") == "failed"
        with open(os.environ["GITHUB_OUTPUT"], "a") as outputs:
            outputs.write("publish=" + str(publish).lower() + "\n")
        if len(password) >= 32:
            # Only ciphertext diagnostics may be uploaded from this public repository.
            for candidate in (root / "state", root):
                try:
                    if (candidate / "diagnostics.log").is_file():
                        export_diagnostics(candidate, out / "diagnostics.log.gpg", password)
                        break
                except Exception:
                    pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SigningError as error:
        print("::error::" + str(error))
        sys.exit(1)
