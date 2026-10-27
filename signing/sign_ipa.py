"""Re-sign, then independently verify with Apple's native codesign tool."""
import hashlib
import json
import plistlib
import posixpath
import stat
import zipfile
from pathlib import Path
from common import SigningError, run_private
from profile import certificate_expiry, decode_profile, validate
from tool import safe_name


def check_zip(path):
    with zipfile.ZipFile(path) as archive:
        names, total = set(), 0
        for entry in archive.infolist():
            name = safe_name(entry.filename).rstrip("/")
            if name in names or not (name in ("Payload", "Payload/Runner.app") or name.startswith("Payload/Runner.app/")):
                raise SigningError("invalid_ipa_layout")
            names.add(name)
            total += entry.file_size
            if total > 1024 * 1024 * 1024:
                raise SigningError("ipa_too_large")
            if stat.S_ISLNK(entry.external_attr >> 16):
                target = archive.read(entry).decode()
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
                if target.startswith("/") or not resolved.startswith("Payload/Runner.app/"):
                    raise SigningError("unsafe_ipa_symlink")
        if "Payload/Runner.app/Info.plist" not in names:
            raise SigningError("ipa_info_missing")


def sign(tool, state, identity, certificate, build):
    state = Path(state)
    original = state / "unsigned.ipa"
    check_zip(original)
    signed = state / "signed.ipa"
    run_private([str(tool), "sign", str(original), "--p12", str(state / "certificate.p12"),
                 "--password", identity["p12Password"], "--profile", str(state / "profile.mobileprovision"),
                 "--bundle-id", identity["bundleIdentifier"], "--output", str(signed)], state, "ipa_signing", timeout=300)
    if not signed.is_file():
        raise SigningError("signed_ipa_missing")
    check_zip(signed)
    verify_root = state / "verify"
    verify_root.mkdir(exist_ok=True)
    run_private(["ditto", "-xk", str(signed), str(verify_root)], state, "ipa_unpack")
    app = verify_root / "Payload/Runner.app"
    run_private(["codesign", "--verify", "--deep", "--strict", str(app)], state, "native_signature_verification")
    info = plistlib.loads((app / "Info.plist").read_bytes())
    version = str(info["CFBundleShortVersionString"]) + "+" + str(info["CFBundleVersion"])
    if info["CFBundleIdentifier"] != identity["bundleIdentifier"] or version != build["applicationVersion"]:
        raise SigningError("signed_app_identity_mismatch")
    profile = app / "embedded.mobileprovision"
    if profile.read_bytes() != (state / "profile.mobileprovision").read_bytes():
        raise SigningError("embedded_profile_changed")
    expires = min(validate(decode_profile(profile, state), identity, certificate), certificate_expiry(certificate, state))
    entitlement_data = run_private(["codesign", "-d", "--entitlements", "-", "--xml", str(app)], state, "signed_entitlements")
    entitlements = plistlib.loads(entitlement_data)
    if entitlements.get("application-identifier") != identity["teamId"] + "." + identity["bundleIdentifier"]:
        raise SigningError("signed_entitlements_mismatch")
    architectures = run_private(["xcrun", "lipo", "-archs", str(app / info["CFBundleExecutable"])], state, "signed_architecture").decode().split()
    if architectures != ["arm64"]:
        raise SigningError("signed_arm64_architecture_required")
    exports = run_private(["xcrun", "dyld_info", "-exports", str(app / info["CFBundleExecutable"])], state, "tokenizer_exports")
    if not all(symbol in exports for symbol in (b"nai_qwen_count_json", b"nai_qwen_count_free")):
        raise SigningError("signed_tokenizer_symbols_missing")
    return {"schema": 1, "status": "signed", "version": version, "architectures": architectures, "expiresAt": expires.isoformat(),
            "signatureChecksPassed": True, "deviceProfileChecked": True, "tokenizerSymbolsExported": True,
            "requiresDeviceInstallation": True, "physicalIPhoneTested": False,
            "sha256": hashlib.sha256(signed.read_bytes()).hexdigest(), "bytes": signed.stat().st_size}
