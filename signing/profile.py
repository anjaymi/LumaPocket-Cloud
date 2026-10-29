"""Reject wrong-device, stale and mismatched free provisioning profiles."""
import datetime as dt
import json
import plistlib
import re
import ssl
from pathlib import Path
from urllib.parse import urlsplit
from common import SigningError, executable, run_private

UTC = dt.timezone.utc


def validate_local_inputs(udid, anisette_url):
    if not re.fullmatch(r"(?:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}|[0-9A-Fa-f]{40})", udid):
        raise SigningError("invalid_device_udid")
    server = urlsplit(anisette_url)
    if server.scheme != "https" or not server.hostname or server.username or server.password or server.query or server.fragment:
        raise SigningError("https_anisette_server_required")


def utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def identity_from(path):
    identity = json.loads(Path(path).read_text())
    team = identity.get("teamId", "")
    if identity.get("schema") != 1 or not re.fullmatch(r"[A-Z0-9]{10}", team):
        raise SigningError("invalid_team_identity")
    if identity.get("bundleIdentifier") != "io.lumapocket.client." + team.lower():
        raise SigningError("invalid_app_identity")
    validate_local_inputs(identity.get("deviceUdid", ""), identity.get("anisetteURL", ""))
    for key in ("sessionPassword", "machinePassword", "p12Password"):
        if len(identity.get(key, "")) < 32:
            raise SigningError("incomplete_authorized_state")
    return identity


def decode_profile(path, root):
    data = run_private([executable("openssl"), "cms", "-verify", "-inform", "DER", "-in", str(path), "-noverify"],
                       root, "profile_cms_verification")
    try:
        return plistlib.loads(data)
    except Exception:
        raise SigningError("invalid_profile_plist") from None


def certificate_der(p12, password, root):
    # CodeSignKit's P12 does not set OpenSSL's localKeyID bag attribute.
    # -clcerts silently removes its sole certificate while returning success.
    pem = run_private([executable("openssl"), "pkcs12", "-in", str(p12), "-passin", "stdin", "-nokeys"],
                      root, "identity_certificate", data=(password + "\n").encode())
    certificates = re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem, re.S)
    if len(certificates) != 1:
        raise SigningError('single_identity_certificate_required')
    return run_private([executable("openssl"), "x509", "-outform", "DER"], root, "certificate_decode", data=certificates[0])


def certificate_expiry(certificate, root):
    value = run_private([executable("openssl"), "x509", "-inform", "DER", "-enddate", "-noout"],
                        root, "certificate_expiry", data=certificate).decode().strip()
    try:
        return dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(value.split("=", 1)[1]), tz=UTC)
    except (ValueError, IndexError):
        raise SigningError("invalid_certificate_expiry") from None


def validate(profile, identity, certificate, now=None, minimum_hours=12):
    now = utc(now or dt.datetime.now(UTC))
    created, expires = profile.get("CreationDate"), profile.get("ExpirationDate")
    if not isinstance(created, dt.datetime) or not isinstance(expires, dt.datetime):
        raise SigningError("profile_dates_missing")
    created, expires = utc(created), utc(expires)
    if created > now + dt.timedelta(minutes=5) or expires <= now + dt.timedelta(hours=minimum_hours):
        raise SigningError("profile_expired_or_too_short")
    if expires - created > dt.timedelta(days=8):
        raise SigningError("unexpected_nonfree_profile_lifetime")
    team = identity["teamId"]
    entitlements = profile.get("Entitlements", {})
    if profile.get("TeamIdentifier") != [team] or entitlements.get("com.apple.developer.team-identifier") != team:
        raise SigningError("profile_team_mismatch")
    if entitlements.get("application-identifier") != team + "." + identity["bundleIdentifier"]:
        raise SigningError("profile_bundle_mismatch")
    if entitlements.get("get-task-allow") is not True or profile.get("ProvisionsAllDevices"):
        raise SigningError("personal_development_profile_required")
    if identity["deviceUdid"] not in profile.get("ProvisionedDevices", []):
        raise SigningError("profile_device_mismatch")
    if certificate not in profile.get("DeveloperCertificates", []):
        raise SigningError("profile_certificate_mismatch")
    return expires


def renewal_due(expires, now=None):
    return utc(expires) <= utc(now or dt.datetime.now(UTC)) + dt.timedelta(hours=48)


def ensure_extended(previous, fresh, was_due):
    if was_due and previous is not None and utc(fresh) <= utc(previous):
        raise SigningError("apple_did_not_extend_profile")
