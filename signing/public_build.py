"""Everyone shares public unsigned binaries; Apple state never leaves its scope."""
import hashlib
import json
import re
from common import SigningError
from repository import UPSTREAM, UPSTREAM_ID, UPSTREAM_OWNER_ID, Scope, UPSTREAM_SCOPE
from sign_ipa import check_zip


def release_assets(release):
    tag = release.get("tag_name", "")
    if (release.get("draft") is not False or release.get("prerelease") is not False
            or not re.fullmatch(r"ios-unsigned-[0-9]+", tag)
            or release.get("author", {}).get("id") not in (UPSTREAM_OWNER_ID, 41898282)):
        raise SigningError("trusted_unsigned_release_required")
    assets = release.get("assets", [])
    names = [item.get("name", "") for item in assets]
    if len(names) != len(set(names)) or len(assets) != 2 or "unsigned-manifest.json" not in names:
        raise SigningError("incomplete_unsigned_release")
    return tag, {item["name"]: item for item in assets}


def validate_manifest(manifest, tag, assets):
    build = manifest.get("build", {})
    version = build.get("applicationVersion", "")
    filename = "LumaPocket_" + version + "_unsigned.ipa"
    if (manifest.get("schema") != 1 or manifest.get("repository") != UPSTREAM
            or manifest.get("repositoryId") != UPSTREAM_ID or manifest.get("ownerId") != UPSTREAM_OWNER_ID
            or build.get("bundleIdentifier") != "io.lumapocket.client"
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+", version)
            or type(manifest.get("runId")) is not int or manifest["runId"] <= 0
            or tag != "ios-unsigned-" + str(manifest["runId"])
            or not re.fullmatch(r"[0-9a-f]{40}", manifest.get("sourceRevision", ""))
            or not re.fullmatch(r"[0-9a-f]{64}", manifest.get("sha256", ""))
            or manifest.get("filename") != filename or set(assets) != {filename, "unsigned-manifest.json"}):
        raise SigningError("invalid_unsigned_release_manifest")
    item = assets[filename]
    if (item.get("digest") != "sha256:" + manifest["sha256"] or item.get("size") != manifest.get("bytes")
            or type(item.get("size")) is not int or not 0 < item["size"] <= 256 * 1024 * 1024):
        raise SigningError("unsigned_manifest_asset_mismatch")
    return build, item


def cached(state):
    try:
        manifest = json.loads((state / "unsigned-build.json").read_text())["manifest"]
        filename = manifest["filename"]
        assets = {filename: {"digest": "sha256:" + manifest["sha256"], "size": manifest["bytes"]},
                  "unsigned-manifest.json": {}}
        build, _ = validate_manifest(manifest, "ios-unsigned-" + str(manifest["runId"]), assets)
        data = (state / "unsigned.ipa").read_bytes()
        if len(data) != manifest["bytes"] or hashlib.sha256(data).hexdigest() != manifest["sha256"]:
            return None
        return manifest, build
    except (OSError, ValueError, TypeError, KeyError, SigningError):
        return None


def record(state, manifest, build, update_check):
    (state / "unsigned-build.json").write_text(json.dumps({"manifest": manifest, "build": build,
        "sha256": manifest["sha256"], "updateCheck": update_check}))


def version_number(build):
    return tuple(int(value) for value in re.split(r"[.+]", build["applicationVersion"]))


def unsigned(github, state):
    previous = cached(state)
    if github.scope != UPSTREAM_SCOPE:
        raise SigningError("trusted_unsigned_repository_required")
    try:
        return refresh(github, state, previous)
    except SigningError as error:
        if previous and str(error) in ("github_download_unavailable", "github_request_rejected"):
            manifest, build = previous
            record(state, manifest, build, "using_verified_cache_update_temporarily_unavailable")
            print("Public update unavailable; using the verified cached unsigned build.")
            return build, False
        raise


def refresh(github, state, previous):
    if github.scope != UPSTREAM_SCOPE or Scope.from_metadata(github.get("")) != UPSTREAM_SCOPE:
        raise SigningError("trusted_unsigned_repository_required")
    release = github.get("releases/latest")
    tag, assets = release_assets(release)
    if assets["unsigned-manifest.json"].get("size", 0) > 65536:
        raise SigningError("unsigned_manifest_too_large")
    manifest = json.loads(github.public_asset(assets["unsigned-manifest.json"], tag))
    build, item = validate_manifest(manifest, tag, assets)
    original = state / "unsigned.ipa"
    if previous:
        if version_number(build) < version_number(previous[1]):
            record(state, previous[0], previous[1], "older_public_version_ignored")
            return previous[1], False
        if previous[0] == manifest:
            record(state, manifest, build, "current")
            return build, False
    data = github.public_asset(item, tag)
    if hashlib.sha256(data).hexdigest() != manifest["sha256"]:
        raise SigningError("unsigned_ipa_digest_mismatch")
    pending = state / "unsigned-download.ipa"
    pending.write_bytes(data)
    check_zip(pending)
    pending.replace(original)
    record(state, manifest, build, "current")
    return build, True
