"""Publish only verified unsigned build files, without personal signing state."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import sys
import time
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "signing"))
from common import SigningError
from github_api import GitHub
from local_repositories import gh, viewer
from repository import UPSTREAM, UPSTREAM_ID, UPSTREAM_OWNER_ID, UPSTREAM_SCOPE
from sign_ipa import check_zip


def unpack(package, directory, run, config):
    version = config["applicationVersion"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+", version):
        raise SigningError("invalid_unsigned_build_version")
    filename = "LumaPocket_" + version + "_unsigned.ipa"
    with zipfile.ZipFile(package) as archive:
        names = archive.namelist()
        if len(names) != 3 or set(names) != {filename, filename + ".SHA256.txt", "build-report.json"}:
            raise SigningError("unexpected_unsigned_artifact")
        if archive.getinfo(filename).file_size > 256 * 1024 * 1024:
            raise SigningError("unsigned_ipa_too_large")
        data = archive.read(filename)
        report = json.loads(archive.read("build-report.json"))
    digest = hashlib.sha256(data).hexdigest()
    if (report.get("sha256", "").lower() != digest or report.get("bytes") != len(data)
            or report.get("version") != version or report.get("architectures") != "arm64"
            or report.get("bundleIdentifier") != config["bundleIdentifier"]
            or report.get("requiresLocalSigning") is not True or report.get("tokenizerSymbolsExported") is not True):
        raise SigningError("unsigned_build_report_mismatch")
    ipa = directory / filename
    ipa.write_bytes(data)
    check_zip(ipa)
    with zipfile.ZipFile(ipa) as archive:
        info = plistlib.loads(archive.read("Payload/Runner.app/Info.plist"))
        if ("Payload/Runner.app/embedded.mobileprovision" in archive.namelist()
                or info.get("CFBundleIdentifier") != config["bundleIdentifier"]
                or str(info.get("CFBundleShortVersionString")) + "+" + str(info.get("CFBundleVersion")) != version):
            raise SigningError("personal_or_mismatched_ipa_cannot_be_published")
    manifest = {"schema": 1, "repository": UPSTREAM, "repositoryId": UPSTREAM_ID, "ownerId": UPSTREAM_OWNER_ID,
                "runId": run["id"], "sourceRevision": run["head_sha"], "filename": filename,
                "sha256": digest, "bytes": len(data), "build": config}
    path = directory / "unsigned-manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return ipa, path


def verify_build(github, run_id):
    run = github.get("actions/runs/" + str(run_id))
    workflow_id = github.get("actions/workflows/ios.yml")["id"]
    if (run.get("head_repository", {}).get("id") != UPSTREAM_ID or run.get("actor", {}).get("id") != UPSTREAM_OWNER_ID
            or run.get("head_branch") != "main" or run.get("event") not in ("push", "workflow_dispatch")
            or run.get("workflow_id") != workflow_id or not re.fullmatch(r"[0-9a-f]{40}", run.get("head_sha", ""))):
        raise SigningError("trusted_upstream_build_required")
    jobs = github.get("actions/runs/" + str(run_id) + "/jobs?per_page=100")["jobs"]
    if not any(job.get("name") == "build" and job.get("conclusion") == "success" for job in jobs):
        raise SigningError("successful_unsigned_build_job_required")
    return run


def find_release(github, tag):
    published = github.get("releases/tags/" + tag, missing_ok=True)
    if published is not None:
        return published
    drafts = [item for item in github.get("releases?per_page=100") if item["tag_name"] == tag]
    if len(drafts) > 1:
        raise SigningError("duplicate_unsigned_release_drafts")
    return drafts[0] if drafts else None


def release_by_id(github, release_id):
    for attempt in range(7):
        release = github.get("releases/" + str(release_id), missing_ok=True)
        if release is not None:
            return release
        time.sleep(min(1 << attempt, 4))
    raise SigningError("created_unsigned_draft_not_ready_retry_publish")


def publish(github, run_id, directory):
    run = verify_build(github, run_id)
    config = json.loads(base64.b64decode(github.get("contents/build.json?ref=" + run["head_sha"])["content"]))
    artifacts = github.get("actions/runs/" + str(run_id) + "/artifacts?per_page=100")["artifacts"]
    candidates = [item for item in artifacts if item["name"] == "LumaPocket-iOS-unsigned" and not item["expired"]]
    if len(candidates) != 1:
        raise SigningError("one_verified_unsigned_artifact_required")
    package = directory / "verified-build.zip"
    github.download_artifact(candidates[0], package)
    files = unpack(package, directory, run, config)
    tag = "ios-unsigned-" + str(run_id)
    release = find_release(github, tag)
    if release is None:
        notes = ("Unsigned iOS/iPadOS test build " + config["applicationVersion"] +
                 ". Each tester signs it using their own Apple account.\n\n" +
                 "Build verification: https://github.com/" + UPSTREAM + "/actions/runs/" + str(run_id) + "\n")
        release = github.write("releases", {"tag_name": tag, "target_commitish": run["head_sha"], "draft": True,
            "prerelease": False, "name": "LumaPocket iOS " + config["applicationVersion"] + " (unsigned)", "body": notes})
    release_id = release["id"]
    for path in files:
        release = release_by_id(github, release_id)
        matches = [item for item in release["assets"] if item["name"] == path.name]
        expected_digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if not matches:
            if not release["draft"]:
                raise SigningError("published_unsigned_release_is_immutable")
            print("Uploading public unsigned file: " + path.name, flush=True)
            try:
                github.upload_unsigned_asset(release_id, path)
            except SigningError:
                # A transport error may happen after the server accepted the file.
                pass
            for attempt in range(7):
                matches = [item for item in release_by_id(github, release_id)["assets"] if item["name"] == path.name]
                if matches and matches[0].get("digest") == expected_digest:
                    break
                time.sleep(min(1 << attempt, 4))
        if len(matches) != 1 or matches[0].get("digest") != expected_digest or matches[0]["size"] != path.stat().st_size:
            raise SigningError("unsigned_release_upload_incomplete_retry_publish")
    release = release_by_id(github, release_id)
    if len(release["assets"]) != 2:
        raise SigningError("unexpected_files_in_unsigned_release")
    github.write("releases/" + str(release_id), {"draft": False, "make_latest": "true"}, "PATCH")
    print("Public unsigned build: https://github.com/" + UPSTREAM + "/releases/tag/" + tag, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", type=int, default=int(os.environ.get("GITHUB_RUN_ID", "0")))
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") == "true":
        if (os.environ.get("GITHUB_REPOSITORY_ID") != str(UPSTREAM_ID)
                or os.environ.get("GITHUB_ACTOR_ID") != str(UPSTREAM_OWNER_ID)
                or os.environ.get("GITHUB_REF") != "refs/heads/main"):
            raise SigningError("upstream_owner_only_publication")
        token = os.environ["GITHUB_TOKEN"]
    else:
        if viewer()["id"] != UPSTREAM_OWNER_ID:
            raise SigningError("upstream_owner_only_publication")
        token = gh(["auth", "token"]).decode().strip()
    directory = Path(os.environ.get("RUNNER_TEMP", ".lumapocket-signing")) / "public-unsigned-release"
    directory.mkdir(parents=True, exist_ok=True)
    publish(GitHub(token, UPSTREAM_SCOPE), args.run_id, directory)


if __name__ == "__main__":
    try:
        main()
    except SigningError as error:
        print("::error::" + str(error))
        sys.exit(1)
