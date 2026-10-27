"""Read only successful owner builds; strip API credentials on redirects."""
import hashlib
import json
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlsplit
from common import SigningError
from repository import Scope, UPSTREAM, UPSTREAM_ID, UPSTREAM_SCOPE

REPOSITORY = UPSTREAM
REPOSITORY_ID = UPSTREAM_ID


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        if urlsplit(new_url).scheme != "https":
            raise SigningError("insecure_artifact_redirect")
        redirected = super().redirect_request(request, fp, code, message, headers, new_url)
        if urlsplit(new_url).hostname != "api.github.com":
            redirected.remove_header("Authorization")
        return redirected


def trusted_run(run, workflow_id, scope=UPSTREAM_SCOPE):
    return (run.get("conclusion") == "success" and run.get("status") == "completed"
            and run.get("head_branch") == "main" and run.get("workflow_id") == workflow_id
            and run.get("head_repository", {}).get("id") == scope.repository_id
            and run.get("actor", {}).get("id") == scope.owner_id
            and run.get("actor", {}).get("login", "").lower() == scope.owner.lower()
            and run.get("event") in ("push", "workflow_dispatch", "schedule"))


class GitHub:
    def __init__(self, token, scope=UPSTREAM_SCOPE):
        self.token = token
        self.scope = scope
        self.opener = urllib.request.build_opener(SafeRedirect())

    def get(self, path, binary=False, missing_ok=False):
        url = "https://api.github.com/repos/" + self.scope.repository + ("/" + path if path else "")
        headers = {
            "User-Agent": "LumaPocket-self-test", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        return self.request(urllib.request.Request(url, headers=headers), binary, missing_ok)

    def request(self, request, binary=False, missing_ok=False):
        for attempt in range(3):
            try:
                with self.opener.open(request, timeout=90) as response:
                    data = response.read(512 * 1024 * 1024 + 1)
                    if len(data) > 512 * 1024 * 1024:
                        raise SigningError("artifact_too_large")
                return data if binary else json.loads(data)
            except urllib.error.HTTPError as error:
                if error.code == 404 and missing_ok:
                    return None
                if error.code not in (429, 500, 502, 503, 504):
                    raise SigningError("github_request_rejected") from None
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                pass
            except (ValueError, UnicodeError):
                raise SigningError("invalid_github_response") from None
            if attempt < 2:
                time.sleep(1 + attempt)
        raise SigningError("github_download_unavailable")

    def public_asset(self, item, tag):
        url = item.get("browser_download_url", "")
        parsed = urlsplit(url)
        prefix = "/" + self.scope.repository + "/releases/download/" + tag + "/"
        if parsed.scheme != "https" or parsed.netloc != "github.com" or not parsed.path.startswith(prefix) or parsed.query or parsed.fragment:
            raise SigningError("unexpected_public_release_asset_url")
        # Public installation packages require no user's token at the asset host.
        data = self.request(urllib.request.Request(url, headers={"User-Agent": "LumaPocket"}), binary=True)
        digest = item.get("digest", "")
        if digest != "sha256:" + hashlib.sha256(data).hexdigest() or len(data) != item.get("size"):
            raise SigningError("public_release_asset_digest_mismatch")
        return data

    def artifact(self, workflow, name):
        workflow_id = self.get("actions/workflows/" + workflow)["id"]
        runs = self.get(f"actions/workflows/{workflow_id}/runs?branch=main&status=completed&per_page=30")
        for run in runs.get("workflow_runs", []):
            if not trusted_run(run, workflow_id, self.scope):
                continue
            artifacts = self.get(f"actions/runs/{int(run['id'])}/artifacts?per_page=100")["artifacts"]
            for item in artifacts:
                if item.get("name") == name and not item.get("expired"):
                    return run, item
        return None

    def download_artifact(self, item, destination):
        digest = item.get("digest", "")
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise SigningError("artifact_digest_missing")
        data = self.get(f"actions/artifacts/{int(item['id'])}/zip", binary=True)
        if hashlib.sha256(data).hexdigest() != digest[7:]:
            raise SigningError("artifact_digest_mismatch")
        Path(destination).write_bytes(data)

    def restore_state(self, destination, root):
        found = self.artifact("free-signing.yml", "LumaPocket-free-sign")
        if found is None:
            return False
        _, item = found
        package = Path(root) / "previous-signing.zip"
        self.download_artifact(item, package)
        with zipfile.ZipFile(package) as archive:
            names = archive.namelist()
            allowed = {"signing-state.tar.gz.gpg", "LumaPocket_signed.ipa.gpg", "signing-report.json", "diagnostics.log.gpg"}
            if len(names) != len(set(names)) or not set(names) <= allowed or "signing-state.tar.gz.gpg" not in names:
                raise SigningError("unexpected_signing_artifact")
            Path(destination).write_bytes(archive.read("signing-state.tar.gz.gpg"))
        return True

    def unsigned(self, state):
        from public_build import unsigned
        return unsigned(GitHub(self.token, UPSTREAM_SCOPE), Path(state))
