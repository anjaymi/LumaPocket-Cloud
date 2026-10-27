"""Exercise cross-repository public reads with only this job's read-only token."""
import json
import os
from pathlib import Path
from common import SigningError
from github_api import GitHub
from public_build import release_assets, validate_manifest
from repository import Scope, UPSTREAM_SCOPE


def main():
    scope = Scope(os.environ["GITHUB_REPOSITORY"], int(os.environ["GITHUB_REPOSITORY_ID"]),
                  int(os.environ["GITHUB_REPOSITORY_OWNER_ID"]))
    token = os.environ["GITHUB_TOKEN"]
    if Scope.from_metadata(GitHub(token, scope).get("")) != scope:
        raise SigningError("current_repository_identity_mismatch")
    public = GitHub(token, UPSTREAM_SCOPE)
    if Scope.from_metadata(public.get("")) != UPSTREAM_SCOPE:
        raise SigningError("trusted_unsigned_repository_required")
    release = public.get("releases/latest")
    tag, assets = release_assets(release)
    manifest = json.loads(public.public_asset(assets["unsigned-manifest.json"], tag))
    build, _ = validate_manifest(manifest, tag, assets)
    report = {"schema": 1, "repositoryScope": scope.as_dict(), "publicUpstreamVerified": True,
              "release": tag, "version": build["applicationVersion"], "usesAppleCredentials": False,
              "usesOtherUsersSigningState": False}
    out = Path(os.environ["RUNNER_TEMP"]) / "lumapocket-signing-check-out"
    out.mkdir(exist_ok=True)
    (out / "public-feed-check.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SigningError as error:
        print("::error::" + str(error))
        raise SystemExit(1)
