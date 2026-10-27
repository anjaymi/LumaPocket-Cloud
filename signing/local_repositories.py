"""Create/select an owner's public signing repository before Apple login."""
from contextlib import contextmanager
from functools import lru_cache
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
from common import SigningError
from github_api import GitHub
from repository import PROTOCOL, Scope, UPSTREAM, UPSTREAM_SCOPE


def gh(arguments, data=None, missing_ok=False, token=None):
    env = os.environ.copy()
    env["GODEBUG"] = "http2client=0"
    if token is not None:
        env["GH_TOKEN"] = token
    read_only = (arguments[:2] in (["auth", "token"], ["variable", "list"]) or
                 arguments[0] == "api" and not any(arg in arguments for arg in ("--method", "--input", "-X", "-f", "-F")))
    if arguments[0] == "api" and read_only:
        # Native HTTPS avoids CLI transport resets on some Windows networks.
        token = token or gh(["auth", "token"]).decode().strip()
        path = arguments[1]
        if path.startswith("/") or "://" in path:
            raise SigningError("github_api_relative_path_required")
        request = urllib.request.Request("https://api.github.com/" + path,
            headers={"Authorization": "Bearer " + token, "User-Agent": "LumaPocket"})
        value = GitHub(token).request(request, missing_ok=missing_ok)
        return None if value is None else json.dumps(value).encode()
    for attempt in range(3 if read_only else 1):
        try:
            result = subprocess.run(["gh", *arguments], input=data, capture_output=True, timeout=60 if read_only else 180, env=env)
        except (OSError, subprocess.TimeoutExpired):
            if not read_only or attempt == 2:
                raise SigningError("github_cli_unavailable_check_network_and_gh_auth") from None
        else:
            if not result.returncode:
                return result.stdout
            if missing_ok and b"HTTP 404" in result.stderr:
                return None
            if not read_only or not any(word in result.stderr.lower() for word in (b"eof", b"timeout", b"timed out", b"tls", b"reset", b"forcibly closed")):
                raise SigningError("github_cli_failed_check_network_and_gh_auth")
        if attempt < 2:
            time.sleep(1 + attempt)
    raise SigningError("github_cli_unavailable_check_network_and_gh_auth")


@lru_cache(maxsize=1)
def viewer():
    value = json.loads(gh(["api", "user"]))
    if value.get("type") != "User" or type(value.get("id")) is not int:
        raise SigningError("personal_github_account_required")
    return {"id": value["id"], "login": value["login"]}


def client(scope):
    # Pin the token to this owner, even if another window switches gh's active user.
    token = gh(["auth", "token", "--hostname", "github.com", "--user", scope.owner]).decode().strip()
    user = json.loads(gh(["api", "user"], token=token))
    if user.get("id") != scope.owner_id:
        raise SigningError("github_token_belongs_to_another_owner")
    return GitHub(token, scope)


def repository_gh(github, arguments, data=None):
    if "--repo" not in arguments or arguments[arguments.index("--repo") + 1] != github.scope.repository:
        raise SigningError("github_write_target_must_match_authorized_repository")
    if arguments[:2] == ["variable", "list"]:
        return json.dumps(github.get("actions/variables?per_page=100")["variables"]).encode()
    if arguments[:2] == ["variable", "set"]:
        github.set_variable(arguments[2], arguments[arguments.index("--body") + 1])
        return b""
    if arguments[:2] == ["workflow", "enable"]:
        github.write("actions/workflows/free-signing.yml/enable", method="PUT")
        return b""
    if arguments[:2] == ["workflow", "run"]:
        github.write("actions/workflows/free-signing.yml/dispatches", {"ref": "main", "inputs": {"mode": "renew", "reset_state": True}})
        return b""
    return gh(arguments, data, token=github.token)


def save_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_suffix(".pending")
    pending.write_text(json.dumps(value, indent=2), encoding="utf-8")
    if os.name != "nt":
        pending.chmod(0o600)
    pending.replace(path)


def profile_home(base, scope):
    return Path(base) / "profiles" / str(scope.owner_id) / str(scope.repository_id)


def setup(base, repository=None, name="LumaPocket-Cloud"):
    user = viewer()
    repository = repository or user["login"] + "/" + name
    # Validate names and ownership before a repository can be created or selected.
    candidate = Scope(repository, 1, user["id"])
    if candidate.owner.lower() != user["login"].lower():
        raise SigningError("current_github_account_must_own_repository")
    raw = gh(["api", "repos/" + repository], missing_ok=True)
    if raw is None:
        print("Creating your public signing repository: " + repository)
        gh(["repo", "create", repository, "--public", "--template", UPSTREAM,
            "--description", "Personal encrypted iOS signing workspace"])
        raw = gh(["api", "repos/" + repository])
    scope = Scope.from_metadata(json.loads(raw), user)
    if scope == UPSTREAM_SCOPE:
        raise SigningError("shared_build_repository_cannot_store_personal_signing_state")
    github = client(scope)
    import base64
    # GitHub can return repository metadata before template files are available.
    for attempt in range(7):
        protocol = github.get("contents/signing/protocol.json?ref=main", missing_ok=True)
        if protocol is not None:
            break
        time.sleep(min(1 << attempt, 8))
    if protocol is None:
        raise SigningError("personal_template_not_ready_retry_setup")
    if json.loads(base64.b64decode(protocol["content"])) != {"schema": PROTOCOL, "upstream": UPSTREAM}:
        raise SigningError("repository_needs_current_signing_template")
    variables = json.loads(repository_gh(github, ["variable", "list", "--repo", repository, "--json", "name,value"]))
    current = {value["name"]: value["value"] for value in variables}
    expected = {"SIGNING_REPOSITORY_ID": str(scope.repository_id), "SIGNING_OWNER_ID": str(scope.owner_id)}
    if any(current.get(key) != value for key, value in expected.items()):
        repository_gh(github, ["variable", "set", "FREE_SIGNING_ENABLED", "--repo", repository, "--body", "false"])
        for key, value in expected.items():
            repository_gh(github, ["variable", "set", key, "--repo", repository, "--body", value])
    repository_gh(github, ["workflow", "enable", "free-signing.yml", "--repo", repository])
    home = profile_home(base, scope)
    save_json(home / "repository.json", scope.as_dict())
    save_json(Path(base) / ("active-" + str(scope.owner_id) + ".json"), scope.as_dict())
    print("Your isolated repository is ready: https://github.com/" + repository)
    print("Next: signing\\start.cmd authorize")
    return scope, home


def selected(base, repository=None):
    user = viewer()
    if repository:
        scope = Scope.from_metadata(json.loads(gh(["api", "repos/" + repository])), user)
    else:
        active = Path(base) / ("active-" + str(user["id"]) + ".json")
        if not active.is_file():
            raise SigningError("run_setup_for_current_github_account_first")
        scope = Scope.from_dict(json.loads(active.read_text()))
        actual = Scope.from_metadata(json.loads(gh(["api", "repos/" + scope.repository])), user)
        if scope != actual:
            raise SigningError("repository_identity_changed_run_setup_again")
    if scope == UPSTREAM_SCOPE:
        raise SigningError("shared_build_repository_cannot_store_personal_signing_state")
    home = profile_home(base, scope)
    if not (home / "repository.json").is_file() or Scope.from_dict(json.loads((home / "repository.json").read_text())) != scope:
        raise SigningError("run_setup_for_current_github_account_first")
    return scope, home


@contextmanager
def profile_lock(home):
    """OS locks release on crashes and prevent two local authorizations colliding."""
    home.mkdir(parents=True, exist_ok=True)
    with open(home / "operation.lock", "a+b") as stream:
        if os.fstat(stream.fileno()).st_size == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SigningError("local_profile_in_use_close_other_signing_window") from None
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)
