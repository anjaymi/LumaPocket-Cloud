"""Private subprocess handling for the personal signing experiment."""
import os
import shutil
import subprocess
from pathlib import Path


class SigningError(Exception):
    """Only this fixed, non-sensitive error code may enter public CI logs."""


def private_env(root):
    allowed = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
               "APPDATA", "LOCALAPPDATA", "LANG", "LC_ALL", "DEVELOPER_DIR")
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    env["XDG_CONFIG_HOME"] = str(Path(root) / "config")
    return env


def run_private(args, root, stage, data=None, timeout=180, interactive=False):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    try:
        if interactive:
            result = subprocess.run(args, env=private_env(root), timeout=timeout)
            if result.returncode:
                raise SigningError(stage + "_failed")
            return b""
        result = subprocess.run(args, input=data if data is not None else b"n\nn\nn\n",
                                capture_output=True, env=private_env(root), timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        raise SigningError(stage + "_unavailable") from None
    log = root / "diagnostics.log"
    with open(log, "ab") as stream:
        stream.write(result.stdout[-512000:] + result.stderr[-512000:])
    if os.name != "nt":
        log.chmod(0o600)
    if result.returncode:
        text = (result.stdout + result.stderr).decode(errors="replace").lower()
        if stage == 'apple_portal' and ('maximum number of certificates' in text or 'too many certificates' in text):
            raise SigningError('apple_certificate_limit_reached')
        if any(word in text for word in ("session expired", "re-authenticate", "incorrect credentials", "two-factor", "verification code")):
            raise SigningError("reauthorization_required")
        raise SigningError(stage + "_failed")
    return result.stdout


def executable(name):
    if name == "openssl" and os.name != "nt":
        for candidate in ("/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl"):
            if Path(candidate).is_file():
                return candidate
    found = shutil.which(name)
    if found:
        return found
    if os.name == "nt":
        candidate = Path("C:/Program Files/Git/usr/bin") / (name + ".exe")
        if candidate.is_file():
            return str(candidate)
    raise SigningError(name + "_required")
