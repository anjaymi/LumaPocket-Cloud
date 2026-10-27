"""Only encrypted state/IPA files leave the runner."""
import io
import os
import tarfile
import tempfile
from pathlib import Path
from common import SigningError, executable, run_private

STATE_FILES = {"identity.json", "session.dat", "machine.dat", "certificate.p12",
               "profile.mobileprovision", "unsigned.ipa", "unsigned-build.json", "last-success.json"}
REQUIRED_FILES = {"identity.json", "session.dat", "machine.dat", "certificate.p12"}


def crypt(source, destination, password, root, decrypt=False):
    if len(password) < 32 or "\n" in password or "\r" in password:
        raise SigningError("invalid_state_passphrase")
    # Agent socket paths are limited on macOS and in Git for Windows' MSYS.
    # Keep the GPG home separate from potentially long private work paths.
    with tempfile.TemporaryDirectory(prefix="lp-gpg-", dir="/tmp" if os.name != "nt" else None) as short_home:
        home = Path(short_home)
        if os.name != "nt":
            home.chmod(0o700)
        try:
            _crypt(source, destination, password, root, home, decrypt)
        finally:
            try:
                run_private([executable("gpgconf"), "--homedir", _home_arg(home), "--kill", "gpg-agent"],
                            root, "isolated_agent_cleanup", timeout=15)
            except SigningError:
                pass


def _home_arg(home):
    if os.name == "nt" and home.drive:
        return "/" + home.drive[0].lower() + home.as_posix()[2:]
    return str(home)


def _crypt(source, destination, password, root, home, decrypt):
    args = [executable("gpg"), "--no-options", "--homedir", _home_arg(home), "--batch", "--yes", "--pinentry-mode", "loopback",
            "--no-symkey-cache", "--passphrase-fd", "0", "--output", str(destination)]
    args += ["--decrypt"] if decrypt else ["--symmetric", "--cipher-algo", "AES256", "--compress-level", "0"]
    run_private(args + [str(source)], root, "state_decryption" if decrypt else "state_encryption",
                data=password.encode(), timeout=180)


def extract_state(archive_path, target):
    target = Path(target)
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path) as archive:
        names, total = set(), 0
        members = archive.getmembers()
        for member in members:
            if member.name not in STATE_FILES or member.name in names or not member.isfile():
                raise SigningError("invalid_state_archive")
            total += member.size
            if member.size < 0 or total > 256 * 1024 * 1024:
                raise SigningError("state_archive_too_large")
            names.add(member.name)
        if not REQUIRED_FILES <= names:
            raise SigningError("incomplete_authorized_state")
        for member in members:
            path = target / member.name
            path.write_bytes(archive.extractfile(member).read())
            if os.name != "nt":
                path.chmod(0o600)
    # Machine-derived SS01 sessions cannot be restored on a different runner.
    if (target / "session.dat").read_bytes()[:4] != b"SS02":
        raise SigningError("portable_password_session_required")


def export_state(source, destination, password, root):
    source = Path(source)
    archive_path = Path(root) / "state.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        for name in sorted(STATE_FILES):
            path = source / name
            if path.is_file():
                if path.is_symlink():
                    raise SigningError("invalid_state_archive")
                archive.add(path, arcname=name, recursive=False)
    crypt(archive_path, destination, password, root)


def export_diagnostics(root, destination, password):
    log = Path(root) / "diagnostics.log"
    if log.is_file():
        crypt(log, destination, password, root)
