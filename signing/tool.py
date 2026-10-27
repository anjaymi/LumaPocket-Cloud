"""Install the frozen upstream release; never execute an unchecked download."""
import hashlib
import json
import os
import platform
import stat
import subprocess
import tarfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent


def safe_name(name):
    normalized = name.removeprefix("./")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
        raise ValueError("Unsafe archive member")
    return path.as_posix()


def download(url, destination, limit=128 * 1024 * 1024):
    request = urllib.request.Request(url, headers={"User-Agent": "LumaPocket-iOS-build"})
    with urllib.request.urlopen(request, timeout=60) as response, open(destination, "wb") as output:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > limit:
                raise ValueError("Download exceeds size limit")
            output.write(chunk)


def install(root):
    config = json.loads((HERE / "toolchain.json").read_text())
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "x86_64"
    spec = config["archives"][platform.system() + "-" + arch]
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    archive = root / ("release.zip" if spec["url"].endswith(".zip") else "release.tar.gz")
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != spec["sha256"]:
        download(spec["url"], archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != spec["sha256"]:
        raise ValueError("Upstream release checksum mismatch")
    binaries = root / "bin"
    binaries.mkdir(exist_ok=True)
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as package:
            seen = set()
            for member in package.infolist():
                name = safe_name(member.filename)
                if name in seen or stat.S_ISLNK(member.external_attr >> 16):
                    raise ValueError("Duplicate/symbolic tool entry")
                seen.add(name)
                target = binaries / name
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    if member.file_size > 128 * 1024 * 1024:
                        raise ValueError("Oversized tool entry")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(package.read(member))
    else:
        with tarfile.open(archive) as package:
            seen = set()
            for member in package.getmembers():
                name = safe_name(member.name)
                if name in seen or not (member.isfile() or member.isdir()):
                    raise ValueError("Duplicate/special tool entry")
                seen.add(name)
                target = binaries / name
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(package.extractfile(member).read())
                    target.chmod(member.mode & 0o777)
    name = "sidesign.exe" if os.name == "nt" else "sidesign"
    candidates = list(binaries.rglob(name))
    if len(candidates) != 1:
        raise ValueError("Expected exactly one signing executable")
    if os.name == "nt":
        runtime = config.get("windowsRuntime")
        if runtime is None:
            raise RuntimeError("Portable Swift runtime must be configured")
        runtime_zip = HERE / runtime["file"]
        if hashlib.sha256(runtime_zip.read_bytes()).hexdigest() != runtime["sha256"]:
            raise ValueError("Swift runtime checksum mismatch")
        with zipfile.ZipFile(runtime_zip) as package:
            seen = set()
            for member in package.infolist():
                entry = safe_name(member.filename)
                if "/" in entry or entry in seen or member.file_size > 128 * 1024 * 1024 or stat.S_ISLNK(member.external_attr >> 16):
                    raise ValueError("Unsafe runtime entry")
                seen.add(entry)
                (candidates[0].parent / entry).write_bytes(package.read(member))
    return candidates[0].resolve()


def check(root):
    from common import private_env
    tool = install(root)
    result = subprocess.run([str(tool), "--help"], capture_output=True, text=True, timeout=30, env=private_env(root))
    if result.returncode or not all(word in result.stdout.lower() for word in ("sign", "profile", "dev")):
        raise RuntimeError("Verified signing tool failed its startup check")
    return {"version": "0.1.7", "platform": platform.system(), "startupCheck": True}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.root)))
