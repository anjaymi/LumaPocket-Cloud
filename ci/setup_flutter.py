import hashlib
import json
import os
import platform
import subprocess
import tempfile
from pathlib import Path

config = json.loads(Path("build.json").read_text())
version = config["flutterVersion"]
root = Path(os.environ["RUNNER_TEMP"]) / "lumapocket-flutter"
sdk = root / "flutter"
if not (sdk / "bin/flutter").is_file():
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        index = Path(temporary) / "releases.json"
        base = "https://storage.googleapis.com/flutter_infra_release/releases"
        subprocess.run(["curl", "--fail", "--location", "--retry", "3", "--connect-timeout", "20", "--max-time", "180", "-o", str(index), base + "/releases_macos.json"], check=True)
        releases = json.loads(index.read_text())
        arch = "arm64" if platform.machine() == "arm64" else "x64"
        release = next(item for item in releases["releases"] if item["version"] == version and item["channel"] == "stable" and item.get("dart_sdk_arch", "x64") == arch)
        archive = Path(temporary) / "flutter.zip"
        subprocess.run(["curl", "--fail", "--location", "--retry", "3", "--connect-timeout", "20", "--max-time", "600", "-o", str(archive), releases["base_url"] + "/" + release["archive"]], check=True)
        assert hashlib.file_digest(archive.open("rb"), "sha256").hexdigest() == release["sha256"]
        subprocess.run(["ditto", "-xk", str(archive), str(root)], check=True)
with open(os.environ["GITHUB_PATH"], "a") as stream:
    stream.write(str(sdk / "bin") + "\n")
subprocess.run([str(sdk / "bin/flutter"), "--no-version-check", "--version"], check=True)
