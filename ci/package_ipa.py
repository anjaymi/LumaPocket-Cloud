import hashlib
import json
import os
import plistlib
import shutil
import subprocess
from pathlib import Path

config = json.loads(Path("build.json").read_text())
app = Path(os.environ["LUMAPOCKET_APP"]) / "build/ios/iphoneos/Runner.app"
assert app.is_dir()
info = plistlib.loads((app / "Info.plist").read_bytes())
assert info["CFBundleIdentifier"] == config["bundleIdentifier"]
assert not (app / "embedded.mobileprovision").exists()
executable = app / info["CFBundleExecutable"]
architectures = subprocess.check_output(["xcrun", "lipo", "-archs", str(executable)], text=True).strip()
assert "arm64" in architectures.split()
exports = subprocess.check_output(["xcrun", "dyld_info", "-exports", str(executable)], text=True)
for symbol in ["nai_qwen_count_json", "nai_qwen_count_free"]:
    assert symbol in exports, "Required offline tokenizer symbol was stripped: " + symbol
for framework in ["App", "Flutter"]:
    assert (app / "Frameworks" / (framework + ".framework") / framework).is_file()
out = Path(os.environ["RUNNER_TEMP"]) / "lumapocket-out"
out.mkdir(exist_ok=True)
payload = Path(os.environ["RUNNER_TEMP"]) / "lumapocket-payload" / "Payload"
payload.mkdir(parents=True, exist_ok=True)
shutil.copytree(app, payload / "Runner.app", symlinks=True)
version = str(info["CFBundleShortVersionString"]) + "+" + str(info["CFBundleVersion"])
ipa = out / ("LumaPocket_" + version + "_unsigned.ipa")
subprocess.run(["ditto", "-c", "-k", "--keepParent", str(payload), str(ipa)], check=True)
digest = hashlib.sha256(ipa.read_bytes()).hexdigest().upper()
(ipa.with_suffix(ipa.suffix + ".SHA256.txt")).write_text(digest + "  " + ipa.name + "\n")
report = {"displayName": info["CFBundleDisplayName"], "bundleIdentifier": info["CFBundleIdentifier"], "version": version, "architectures": architectures, "requiresLocalSigning": True, "tokenizerSymbolsExported": True, "sha256": digest, "bytes": ipa.stat().st_size}
(out / "build-report.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
