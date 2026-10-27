import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

config = json.loads(Path("build.json").read_text())
temporary = Path(os.environ["RUNNER_TEMP"])
source = temporary / "lumapocket-source"
source.mkdir(exist_ok=True)
with tarfile.open(temporary / "lumapocket-source.tar.gz") as archive:
    for member in archive.getmembers():
        destination = (source / member.name).resolve()
        assert destination.is_relative_to(source.resolve()) and (member.isfile() or member.isdir())
    archive.extractall(source, filter="data")
workspace = temporary / "lumapocket-build"
workspace.mkdir(exist_ok=True)
app = workspace / "app"
subprocess.run(["flutter", "--no-version-check", "config", "--no-enable-swift-package-manager"], check=True)
subprocess.run(["flutter", "--no-version-check", "create", "--platforms=ios", "--project-name=flutter_app", "--org=io.lumapocket", "--no-pub", str(app)], check=True)
for item in (source / "app").iterdir():
    destination = app / item.name
    if item.is_dir():
        shutil.copytree(item, destination, dirs_exist_ok=True)
    else:
        shutil.copy2(item, destination)
shutil.copytree(source / "rust-core", workspace / "rust-core", dirs_exist_ok=True)
# The template test refers to its generated sample widget, not this application.
shutil.rmtree(app / "test")
with open(os.environ["GITHUB_ENV"], "a") as stream:
    stream.write("LUMAPOCKET_WORKSPACE=" + str(workspace) + "\n")
    stream.write("LUMAPOCKET_APP=" + str(app) + "\n")
print("Prepared isolated mobile source, without user configuration or Git history.")
