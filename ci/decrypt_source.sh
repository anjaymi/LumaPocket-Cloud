#!/bin/bash
set -euo pipefail
: "${SOURCE_PASSPHRASE:?Missing BUILD_SOURCE_PASSPHRASE repository secret}"
python3 - <<'PY'
import hashlib, json
from pathlib import Path
config = json.loads(Path('build.json').read_text())
assert hashlib.sha256(Path('source/source.tar.gz.gpg').read_bytes()).hexdigest() == config['sourceEncryptedSha256']
PY
printf '%s' "$SOURCE_PASSPHRASE" | gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 --output "$RUNNER_TEMP/lumapocket-source.tar.gz" --decrypt source/source.tar.gz.gpg
python3 ci/prepare_project.py
