"""Offline SideSign/loopback compatibility check with synthetic data only."""
import base64
import io
import json
from pathlib import Path
import subprocess
from unittest.mock import patch

from common import private_env
from v3_guard import v3_only_server

# Fake ADI1 data, encrypted with the publicly known password below. This has
# never belonged to an Apple account and never contacts Apple or SideStore.
_MACHINE = ('QURJMUjdSqZtT3dfkXFqVw4iOKMldN9p0HVzJA0QJuxHrJdjsrBr6Zw8aZMuv2k/Y7PJu5aXN43nX0AnhHWOL28BhSsgQiowNUPUp6nJcJIGl04UofAH4nu5mEzaXgyRr8xxRhfeF4H4L9NNTaZFPgKLrY/Ar01ndeIscJCDs3rw+rDUtDjZ62EBwvZq4bD5lrTZJ4L6HjSFwDRnGlqJmxNjLpFhmMeDzjXXTZC5umNMYYYB')


class FakeUpstream:
    def open(self, request, timeout):
        if request.full_url.endswith('/v3/client_info'):
            value = {'client_info': 'synthetic'}
        elif request.full_url.endswith('/v3/get_headers'):
            value = {'X-Apple-I-MD': 'c3ludGhldGlj', 'X-Apple-I-MD-M': 'c3ludGhldGlj'}
        else:
            raise ValueError('unexpected_fixture_endpoint')
        return io.BytesIO(json.dumps(value).encode())


def check_guard(tool, root):
    root = Path(root)
    machine = root / 'synthetic-machine.dat'
    machine.write_bytes(base64.b64decode(_MACHINE))
    try:
        with patch('v3_guard.build_opener', return_value=FakeUpstream()):
            with v3_only_server('https://fixture.invalid') as server:
                result = subprocess.run([
                    str(tool), 'dev', 'login', '--apple-id', 'fixture@example.invalid',
                    '--encrypt-password', 'fixture-session-only', '--machine-password', 'fixture-only',
                    '--machine-path', str(machine), '--server', server, '--strict',
                ], input=b'', stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    env=private_env(root), timeout=45)
        if b'Enter password for fixture@example.invalid:' not in result.stdout:
            raise RuntimeError('Offline SideSign V3 relay did not reach its password prompt')
    finally:
        machine.unlink(missing_ok=True)
