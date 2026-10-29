"""Keep a short-lived, encrypted local checkpoint after successful Apple login."""
import json
from pathlib import Path
import tarfile
import time

from common import SigningError
from profile import validate_local_inputs
from repository import assert_identity_scope
from storage import crypt

FILES = {'identity.json', 'session.dat', 'machine.dat', 'certificate.p12', 'profile.mobileprovision',
         'certificate-request.key', 'certificate-request.csr'}
REQUIRED = {'identity.json', 'session.dat', 'machine.dat'}
MAX_AGE = 6 * 60 * 60


def active_session(root):
    root = Path(root)
    candidates = [root / 'session.dat', root / 'config/.sidesign/session/session.dat']
    candidates += list((root / 'config/.sidesign/session').glob('session_*.dat'))
    found = []
    for path in candidates:
        if path.is_file() and not path.is_symlink() and 4 < path.stat().st_size < 1024 * 1024:
            data = path.read_bytes()
            if data[:4] == b'SS02':
                found.append((path, data))
    if not found or any(data != found[0][1] for _, data in found):
        raise SigningError('portable_authorization_session_missing')
    return found[0][0]


def save_pending(root, home, password, identity):
    root, home = Path(root), Path(home)
    (root / 'identity.json').write_text(json.dumps(identity), encoding='utf-8')
    if not REQUIRED <= {p.name for p in root.iterdir() if p.is_file()}:
        raise SigningError('incomplete_local_checkpoint')
    pending = home / 'pending-authorization.gpg.pending'
    raw = root / 'pending-export.tar.gz'
    try:
        with tarfile.open(raw, 'w:gz') as archive:
            for name in sorted(FILES):
                path = root / name
                if path.is_symlink():
                    raise SigningError('invalid_local_checkpoint')
                if path.is_file():
                    archive.add(path, arcname=name, recursive=False)
        crypt(raw, pending, password, root)
        pending.replace(home / 'pending-authorization.gpg')
    finally:
        pending.unlink(missing_ok=True)
        raw.unlink(missing_ok=True)


def restore_pending(root, home, password, scope):
    root, home = Path(root), Path(home)
    encrypted = home / 'pending-authorization.gpg'
    if not encrypted.exists():
        return None
    if encrypted.is_symlink():
        raise SigningError('invalid_local_checkpoint')
    if time.time() - encrypted.stat().st_mtime > MAX_AGE:
        encrypted.unlink()
        return None
    raw = root / 'pending-state.tar.gz'
    crypt(encrypted, raw, password, root, decrypt=True)
    with tarfile.open(raw) as archive:
        members = archive.getmembers()
        names = [m.name for m in members]
        if (len(names) != len(set(names)) or not REQUIRED <= set(names) or
                not set(names) <= FILES or any(not m.isfile() or m.size < 0 for m in members) or
                sum(m.size for m in members) > 8 * 1024 * 1024):
            raise SigningError('invalid_local_checkpoint')
        payload = {m.name: archive.extractfile(m).read() for m in members}
    try:
        identity = json.loads(payload['identity.json'])
        if identity.get('schema') != 1 or any(len(identity.get(k, '')) < 32 for k in
                ('sessionPassword', 'machinePassword', 'p12Password')):
            raise ValueError()
        assert_identity_scope(identity, scope)
        validate_local_inputs(identity.get('deviceUdid', ''), identity.get('anisetteURL', ''))
        if payload['session.dat'][:4] != b'SS02' or payload['machine.dat'][:4] != b'ADI1':
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise SigningError('invalid_local_checkpoint') from None
    for name, data in payload.items():
        (root / name).write_bytes(data)
    raw.unlink()
    return identity
