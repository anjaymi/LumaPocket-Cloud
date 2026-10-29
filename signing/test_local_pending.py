"""Interrupted authorization must preserve only encrypted, correctly scoped state."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

from common import SigningError
import local
import local_pending as pending
from repository import Scope, bind_account

ALICE = Scope('alice/LumaPocket-Cloud', 1001, 101)
BOB = Scope('bob/LumaPocket-Cloud', 2002, 202)


def identity():
    value = {'schema': 1, 'deviceUdid': '00000000-0000000000000000',
             'anisetteURL': 'https://new.ani.sidestore.io',
             'sessionPassword': 'fixture-session-' * 4, 'machinePassword': 'fixture-machine-' * 4,
             'p12Password': 'fixture-p12-' * 4}
    bind_account(value, ALICE, 'alice@example.invalid')
    return value


def fixture_crypt(source, destination, password, root, decrypt=False):
    shutil.copyfile(source, destination)


class PendingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.root = self.home / 'work'
        self.root.mkdir()
        (self.root / 'session.dat').write_bytes(b'SS02synthetic-session-only')
        (self.root / 'machine.dat').write_bytes(b'ADI1synthetic-device-only')

    def test_real_gpg_checkpoint_roundtrip_excludes_logs_and_large_ipa(self):
        (self.root / 'diagnostics.log').write_bytes(b'PRIVATE_FIXTURE_NOT_TO_EXPORT')
        (self.root / 'unsigned.ipa').write_bytes(b'public-fixture-ipa')
        key = 'public-offline-checkpoint-key-' * 3
        pending.save_pending(self.root, self.home, key, identity())
        encrypted = (self.home / 'pending-authorization.gpg').read_bytes()
        self.assertNotIn(b'fixture-session', encrypted)
        restored = self.home / 'restored'
        restored.mkdir()
        self.assertEqual(pending.restore_pending(restored, self.home, key, ALICE), identity())
        self.assertTrue(pending.REQUIRED <= {p.name for p in restored.iterdir()})
        self.assertFalse((restored / 'unsigned.ipa').exists())
        self.assertNotIn(b'PRIVATE_FIXTURE_NOT_TO_EXPORT', (restored / 'diagnostics.log').read_bytes())

    def test_checkpoint_rejects_another_repository_and_old_session_format(self):
        with patch.object(pending, 'crypt', fixture_crypt):
            pending.save_pending(self.root, self.home, 'fixture', identity())
            with self.assertRaisesRegex(SigningError, 'another_repository'):
                pending.restore_pending(self.root, self.home, 'fixture', BOB)
            (self.root / 'session.dat').write_bytes(b'SS01machine-bound')
            pending.save_pending(self.root, self.home, 'fixture', identity())
            with self.assertRaisesRegex(SigningError, 'invalid_local_checkpoint'):
                pending.restore_pending(self.root, self.home, 'fixture', ALICE)

    def test_stale_checkpoint_starts_fresh_without_decrypting(self):
        path = self.home / 'pending-authorization.gpg'
        path.write_bytes(b'fixture-encrypted-state')
        old = time.time() - pending.MAX_AGE - 10
        os.utime(path, (old, old))
        with patch.object(pending, 'crypt') as decrypt:
            self.assertIsNone(pending.restore_pending(self.root, self.home, 'fixture', ALICE))
            decrypt.assert_not_called()

    def test_duplicate_and_link_members_rejected_before_writing(self):
        raw = self.home / 'pending-authorization.gpg'
        with tarfile.open(raw, 'w:gz') as archive:
            for name in ('identity.json', 'session.dat', 'machine.dat', '../outside'):
                member = tarfile.TarInfo(name)
                member.size = 1
                archive.addfile(member, io.BytesIO(b'x'))
        restored = self.home / 'restored'
        restored.mkdir()
        with patch.object(pending, 'crypt', fixture_crypt), self.assertRaisesRegex(SigningError, 'invalid_local_checkpoint'):
            pending.restore_pending(restored, self.home, 'fixture', ALICE)
        self.assertFalse((self.home / 'outside').exists())

    def test_session_path_can_be_explicit_or_upstream_default(self):
        self.assertEqual(pending.active_session(self.root), self.root / 'session.dat')
        default = self.root / 'config/.sidesign/session/session.dat'
        default.parent.mkdir(parents=True)
        shutil.move(self.root / 'session.dat', default)
        self.assertEqual(pending.active_session(self.root), default)
        (self.root / 'session.dat').write_bytes(b'SS02different-session')
        with self.assertRaises(SigningError):
            pending.active_session(self.root)

    def test_different_device_or_account_cannot_resume_checkpoint(self):
        key = 'public-offline-checkpoint-key-' * 3
        pending.save_pending(self.root, self.home, key, identity())
        for udid, email, error in [('00000000-1111111111111111', 'alice@example.invalid', 'checkpoint_device_mismatch'),
                                   ('00000000-0000000000000000', 'bob@example.invalid', 'different_apple_account')]:
            args = argparse.Namespace(udid=udid, apple_id=email, anisette_url='https://new.ani.sidestore.io')
            with patch.object(local, 'run_private') as login, patch.object(local, 'Apple') as portal, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(SigningError, error):
                    local.authorize(self.home, args, key, ALICE)
                login.assert_not_called()
                portal.assert_not_called()

    def test_failed_portal_resumes_without_repeating_password_or_creating_new_certificate(self):
        args = argparse.Namespace(udid='00000000-0000000000000000', apple_id='alice@example.invalid',
                                  anisette_url='https://new.ani.sidestore.io')
        key = 'public-offline-checkpoint-key-' * 3

        def native_login(command, root, *unused, **kwargs):
            (root / 'session.dat').write_bytes(b'SS02synthetic-session-only')
            (root / 'machine.dat').write_bytes(b'ADI1synthetic-device-only')

        class InterruptedPortal:
            def __init__(self, tool, root, value):
                self.root, self.identity = root, value

            def bootstrap(self):
                (self.root / 'certificate.p12').write_bytes(b'synthetic-private-key-only')
                raise SigningError('apple_portal_failed')

        class FinishedPortal(InterruptedPortal):
            def bootstrap(self):
                if (self.root / 'certificate.p12').read_bytes() != b'synthetic-private-key-only':
                    raise AssertionError('private key was not recovered')
                self.identity.update(teamId='TESTTEAM01', bundleIdentifier='io.lumapocket.client.testteam01')
                (self.root / 'identity.json').write_text(json.dumps(self.identity))

        with patch.object(local, 'install', return_value=Path('fixture.exe')), patch.object(local, 'run_private', side_effect=native_login) as login, \
             patch.object(local, 'publish') as publish, contextlib.redirect_stdout(io.StringIO()):
            with patch.object(local, 'Apple', InterruptedPortal):
                with self.assertRaisesRegex(SigningError, 'apple_portal_failed'):
                    local.authorize(self.home, args, key, ALICE)
            self.assertTrue((self.home / 'pending-authorization.gpg').exists())
            publish.assert_not_called()
            with patch.object(local, 'Apple', FinishedPortal):
                local.authorize(self.home, args, key, ALICE)
            self.assertEqual(login.call_count, 1)
            publish.assert_called_once()
            self.assertFalse((self.home / 'pending-authorization.gpg').exists())


if __name__ == '__main__':
    unittest.main()
