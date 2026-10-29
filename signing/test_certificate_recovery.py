"""Use disposable real keys/certificates to exercise recovery after issuance."""
import base64
import json
from pathlib import Path
import tempfile
import unittest

from certificate_recovery import recover, public_certificates
from common import executable, run_private
from profile import certificate_der


def certificate(root, name):
    ssl = executable('openssl')
    key, pem = root / (name + '.key'), root / (name + '.pem')
    run_private([ssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                 '-subj', '/CN=Offline fixture only', '-keyout', str(key), '-out', str(pem)],
                root, 'fixture_certificate')
    der = run_private([ssl, 'x509', '-in', str(pem), '-outform', 'DER'], root, 'fixture_certificate_der')
    return key.read_bytes(), der


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key, self.match = certificate(self.root, 'matching')
        _, self.other = certificate(self.root, 'other')

    def apple(self, certs):
        outer = self
        class FixturePortal:
            state = outer.root
            identity = {'p12Password': 'public-offline-recovery-only'}
            calls = []

            def portal(self, *args):
                self.calls.append(args)
                value = {'data': [{'attributes': {'certificateContent': base64.b64encode(
                    c).decode()}} for c in certs]}
                return 'fixture sendServicesRequest response: ' + json.dumps(value)
        return FixturePortal()

    def save_key(self):
        (self.root / 'certificate-request.key').write_bytes(self.key)

    def test_recovers_only_matching_public_key_without_issuing_or_revoking(self):
        self.save_key()
        portal = self.apple([self.other, self.match])
        self.assertTrue(recover(portal))
        self.assertEqual(certificate_der(self.root / 'certificate.p12', 'public-offline-recovery-only', self.root), self.match)
        self.assertEqual(portal.calls, [('certs', 'list', '--verbose')])
        self.assertFalse((self.root / 'certificate-recovered.pending.p12').exists())

    def test_another_private_key_is_never_adopted(self):
        self.save_key()
        self.assertFalse(recover(self.apple([self.other])))
        self.assertFalse((self.root / 'certificate.p12').exists())

    def test_missing_key_makes_no_portal_request(self):
        portal = self.apple([self.match])
        self.assertFalse(recover(portal))
        self.assertEqual(portal.calls, [])

    def test_parser_ignores_malformed_payloads(self):
        for value in ({'data': [None, {'attributes': None}, {'attributes': {'certificateContent': 'bad!'}}]}, None, []):
            self.assertEqual(public_certificates('sendServicesRequest response: ' + json.dumps(value)), [])


if __name__ == '__main__':
    unittest.main()
