"""Recover an issued certificate only when its public key matches our saved key."""
import base64
import json
from pathlib import Path
import re

from common import SigningError, executable, run_private


def public_certificates(text):
    certificates = []
    for part in re.split(r'send(?:Services)?Request response: ', text)[1:]:
        try:
            value, _ = json.JSONDecoder().raw_decode(part.lstrip())
        except ValueError:
            continue
        if not isinstance(value, dict) or not isinstance(value.get('data'), list):
            continue
        for item in value['data']:
            if not isinstance(item, dict):
                continue
            attrs = item.get('attributes', {})
            if not isinstance(attrs, dict):
                continue
            content = attrs.get('certificateContent')
            if not isinstance(content, str) or len(content) > 128 * 1024:
                continue
            try:
                certificates.append(base64.b64decode(content, validate=True))
            except ValueError:
                continue
    return certificates


def recover(apple):
    root, identity = apple.state, apple.identity
    key = root / 'certificate-request.key'
    if not key.is_file() or key.is_symlink():
        return False
    ssl = executable('openssl')
    output = root / 'certificate-recovered.pending.p12'
    try:
        public_key = run_private([ssl, 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'],
                                 root, 'recovery_public_key')
        certificates = public_certificates(apple.portal('certs', 'list', '--verbose'))
        for certificate in certificates:
            pem = run_private([ssl, 'x509', '-inform', 'DER', '-outform', 'PEM'],
                              root, 'recovery_certificate', data=certificate)
            public_pem = run_private([ssl, 'x509', '-pubkey', '-noout'], root,
                                     'recovery_certificate_key', data=pem)
            candidate = run_private([ssl, 'pkey', '-pubin', '-outform', 'DER'], root,
                                    'recovery_certificate_key', data=public_pem)
            if candidate != public_key:
                continue
            path = root / 'recovered-certificate.pem'
            path.write_bytes(pem)
            run_private([ssl, 'pkcs12', '-export', '-in', str(path), '-inkey', str(key),
                         '-out', str(output), '-passout', 'stdin'],
                        root, 'recovery_pkcs12', data=(identity['p12Password'] + '\n').encode())
            output.replace(root / 'certificate.p12')
            return True
    except SigningError:
        return False
    finally:
        output.unlink(missing_ok=True)
    return False
