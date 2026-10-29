"""Exercise real CSR/PKCS#12 operations with disposable, non-Apple fixtures."""
import json
import os
import platform
import sys
import unittest
from pathlib import Path
from common import executable, run_private
from tool import check, install


def main():
    root = Path(os.environ.get("RUNNER_TEMP", ".lumapocket-signing")) / "lumapocket-signing-probe"
    root.mkdir(parents=True, exist_ok=True)
    suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():
        raise RuntimeError("Signing regression tests failed")
    report = check(root / "tool")
    tool = install(root / "tool")
    from guard_probe import check_guard
    check_guard(tool, root)
    csr, key = root / "fixture.csr", root / "fixture.key"
    run_private([str(tool), "csr", "--name", "LumaPocket offline fixture", "--output-csr", str(csr),
                 "--output-key", str(key)], root, "fixture_csr")
    ssl = executable("openssl")
    csr_format = "PEM" if csr.read_bytes().startswith(b"-----BEGIN") else "DER"
    key_format = "PEM" if key.read_bytes().startswith(b"-----BEGIN") else "DER"
    run_private([ssl, "req", "-inform", csr_format, "-in", str(csr), "-noout", "-verify"], root, "fixture_csr_verify")
    pem = root / "fixture.pem"
    run_private([ssl, "req", "-inform", csr_format, "-in", str(csr), "-keyform", key_format, "-key", str(key),
                 "-x509", "-days", "1", "-out", str(pem)], root, "fixture_certificate")
    certificate = root / "fixture.der"
    run_private([ssl, "x509", "-in", str(pem), "-outform", "DER", "-out", str(certificate)], root, "fixture_der")
    p12 = root / "fixture.p12"
    fixture_password = "offline-fixture-only-not-a-real-apple-password"
    run_private([str(tool), "p12", "create", "--cert", str(certificate), "--key", str(key),
                 "--password", fixture_password, "--output", str(p12)], root, "fixture_p12_create")
    extracted_cert, extracted_key = root / "extracted.der", root / "extracted.key"
    run_private([str(tool), "p12", "extract", "--input", str(p12), "--password", fixture_password,
                 "--output-cert", str(extracted_cert), "--output-key", str(extracted_key)], root, "fixture_p12_extract")
    extracted_format = "PEM" if extracted_cert.read_bytes().startswith(b"-----BEGIN") else "DER"
    normalized = run_private([ssl, "x509", "-inform", extracted_format, "-in", str(extracted_cert), "-outform", "DER"], root, "fixture_roundtrip_der")
    if normalized != certificate.read_bytes() or not extracted_key.stat().st_size:
        raise RuntimeError("PKCS12 round-trip failed")
    report.update(schema=1, testsPassed=result.testsRun - len(result.skipped), testsSkipped=len(result.skipped),
                  csrSignatureVerified=True, pkcs12RoundTrip=True, v3GuardCompatible=True,
                  realAppleAccountUsed=False, realDeviceUsed=False)
    out = root.parent / "lumapocket-signing-check-out"
    out.mkdir(exist_ok=True)
    (out / ("tool-check-" + platform.system() + ".json")).write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
