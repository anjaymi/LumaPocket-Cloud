"""Reuse one Personal Team and one certificate; never revoke another signer."""
import json
import re
from pathlib import Path
from common import SigningError, run_private
from profile import certificate_der, decode_profile, validate
from v3_guard import v3_only_server
from certificate_recovery import recover


class Apple:
    def __init__(self, tool, state, identity):
        self.tool, self.state, self.identity = str(tool), Path(state), identity

    def portal(self, *arguments):
        i = self.identity
        with v3_only_server(i["anisetteURL"], on_failure=lambda reason: print('Anisette transport: ' + reason, flush=True)) as server:
            command = [self.tool, "dev", *arguments, "--session", str(self.state / "session.dat"),
                       "--password", i["sessionPassword"], "--machine-password", i["machinePassword"],
                       "--machine-path", str(self.state / "machine.dat"), "--server", server, "--strict"]
            return run_private(command, self.state, "apple_portal", timeout=150).decode(errors="replace")

    def personal_team(self):
        print('Signing phase: personal_team', flush=True)
        text = self.portal("teams")
        teams = re.findall(r"\(ID: ([A-Z0-9]{10}), Type: (\d)\)", text)
        # Upstream operations use the first returned team. Refuse ambiguous accounts.
        if len(teams) != 1 or teams[0][1] != "3":
            raise SigningError("single_personal_team_required")
        expected = self.identity.get("teamId")
        if expected and teams[0][0] != expected:
            raise SigningError("apple_team_changed")
        self.identity["teamId"] = teams[0][0]
        return teams[0][0]

    def ensure_registration(self):
        i = self.identity
        print('Signing phase: register_device', flush=True)
        if i["deviceUdid"] not in self.portal("devices", "list"):
            self.portal("devices", "register", "--name", "LumaPocket personal iPhone or iPad", "--udid", i["deviceUdid"])
        if i["bundleIdentifier"] not in self.portal("appids", "list"):
            print('Signing phase: register_app', flush=True)
            self.portal("appids", "register", "--name", "LumaPocket", "--bundle-id", i["bundleIdentifier"])

    def certificate(self, create=False):
        print('Signing phase: certificate', flush=True)
        p12 = self.state / "certificate.p12"
        if not p12.is_file():
            if not create:
                raise SigningError("signing_certificate_missing")
            if not recover(self):
                try:
                    self.portal("certs", "create", "--name", "LumaPocket self-test", "--output", str(p12))
                except SigningError:
                    if not recover(self):
                        raise
        try:
            der = certificate_der(p12, self.identity["p12Password"], self.state)
        except SigningError:
            if not create or not recover(self):
                raise
            der = certificate_der(p12, self.identity["p12Password"], self.state)
        from common import executable
        run_private([executable("openssl"), "x509", "-inform", "DER", "-checkend", "43200", "-noout"],
                    self.state, "certificate_requires_replacement", data=der)
        serial = run_private([executable("openssl"), "x509", "-inform", "DER", "-noout", "-serial"],
                             self.state, "certificate_serial", data=der).decode().strip().split("=", 1)[-1]
        certificates = self.portal("certs", "list")
        serials = re.findall(r"Serial:\s*([0-9A-Fa-f]+)", certificates)
        if not any(value.lstrip("0").lower() == serial.lstrip("0").lower() for value in serials):
            raise SigningError("certificate_revoked_or_missing")
        return der

    def refresh_profile(self, certificate):
        print('Signing phase: provisioning_profile', flush=True)
        profile = self.state / "profile.mobileprovision"
        self.portal("profiles", "download", "--bundle-id", self.identity["bundleIdentifier"],
                    "--xcode", "--output", str(profile))
        return validate(decode_profile(profile, self.state), self.identity, certificate)

    def bootstrap(self):
        team = self.personal_team()
        self.identity["bundleIdentifier"] = "io.lumapocket.client." + team.lower()
        self.ensure_registration()
        certificate = self.certificate(create=True)
        self.refresh_profile(certificate)
        (self.state / "identity.json").write_text(json.dumps(self.identity))
