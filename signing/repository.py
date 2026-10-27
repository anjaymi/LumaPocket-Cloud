"""Numeric GitHub identities bind each encrypted Apple state to one repository."""
from dataclasses import dataclass
import hashlib
import re
from common import SigningError

UPSTREAM = "anjaymi/LumaPocket"
UPSTREAM_ID = 1435778522
UPSTREAM_OWNER_ID = 129140237
PROTOCOL = 2


@dataclass(frozen=True)
class Scope:
    repository: str
    repository_id: int
    owner_id: int

    def __post_init__(self):
        if not isinstance(self.repository, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}", self.repository):
            raise SigningError("invalid_personal_repository")
        if any(type(value) is not int or value <= 0 for value in (self.repository_id, self.owner_id)):
            raise SigningError("invalid_repository_numeric_identity")

    @property
    def owner(self):
        return self.repository.split("/", 1)[0]

    def as_dict(self):
        return {"repository": self.repository, "repositoryId": self.repository_id, "ownerId": self.owner_id}

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict) or set(value) != {"repository", "repositoryId", "ownerId"}:
            raise SigningError("repository_binding_missing")
        return cls(value["repository"], value["repositoryId"], value["ownerId"])

    @classmethod
    def from_metadata(cls, metadata, viewer=None):
        owner = metadata.get("owner", {})
        scope = cls(metadata.get("full_name"), metadata.get("id"), owner.get("id"))
        if owner.get("type") != "User" or owner.get("login", "").lower() != scope.owner.lower():
            raise SigningError("personal_github_account_required")
        if metadata.get("private") is not False or metadata.get("default_branch") != "main":
            raise SigningError("public_personal_repository_on_main_required")
        if viewer is not None and (viewer.get("id") != scope.owner_id or viewer.get("login", "").lower() != scope.owner.lower()
                                   or metadata.get("permissions", {}).get("admin") is not True):
            raise SigningError("current_github_account_must_own_repository")
        return scope

    @classmethod
    def from_environment(cls, env):
        try:
            scope = cls(env.get("GITHUB_REPOSITORY"), int(env["GITHUB_REPOSITORY_ID"]), int(env["GITHUB_REPOSITORY_OWNER_ID"]))
        except (KeyError, ValueError, TypeError):
            raise SigningError("repository_numeric_context_required") from None
        if env.get("GITHUB_REF") != "refs/heads/main" or env.get("GITHUB_ACTOR", "").lower() != scope.owner.lower():
            raise SigningError("owner_on_main_required")
        if env.get("GITHUB_ACTOR_ID") != str(scope.owner_id):
            raise SigningError("owner_numeric_context_required")
        if env.get("SIGNING_REPOSITORY_ID") != str(scope.repository_id) or env.get("SIGNING_OWNER_ID") != str(scope.owner_id):
            raise SigningError("run_personal_repository_setup_first")
        if scope == UPSTREAM_SCOPE:
            raise SigningError("shared_build_repository_cannot_store_personal_signing_state")
        return scope


UPSTREAM_SCOPE = Scope(UPSTREAM, UPSTREAM_ID, UPSTREAM_OWNER_ID)


def account_binding(apple_id):
    value = apple_id.strip().casefold()
    if "@" not in value or "\n" in value or "\r" in value:
        raise SigningError("apple_account_required")
    return hashlib.sha256(value.encode()).hexdigest()


def bind_account(identity, scope, apple_id):
    if "repositoryScope" in identity:
        assert_identity_scope(identity, scope)
    fingerprint = account_binding(apple_id)
    if identity.get("accountBinding", fingerprint) != fingerprint:
        raise SigningError("different_apple_account_requires_separate_repository")
    identity.update(repositoryScope=scope.as_dict(), accountBinding=fingerprint)


def assert_identity_scope(identity, scope):
    if Scope.from_dict(identity.get("repositoryScope")) != scope:
        raise SigningError("authorized_state_belongs_to_another_repository")
    if not re.fullmatch(r"[0-9a-f]{64}", identity.get("accountBinding", "")):
        raise SigningError("apple_account_binding_missing")


def assert_report_scope(report, scope):
    if report.get("repositoryScope") != scope.as_dict():
        raise SigningError("signed_artifact_belongs_to_another_repository")
