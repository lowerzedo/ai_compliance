"""Network-isolated botocore STS stubs used by AWS tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import boto3  # type: ignore[import-untyped]
from botocore.stub import Stubber  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from datetime import datetime

    from cai_verify.aws import AwsSession, AwsStsClient

_SYNTHETIC_ACCESS_KEY = "ASIASYNTHETIC000001"
_SYNTHETIC_SECRET_KEY = "s" * 40
_SYNTHETIC_SESSION_TOKEN = "synthetic-session-token"  # noqa: S105
_SYNTHETIC_SOURCE_ACCESS_KEY = "synthetic-source-key"
_SYNTHETIC_SOURCE_SECRET_KEY = "synthetic-source-secret"  # noqa: S105
_SYNTHETIC_SOURCE_SESSION_TOKEN = "synthetic-source-token"  # noqa: S105


@dataclass(frozen=True, slots=True)
class StaticStsSession:
    """A session that can return only one pre-stubbed STS client."""

    sts: AwsStsClient

    def client(self, service_name: str, **kwargs: object) -> object:
        """Return the STS stub and reject accidental service expansion."""
        del kwargs
        if service_name != "sts":
            message = "test session supports STS only"
            raise ValueError(message)
        return self.sts


@dataclass(slots=True)
class QueueSessionFactory:
    """Return pre-stubbed sessions in expected provider call order."""

    sessions: list[AwsSession]
    current_profiles: list[str | None] = field(default_factory=list)
    assumed_session_created: bool = False

    def create_current_session(
        self,
        *,
        profile_name: str | None,
        region_name: str,
    ) -> AwsSession:
        """Return the next session without consulting local AWS configuration."""
        assert region_name == "eu-west-2"
        self.current_profiles.append(profile_name)
        return self.sessions.pop(0)

    def create_assumed_session(
        self,
        *,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        region_name: str,
    ) -> AwsSession:
        """Validate synthetic credentials without retaining them."""
        assert access_key_id == _SYNTHETIC_ACCESS_KEY
        assert secret_access_key == _SYNTHETIC_SECRET_KEY
        assert session_token == _SYNTHETIC_SESSION_TOKEN
        assert region_name == "eu-west-2"
        self.assumed_session_created = True
        return self.sessions.pop(0)

    def create_sts_client(
        self,
        session: AwsSession,
        *,
        region_name: str,
    ) -> AwsStsClient:
        """Return the session's already-stubbed client."""
        assert region_name == "eu-west-2"
        return cast("AwsStsClient", session.client("sts"))


def sts_client() -> tuple[AwsStsClient, Stubber]:
    """Create an STS client with explicit synthetic credentials and no I/O."""
    client = boto3.client(
        "sts",
        region_name="eu-west-2",
        aws_access_key_id=_SYNTHETIC_SOURCE_ACCESS_KEY,
        aws_secret_access_key=_SYNTHETIC_SOURCE_SECRET_KEY,
        aws_session_token=_SYNTHETIC_SOURCE_SESSION_TOKEN,
    )
    return cast("AwsStsClient", client), Stubber(client)


def add_caller_identity(
    stubber: Stubber,
    *,
    account_id: str = "111122223333",
    partition: str = "aws",
    resource: str = "user/synthetic-doctor",
) -> None:
    """Queue a synthetic GetCallerIdentity response."""
    stubber.add_response(
        "get_caller_identity",
        {
            "Account": account_id,
            "Arn": f"arn:{partition}:iam::{account_id}:{resource}",
            "UserId": "SYNTHETICUSERID",
        },
        {},
    )


def add_assume_role(
    stubber: Stubber,
    *,
    expires_at: datetime,
    external_id: str,
    account_id: str = "111122223333",
    partition: str = "aws",
) -> None:
    """Queue a synthetic AssumeRole response with exact expected parameters."""
    stubber.add_response(
        "assume_role",
        {
            "AssumedRoleUser": {
                "AssumedRoleId": "SYNTHETICROLEID:cai-verify-synthetic",
                "Arn": (
                    f"arn:{partition}:sts::{account_id}:"
                    "assumed-role/cai-verify-unauthorized/cai-verify-synthetic"
                ),
            },
            "Credentials": {
                "AccessKeyId": _SYNTHETIC_ACCESS_KEY,
                "SecretAccessKey": _SYNTHETIC_SECRET_KEY,
                "SessionToken": _SYNTHETIC_SESSION_TOKEN,
                "Expiration": expires_at,
            },
        },
        {
            "ExternalId": external_id,
            "RoleArn": (
                f"arn:{partition}:iam::{account_id}:role/cai-verify-unauthorized"
            ),
            "RoleSessionName": "cai-verify-synthetic",
        },
    )


def sessions(*clients: AwsStsClient) -> list[AwsSession]:
    """Wrap STS clients as queueable SDK sessions."""
    return [StaticStsSession(client) for client in clients]


def activate(*stubbers: Stubber) -> None:
    """Activate a collection of botocore stubs."""
    for stubber in stubbers:
        stubber.activate()


def deactivate(*stubbers: Stubber) -> None:
    """Assert all queued calls occurred, then deactivate the stubs."""
    for stubber in stubbers:
        stubber.assert_no_pending_responses()
        stubber.deactivate()
