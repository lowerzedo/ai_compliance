"""Tests for AWS identity acquisition and redaction."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest
import yaml

from cai_verify.aws import (
    AssumedRoleAwsIdentityProvider,
    AwsIdentityError,
    AwsIdentityFailureCode,
    AwsSession,
    AwsStsClient,
    Boto3AwsSessionFactory,
    CurrentAwsIdentityProvider,
)
from cai_verify.config import (
    AssumedRoleIdentity,
    CurrentAwsIdentity,
    VerificationSuite,
)
from cai_verify.plugins import (
    ExecutionContext,
    IdentityProvider,
    IdentityRequest,
    ScopedIdentity,
)
from tests.aws.stubs import (
    QueueSessionFactory,
    activate,
    add_assume_role,
    add_caller_identity,
    deactivate,
    sessions,
    sts_client,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

_FIXTURE = Path(__file__).parents[1] / "fixtures/suites/valid/full.yaml"
_EVALUATED_AT = datetime(2026, 7, 26, 12, tzinfo=UTC)
_ENVIRONMENT = {
    "CAI_VERIFY_AWS_PROFILE": "synthetic-readonly-profile",
    "CAI_VERIFY_EXTERNAL_ID": "synthetic-external-id",
}


def test_current_identity_uses_profile_and_returns_safe_lease() -> None:
    """The current provider proves identity without exposing principal data."""
    suite = _suite()
    identity = cast("CurrentAwsIdentity", suite.identities[0])
    client, stubber = sts_client()
    add_caller_identity(stubber)
    factory = QueueSessionFactory(sessions(client))
    activate(stubber)
    try:
        provider = CurrentAwsIdentityProvider(
            environment=_ENVIRONMENT,
            session_factory=factory,
        )
        lease = provider.provide_identity(_request(suite, identity))

        assert isinstance(provider, IdentityProvider)
        assert isinstance(lease, ScopedIdentity)
        assert provider.metadata.capabilities == ("identity.aws-current",)
        assert factory.current_profiles == ["synthetic-readonly-profile"]
        assert lease.identity_id == "evidence-reader"
        assert lease.expires_at is None
        assert lease.matches_account("111122223333")
        assert lease.matches_partition("aws")
        rendered = repr(provider) + repr(lease)
        assert "synthetic-readonly-profile" not in rendered
        assert "111122223333" not in rendered

        lease.close()
        assert lease.closed
        assert not lease.matches_account("111122223333")
    finally:
        deactivate(stubber)


def test_assumed_role_uses_external_id_and_temporary_credentials() -> None:
    """AssumeRole inputs are exact and temporary secrets remain opaque."""
    suite = _suite()
    identity = cast("AssumedRoleIdentity", suite.identities[1])
    base_client, base_stubber = sts_client()
    assumed_client, assumed_stubber = sts_client()
    expiry = _EVALUATED_AT + timedelta(hours=1)
    add_assume_role(
        base_stubber,
        expires_at=expiry,
        external_id=_ENVIRONMENT["CAI_VERIFY_EXTERNAL_ID"],
    )
    add_caller_identity(
        assumed_stubber,
        resource="assumed-role/cai-verify-unauthorized/cai-verify-synthetic",
    )
    factory = QueueSessionFactory(sessions(base_client, assumed_client))
    activate(base_stubber, assumed_stubber)
    try:
        provider = AssumedRoleAwsIdentityProvider(
            environment=_ENVIRONMENT,
            session_factory=factory,
        )
        lease = provider.provide_identity(_request(suite, identity))

        assert isinstance(provider, IdentityProvider)
        assert isinstance(lease, ScopedIdentity)
        assert provider.metadata.capabilities == ("identity.aws-assume-role",)
        assert factory.current_profiles == [None]
        assert factory.assumed_session_created
        assert lease.expires_at == expiry
        assert lease.matches_account("111122223333")
        assert _ENVIRONMENT["CAI_VERIFY_EXTERNAL_ID"] not in repr(provider)
        lease.close()
    finally:
        deactivate(base_stubber, assumed_stubber)


def test_sdk_exception_details_are_redacted() -> None:
    """Credential and SDK exceptions collapse to one stable failure category."""
    suite = _suite()
    identity = cast("CurrentAwsIdentity", suite.identities[0])
    secret = "sdk-exception-secret-must-not-leak"  # noqa: S105
    factory = _FailingSessionFactory(secret)
    provider = CurrentAwsIdentityProvider(
        environment=_ENVIRONMENT,
        session_factory=factory,
    )

    with pytest.raises(AwsIdentityError) as caught:
        provider.provide_identity(_request(suite, identity))

    assert caught.value.code is AwsIdentityFailureCode.ACQUISITION_FAILED
    assert secret not in str(caught.value)
    assert secret not in repr(provider)


def test_missing_environment_value_names_only_the_identity() -> None:
    """Missing profile/external-ID values never expose neighboring values."""
    suite = _suite()
    identity = cast("CurrentAwsIdentity", suite.identities[0])
    provider = CurrentAwsIdentityProvider(
        environment={"NEIGHBOR": "neighbor-secret-must-not-leak"},
        session_factory=_FailingSessionFactory("unused"),
    )

    with pytest.raises(AwsIdentityError) as caught:
        provider.provide_identity(_request(suite, identity))

    assert caught.value.code is AwsIdentityFailureCode.ENVIRONMENT_VALUE_INVALID
    assert "neighbor-secret-must-not-leak" not in str(caught.value)


def test_boto3_factory_bounds_clients_and_ignores_endpoint_overrides(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """SDK configuration cannot redirect STS or create unbounded calls."""
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "missing-config"))
    monkeypatch.setenv(
        "AWS_SHARED_CREDENTIALS_FILE",
        str(tmp_path / "missing-credentials"),
    )
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ENDPOINT_URL_STS", "http://127.0.0.1:9")
    source_secret = "synthetic-source-secret"  # noqa: S105
    source_token = "synthetic-source-token"  # noqa: S105
    factory = Boto3AwsSessionFactory()
    session = factory.create_assumed_session(
        access_key_id="synthetic-source-key",
        secret_access_key=source_secret,
        session_token=source_token,
        region_name="eu-west-2",
    )

    client = cast(
        "Any",
        factory.create_sts_client(session, region_name="eu-west-2"),
    )

    assert client.meta.endpoint_url == "https://sts.eu-west-2.amazonaws.com"
    assert client.meta.config.connect_timeout == factory.connect_timeout_seconds
    assert client.meta.config.read_timeout == factory.read_timeout_seconds
    assert client.meta.config.retries["total_max_attempts"] == factory.max_attempts


def _suite() -> VerificationSuite:
    loaded = yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))
    return VerificationSuite.model_validate(loaded)


def _request(
    suite: VerificationSuite,
    identity: CurrentAwsIdentity | AssumedRoleIdentity,
) -> IdentityRequest:
    return IdentityRequest(
        context=ExecutionContext(
            run_id="aws-identity-test",
            scenario_id="identity-preflight",
            target=suite.target,
        ),
        identity=identity,
    )


class _FailingStsClient:
    def __init__(self, secret: str) -> None:
        self._secret = secret

    def get_caller_identity(self) -> Mapping[str, object]:
        raise RuntimeError(self._secret)

    def assume_role(self, **kwargs: str) -> Mapping[str, object]:
        del kwargs
        raise RuntimeError(self._secret)


class _FailingSession:
    def __init__(self, secret: str) -> None:
        self._client = _FailingStsClient(secret)

    def client(self, service_name: str, **kwargs: object) -> object:
        del service_name, kwargs
        return self._client


class _FailingSessionFactory:
    def __init__(self, secret: str) -> None:
        self._secret = secret

    def create_current_session(
        self,
        *,
        profile_name: str | None,
        region_name: str,
    ) -> AwsSession:
        del profile_name, region_name
        return _FailingSession(self._secret)

    def create_assumed_session(
        self,
        *,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        region_name: str,
    ) -> AwsSession:
        del access_key_id, secret_access_key, session_token, region_name
        return _FailingSession(self._secret)

    def create_sts_client(
        self,
        session: AwsSession,
        *,
        region_name: str,
    ) -> AwsStsClient:
        del region_name
        return cast("AwsStsClient", session.client("sts"))
