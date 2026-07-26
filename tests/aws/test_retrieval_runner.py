"""Tests for the minimal single-chain AWS retrieval runner."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
import yaml
from botocore.credentials import Credentials  # type: ignore[import-untyped]

from cai_verify.aws import (
    AwsRetrievalRunError,
    AwsRetrievalRunFailureCode,
    AwsRetrievalRunOptions,
    AwsScopedIdentity,
    AwsSession,
    AwsSigV4ActionAdapter,
    AwsStsClient,
    CloudWatchLogsProbeAdapter,
    run_aws_retrieval_chain,
)
from cai_verify.aws.action import _AwsHttpRequest, _AwsHttpResponse
from cai_verify.config import VerificationSuite
from cai_verify.core import AssertionStatus, CliExitCode

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cai_verify.aws import AwsSessionFactory

_FIXTURE = (
    Path(__file__).parents[1]
    / "fixtures"
    / "suites"
    / "valid"
    / "reciprocal-retrieval.yaml"
)
_NOW = datetime(2026, 7, 26, 12, tzinfo=UTC)
_ACCOUNT_ID = "111122223333"
_BASELINE = "synthetic-requester-a-canary"
_BOUNDARY = "synthetic-requester-b-canary"
_ENVIRONMENT = {
    "SYNTHETIC_REQUESTER_A_CANARY": _BASELINE,
    "SYNTHETIC_REQUESTER_B_CANARY": _BOUNDARY,
}


@dataclass(slots=True)
class _CorrelationState:
    value: str | None = None


@dataclass(slots=True)
class _EchoTransport:
    state: _CorrelationState
    calls: int = 0

    def send(self, request: _AwsHttpRequest, /) -> _AwsHttpResponse:
        self.calls += 1
        correlation = request.header_map()["X-Cai-Correlation-Id"]
        self.state.value = correlation
        return _AwsHttpResponse(
            status=200,
            correlation_id=correlation,
            too_large=False,
        )


@dataclass(slots=True)
class _LogsClient:
    state: _CorrelationState
    calls: list[dict[str, object]] = field(default_factory=list)

    def filter_log_events(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(kwargs)
        correlation = self.state.value
        assert correlation is not None
        message = json.dumps(
            {
                "canaries": [_BASELINE],
                "correlationId": correlation,
                "eventKind": "retrievalCanary",
                "eventTime": "2026-07-26T12:00:00.000Z",
                "phase": "PRE_GENERATION",
                "retrievalStatus": "SUCCEEDED",
                "retrievedItemCount": 1,
                "scanStatus": "COMPLETE",
                "schemaVersion": "1",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        return {
            "events": [
                {
                    "eventId": "synthetic-retrieval-event",
                    "message": message,
                    "timestamp": int(_NOW.timestamp() * 1000),
                }
            ],
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "searchedLogStreams": [
                {
                    "logStreamName": "synthetic-stream",
                    "searchedCompletely": True,
                }
            ],
        }


@dataclass(slots=True)
class _StsClient:
    expires_at: datetime = _NOW + timedelta(hours=1)

    def get_caller_identity(self) -> Mapping[str, object]:
        return {
            "Account": _ACCOUNT_ID,
            "Arn": (
                f"arn:aws:sts::{_ACCOUNT_ID}:assumed-role/synthetic/synthetic-session"
            ),
            "UserId": "SYNTHETIC",
        }

    def assume_role(self, **kwargs: str) -> Mapping[str, object]:
        del kwargs
        return {
            "Credentials": {
                "AccessKeyId": "synthetic-access-key",
                "Expiration": self.expires_at,
                "SecretAccessKey": "synthetic-secret-key",
                "SessionToken": "synthetic-session-token",
            }
        }


@dataclass(slots=True)
class _Session:
    sts: _StsClient
    logs: _LogsClient
    services: list[str] = field(default_factory=list)

    def client(self, service_name: str, **kwargs: object) -> object:
        del kwargs
        self.services.append(service_name)
        if service_name == "sts":
            return self.sts
        if service_name == "logs":
            return self.logs
        message = "unexpected AWS service"
        raise AssertionError(message)

    def get_credentials(self) -> Credentials:
        return Credentials(
            "synthetic-access-key",
            "synthetic-secret-key",
            "synthetic-session-token",
        )


@dataclass(slots=True)
class _SessionFactory:
    base_sessions: list[_Session]
    lease_sessions: list[_Session]
    created: list[_Session] = field(default_factory=list)

    def create_current_session(
        self,
        *,
        profile_name: str | None,
        region_name: str,
    ) -> AwsSession:
        assert profile_name is None
        assert region_name == "eu-west-2"
        return cast("AwsSession", self.base_sessions.pop(0))

    def create_assumed_session(
        self,
        *,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        region_name: str,
    ) -> AwsSession:
        del access_key_id, secret_access_key, session_token
        assert region_name == "eu-west-2"
        session = self.lease_sessions.pop(0)
        self.created.append(session)
        return cast("AwsSession", session)

    def create_sts_client(
        self,
        session: AwsSession,
        *,
        region_name: str,
    ) -> AwsStsClient:
        assert region_name == "eu-west-2"
        return cast("AwsStsClient", session.client("sts"))


def test_runner_executes_one_preseeded_chain_and_closes_both_leases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One action, one correlated probe, and one evaluator produce PASS."""
    suite = _suite()
    state = _CorrelationState()
    transport = _EchoTransport(state)
    logs = _LogsClient(state)
    factory = _factory(logs)
    closed: list[str] = []
    original_close = AwsScopedIdentity.close

    def close(lease: AwsScopedIdentity) -> None:
        closed.append(lease.identity_id)
        original_close(lease)

    monkeypatch.setattr(AwsScopedIdentity, "close", close)
    result = run_aws_retrieval_chain(
        suite,
        AwsRetrievalRunOptions(
            run_id="synthetic-aws-retrieval-run",
            assertion_id="requester-a-retrieval-boundary",
            environment=_ENVIRONMENT,
            session_factory=cast("AwsSessionFactory", factory),
            clock=lambda: _NOW,
            monotonic=lambda: 1.0,
            action_adapter=AwsSigV4ActionAdapter(
                environment=_ENVIRONMENT,
                transport=transport,
                clock=lambda: _NOW,
            ),
            probe_adapter=CloudWatchLogsProbeAdapter(
                environment=_ENVIRONMENT,
                suite_max_age=timedelta(minutes=5),
                clock_skew_tolerance=timedelta(seconds=30),
                clock=lambda: _NOW,
                monotonic=lambda: 1.0,
            ),
        ),
    )

    assert result.assertion_result.status is AssertionStatus.PASS
    assert result.exit_code is CliExitCode.SUCCESS
    assert transport.calls == 1
    assert len(logs.calls) == 1
    assert closed == ["evidence-reader", "requester-a"]
    assert b'"status":"PASS"' in result.json_report
    assert b"PASS" in result.terminal_report


def test_runner_rejects_equal_canaries_before_identity_or_application_work() -> None:
    """Pre-seeded canary configuration is validated before STS or action use."""
    state = _CorrelationState()
    transport = _EchoTransport(state)
    factory = _factory(_LogsClient(state))

    with pytest.raises(AwsRetrievalRunError) as caught:
        run_aws_retrieval_chain(
            _suite(),
            AwsRetrievalRunOptions(
                run_id="synthetic-aws-retrieval-run",
                assertion_id="requester-a-retrieval-boundary",
                environment={
                    "SYNTHETIC_REQUESTER_A_CANARY": "same",
                    "SYNTHETIC_REQUESTER_B_CANARY": "same",
                },
                session_factory=cast("AwsSessionFactory", factory),
                clock=lambda: _NOW,
                action_adapter=AwsSigV4ActionAdapter(
                    environment={},
                    transport=transport,
                    clock=lambda: _NOW,
                ),
            ),
        )

    assert caught.value.code is AwsRetrievalRunFailureCode.INVALID_ENVIRONMENT
    assert factory.created == []
    assert transport.calls == 0


def test_runner_closes_an_expired_evidence_lease_on_validation_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lease acquired before a boundary failure is still always closed."""
    state = _CorrelationState()
    logs = _LogsClient(state)
    factory = _factory(logs, evidence_expiry=_NOW)
    closed: list[str] = []
    original_close = AwsScopedIdentity.close

    def close(lease: AwsScopedIdentity) -> None:
        closed.append(lease.identity_id)
        original_close(lease)

    monkeypatch.setattr(AwsScopedIdentity, "close", close)
    with pytest.raises(AwsRetrievalRunError) as caught:
        run_aws_retrieval_chain(
            _suite(),
            AwsRetrievalRunOptions(
                run_id="synthetic-aws-retrieval-run",
                assertion_id="requester-a-retrieval-boundary",
                environment=_ENVIRONMENT,
                session_factory=cast("AwsSessionFactory", factory),
                clock=lambda: _NOW,
            ),
        )

    assert caught.value.code is AwsRetrievalRunFailureCode.IDENTITY_UNAVAILABLE
    assert closed == ["evidence-reader"]
    assert logs.calls == []


def _suite() -> VerificationSuite:
    return VerificationSuite.model_validate(
        yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))
    )


def _factory(
    logs: _LogsClient,
    *,
    evidence_expiry: datetime | None = None,
) -> _SessionFactory:
    evidence_sts = _StsClient(expires_at=evidence_expiry or _NOW + timedelta(hours=1))
    requester_sts = _StsClient()
    return _SessionFactory(
        base_sessions=[
            _Session(sts=evidence_sts, logs=logs),
            _Session(sts=requester_sts, logs=logs),
        ],
        lease_sessions=[
            _Session(sts=evidence_sts, logs=logs),
            _Session(sts=requester_sts, logs=logs),
        ],
    )
