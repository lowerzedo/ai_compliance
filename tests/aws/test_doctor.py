"""Tests for deterministic AWS doctor reporting."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import yaml

from cai_verify.aws import AwsDoctorIssueCode, run_aws_doctor
from cai_verify.config import VerificationSuite
from tests.aws.stubs import (
    QueueSessionFactory,
    activate,
    add_assume_role,
    add_caller_identity,
    deactivate,
    sessions,
    sts_client,
)

_FIXTURE = Path(__file__).parents[1] / "fixtures/suites/valid/full.yaml"
_LOCAL_FIXTURE = Path(__file__).parents[2] / "examples/local/synthetic-suite.json"
_EVALUATED_AT = datetime(2026, 7, 26, 12, tzinfo=UTC)
_ENVIRONMENT = {
    "CAI_VERIFY_AWS_PROFILE": "synthetic-readonly-profile",
    "CAI_VERIFY_EXTERNAL_ID": "synthetic-external-id",
}


def test_aws_doctor_is_ready_without_disclosing_identity_values() -> None:
    """Successful identity checks report boundaries, not accounts or ARNs."""
    suite = _cloud_suite()
    current_client, current_stubber = sts_client()
    base_client, base_stubber = sts_client()
    assumed_client, assumed_stubber = sts_client()
    add_caller_identity(current_stubber)
    add_assume_role(
        base_stubber,
        expires_at=_EVALUATED_AT + timedelta(hours=1),
        external_id=_ENVIRONMENT["CAI_VERIFY_EXTERNAL_ID"],
    )
    add_caller_identity(
        assumed_stubber,
        resource="assumed-role/cai-verify-unauthorized/cai-verify-synthetic",
    )
    factory = QueueSessionFactory(
        sessions(current_client, base_client, assumed_client),
    )
    activate(current_stubber, base_stubber, assumed_stubber)
    try:
        result = run_aws_doctor(
            suite,
            environment=_ENVIRONMENT,
            session_factory=factory,
            evaluated_at=_EVALUATED_AT,
        )
    finally:
        deactivate(current_stubber, base_stubber, assumed_stubber)

    assert result.ready
    assert [check.identity_id for check in result.identities] == [
        "evidence-reader",
        "unauthorized-caller",
    ]
    assert all(check.ready for check in result.identities)
    reports = result.to_json_bytes() + result.to_terminal_bytes()
    assert b"111122223333" not in reports
    assert b"arn:aws" not in reports
    assert _ENVIRONMENT["CAI_VERIFY_AWS_PROFILE"].encode() not in reports
    assert _ENVIRONMENT["CAI_VERIFY_EXTERNAL_ID"].encode() not in reports
    payload = json.loads(result.to_json_bytes())
    assert payload["schema_version"] == "1"
    assert payload["ready"] is True
    assert "not a security or compliance assessment" in " ".join(
        cast("list[str]", payload["limitations"]),
    )


def test_account_mismatch_and_expired_role_are_not_ready() -> None:
    """A mismatched current account and expired role can never look ready."""
    suite = _cloud_suite()
    current_client, current_stubber = sts_client()
    base_client, base_stubber = sts_client()
    assumed_client, assumed_stubber = sts_client()
    add_caller_identity(current_stubber, account_id="999900001111")
    add_assume_role(
        base_stubber,
        expires_at=_EVALUATED_AT - timedelta(seconds=1),
        external_id=_ENVIRONMENT["CAI_VERIFY_EXTERNAL_ID"],
    )
    add_caller_identity(
        assumed_stubber,
        resource="assumed-role/cai-verify-unauthorized/cai-verify-synthetic",
    )
    factory = QueueSessionFactory(
        sessions(current_client, base_client, assumed_client),
    )
    activate(current_stubber, base_stubber, assumed_stubber)
    try:
        result = run_aws_doctor(
            suite,
            environment=_ENVIRONMENT,
            session_factory=factory,
            evaluated_at=_EVALUATED_AT,
        )
    finally:
        deactivate(current_stubber, base_stubber, assumed_stubber)

    assert not result.ready
    checks = {check.identity_id: check for check in result.identities}
    assert checks["evidence-reader"].issues == (AwsDoctorIssueCode.ACCOUNT_MISMATCH,)
    assert checks["unauthorized-caller"].issues == (
        AwsDoctorIssueCode.IDENTITY_EXPIRED,
    )


def test_local_suite_is_rejected_before_any_sdk_session_is_created() -> None:
    """The AWS doctor cannot silently reinterpret a local target as AWS."""
    suite = VerificationSuite.model_validate(
        json.loads(_LOCAL_FIXTURE.read_bytes()),
    )
    factory = QueueSessionFactory([])

    result = run_aws_doctor(
        suite,
        environment={},
        session_factory=factory,
        evaluated_at=_EVALUATED_AT,
    )

    assert not result.ready
    assert result.identities == ()
    assert result.issues == (
        AwsDoctorIssueCode.TARGET_ACCOUNT_MISSING,
        AwsDoctorIssueCode.TARGET_NOT_AWS,
    )
    assert factory.current_profiles == []


def _cloud_suite() -> VerificationSuite:
    loaded = yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))
    return VerificationSuite.model_validate(loaded)
