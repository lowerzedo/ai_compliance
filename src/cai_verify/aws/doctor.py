"""Deterministic AWS readiness checks built on read-only STS operations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, final

from cai_verify.aws.execution_policy import (
    AwsExecutionPolicy,
    authorize_aws_execution,
)
from cai_verify.aws.identity import (
    AssumedRoleAwsIdentityProvider,
    AwsIdentityError,
    AwsScopedIdentity,
    AwsSessionFactory,
    Boto3AwsSessionFactory,
    CurrentAwsIdentityProvider,
    _expected_account,
    _expected_partition,
    _partition_for_region,
)
from cai_verify.config import (
    AssumedRoleIdentity,
    CurrentAwsIdentity,
    VerificationSuite,
)
from cai_verify.config.models import DeploymentEnvironment
from cai_verify.plugins import ExecutionContext, IdentityRequest

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cai_verify.config import Identity

AWS_DOCTOR_SCHEMA_VERSION = "1"
_LIMITATIONS = (
    "The doctor checks identity acquisition with STS only; it does not test "
    "service permissions or application controls.",
    "A READY result is a runtime preflight result, not a security or compliance "
    "assessment.",
    "Credential expiry is reported only when the credential source supplies it.",
)


class AwsDoctorIssueCode(StrEnum):
    """Stable machine-readable AWS readiness finding categories."""

    ACCOUNT_MISMATCH = "account_mismatch"
    IDENTITY_ACQUISITION_FAILED = "identity_acquisition_failed"
    IDENTITY_EXPIRED = "identity_expired"
    ENVIRONMENT_VALUE_INVALID = "environment_value_invalid"
    INVALID_AWS_RESPONSE = "invalid_aws_response"
    PARTITION_MISMATCH = "partition_mismatch"
    ROLE_TARGET_PARTITION_MISMATCH = "role_target_partition_mismatch"
    SDK_UNAVAILABLE = "aws_sdk_unavailable"
    TARGET_ACCOUNT_MISSING = "target_account_missing"
    TARGET_NOT_AWS = "target_not_aws"


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class AwsIdentityCheck:
    """One identity's readiness result without account or principal values."""

    identity_id: str
    identity_type: str
    ready: bool
    account_matches: bool | None
    partition_matches: bool | None
    expires_at: datetime | None
    issues: tuple[AwsDoctorIssueCode, ...]

    def to_dict(self) -> dict[str, object]:
        """Return the stable JSON representation of this identity check."""
        return {
            "account_matches": self.account_matches,
            "expires_at": (
                _timestamp(self.expires_at) if self.expires_at is not None else None
            ),
            "identity_id": self.identity_id,
            "identity_type": self.identity_type,
            "issues": [issue.value for issue in self.issues],
            "partition_matches": self.partition_matches,
            "ready": self.ready,
        }


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class AwsDoctorResult:
    """Complete AWS readiness result for one validated suite."""

    target_id: str
    target_environment: str
    region: str | None
    ready: bool
    identities: tuple[AwsIdentityCheck, ...]
    issues: tuple[AwsDoctorIssueCode, ...]
    limitations: tuple[str, ...] = _LIMITATIONS

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic machine-readable report payload."""
        return {
            "identities": [identity.to_dict() for identity in self.identities],
            "issues": [issue.value for issue in self.issues],
            "limitations": list(self.limitations),
            "ready": self.ready,
            "region": self.region,
            "schema_version": AWS_DOCTOR_SCHEMA_VERSION,
            "target_environment": self.target_environment,
            "target_id": self.target_id,
        }

    def to_json_bytes(self) -> bytes:
        """Render canonical JSON without a trailing newline."""
        return json.dumps(
            self.to_dict(),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

    def to_terminal_bytes(self) -> bytes:
        """Render stable terminal text without raw account or principal values."""
        state = "READY" if self.ready else "NOT READY"
        region = self.region or "-"
        lines = [
            f"AWS doctor: {state}",
            (f"Target: {self.target_id} ({self.target_environment}, {region})"),
        ]
        lines.extend(f"Issue: {issue.value}" for issue in self.issues)
        for identity in self.identities:
            identity_state = "READY" if identity.ready else "NOT READY"
            lines.append(
                f"[{identity_state}] {identity.identity_id} ({identity.identity_type})"
            )
            lines.append(
                f"  account boundary: {_match_text(value=identity.account_matches)}"
            )
            lines.append(
                f"  partition boundary: {_match_text(value=identity.partition_matches)}"
            )
            expiry = (
                _timestamp(identity.expires_at)
                if identity.expires_at is not None
                else "not reported"
            )
            lines.append(f"  expires: {expiry}")
            lines.extend(f"  issue: {issue.value}" for issue in identity.issues)
        lines.append("Limitations:")
        lines.extend(f"- {limitation}" for limitation in self.limitations)
        return ("\n".join(lines) + "\n").encode()


def run_aws_doctor(
    suite: VerificationSuite,
    *,
    execution_policy: AwsExecutionPolicy,
    environment: Mapping[str, str],
    session_factory: AwsSessionFactory | None = None,
    evaluated_at: datetime | None = None,
) -> AwsDoctorResult:
    """Check declared AWS identities with read-only, bounded STS operations."""
    target = suite.target
    top_level_issues: list[AwsDoctorIssueCode] = []
    if target.environment is DeploymentEnvironment.LOCAL:
        top_level_issues.append(AwsDoctorIssueCode.TARGET_NOT_AWS)
    if target.aws_account_id is None:
        top_level_issues.append(AwsDoctorIssueCode.TARGET_ACCOUNT_MISSING)
    if top_level_issues:
        return AwsDoctorResult(
            target_id=target.id,
            target_environment=target.environment.value,
            region=target.aws_region,
            ready=False,
            identities=(),
            issues=tuple(sorted(top_level_issues, key=lambda issue: issue.value)),
        )

    authorize_aws_execution(
        execution_policy,
        target=target,
        identities=suite.identities,
    )
    now = (evaluated_at or datetime.now(UTC)).astimezone(UTC)
    factory = session_factory or Boto3AwsSessionFactory()
    context = ExecutionContext(
        run_id="aws-doctor",
        scenario_id="identity-preflight",
        target=target,
    )
    checks = tuple(
        _check_identity(
            identity,
            context=context,
            environment=environment,
            session_factory=factory,
            evaluated_at=now,
        )
        for identity in sorted(suite.identities, key=lambda item: item.id)
    )
    return AwsDoctorResult(
        target_id=target.id,
        target_environment=target.environment.value,
        region=target.aws_region,
        ready=bool(checks) and all(check.ready for check in checks),
        identities=checks,
        issues=(),
    )


def _check_identity(
    identity: Identity,
    *,
    context: ExecutionContext,
    environment: Mapping[str, str],
    session_factory: AwsSessionFactory,
    evaluated_at: datetime,
) -> AwsIdentityCheck:
    request = IdentityRequest(context=context, identity=identity)
    try:
        if isinstance(identity, CurrentAwsIdentity):
            lease = CurrentAwsIdentityProvider(
                environment=environment,
                session_factory=session_factory,
            ).provide_identity(request)
        elif isinstance(identity, AssumedRoleIdentity):
            lease = AssumedRoleAwsIdentityProvider(
                environment=environment,
                session_factory=session_factory,
            ).provide_identity(request)
        else:
            return _failed_check(
                identity,
                AwsDoctorIssueCode.IDENTITY_ACQUISITION_FAILED,
            )
    except AwsIdentityError as error:
        return _failed_check(identity, AwsDoctorIssueCode(error.code.value))

    try:
        return _lease_check(identity, lease, context, evaluated_at=evaluated_at)
    finally:
        lease.close()


def _lease_check(
    identity: Identity,
    lease: AwsScopedIdentity,
    context: ExecutionContext,
    *,
    evaluated_at: datetime,
) -> AwsIdentityCheck:
    target = context.target
    expected_account = _expected_account(identity, target)
    expected_partition = _expected_partition(identity, target)
    account_matches = (
        lease.matches_account(expected_account)
        if expected_account is not None
        else None
    )
    partition_matches = (
        lease.matches_partition(expected_partition)
        if expected_partition is not None
        else None
    )
    issues: list[AwsDoctorIssueCode] = []
    if account_matches is False:
        issues.append(AwsDoctorIssueCode.ACCOUNT_MISMATCH)
    if partition_matches is False:
        issues.append(AwsDoctorIssueCode.PARTITION_MISMATCH)
    if (
        isinstance(identity, AssumedRoleIdentity)
        and target.aws_region is not None
        and expected_partition != _partition_for_region(target.aws_region)
    ):
        issues.append(AwsDoctorIssueCode.ROLE_TARGET_PARTITION_MISMATCH)
    if lease.expires_at is not None and lease.expires_at <= evaluated_at:
        issues.append(AwsDoctorIssueCode.IDENTITY_EXPIRED)
    ordered_issues = tuple(sorted(issues, key=lambda issue: issue.value))
    return AwsIdentityCheck(
        identity_id=identity.id,
        identity_type=identity.type,
        ready=not ordered_issues,
        account_matches=account_matches,
        partition_matches=partition_matches,
        expires_at=lease.expires_at,
        issues=ordered_issues,
    )


def _failed_check(
    identity: Identity,
    issue: AwsDoctorIssueCode,
) -> AwsIdentityCheck:
    return AwsIdentityCheck(
        identity_id=identity.id,
        identity_type=identity.type,
        ready=False,
        account_matches=None,
        partition_matches=None,
        expires_at=None,
        issues=(issue,),
    )


def _timestamp(value: datetime) -> str:
    return (
        value.astimezone(UTC)
        .isoformat(timespec="microseconds")
        .replace(
            "+00:00",
            "Z",
        )
    )


def _match_text(*, value: bool | None) -> str:
    if value is True:
        return "MATCH"
    if value is False:
        return "MISMATCH"
    return "NOT CHECKED"
