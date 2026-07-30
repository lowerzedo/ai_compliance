"""Network-isolated contract tests for reciprocal AWS retrieval execution."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Never, cast

import pytest
from botocore.credentials import Credentials  # type: ignore[import-untyped]

import cai_verify.aws.reciprocal_retrieval_runner as reciprocal_module
from cai_verify.assertions import RetrievalBoundaryEvaluator
from cai_verify.aws import (
    AwsExecutionPolicy,
    AwsExecutionPolicyError,
    AwsExecutionPolicyFailureCode,
    AwsReciprocalRetrievalRunError,
    AwsReciprocalRetrievalRunFailureCode,
    AwsReciprocalRetrievalRunOptions,
    AwsReciprocalRetrievalRunResult,
    AwsReciprocalRetrievalRunStage,
    AwsScopedIdentity,
    AwsSession,
    AwsSessionFactory,
    AwsSigV4ActionAdapter,
    AwsStsClient,
    CloudWatchLogsProbeAdapter,
    load_aws_execution_policy,
    run_aws_reciprocal_retrieval,
)
from cai_verify.aws.action import _AwsHttpRequest, _AwsHttpResponse
from cai_verify.config import (
    AssumedRoleIdentity,
    AwsSigV4Action,
    CloudWatchLogsProbe,
    CurrentAwsIdentity,
    RetrievalBoundaryAssertion,
    RetrievalCanaryDeclaration,
    VerificationSuite,
    load_suite,
)
from cai_verify.config.models import ObservationKind
from cai_verify.core import AssertionResult, AssertionStatus, CliExitCode, RedactedValue
from cai_verify.evidence import (
    RunDirectory,
    RunManifest,
    Sensitivity,
    verify_run_integrity,
)
from cai_verify.plugins import (
    ActionExecutionResult,
    ActionOutcome,
    ActionRequest,
    AssertionEvaluationRequest,
    ProbeRequest,
    ProbeResult,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

_ROOT = Path(__file__).parents[2]
_SUITE_PATH = _ROOT / "examples/aws/reciprocal-retrieval-suite.json"
_POLICY_PATH = _ROOT / "examples/aws/reciprocal-retrieval-policy.json"
_NOW = datetime(2026, 7, 28, 12, tzinfo=UTC)
_ACCOUNT = "111122223333"
_REGION = "eu-west-2"
_SCENARIO_ID = "reciprocal-requester-retrieval"
_BASELINE = "synthetic-alpha-canary-for-requester-a"
_BOUNDARY = "synthetic-alpha-canary-for-requester-b"
_ENVIRONMENT = {
    "CAI_REQUESTER_A_CANARY": _BASELINE,
    "CAI_REQUESTER_B_CANARY": _BOUNDARY,
}
_ACCESS_KEY = "ASIASYNTHETIC000001"
_SECRET_KEY = "synthetic-secret-key-material-for-tests-only"  # noqa: S105
_SESSION_TOKEN = "synthetic-session-token-for-tests-only"  # noqa: S105
_DIRECTION_COUNT = 2
_IDENTITY_COUNT = 3
_EVIDENCE_IDENTITY_POSITION = 2
_STS_CALL_COUNT = 6
_FILTER_PATTERN_PART_COUNT = 3
_HTTPS_PORT = 443
_NON_MANIFEST_ARTIFACT_COUNT = 9
_BUNDLE_FILE_COUNT = 10
_INTERNAL_ARTIFACT_COUNT = 5
_PUBLIC_ARTIFACT_COUNT = 4
_MIN_CLOCK_CALLS = 12
_MIN_MONOTONIC_CALLS = 20
_ACTION_LIMITATIONS = (
    "Request and response bodies, credentials, and signing headers are excluded "
    "from normalized evidence.",
    "The result reports one bounded application response; it does not establish "
    "service permission coverage or compliance.",
)


def _item_path(category: str, identifier: str) -> str:
    digest = hashlib.sha256(identifier.encode()).hexdigest()[:16]
    return f"{category}/item-{digest}.json"


@dataclass(slots=True)
class _StepClock:
    """Return deterministic, distinct wall-clock samples."""

    calls: list[datetime] = field(default_factory=list)

    def __call__(self) -> datetime:
        value = _NOW + timedelta(milliseconds=100 * len(self.calls))
        self.calls.append(value)
        return value


@dataclass(slots=True)
class _StepMonotonic:
    """Return deterministic, bounded scheduling samples."""

    value: float = 0.0
    calls: int = 0

    def __call__(self) -> float:
        self.calls += 1
        self.value += 0.01
        return self.value


@dataclass(slots=True)
class _CorrelationLedger:
    values: list[str] = field(default_factory=list, repr=False)


@dataclass(slots=True)
class _EchoTransport:
    """Echo generated application correlations without network access."""

    behaviors: tuple[str, str]
    ledger: _CorrelationLedger
    events: list[str]
    calls: list[_AwsHttpRequest] = field(default_factory=list)

    def send(self, request: _AwsHttpRequest, /) -> _AwsHttpResponse:
        position = len(self.calls)
        self.calls.append(request)
        self.events.append(f"action:{position}")
        correlation = request.header_map()["X-Cai-Correlation-Id"]
        self.ledger.values.append(correlation)
        status = 500 if self.behaviors[position] == "error" else 200
        return _AwsHttpResponse(
            status=status,
            correlation_id=correlation,
            too_large=False,
            aws_request_ids=(f"synthetic-aws-request-{position}",),
        )


@dataclass(slots=True)
class _LogsClient:
    """Return one exact retrieval record for each generated correlation."""

    behaviors: tuple[str, str]
    ledger: _CorrelationLedger
    events: list[str]
    event_correlations: tuple[str, str] | None = None
    calls: list[dict[str, object]] = field(default_factory=list)

    def filter_log_events(self, **kwargs: object) -> Mapping[str, object]:
        position = len(self.calls)
        self.calls.append(kwargs)
        self.events.append(f"probe:{position}")
        correlation = _filter_correlation(kwargs)
        assert correlation == self.ledger.values[position]
        event_correlation = (
            correlation
            if self.event_correlations is None
            else self.event_correlations[position]
        )
        baseline = _BASELINE if position == 0 else _BOUNDARY
        boundary = _BOUNDARY if position == 0 else _BASELINE
        behavior = self.behaviors[position]
        if behavior == "fail":
            canaries = [baseline, boundary]
        elif behavior == "inconclusive":
            canaries = []
        else:
            canaries = [baseline]
        message = json.dumps(
            {
                "canaries": canaries,
                "correlationId": event_correlation,
                "eventKind": "retrievalCanary",
                "eventTime": "2026-07-28T12:00:00.000Z",
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
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "events": [
                {
                    "eventId": f"synthetic-cloudwatch-event-{position}",
                    "message": message,
                    "timestamp": int(_NOW.timestamp() * 1000),
                }
            ],
            "searchedLogStreams": [
                {
                    "logStreamName": "synthetic-stream",
                    "searchedCompletely": True,
                }
            ],
        }


@dataclass(slots=True)
class _SyntheticStsClient:
    """Implement only AssumeRole and GetCallerIdentity."""

    factory: _SyntheticSessionFactory
    role_arn: str | None

    def assume_role(self, **kwargs: str) -> Mapping[str, object]:
        assert self.role_arn is None
        role_arn = kwargs["RoleArn"]
        self.factory.assumed_roles.append(role_arn)
        self.factory.pending_role = role_arn
        self.factory.events.append(f"assume:{_identity_label(role_arn)}")
        return {
            "Credentials": {
                "AccessKeyId": _ACCESS_KEY,
                "Expiration": _NOW + timedelta(hours=1),
                "SecretAccessKey": _SECRET_KEY,
                "SessionToken": _SESSION_TOKEN,
            }
        }

    def get_caller_identity(self) -> Mapping[str, object]:
        assert self.role_arn is not None
        role_name = self.role_arn.rsplit("/", maxsplit=1)[-1]
        self.factory.caller_identity_roles.append(self.role_arn)
        self.factory.events.append(f"identity:{_identity_label(self.role_arn)}")
        return {
            "Account": _ACCOUNT,
            "Arn": (f"arn:aws:sts::{_ACCOUNT}:assumed-role/{role_name}/{role_name}"),
            "UserId": "SYNTHETIC",
        }


@dataclass(slots=True)
class _SyntheticSession:
    """Hold only synthetic signer credentials and the exact allowed clients."""

    factory: _SyntheticSessionFactory
    role_arn: str | None

    def client(self, service_name: str, **kwargs: object) -> object:
        region = kwargs.get("region_name")
        if region is not None:
            assert region == _REGION
        self.factory.service_calls.append((service_name, region))
        if service_name == "sts":
            return _SyntheticStsClient(self.factory, self.role_arn)
        if service_name == "logs" and self.role_arn is not None:
            assert _identity_label(self.role_arn) == "evidence-reader"
            return self.factory.logs
        message = f"unexpected synthetic service: {service_name}"
        raise AssertionError(message)

    def get_credentials(self) -> Credentials:
        assert self.role_arn is not None
        return Credentials(_ACCESS_KEY, _SECRET_KEY, _SESSION_TOKEN)


@dataclass(slots=True)
class _SyntheticSessionFactory:
    """Acquire exactly three synthetic assumed-role leases."""

    logs: _LogsClient
    events: list[str]
    pending_role: str | None = None
    current_session_regions: list[str] = field(default_factory=list)
    assumed_session_regions: list[str] = field(default_factory=list)
    sts_client_regions: list[str] = field(default_factory=list)
    assumed_roles: list[str] = field(default_factory=list)
    caller_identity_roles: list[str] = field(default_factory=list)
    service_calls: list[tuple[str, str | None]] = field(default_factory=list)

    def create_current_session(
        self,
        *,
        profile_name: str | None,
        region_name: str,
    ) -> AwsSession:
        assert profile_name is None
        assert region_name == _REGION
        self.current_session_regions.append(region_name)
        return cast("AwsSession", _SyntheticSession(self, None))

    def create_assumed_session(
        self,
        *,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        region_name: str,
    ) -> AwsSession:
        assert access_key_id == _ACCESS_KEY
        assert secret_access_key == _SECRET_KEY
        assert session_token == _SESSION_TOKEN
        assert region_name == _REGION
        assert self.pending_role is not None
        role_arn = self.pending_role
        self.pending_role = None
        self.assumed_session_regions.append(region_name)
        return cast("AwsSession", _SyntheticSession(self, role_arn))

    def create_sts_client(
        self,
        session: AwsSession,
        *,
        region_name: str,
    ) -> AwsStsClient:
        assert region_name == _REGION
        self.sts_client_regions.append(region_name)
        return cast("AwsStsClient", session.client("sts", region_name=region_name))


@dataclass(slots=True)
class _Runtime:
    """Injected state retained for exact contract assertions."""

    clock: _StepClock
    monotonic: _StepMonotonic
    ledger: _CorrelationLedger
    events: list[str]
    transport: _EchoTransport
    logs: _LogsClient
    factory: _SyntheticSessionFactory
    action_adapter: AwsSigV4ActionAdapter
    probe_adapter: CloudWatchLogsProbeAdapter


@dataclass(slots=True)
class _NoCallFactory:
    """Reject any identity acquisition attempted before pure validation."""

    called: bool = False

    def create_current_session(
        self,
        *,
        profile_name: str | None,
        region_name: str,
    ) -> AwsSession:
        del profile_name, region_name
        self.called = True
        message = "identity session must not be created"
        raise AssertionError(message)

    def create_assumed_session(
        self,
        *,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        region_name: str,
    ) -> AwsSession:
        del access_key_id, secret_access_key, session_token, region_name
        self.called = True
        message = "assumed session must not be created"
        raise AssertionError(message)

    def create_sts_client(
        self,
        session: AwsSession,
        *,
        region_name: str,
    ) -> AwsStsClient:
        del session, region_name
        self.called = True
        message = "STS client must not be created"
        raise AssertionError(message)


class _SingleReadEnvironment(dict[str, str]):
    """Reject repeated reads so resolution cannot drift after validation."""

    def __init__(self, values: Mapping[str, str]) -> None:
        super().__init__(values)
        self.reads: dict[str, int] = {}

    def __getitem__(self, key: str) -> str:
        self.reads[key] = self.reads.get(key, 0) + 1
        if self.reads[key] != 1:
            message = "environment value was read more than once"
            raise AssertionError(message)
        return super().__getitem__(key)


@dataclass(slots=True)
class _FailingSessionFactory:
    """Fail one synthetic identity acquisition before any external operation."""

    delegate: _SyntheticSessionFactory
    fail_on_current_call: int
    current_calls: int = 0

    def create_current_session(
        self,
        *,
        profile_name: str | None,
        region_name: str,
    ) -> AwsSession:
        position = self.current_calls
        self.current_calls += 1
        if position == self.fail_on_current_call:
            message = "synthetic identity acquisition diagnostic"
            raise RuntimeError(message)
        return self.delegate.create_current_session(
            profile_name=profile_name,
            region_name=region_name,
        )

    def create_assumed_session(
        self,
        *,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        region_name: str,
    ) -> AwsSession:
        return self.delegate.create_assumed_session(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            region_name=region_name,
        )

    def create_sts_client(
        self,
        session: AwsSession,
        *,
        region_name: str,
    ) -> AwsStsClient:
        return self.delegate.create_sts_client(
            session,
            region_name=region_name,
        )


@dataclass(slots=True)
class _InvalidLease:
    """Closeable lookalike that must fail the exact lease type boundary."""

    identity_id: str
    expires_at: datetime | None = None
    closed: bool = False

    def close(self) -> None:
        self.closed = True


@dataclass(slots=True)
class _DuplicateCorrelationActionAdapter:
    """Return valid built-in shapes with an intentionally reused correlation."""

    ledger: _CorrelationLedger
    calls: int = 0

    def execute_action(self, request: ActionRequest, /) -> ActionExecutionResult:
        self.calls += 1
        correlation = "duplicate-application-correlation"
        self.ledger.values.append(correlation)
        return ActionExecutionResult(
            action_id=request.action.id,
            outcome=ActionOutcome.SUCCEEDED,
            started_at=_NOW,
            completed_at=_NOW,
            observed=RedactedValue(
                {
                    "correlation_state": "MATCHED",
                    "http_status": 200,
                    "response_too_large": False,
                    "service": "execute-api",
                    "signing_region": _REGION,
                }
            ),
            correlation_ids=(correlation,),
            limitations=_ACTION_LIMITATIONS,
        )


@dataclass(slots=True)
class _FixedCorrelationActionAdapter:
    """Return two unique predetermined correlations for swap testing."""

    correlations: tuple[str, str]
    ledger: _CorrelationLedger
    events: list[str]
    calls: int = 0

    def execute_action(self, request: ActionRequest, /) -> ActionExecutionResult:
        position = self.calls
        self.calls += 1
        correlation = self.correlations[position]
        self.ledger.values.append(correlation)
        self.events.append(f"action:{position}")
        return ActionExecutionResult(
            action_id=request.action.id,
            outcome=ActionOutcome.SUCCEEDED,
            started_at=_NOW,
            completed_at=_NOW,
            observed=RedactedValue(
                {
                    "correlation_state": "MATCHED",
                    "http_status": 200,
                    "response_too_large": False,
                    "service": "execute-api",
                    "signing_region": _REGION,
                }
            ),
            correlation_ids=(correlation,),
            limitations=_ACTION_LIMITATIONS,
        )


@dataclass(slots=True)
class _ExplodingActionAdapter:
    """Raise at one action stage while allowing earlier chains to complete."""

    delegate: AwsSigV4ActionAdapter
    fail_at: int
    calls: int = 0

    def execute_action(self, request: ActionRequest, /) -> ActionExecutionResult:
        position = self.calls
        self.calls += 1
        if position == self.fail_at:
            message = "synthetic action exception diagnostic"
            raise RuntimeError(message)
        return self.delegate.execute_action(request)


@dataclass(slots=True)
class _ExplodingProbeAdapter:
    """Raise at one probe stage while allowing earlier chains to complete."""

    delegate: CloudWatchLogsProbeAdapter
    fail_at: int
    calls: int = 0

    def collect_evidence(self, request: ProbeRequest, /) -> ProbeResult:
        position = self.calls
        self.calls += 1
        if position == self.fail_at:
            message = "synthetic probe exception diagnostic"
            raise RuntimeError(message)
        return self.delegate.collect_evidence(request)


@dataclass(slots=True)
class _EventBudget:
    """Exhaust the orchestration budget immediately after one stage event."""

    events: list[str]
    exhaust_after: str
    calls: int = 0

    def __call__(self) -> float:
        self.calls += 1
        if self.exhaust_after in self.events:
            return 301.0
        return self.calls / 100.0


def test_example_contract_executes_real_adapters_and_finalizes_redacted_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Examples drive signing, Logs normalization, evaluation, and evidence."""
    runtime = _runtime(("pass", "pass"))
    closed: list[str] = []
    original_close = AwsScopedIdentity.close
    original_evaluate = RetrievalBoundaryEvaluator.evaluate_assertion

    def close(lease: AwsScopedIdentity) -> None:
        closed.append(lease.identity_id)
        runtime.events.append(f"close:{lease.identity_id}")
        original_close(lease)

    def evaluate(
        evaluator: RetrievalBoundaryEvaluator,
        request: AssertionEvaluationRequest,
        /,
    ) -> AssertionResult:
        assert closed == ["requester-a", "requester-b", "evidence-reader"]
        runtime.events.append(f"evaluate:{request.assertion.id}")
        return original_evaluate(evaluator, request)

    monkeypatch.setattr(AwsScopedIdentity, "close", close)
    monkeypatch.setattr(RetrievalBoundaryEvaluator, "evaluate_assertion", evaluate)

    result = _run(tmp_path, "example-contract", runtime)

    assert result.status is AssertionStatus.PASS
    assert result.exit_code is CliExitCode.SUCCESS
    assert [item.status for item in result.assertion_results] == [
        AssertionStatus.PASS,
        AssertionStatus.PASS,
    ]
    assert not hasattr(result, "action_results")
    assert not hasattr(result, "probe_results")
    assert all(value not in repr(result) for value in runtime.ledger.values)
    assert len(runtime.transport.calls) == _DIRECTION_COUNT
    assert len(runtime.logs.calls) == _DIRECTION_COUNT
    _assert_exact_outbound_contract(runtime)
    _assert_lifecycle(runtime, closed)
    _assert_bundle(result, runtime)


def test_required_environment_is_snapshotted_once_before_aws_access(
    tmp_path: Path,
) -> None:
    """Built-in providers and adapters reuse one immutable resolved environment."""
    runtime = _runtime(("pass", "pass"))
    environment = _SingleReadEnvironment(_ENVIRONMENT)

    result = _run(
        tmp_path,
        "single-read-environment",
        runtime,
        environment=environment,
    )

    assert result.status is AssertionStatus.PASS
    assert environment.reads == {
        "CAI_REQUESTER_A_CANARY": 1,
        "CAI_REQUESTER_B_CANARY": 1,
    }


@pytest.mark.parametrize(
    ("behaviors", "expected_assertions", "expected_status", "expected_exit"),
    [
        (
            ("pass", "pass"),
            (AssertionStatus.PASS, AssertionStatus.PASS),
            AssertionStatus.PASS,
            CliExitCode.SUCCESS,
        ),
        (
            ("fail", "pass"),
            (AssertionStatus.FAIL, AssertionStatus.PASS),
            AssertionStatus.FAIL,
            CliExitCode.ASSERTION_FAILED,
        ),
        (
            ("fail", "fail"),
            (AssertionStatus.FAIL, AssertionStatus.FAIL),
            AssertionStatus.FAIL,
            CliExitCode.ASSERTION_FAILED,
        ),
        (
            ("pass", "inconclusive"),
            (AssertionStatus.PASS, AssertionStatus.INCONCLUSIVE),
            AssertionStatus.INCONCLUSIVE,
            CliExitCode.INCONCLUSIVE,
        ),
        (
            ("pass", "error"),
            (AssertionStatus.PASS, AssertionStatus.ERROR),
            AssertionStatus.ERROR,
            CliExitCode.EXECUTION_ERROR,
        ),
        (
            ("fail", "error"),
            (AssertionStatus.FAIL, AssertionStatus.ERROR),
            AssertionStatus.FAIL,
            CliExitCode.ASSERTION_FAILED,
        ),
    ],
)
def test_aggregate_semantics_preserve_two_normalized_directions(
    tmp_path: Path,
    behaviors: tuple[str, str],
    expected_assertions: tuple[AssertionStatus, AssertionStatus],
    expected_status: AssertionStatus,
    expected_exit: CliExitCode,
) -> None:
    """The second direction runs and is finalized for every normalized status."""
    runtime = _runtime(behaviors)

    result = _run(
        tmp_path,
        f"aggregate-{behaviors[0]}-{behaviors[1]}",
        runtime,
    )

    assert tuple(item.status for item in result.assertion_results) == (
        expected_assertions
    )
    assert result.status is expected_status
    assert result.exit_code is expected_exit
    assert len(runtime.transport.calls) == _DIRECTION_COUNT
    assert len(runtime.logs.calls) == _DIRECTION_COUNT
    assert verify_run_integrity(result.evidence_path).valid
    assert (result.evidence_path / "manifest.json").is_file()


def test_optional_progress_observer_emits_only_fixed_ordered_stages(
    tmp_path: Path,
) -> None:
    """Successful coordination exposes no identifiers or runtime diagnostics."""
    stages: list[AwsReciprocalRetrievalRunStage] = []

    result = _run(
        tmp_path,
        "progress-success",
        _runtime(("pass", "pass")),
        progress=stages.append,
    )

    assert result.status is AssertionStatus.PASS
    assert stages == [
        AwsReciprocalRetrievalRunStage.VALIDATION,
        AwsReciprocalRetrievalRunStage.AUTHORIZATION,
        AwsReciprocalRetrievalRunStage.IDENTITY_ACQUISITION,
        AwsReciprocalRetrievalRunStage.DIRECTION_ONE,
        AwsReciprocalRetrievalRunStage.DIRECTION_TWO,
        AwsReciprocalRetrievalRunStage.EVALUATION,
        AwsReciprocalRetrievalRunStage.FINALIZATION,
        AwsReciprocalRetrievalRunStage.INTEGRITY_VERIFICATION,
        AwsReciprocalRetrievalRunStage.COMPLETE,
    ]


def test_progress_observer_failure_is_advisory_and_run_failure_is_fixed(
    tmp_path: Path,
) -> None:
    """Observer exceptions cannot alter execution; run errors end at failed."""
    emitted: list[AwsReciprocalRetrievalRunStage] = []

    def observer(stage: AwsReciprocalRetrievalRunStage) -> None:
        emitted.append(stage)
        if stage is AwsReciprocalRetrievalRunStage.AUTHORIZATION:
            message = "observer diagnostic must stay private"
            raise RuntimeError(message)

    result = _run(
        tmp_path,
        "progress-observer-error",
        _runtime(("pass", "pass")),
        progress=observer,
    )
    assert result.status is AssertionStatus.PASS
    assert emitted[-1] is AwsReciprocalRetrievalRunStage.COMPLETE

    failed: list[AwsReciprocalRetrievalRunStage] = []
    with pytest.raises(AwsReciprocalRetrievalRunError):
        run_aws_reciprocal_retrieval(
            _suite(),
            AwsReciprocalRetrievalRunOptions(
                run_id="progress-invalid",
                scenario_id="missing",
                evidence_root=tmp_path,
                execution_policy=load_aws_execution_policy(_POLICY_PATH),
                environment=_ENVIRONMENT,
                progress=failed.append,
            ),
        )
    assert failed == [
        AwsReciprocalRetrievalRunStage.VALIDATION,
        AwsReciprocalRetrievalRunStage.FAILED,
    ]


@pytest.mark.parametrize(
    "case",
    [
        "zero_chains",
        "one_chain",
        "partial_pair",
        "three_chains",
        "extra_action",
        "non_execute_api",
        "mutating_action",
        "region_mismatch",
        "identical_effective_requesters",
        "different_evidence_identities",
        "aliased_evidence_identity",
        "evidence_identity_overlaps_requester",
        "different_log_groups",
        "extra_observation",
        "non_reversed_canaries",
        "reused_action_and_probe",
        "unsafe_assertion_limitation",
        "missing_scenario",
    ],
)
def test_invalid_exact_pair_is_rejected_before_reservation_or_identity(
    tmp_path: Path,
    case: str,
) -> None:
    """Mixed-purpose and ambiguous scenarios cannot reserve or access AWS."""
    suite = _invalid_suite(case)
    factory = _NoCallFactory()
    scenario_id = "missing-scenario" if case == "missing_scenario" else _SCENARIO_ID

    with pytest.raises(AwsReciprocalRetrievalRunError) as caught:
        run_aws_reciprocal_retrieval(
            suite,
            AwsReciprocalRetrievalRunOptions(
                run_id=f"invalid-{case}",
                scenario_id=scenario_id,
                evidence_root=tmp_path,
                execution_policy=load_aws_execution_policy(_POLICY_PATH),
                environment=_ENVIRONMENT,
                session_factory=cast("AwsSessionFactory", factory),
                clock=lambda: _NOW,
                monotonic=lambda: 0.0,
            ),
        )

    assert (
        caught.value.code is AwsReciprocalRetrievalRunFailureCode.INVALID_CONFIGURATION
    )
    assert not factory.called
    assert list(tmp_path.iterdir()) == []


def test_invalid_canary_environment_is_rejected_before_reservation(
    tmp_path: Path,
) -> None:
    """Equal canaries fail before sessions, actions, or evidence reservation."""
    factory = _NoCallFactory()

    with pytest.raises(AwsReciprocalRetrievalRunError) as caught:
        run_aws_reciprocal_retrieval(
            _suite(),
            AwsReciprocalRetrievalRunOptions(
                run_id="invalid-environment",
                scenario_id=_SCENARIO_ID,
                evidence_root=tmp_path,
                execution_policy=load_aws_execution_policy(_POLICY_PATH),
                environment={
                    "CAI_REQUESTER_A_CANARY": "same-synthetic-canary",
                    "CAI_REQUESTER_B_CANARY": "same-synthetic-canary",
                },
                session_factory=cast("AwsSessionFactory", factory),
            ),
        )

    assert caught.value.code is AwsReciprocalRetrievalRunFailureCode.INVALID_ENVIRONMENT
    assert not factory.called
    assert list(tmp_path.iterdir()) == []


def test_policy_denial_precedes_reservation_identity_and_target_access(
    tmp_path: Path,
) -> None:
    """The untrusted suite cannot reserve a run or reach an AWS-capable seam."""
    payload = load_aws_execution_policy(_POLICY_PATH).model_dump(
        mode="json",
        by_alias=True,
    )
    payload["applicationEndpoint"] = "https://denied.sandbox.example.test/v1"
    factory = _NoCallFactory()

    with pytest.raises(AwsExecutionPolicyError) as caught:
        run_aws_reciprocal_retrieval(
            _suite(),
            AwsReciprocalRetrievalRunOptions(
                run_id="policy-denied",
                scenario_id=_SCENARIO_ID,
                evidence_root=tmp_path,
                execution_policy=AwsExecutionPolicy.model_validate(payload),
                environment=_ENVIRONMENT,
                session_factory=cast("AwsSessionFactory", factory),
            ),
        )

    assert caught.value.code is AwsExecutionPolicyFailureCode.UNAUTHORIZED_ENDPOINT
    assert not factory.called
    assert list(tmp_path.iterdir()) == []


def test_digest_prefix_collision_is_rejected_before_reservation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Precomputed hashed names must be unique before any state is reserved."""
    factory = _NoCallFactory()

    def colliding_path(category: str, identifier: str) -> str:
        del identifier
        return f"{category}/item-0000000000000000.json"

    monkeypatch.setattr(reciprocal_module, "_item_path", colliding_path)
    with pytest.raises(AwsReciprocalRetrievalRunError) as caught:
        run_aws_reciprocal_retrieval(
            _suite(),
            AwsReciprocalRetrievalRunOptions(
                run_id="digest-collision",
                scenario_id=_SCENARIO_ID,
                evidence_root=tmp_path,
                execution_policy=load_aws_execution_policy(_POLICY_PATH),
                environment=_ENVIRONMENT,
                session_factory=cast("AwsSessionFactory", factory),
            ),
        )

    assert (
        caught.value.code is AwsReciprocalRetrievalRunFailureCode.INVALID_CONFIGURATION
    )
    assert not factory.called
    assert list(tmp_path.iterdir()) == []


def test_existing_run_prevents_all_identity_and_target_access(tmp_path: Path) -> None:
    """Exclusive reservation precedes STS, application, and Logs operations."""
    run_path = tmp_path / "existing-run"
    run_path.mkdir()
    factory = _NoCallFactory()

    with pytest.raises(AwsReciprocalRetrievalRunError) as caught:
        run_aws_reciprocal_retrieval(
            _suite(),
            AwsReciprocalRetrievalRunOptions(
                run_id=run_path.name,
                scenario_id=_SCENARIO_ID,
                evidence_root=tmp_path,
                execution_policy=load_aws_execution_policy(_POLICY_PATH),
                environment=_ENVIRONMENT,
                session_factory=cast("AwsSessionFactory", factory),
            ),
        )

    assert (
        caught.value.code is AwsReciprocalRetrievalRunFailureCode.EVIDENCE_RUN_COLLISION
    )
    assert not factory.called
    assert list(run_path.iterdir()) == []


@pytest.mark.parametrize(
    "case",
    [
        "invalid_type",
        "closed",
        "expired",
        "naive_expiry",
        "wrong_identity_id",
        "wrong_account",
        "wrong_partition",
    ],
)
def test_invalid_acquired_lease_fails_before_action_and_closes_all_acquired_leases(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    case: str,
) -> None:
    """Every exact lease boundary is checked before application execution."""
    runtime = _runtime(("pass", "pass"))
    acquired: list[AwsScopedIdentity | _InvalidLease] = []

    def acquire(
        identity: CurrentAwsIdentity | AssumedRoleIdentity,
        **_kwargs: object,
    ) -> AwsScopedIdentity:
        position = len(acquired)
        lease: AwsScopedIdentity | _InvalidLease = _synthetic_lease(identity.id)
        if position == _EVIDENCE_IDENTITY_POSITION:
            lease = _lease_for_failure(case, identity.id)
        acquired.append(lease)
        return cast("AwsScopedIdentity", lease)

    monkeypatch.setattr(reciprocal_module, "_acquire_identity", acquire)
    with pytest.raises(AwsReciprocalRetrievalRunError) as caught:
        _run(tmp_path, f"invalid-lease-{case}", runtime)

    abandoned = tmp_path / f"invalid-lease-{case}"
    assert (
        caught.value.code is AwsReciprocalRetrievalRunFailureCode.IDENTITY_UNAVAILABLE
    )
    assert len(acquired) == _IDENTITY_COUNT
    assert all(lease.closed for lease in acquired)
    assert runtime.transport.calls == []
    assert runtime.logs.calls == []
    assert abandoned.is_dir()
    assert not (abandoned / "manifest.json").exists()


def test_lease_expiring_between_acquisition_and_pre_action_validation_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """All three leases are revalidated together immediately before action one."""
    runtime = _runtime(("pass", "pass"))
    acquired: list[AwsScopedIdentity] = []

    def acquire(
        identity: CurrentAwsIdentity | AssumedRoleIdentity,
        **_kwargs: object,
    ) -> AwsScopedIdentity:
        expires_at = (
            _NOW + timedelta(milliseconds=250)
            if len(acquired) == _EVIDENCE_IDENTITY_POSITION
            else _NOW + timedelta(hours=1)
        )
        lease = _synthetic_lease(identity.id, expires_at=expires_at)
        acquired.append(lease)
        return lease

    monkeypatch.setattr(reciprocal_module, "_acquire_identity", acquire)
    with pytest.raises(AwsReciprocalRetrievalRunError) as caught:
        _run(tmp_path, "lease-expired-before-action", runtime)

    assert (
        caught.value.code is AwsReciprocalRetrievalRunFailureCode.IDENTITY_UNAVAILABLE
    )
    assert len(acquired) == _IDENTITY_COUNT
    assert all(lease.closed for lease in acquired)
    assert runtime.transport.calls == []
    assert runtime.logs.calls == []
    assert not (tmp_path / "lease-expired-before-action" / "manifest.json").exists()


@pytest.mark.parametrize(
    ("fail_at", "expected_closed"),
    [
        (0, []),
        (1, ["requester-a"]),
        (2, ["requester-a", "requester-b"]),
    ],
)
def test_identity_acquisition_failure_closes_every_previously_acquired_lease(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fail_at: int,
    expected_closed: list[str],
) -> None:
    """Acquisition exceptions are redacted and clean up earlier identities."""
    runtime = _runtime(("pass", "pass"))
    failing_factory = _FailingSessionFactory(runtime.factory, fail_at)
    closed: list[str] = []
    original_close = AwsScopedIdentity.close

    def close(lease: AwsScopedIdentity) -> None:
        closed.append(lease.identity_id)
        original_close(lease)

    monkeypatch.setattr(AwsScopedIdentity, "close", close)
    with pytest.raises(AwsReciprocalRetrievalRunError) as caught:
        _run(
            tmp_path,
            f"identity-acquisition-{fail_at}",
            runtime,
            session_factory=cast("AwsSessionFactory", failing_factory),
        )

    abandoned = tmp_path / f"identity-acquisition-{fail_at}"
    assert (
        caught.value.code is AwsReciprocalRetrievalRunFailureCode.IDENTITY_UNAVAILABLE
    )
    assert "synthetic identity acquisition diagnostic" not in str(caught.value)
    assert closed == expected_closed
    assert runtime.transport.calls == []
    assert runtime.logs.calls == []
    assert abandoned.is_dir()
    assert not (abandoned / "manifest.json").exists()


@pytest.mark.parametrize(
    ("stage", "fail_at", "expected_actions", "expected_probes"),
    [
        ("action", 0, 0, 0),
        ("action", 1, 1, 1),
        ("probe", 0, 1, 0),
        ("probe", 1, 2, 1),
    ],
)
def test_action_and_probe_exceptions_close_all_leases(  # noqa: PLR0913
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stage: str,
    fail_at: int,
    expected_actions: int,
    expected_probes: int,
) -> None:
    """Raised adapter diagnostics remain private and never strand a lease."""
    runtime = _runtime(("pass", "pass"))
    closed: list[str] = []
    original_close = AwsScopedIdentity.close
    action_adapter: AwsSigV4ActionAdapter = runtime.action_adapter
    probe_adapter: CloudWatchLogsProbeAdapter = runtime.probe_adapter

    def close(lease: AwsScopedIdentity) -> None:
        closed.append(lease.identity_id)
        original_close(lease)

    monkeypatch.setattr(AwsScopedIdentity, "close", close)
    if stage == "action":
        action_adapter = cast(
            "AwsSigV4ActionAdapter",
            _ExplodingActionAdapter(runtime.action_adapter, fail_at),
        )
    else:
        probe_adapter = cast(
            "CloudWatchLogsProbeAdapter",
            _ExplodingProbeAdapter(runtime.probe_adapter, fail_at),
        )

    run_id = f"{stage}-exception-{fail_at}"
    with pytest.raises(AwsReciprocalRetrievalRunError) as caught:
        _run(
            tmp_path,
            run_id,
            runtime,
            action_adapter=action_adapter,
            probe_adapter=probe_adapter,
        )

    abandoned = tmp_path / run_id
    assert (
        caught.value.code
        is AwsReciprocalRetrievalRunFailureCode.INVALID_NORMALIZED_RESULT
    )
    assert "synthetic action exception diagnostic" not in str(caught.value)
    assert "synthetic probe exception diagnostic" not in str(caught.value)
    assert closed == ["requester-a", "requester-b", "evidence-reader"]
    assert len(runtime.transport.calls) == expected_actions
    assert len(runtime.logs.calls) == expected_probes
    assert abandoned.is_dir()
    assert not (abandoned / "manifest.json").exists()


def test_duplicate_successful_correlations_fail_closed_and_preserve_abandoned_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """One application correlation can never satisfy both reciprocal actions."""
    runtime = _runtime(("pass", "pass"))
    duplicate = _DuplicateCorrelationActionAdapter(runtime.ledger)
    closed: list[str] = []
    original_close = AwsScopedIdentity.close

    def close(lease: AwsScopedIdentity) -> None:
        closed.append(lease.identity_id)
        original_close(lease)

    monkeypatch.setattr(AwsScopedIdentity, "close", close)
    with pytest.raises(AwsReciprocalRetrievalRunError) as caught:
        _run(
            tmp_path,
            "duplicate-correlations",
            runtime,
            action_adapter=cast("AwsSigV4ActionAdapter", duplicate),
        )

    abandoned = tmp_path / "duplicate-correlations"
    assert (
        caught.value.code
        is AwsReciprocalRetrievalRunFailureCode.INVALID_NORMALIZED_RESULT
    )
    assert duplicate.calls == _DIRECTION_COUNT
    assert len(runtime.logs.calls) == 1
    assert closed == ["requester-a", "requester-b", "evidence-reader"]
    assert abandoned.is_dir()
    assert not (abandoned / "manifest.json").exists()


def test_scheduling_budget_exhaustion_preserves_unfinalized_reservation(
    tmp_path: Path,
) -> None:
    """The five-minute budget is enforced before the first identity call."""
    factory = _NoCallFactory()
    values = iter((0.0, 301.0))

    with pytest.raises(AwsReciprocalRetrievalRunError) as caught:
        run_aws_reciprocal_retrieval(
            _suite(),
            AwsReciprocalRetrievalRunOptions(
                run_id="duration-exhausted",
                scenario_id=_SCENARIO_ID,
                evidence_root=tmp_path,
                execution_policy=load_aws_execution_policy(_POLICY_PATH),
                environment=_ENVIRONMENT,
                session_factory=cast("AwsSessionFactory", factory),
                clock=lambda: _NOW,
                monotonic=lambda: next(values),
            ),
        )

    abandoned = tmp_path / "duration-exhausted"
    assert caught.value.code is AwsReciprocalRetrievalRunFailureCode.DURATION_EXHAUSTED
    assert not factory.called
    assert abandoned.is_dir()
    assert not (abandoned / "manifest.json").exists()


@pytest.mark.parametrize(
    ("event", "expected_identities", "expected_actions", "expected_probes"),
    [
        ("identity:requester-a", 1, 0, 0),
        ("action:0", 3, 1, 0),
        ("probe:0", 3, 1, 1),
    ],
)
def test_scheduling_budget_is_enforced_after_identity_action_and_probe_stages(  # noqa: PLR0913
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    event: str,
    expected_identities: int,
    expected_actions: int,
    expected_probes: int,
) -> None:
    """Representative after-stage checks prevent the next stage from starting."""
    runtime = _runtime(("pass", "pass"))
    orchestration_clock = _EventBudget(runtime.events, event)
    closed: list[str] = []
    original_close = AwsScopedIdentity.close

    def close(lease: AwsScopedIdentity) -> None:
        closed.append(lease.identity_id)
        original_close(lease)

    monkeypatch.setattr(AwsScopedIdentity, "close", close)
    run_id = f"duration-after-{event.replace(':', '-')}"
    with pytest.raises(AwsReciprocalRetrievalRunError) as caught:
        _run(
            tmp_path,
            run_id,
            runtime,
            monotonic=orchestration_clock,
        )

    abandoned = tmp_path / run_id
    assert caught.value.code is AwsReciprocalRetrievalRunFailureCode.DURATION_EXHAUSTED
    assert len(runtime.factory.assumed_roles) == expected_identities
    assert len(runtime.transport.calls) == expected_actions
    assert len(runtime.logs.calls) == expected_probes
    assert closed == [
        identity
        for identity in ("requester-a", "requester-b", "evidence-reader")
        if identity
        in {
            _identity_label(role)
            for role in runtime.factory.assumed_roles[:expected_identities]
        }
    ]
    assert abandoned.is_dir()
    assert not (abandoned / "manifest.json").exists()


def test_cross_swapped_correlations_never_satisfy_either_direction(
    tmp_path: Path,
) -> None:
    """A record correlated to the other action is fail-closed in both chains."""
    runtime = _runtime(("pass", "pass"))
    correlations = ("fixed-correlation-a", "fixed-correlation-b")
    runtime.logs.event_correlations = (correlations[1], correlations[0])
    action_adapter = _FixedCorrelationActionAdapter(
        correlations,
        runtime.ledger,
        runtime.events,
    )

    result = _run(
        tmp_path,
        "cross-swapped-correlations",
        runtime,
        action_adapter=cast("AwsSigV4ActionAdapter", action_adapter),
    )

    assert [item.status for item in result.assertion_results] == [
        AssertionStatus.INCONCLUSIVE,
        AssertionStatus.INCONCLUSIVE,
    ]
    assert result.status is AssertionStatus.INCONCLUSIVE
    assert result.exit_code is CliExitCode.INCONCLUSIVE
    assert [_filter_correlation(call) for call in runtime.logs.calls] == list(
        correlations
    )
    assert action_adapter.calls == _DIRECTION_COUNT
    assert verify_run_integrity(result.evidence_path).valid


def test_unstored_assertion_evidence_id_rejects_the_normalized_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Every assertion reference must resolve to one stored action or observation."""
    runtime = _runtime(("pass", "pass"))
    original_evaluate = RetrievalBoundaryEvaluator.evaluate_assertion
    evaluations = 0

    def evaluate(
        evaluator: RetrievalBoundaryEvaluator,
        request: AssertionEvaluationRequest,
        /,
    ) -> AssertionResult:
        nonlocal evaluations
        evaluations += 1
        result = original_evaluate(evaluator, request)
        return replace(result, evidence_ids=("retrieval.missing-evidence",))

    monkeypatch.setattr(RetrievalBoundaryEvaluator, "evaluate_assertion", evaluate)
    with pytest.raises(AwsReciprocalRetrievalRunError) as caught:
        _run(tmp_path, "missing-evidence-id", runtime)

    abandoned = tmp_path / "missing-evidence-id"
    assert (
        caught.value.code
        is AwsReciprocalRetrievalRunFailureCode.INVALID_NORMALIZED_RESULT
    )
    assert evaluations == _DIRECTION_COUNT
    assert len(runtime.transport.calls) == _DIRECTION_COUNT
    assert len(runtime.logs.calls) == _DIRECTION_COUNT
    assert abandoned.is_dir()
    assert not (abandoned / "manifest.json").exists()
    assert not any(path.is_file() for path in abandoned.rglob("*"))


def test_artifact_write_failure_preserves_an_unfinalized_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A filesystem diagnostic is redacted and never gains a manifest."""
    secret = "filesystem-path-secret"  # noqa: S105

    def fail_write(
        _run: RunDirectory,
        _relative_path: str,
        _content: bytes,
        *,
        media_type: str,
        sensitivity: Sensitivity,
    ) -> Never:
        del media_type, sensitivity
        raise OSError(secret)

    monkeypatch.setattr(RunDirectory, "write_evidence", fail_write)
    with pytest.raises(AwsReciprocalRetrievalRunError) as caught:
        _run(tmp_path, "write-failed", _runtime(("pass", "pass")))

    abandoned = tmp_path / "write-failed"
    assert (
        caught.value.code
        is AwsReciprocalRetrievalRunFailureCode.EVIDENCE_PERSISTENCE_FAILED
    )
    assert secret not in str(caught.value)
    assert abandoned.is_dir()
    assert not (abandoned / "manifest.json").exists()


def test_manifest_finalization_failure_preserves_an_unfinalized_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """All written artifacts remain abandoned when manifest publication fails."""
    secret = "manifest-finalization-secret"  # noqa: S105

    def fail_finalize(_run: RunDirectory) -> Never:
        raise OSError(secret)

    monkeypatch.setattr(RunDirectory, "finalize_manifest", fail_finalize)
    with pytest.raises(AwsReciprocalRetrievalRunError) as caught:
        _run(tmp_path, "finalize-failed", _runtime(("pass", "pass")))

    abandoned = tmp_path / "finalize-failed"
    assert (
        caught.value.code
        is AwsReciprocalRetrievalRunFailureCode.EVIDENCE_PERSISTENCE_FAILED
    )
    assert secret not in str(caught.value)
    assert abandoned.is_dir()
    assert not (abandoned / "manifest.json").exists()


def test_post_finalization_verification_failure_preserves_but_does_not_return_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A finalized directory survives a redacted immediate-verification failure."""
    secret = "integrity-verification-secret"  # noqa: S105

    def fail_verification(_path: object) -> Never:
        raise RuntimeError(secret)

    monkeypatch.setattr(
        reciprocal_module,
        "verify_run_integrity",
        fail_verification,
    )
    with pytest.raises(AwsReciprocalRetrievalRunError) as caught:
        _run(tmp_path, "verification-failed", _runtime(("pass", "pass")))

    finalized = tmp_path / "verification-failed"
    assert (
        caught.value.code
        is AwsReciprocalRetrievalRunFailureCode.INTEGRITY_VERIFICATION_FAILED
    )
    assert secret not in str(caught.value)
    assert (finalized / "manifest.json").is_file()
    assert verify_run_integrity(finalized).valid


def test_fixed_inputs_produce_identical_bundles_under_different_roots(
    tmp_path: Path,
) -> None:
    """Evidence paths do not influence any artifact or manifest byte."""
    first = _run(tmp_path / "first", "deterministic-run", _runtime(("pass", "pass")))
    second = _run(
        tmp_path / "second",
        "deterministic-run",
        _runtime(("pass", "pass")),
    )

    assert _bundle_bytes(first.evidence_path) == _bundle_bytes(second.evidence_path)
    assert first.terminal_report == second.terminal_report
    assert first.json_report == second.json_report


@pytest.mark.parametrize(
    "relative_path",
    [
        "run.json",
        _item_path("actions", "retrieve-as-requester-a"),
        _item_path("probes", "requester-a-retrieval"),
        _item_path("results", "requester-a-retrieval-boundary"),
        "reports/report.json",
        "reports/terminal.txt",
        "manifest.json",
    ],
    ids=(
        "run",
        "action",
        "probe",
        "result",
        "json-report",
        "terminal-report",
        "manifest",
    ),
)
def test_offline_verification_detects_tampering_in_every_bundle_category(
    tmp_path: Path,
    relative_path: str,
) -> None:
    """Every reciprocal artifact category is covered by offline integrity."""
    result = _run(
        tmp_path,
        f"tamper-{relative_path.replace('/', '-').replace('.', '-')}",
        _runtime(("pass", "pass")),
    )
    target = result.evidence_path / relative_path
    target.write_bytes(target.read_bytes() + b"x")

    assert not verify_run_integrity(result.evidence_path).valid


def _runtime(behaviors: tuple[str, str]) -> _Runtime:
    clock = _StepClock()
    monotonic = _StepMonotonic()
    ledger = _CorrelationLedger()
    events: list[str] = []
    transport = _EchoTransport(behaviors, ledger, events)
    logs = _LogsClient(behaviors, ledger, events)
    factory = _SyntheticSessionFactory(logs, events)
    return _Runtime(
        clock=clock,
        monotonic=monotonic,
        ledger=ledger,
        events=events,
        transport=transport,
        logs=logs,
        factory=factory,
        action_adapter=AwsSigV4ActionAdapter(
            environment=_ENVIRONMENT,
            transport=transport,
            clock=clock,
        ),
        probe_adapter=CloudWatchLogsProbeAdapter(
            environment=_ENVIRONMENT,
            suite_max_age=timedelta(minutes=5),
            clock_skew_tolerance=timedelta(seconds=30),
            clock=clock,
            monotonic=monotonic,
        ),
    )


def _synthetic_lease(
    identity_id: str,
    *,
    account_id: str = _ACCOUNT,
    partition: str = "aws",
    expires_at: datetime | None = None,
) -> AwsScopedIdentity:
    return AwsScopedIdentity(
        _identity_id=identity_id,
        _account_id=account_id,
        _partition=partition,
        _expires_at=expires_at or _NOW + timedelta(hours=1),
        _session=cast("AwsSession", object()),
    )


def _lease_for_failure(  # noqa: PLR0911 - each malformed lease is explicit.
    case: str,
    identity_id: str,
) -> AwsScopedIdentity | _InvalidLease:
    if case == "invalid_type":
        return _InvalidLease(identity_id)
    if case == "closed":
        lease = _synthetic_lease(identity_id)
        lease.close()
        return lease
    if case == "expired":
        return _synthetic_lease(
            identity_id,
            expires_at=_NOW - timedelta(seconds=1),
        )
    if case == "naive_expiry":
        return _synthetic_lease(
            identity_id,
            expires_at=_NOW.replace(tzinfo=None),
        )
    if case == "wrong_identity_id":
        return _synthetic_lease("unexpected-identity")
    if case == "wrong_account":
        return _synthetic_lease(identity_id, account_id="999900001111")
    if case == "wrong_partition":
        return _synthetic_lease(identity_id, partition="aws-us-gov")
    raise AssertionError(case)


def _run(  # noqa: PLR0913 - injected seams keep contract tests network-isolated.
    evidence_root: Path,
    run_id: str,
    runtime: _Runtime,
    *,
    action_adapter: AwsSigV4ActionAdapter | None = None,
    probe_adapter: CloudWatchLogsProbeAdapter | None = None,
    session_factory: AwsSessionFactory | None = None,
    monotonic: Callable[[], float] | None = None,
    environment: Mapping[str, str] | None = None,
    progress: Callable[[AwsReciprocalRetrievalRunStage], None] | None = None,
) -> AwsReciprocalRetrievalRunResult:
    return run_aws_reciprocal_retrieval(
        _suite(),
        AwsReciprocalRetrievalRunOptions(
            run_id=run_id,
            scenario_id=_SCENARIO_ID,
            evidence_root=evidence_root,
            execution_policy=load_aws_execution_policy(_POLICY_PATH),
            environment=_ENVIRONMENT if environment is None else environment,
            session_factory=session_factory
            or cast("AwsSessionFactory", runtime.factory),
            clock=runtime.clock,
            monotonic=monotonic or runtime.monotonic,
            action_adapter=action_adapter or runtime.action_adapter,
            probe_adapter=probe_adapter or runtime.probe_adapter,
            progress=progress,
        ),
    )


def _suite() -> VerificationSuite:
    return load_suite(_SUITE_PATH)


def _filter_correlation(arguments: Mapping[str, object]) -> str:
    pattern = arguments["filterPattern"]
    assert isinstance(pattern, str)
    pieces = pattern.split('"')
    assert len(pieces) == _FILTER_PATTERN_PART_COUNT
    return pieces[1]


def _identity_label(role_arn: str) -> str:
    if role_arn.endswith("requester-a"):
        return "requester-a"
    if role_arn.endswith("requester-b"):
        return "requester-b"
    return "evidence-reader"


def _assert_exact_outbound_contract(runtime: _Runtime) -> None:
    for request in runtime.transport.calls:
        assert request.method == "POST"
        assert request.hostname == "retrieval.sandbox.example.test"
        assert request.port == _HTTPS_PORT
        assert request.target == "/v1/retrieve"
        assert request.service == "execute-api"
        assert request.region == _REGION
    assert [item["logGroupName"] for item in runtime.logs.calls] == [
        "/aws/cai-verify/synthetic-retrieval",
        "/aws/cai-verify/synthetic-retrieval",
    ]
    assert runtime.factory.current_session_regions == [_REGION] * _IDENTITY_COUNT
    assert runtime.factory.assumed_session_regions == [_REGION] * _IDENTITY_COUNT
    assert runtime.factory.sts_client_regions == [_REGION] * _STS_CALL_COUNT
    assert len(runtime.factory.assumed_roles) == _IDENTITY_COUNT
    assert runtime.factory.assumed_roles[0].endswith("requester-a")
    assert runtime.factory.assumed_roles[1].endswith("requester-b")
    assert runtime.factory.assumed_roles[2].endswith("evidence-reader")
    assert runtime.factory.caller_identity_roles == runtime.factory.assumed_roles
    assert [service for service, _region in runtime.factory.service_calls].count(
        "sts"
    ) == _STS_CALL_COUNT
    assert [service for service, _region in runtime.factory.service_calls].count(
        "logs"
    ) == _DIRECTION_COUNT


def _assert_lifecycle(runtime: _Runtime, closed: list[str]) -> None:
    assert closed == ["requester-a", "requester-b", "evidence-reader"]
    expected = [
        "action:0",
        "close:requester-a",
        "probe:0",
        "action:1",
        "close:requester-b",
        "probe:1",
        "close:evidence-reader",
        "evaluate:requester-a-retrieval-boundary",
        "evaluate:requester-b-retrieval-boundary",
    ]
    positions = [runtime.events.index(item) for item in expected]
    assert positions == sorted(positions)
    assert len(runtime.clock.calls) >= _MIN_CLOCK_CALLS
    assert len(set(runtime.clock.calls)) == len(runtime.clock.calls)
    assert runtime.monotonic.calls >= _MIN_MONOTONIC_CALLS


def _assert_bundle(
    result: AwsReciprocalRetrievalRunResult,
    runtime: _Runtime,
) -> None:
    verification = verify_run_integrity(result.evidence_path)
    assert verification.valid
    assert verification.artifacts_checked == _NON_MANIFEST_ARTIFACT_COUNT
    files = _bundle_bytes(result.evidence_path)
    assert len(files) == _BUNDLE_FILE_COUNT
    assert "manifest.json" in files
    non_manifest = set(files) - {"manifest.json"}
    assert non_manifest == {
        "run.json",
        _item_path("actions", "retrieve-as-requester-a"),
        _item_path("actions", "retrieve-as-requester-b"),
        _item_path("probes", "requester-a-retrieval"),
        _item_path("probes", "requester-b-retrieval"),
        _item_path("results", "requester-a-retrieval-boundary"),
        _item_path("results", "requester-b-retrieval-boundary"),
        "reports/report.json",
        "reports/terminal.txt",
    }
    manifest = RunManifest.from_bytes(files["manifest.json"])
    assert len(manifest.artifacts) == _NON_MANIFEST_ARTIFACT_COUNT
    sensitivities = {
        artifact.path: artifact.sensitivity for artifact in manifest.artifacts
    }
    assert (
        sum(value is Sensitivity.INTERNAL for value in sensitivities.values())
        == _INTERNAL_ARTIFACT_COUNT
    )
    assert (
        sum(value is Sensitivity.PUBLIC for value in sensitivities.values())
        == _PUBLIC_ARTIFACT_COUNT
    )
    assert files["reports/report.json"] == result.json_report
    assert files["reports/terminal.txt"] == result.terminal_report

    run = json.loads(files["run.json"])
    assert set(run) == {
        "action_ids",
        "aggregate_status",
        "assertion_ids",
        "bundle_kind",
        "evidence_schema_version",
        "probe_ids",
        "run_id",
        "scenario_id",
        "target_environment",
        "target_pseudonym_sha256",
        "target_region",
    }
    assert (
        run["target_pseudonym_sha256"]
        == hashlib.sha256(b"synthetic-retrieval-application").hexdigest()
    )
    all_bytes = b"\n".join(files[path] for path in sorted(files))
    forbidden = {
        *runtime.ledger.values,
        _BASELINE,
        _BOUNDARY,
        "CAI_REQUESTER_A_CANARY",
        "CAI_REQUESTER_B_CANARY",
        "111122223333",
        "retrieval.sandbox.example.test",
        "/aws/cai-verify/synthetic-retrieval",
        _ACCESS_KEY,
        _SECRET_KEY,
        _SESSION_TOKEN,
        "synthetic-aws-request-0",
        "synthetic-aws-request-1",
        "arn:aws:iam",
    }
    for value in forbidden:
        assert value.encode() not in all_bytes
    for path, content in files.items():
        if path.endswith(".json"):
            assert (
                json.dumps(
                    json.loads(content),
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
                == content
            )


def _bundle_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _invalid_suite(  # noqa: C901, PLR0912, PLR0915
    case: str,
) -> VerificationSuite:
    suite = _suite()
    scenario = suite.scenarios[0]
    first_action = cast("AwsSigV4Action", scenario.actions[0])
    second_action = cast("AwsSigV4Action", scenario.actions[1])
    first_probe = cast("CloudWatchLogsProbe", scenario.probes[0])
    second_probe = cast("CloudWatchLogsProbe", scenario.probes[1])
    first_assertion = cast("RetrievalBoundaryAssertion", scenario.assertions[0])
    second_assertion = cast("RetrievalBoundaryAssertion", scenario.assertions[1])

    if case == "zero_chains":
        changed = scenario.model_copy(
            update={"actions": (), "probes": (), "assertions": ()}
        )
    elif case == "one_chain":
        changed = scenario.model_copy(
            update={
                "actions": (first_action,),
                "probes": (first_probe,),
                "assertions": (first_assertion,),
            }
        )
    elif case == "partial_pair":
        changed = scenario.model_copy(update={"actions": (first_action,)})
    elif case == "three_chains":
        third_action = second_action.model_copy(
            update={"id": "retrieve-as-requester-c"}
        )
        third_probe = second_probe.model_copy(
            update={
                "id": "requester-c-retrieval",
                "action_ref": third_action.id,
            }
        )
        third_assertion = second_assertion.model_copy(
            update={
                "id": "requester-c-retrieval-boundary",
                "action_ref": third_action.id,
                "probe_ref": third_probe.id,
            }
        )
        changed = scenario.model_copy(
            update={
                "actions": (*scenario.actions, third_action),
                "probes": (*scenario.probes, third_probe),
                "assertions": (*scenario.assertions, third_assertion),
            }
        )
    elif case == "extra_action":
        changed = scenario.model_copy(
            update={
                "actions": (
                    *scenario.actions,
                    second_action.model_copy(update={"id": "unrelated-extra-action"}),
                )
            }
        )
    elif case == "non_execute_api":
        changed = scenario.model_copy(
            update={
                "actions": (
                    first_action.model_copy(update={"service": "bedrock-runtime"}),
                    second_action,
                )
            }
        )
    elif case == "mutating_action":
        changed = scenario.model_copy(
            update={
                "actions": (
                    first_action.model_copy(update={"mutating": True}),
                    second_action,
                )
            }
        )
    elif case == "region_mismatch":
        changed = scenario.model_copy(
            update={
                "actions": (
                    first_action.model_copy(update={"region": "us-east-1"}),
                    second_action,
                )
            }
        )
    elif case == "identical_effective_requesters":
        first_identity = cast("AssumedRoleIdentity", suite.identities[0])
        second_identity = cast("AssumedRoleIdentity", suite.identities[1])
        identities = (
            first_identity,
            second_identity.model_copy(update={"role_arn": first_identity.role_arn}),
            *suite.identities[2:],
        )
        return suite.model_copy(update={"identities": identities})
    elif case == "different_evidence_identities":
        evidence = cast("AssumedRoleIdentity", suite.identities[2])
        second_evidence = evidence.model_copy(
            update={
                "id": "evidence-reader-two",
                "role_arn": (
                    "arn:aws:iam::111122223333:"
                    "role/cai-verify-alpha-evidence-reader-two"
                ),
            }
        )
        changed = scenario.model_copy(
            update={
                "probes": (
                    first_probe,
                    second_probe.model_copy(
                        update={"identity_ref": second_evidence.id}
                    ),
                )
            }
        )
        return suite.model_copy(
            update={
                "identities": (*suite.identities, second_evidence),
                "scenarios": (changed,),
            }
        )
    elif case == "aliased_evidence_identity":
        evidence = cast("AssumedRoleIdentity", suite.identities[2])
        second_evidence = evidence.model_copy(update={"id": "evidence-reader-alias"})
        changed = scenario.model_copy(
            update={
                "probes": (
                    first_probe,
                    second_probe.model_copy(
                        update={"identity_ref": second_evidence.id}
                    ),
                )
            }
        )
        return suite.model_copy(
            update={
                "identities": (*suite.identities, second_evidence),
                "scenarios": (changed,),
            }
        )
    elif case == "evidence_identity_overlaps_requester":
        changed = scenario.model_copy(
            update={
                "probes": (
                    first_probe.model_copy(update={"identity_ref": "requester-a"}),
                    second_probe.model_copy(update={"identity_ref": "requester-a"}),
                )
            }
        )
    elif case == "different_log_groups":
        changed = scenario.model_copy(
            update={
                "probes": (
                    first_probe,
                    second_probe.model_copy(
                        update={"log_group": "/aws/cai-verify/other"}
                    ),
                )
            }
        )
    elif case == "extra_observation":
        changed = scenario.model_copy(
            update={
                "probes": (
                    first_probe.model_copy(
                        update={
                            "observations": (
                                ObservationKind.RETRIEVAL_CANARY,
                                ObservationKind.PROVIDER_INVOCATION,
                            )
                        }
                    ),
                    second_probe,
                )
            }
        )
    elif case == "non_reversed_canaries":
        first_retrieval = cast(
            "RetrievalCanaryDeclaration",
            first_probe.retrieval,
        )
        changed = scenario.model_copy(
            update={
                "probes": (
                    first_probe,
                    second_probe.model_copy(update={"retrieval": first_retrieval}),
                )
            }
        )
    elif case == "reused_action_and_probe":
        changed = scenario.model_copy(
            update={
                "assertions": (
                    first_assertion,
                    second_assertion.model_copy(
                        update={
                            "action_ref": first_action.id,
                            "probe_ref": first_probe.id,
                        }
                    ),
                )
            }
        )
    elif case == "unsafe_assertion_limitation":
        unsafe = first_assertion.limitations[0].model_copy(
            update={"description": "secret assertion limitation must never escape"}
        )
        changed = scenario.model_copy(
            update={
                "assertions": (
                    first_assertion.model_copy(update={"limitations": (unsafe,)}),
                    second_assertion,
                )
            }
        )
    elif case == "missing_scenario":
        return suite
    else:
        raise AssertionError(case)
    return suite.model_copy(update={"scenarios": (changed,)})
