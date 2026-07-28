"""Tests for bounded retrieval evidence readiness preflight."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import boto3  # type: ignore[import-untyped]
import pytest
import yaml
from botocore.stub import Stubber  # type: ignore[import-untyped]

from cai_verify.aws import (
    AwsScopedIdentity,
    AwsSession,
    AwsStsClient,
    RetrievalCorrelationState,
    RetrievalDoctorIssueCode,
    RetrievalDoctorResult,
)
from cai_verify.aws import (
    run_retrieval_doctor as _run_retrieval_doctor,
)
from cai_verify.aws.retrieval_doctor import (
    MAX_RETRIEVAL_RETURNED_TEXT_BYTES,
    _bounded_returned_text_bytes,
)
from cai_verify.config import (
    ActionInput,
    AssumedRoleIdentity,
    CloudWatchLogsProbe,
    EnvironmentReference,
    HttpAction,
    VerificationSuite,
)
from tests.aws.policy import authorizing_execution_policy

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cai_verify.aws import AwsSessionFactory
    from cai_verify.plugins import IdentityRequest

_FIXTURE = (
    Path(__file__).parents[1]
    / "fixtures"
    / "suites"
    / "valid"
    / "reciprocal-retrieval.yaml"
)
_NOW = datetime(2026, 7, 26, 12, tzinfo=UTC)
_ACCOUNT_ID = "111122223333"
_ENVIRONMENT = {
    "SYNTHETIC_REQUESTER_A_CANARY": "synthetic-requester-a-canary",
    "SYNTHETIC_REQUESTER_B_CANARY": "synthetic-requester-b-canary",
}
_EXPECTED_FILTER = {
    "endTime": 1785067200000,
    "filterPattern": (
        '{ $.schemaVersion = "__cai_verify_retrieval_doctor_nonmatch_v1__" }'
    ),
    "interleaved": True,
    "limit": 1,
    "logGroupName": "/aws/cai-verify/synthetic-retrieval",
    "startFromHead": True,
    "startTime": 1785067199000,
    "unmask": False,
}


def run_retrieval_doctor(
    suite: VerificationSuite,
    **kwargs: Any,  # noqa: ANN401 - preserve the production call surface in tests.
) -> RetrievalDoctorResult:
    """Exercise readiness through an independently supplied exact test policy."""
    return _run_retrieval_doctor(
        suite,
        execution_policy=authorizing_execution_policy(suite),
        **kwargs,
    )


@dataclass(slots=True)
class _LogsClient:
    response: object = field(
        default_factory=lambda: {
            "events": [],
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }
    )
    error: Exception | None = None
    calls: list[dict[str, object]] = field(default_factory=list)

    def filter_log_events(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return cast("Mapping[str, object]", self.response)


@dataclass(slots=True)
class _StsClient:
    account_id: str = _ACCOUNT_ID
    partition: str = "aws"
    expires_at: datetime = _NOW + timedelta(hours=1)
    role_parameters: list[dict[str, str]] = field(default_factory=list)

    def get_caller_identity(self) -> Mapping[str, object]:
        parameters = self.role_parameters[-1]
        role_name = parameters["RoleArn"].rsplit("/", maxsplit=1)[-1]
        session_name = parameters["RoleSessionName"]
        return {
            "Account": self.account_id,
            "Arn": (
                f"arn:{self.partition}:sts::{self.account_id}:"
                f"assumed-role/{role_name}/{session_name}"
            ),
            "UserId": "SYNTHETIC",
        }

    def assume_role(self, **kwargs: str) -> Mapping[str, object]:
        self.role_parameters.append(kwargs)
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


@dataclass(slots=True)
class _SessionFactory:
    base_sessions: list[_Session]
    lease_sessions: list[_Session]
    created_lease_sessions: list[_Session] = field(default_factory=list)
    current_profiles: list[str | None] = field(default_factory=list)

    def create_current_session(
        self,
        *,
        profile_name: str | None,
        region_name: str,
    ) -> AwsSession:
        assert region_name == "eu-west-2"
        self.current_profiles.append(profile_name)
        return cast("AwsSession", self.base_sessions.pop(0))

    def create_assumed_session(
        self,
        *,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        region_name: str,
    ) -> AwsSession:
        assert access_key_id == "synthetic-access-key"
        assert secret_access_key == "synthetic-secret-key"  # noqa: S105
        assert session_token == "synthetic-session-token"  # noqa: S105
        assert region_name == "eu-west-2"
        session = self.lease_sessions.pop(0)
        self.created_lease_sessions.append(session)
        return cast("AwsSession", session)

    def create_sts_client(
        self,
        session: AwsSession,
        *,
        region_name: str,
    ) -> AwsStsClient:
        assert region_name == "eu-west-2"
        return cast("AwsStsClient", session.client("sts"))


class _SdkError(RuntimeError):
    def __init__(self, code: str, secret: str = "sdk-secret") -> None:  # noqa: S107
        self.response = {"Error": {"Code": code, "Message": secret}}
        super().__init__(secret)


def test_ready_reciprocal_suite_deduplicates_identity_and_source_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reciprocal contract resolves three leases and one shared source."""
    suite = _suite()
    logs = _LogsClient()
    factory = _factory(logs=logs)
    closed: list[str] = []
    original_close = AwsScopedIdentity.close

    def close(lease: AwsScopedIdentity) -> None:
        closed.append(lease.identity_id)
        original_close(lease)

    monkeypatch.setattr(AwsScopedIdentity, "close", close)

    result = run_retrieval_doctor(
        suite,
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", factory),
        clock=lambda: _NOW,
        monotonic=lambda: 10.0,
    )

    assert result.ready
    assert [check.assertion_id for check in result.checks] == [
        "requester-a-retrieval-boundary",
        "requester-b-retrieval-boundary",
    ]
    assert all(
        check.correlation_state is RetrievalCorrelationState.RUNTIME_REQUIRED
        for check in result.checks
    )
    assert logs.calls == [_EXPECTED_FILTER]
    assert closed == ["evidence-reader", "requester-a", "requester-b"]
    assert factory.created_lease_sessions[0].services == ["sts", "logs"]
    assert factory.created_lease_sessions[1].services == ["sts"]
    assert factory.created_lease_sessions[2].services == ["sts"]
    assert (
        result.to_json_bytes()
        == json.dumps(
            result.to_dict(),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )
    assert result.to_terminal_bytes().startswith(
        b"Retrieval doctor: READY TO ATTEMPT\n"
    )


def test_reciprocal_contract_uses_stubbed_sts_and_one_filter_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validated reciprocal selection crosses bounded STS and Logs SDK models."""
    suite = _suite()
    identities = {identity.id: identity for identity in suite.identities}
    base_sessions: list[_Session] = []
    lease_sessions: list[_Session] = []
    stubbers: list[Stubber] = []
    logs_client = _botocore_client("logs")
    logs_stubber = Stubber(logs_client)
    logs_stubber.add_response("filter_log_events", {"events": []}, _EXPECTED_FILTER)
    stubbers.append(logs_stubber)
    for identity_id in ("evidence-reader", "requester-a", "requester-b"):
        identity = identities[identity_id]
        assert isinstance(identity, AssumedRoleIdentity)
        base_client = _botocore_client("sts")
        base_stubber = Stubber(base_client)
        base_stubber.add_response(
            "assume_role",
            {
                "AssumedRoleUser": {
                    "Arn": (
                        f"arn:aws:sts::{_ACCOUNT_ID}:"
                        f"assumed-role/synthetic/{identity.session_name}"
                    ),
                    "AssumedRoleId": f"SYNTHETIC:{identity.session_name}",
                },
                "Credentials": {
                    "AccessKeyId": "synthetic-access-key",
                    "Expiration": _NOW + timedelta(hours=1),
                    "SecretAccessKey": "synthetic-secret-key",
                    "SessionToken": "synthetic-session-token",
                },
            },
            {
                "RoleArn": identity.role_arn,
                "RoleSessionName": identity.session_name,
            },
        )
        assumed_client = _botocore_client("sts")
        assumed_stubber = Stubber(assumed_client)
        assumed_stubber.add_response(
            "get_caller_identity",
            {
                "Account": _ACCOUNT_ID,
                "Arn": (
                    f"arn:aws:sts::{_ACCOUNT_ID}:"
                    "assumed-role/"
                    f"{identity.role_arn.rsplit('/', maxsplit=1)[-1]}/"
                    f"{identity.session_name}"
                ),
                "UserId": f"SYNTHETIC:{identity.session_name}",
            },
            {},
        )
        base_sessions.append(
            _Session(
                sts=cast("_StsClient", base_client),
                logs=_LogsClient(),
            )
        )
        lease_sessions.append(
            _Session(
                sts=cast("_StsClient", assumed_client),
                logs=cast("_LogsClient", logs_client),
            )
        )
        stubbers.extend((base_stubber, assumed_stubber))
    factory = _SessionFactory(
        base_sessions=base_sessions,
        lease_sessions=lease_sessions,
    )
    closed: list[str] = []
    original_close = AwsScopedIdentity.close

    def close(lease: AwsScopedIdentity) -> None:
        closed.append(lease.identity_id)
        original_close(lease)

    monkeypatch.setattr(AwsScopedIdentity, "close", close)
    for stubber in stubbers:
        stubber.activate()
    try:
        result = run_retrieval_doctor(
            suite,
            environment=_ENVIRONMENT,
            session_factory=cast("AwsSessionFactory", factory),
            clock=lambda: _NOW,
            monotonic=lambda: 9.0,
        )
        for stubber in stubbers:
            stubber.assert_no_pending_responses()
    finally:
        for stubber in stubbers:
            stubber.deactivate()

    assert result.ready
    assert closed == ["evidence-reader", "requester-a", "requester-b"]
    assert (
        len(
            [
                service
                for session in factory.created_lease_sessions
                for service in session.services
                if service == "logs"
            ]
        )
        == 1
    )


def test_chain_order_is_scenario_assertion_action_probe_deterministic() -> None:
    """Declaration order cannot change public check ordering."""
    suite = _suite()
    scenario = suite.scenarios[0]
    object.__setattr__(scenario, "actions", tuple(reversed(scenario.actions)))
    object.__setattr__(scenario, "probes", tuple(reversed(scenario.probes)))
    object.__setattr__(scenario, "assertions", tuple(reversed(scenario.assertions)))

    result = run_retrieval_doctor(
        suite,
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", _factory(logs=_LogsClient())),
        clock=lambda: _NOW,
        monotonic=lambda: 8.0,
    )
    canonical = run_retrieval_doctor(
        _suite(),
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", _factory(logs=_LogsClient())),
        clock=lambda: _NOW,
        monotonic=lambda: 8.0,
    )

    assert [check.assertion_id for check in result.checks] == [
        "requester-a-retrieval-boundary",
        "requester-b-retrieval-boundary",
    ]
    assert result.to_json_bytes() == canonical.to_json_bytes()
    assert result.to_terminal_bytes() == canonical.to_terminal_bytes()


def test_scenario_identity_fallback_and_component_overrides_are_exact() -> None:
    """Action and probe overrides win; absent overrides use the scenario identity."""
    fallback = _single_chain_suite()
    scenario = fallback.scenarios[0]
    object.__setattr__(scenario.actions[0], "identity_ref", None)
    object.__setattr__(scenario.probes[0], "identity_ref", None)
    fallback_factory = _factory(logs=_LogsClient())

    fallback_result = run_retrieval_doctor(
        fallback,
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", fallback_factory),
        clock=lambda: _NOW,
        monotonic=lambda: 2.0,
    )
    override_factory = _factory(logs=_LogsClient())
    override_result = run_retrieval_doctor(
        _single_chain_suite(),
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", override_factory),
        clock=lambda: _NOW,
        monotonic=lambda: 2.0,
    )

    assert fallback_result.ready
    assert len(fallback_factory.current_profiles) == 1
    assert fallback_factory.created_lease_sessions[0].services == ["sts", "logs"]
    assert override_result.ready
    assert len(override_factory.current_profiles) == len(
        ("evidence-reader", "requester-a")
    )
    assert override_factory.created_lease_sessions[0].services == ["sts", "logs"]
    assert override_factory.created_lease_sessions[1].services == ["sts"]


def test_unused_identity_and_environment_reference_are_ignored() -> None:
    """An unused profile reference is neither resolved nor acquired."""
    suite = _single_chain_suite()
    unused = suite.identities[0].model_copy(
        update={
            "id": "unused-identity",
            "profile": EnvironmentReference.model_validate(
                {"source": "environment", "name": "UNUSED_PROFILE"}
            ),
            "type": "awsCurrent",
        }
    )
    object.__setattr__(suite, "identities", (*suite.identities, unused))
    factory = _factory(logs=_LogsClient())

    result = run_retrieval_doctor(
        suite,
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", factory),
        clock=lambda: _NOW,
        monotonic=lambda: 2.0,
    )

    assert result.ready
    assert len(factory.current_profiles) == len(("evidence-reader", "requester-a"))


def test_multiple_sources_are_queried_once_in_deterministic_order() -> None:
    """Unique exact evidence tuples are sorted and never paginated."""
    suite = _suite()
    object.__setattr__(
        suite.scenarios[0].probes[0],
        "log_group",
        "/aws/cai-verify/z-source",
    )
    object.__setattr__(
        suite.scenarios[0].probes[1],
        "log_group",
        "/aws/cai-verify/a-source",
    )
    logs = _LogsClient()

    result = run_retrieval_doctor(
        suite,
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", _factory(logs=logs)),
        clock=lambda: _NOW,
        monotonic=lambda: 2.0,
    )

    assert result.ready
    assert [call["logGroupName"] for call in logs.calls] == [
        "/aws/cai-verify/a-source",
        "/aws/cai-verify/z-source",
    ]
    assert all("nextToken" not in call for call in logs.calls)


def test_ready_report_states_only_runtime_requirements_and_redacts_values() -> None:
    """Readiness never becomes an execution, isolation, or compliance claim."""
    suite = _suite()
    external_id = EnvironmentReference.model_validate(
        {"source": "environment", "name": "SYNTHETIC_EXTERNAL_ID"}
    )
    for identity in suite.identities:
        object.__setattr__(identity, "external_id", external_id)
    logs = _LogsClient(
        response={
            "events": [
                {
                    "eventId": "synthetic-event",
                    "message": "raw-event-secret",
                    "timestamp": 1,
                }
            ],
            "nextToken": "pagination-secret",
            "ResponseMetadata": {
                "HTTPHeaders": {"x-amzn-requestid": "request-secret"},
                "HTTPStatusCode": 200,
                "RequestId": "response-request-secret",
                "RetryAttempts": 0,
            },
        }
    )
    result = run_retrieval_doctor(
        suite,
        environment={
            **_ENVIRONMENT,
            "SYNTHETIC_EXTERNAL_ID": "synthetic-external-id-secret",
            "UNRELATED": "unrelated-environment-secret",
        },
        session_factory=cast("AwsSessionFactory", _factory(logs=logs)),
        clock=lambda: _NOW,
        monotonic=lambda: 4.0,
    )

    reports = (
        result.to_json_bytes() + result.to_terminal_bytes() + repr(result).encode()
    )
    for forbidden in (
        *_ENVIRONMENT.values(),
        "SYNTHETIC_REQUESTER_A_CANARY",
        "SYNTHETIC_REQUESTER_B_CANARY",
        "SYNTHETIC_EXTERNAL_ID",
        "unrelated-environment-secret",
        "synthetic-external-id-secret",
        "requester-a-baseline",
        "synthetic-access-key",
        "synthetic-secret-key",
        "synthetic-session-token",
        "raw-event-secret",
        "pagination-secret",
        "request-secret",
        _ACCOUNT_ID,
        "arn:aws",
        "/aws/cai-verify/synthetic-retrieval",
    ):
        assert forbidden.encode() not in reports
    assert result.ready
    assert result.runtime_requirements == (
        "baseline_document_retrievability",
        "boundary_document_exclusion",
        "complete_fresh_evidence",
        "exact_action_correlation_echo",
        "exactly_correlated_pre_generation_telemetry",
    )


def test_model_bypass_relationship_is_rejected_without_sdk_access() -> None:
    """Malformed scenario-local references fail closed after model bypass."""
    suite = _single_chain_suite()
    object.__setattr__(
        suite.scenarios[0].assertions[0],
        "probe_ref",
        "missing-probe",
    )
    factory = _factory(logs=_LogsClient())

    result = run_retrieval_doctor(
        suite,
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", factory),
        clock=lambda: _NOW,
        monotonic=lambda: 2.0,
    )

    assert not result.ready
    assert RetrievalDoctorIssueCode.INVALID_CONFIGURATION in result.checks[0].issues
    assert result.checks[0].probe_id == "missing-probe"
    assert not result.checks[0].configuration_compatible


def test_selected_action_environment_reference_is_required() -> None:
    """Only an environment-backed input on the selected action is resolved."""
    suite = _single_chain_suite()
    action = suite.scenarios[0].actions[0]
    environment_input = ActionInput.model_validate(
        {
            "location": "json",
            "name": "syntheticPrivateInput",
            "value": {
                "source": "environment",
                "name": "SELECTED_ACTION_VALUE",
            },
        }
    )
    object.__setattr__(action, "inputs", (*action.inputs, environment_input))
    logs = _LogsClient()

    result = run_retrieval_doctor(
        suite,
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", _factory(logs=logs)),
        clock=lambda: _NOW,
        monotonic=lambda: 2.0,
    )

    assert RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_MISSING in (
        result.checks[0].issues
    )
    assert not result.checks[0].configuration_compatible
    assert logs.calls == []


def test_no_retrieval_boundary_assertion_performs_no_sdk_work() -> None:
    """Unrelated assertion, action, and probe declarations are ignored."""
    suite = _suite()
    object.__setattr__(suite.scenarios[0], "assertions", ())
    factory = _factory(logs=_LogsClient())

    result = run_retrieval_doctor(
        suite,
        environment={},
        session_factory=cast("AwsSessionFactory", factory),
        clock=lambda: _NOW,
    )

    assert not result.ready
    assert result.checks == ()
    assert result.issues == (RetrievalDoctorIssueCode.RETRIEVAL_CHECKS_MISSING,)
    assert factory.current_profiles == []


@pytest.mark.parametrize(
    ("value", "expected_issue"),
    [
        (None, RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_MISSING),
        ("", RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_INVALID),
        (123, RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_INVALID),
        ("\ud800", RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_INVALID),
        ("a" * 1025, RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_INVALID),
    ],
)
def test_retrieval_canary_contract_rejects_invalid_values(
    value: object,
    expected_issue: RetrievalDoctorIssueCode,
) -> None:
    """Selected canaries use the exact string, UTF-8, and 1 KiB contract."""
    environment: dict[str, object] = dict(_ENVIRONMENT)
    if value is None:
        environment.pop("SYNTHETIC_REQUESTER_A_CANARY")
    else:
        environment["SYNTHETIC_REQUESTER_A_CANARY"] = value
    logs = _LogsClient()

    result = run_retrieval_doctor(
        _single_chain_suite(),
        environment=cast("Mapping[str, str]", environment),
        session_factory=cast("AwsSessionFactory", _factory(logs=logs)),
        clock=lambda: _NOW,
        monotonic=lambda: 1.0,
    )

    assert not result.ready
    assert expected_issue in result.checks[0].issues
    assert not result.checks[0].canary_contract_ready
    assert logs.calls == []


def test_equal_canaries_are_rejected_but_maximum_size_values_are_ready() -> None:
    """Constant-time distinctness and the inclusive 1 KiB edge are preserved."""
    suite = _single_chain_suite()
    equal = run_retrieval_doctor(
        suite,
        environment={
            "SYNTHETIC_REQUESTER_A_CANARY": "same",
            "SYNTHETIC_REQUESTER_B_CANARY": "same",
        },
        session_factory=cast("AwsSessionFactory", _factory(logs=_LogsClient())),
        clock=lambda: _NOW,
        monotonic=lambda: 2.0,
    )
    logs = _LogsClient()
    maximum = run_retrieval_doctor(
        suite,
        environment={
            "SYNTHETIC_REQUESTER_A_CANARY": "a" * 1024,
            "SYNTHETIC_REQUESTER_B_CANARY": "b" * 1024,
        },
        session_factory=cast("AwsSessionFactory", _factory(logs=logs)),
        clock=lambda: _NOW,
        monotonic=lambda: 2.0,
    )

    assert equal.checks[0].issues == (
        RetrievalDoctorIssueCode.CANARY_VALUES_NOT_DISTINCT,
    )
    assert not equal.ready
    assert maximum.ready
    assert logs.calls == [_EXPECTED_FILTER]


@pytest.mark.parametrize(
    "missing_name",
    ["SYNTHETIC_TELEMETRY_CANARY", "SYNTHETIC_BEDROCK_MODEL_ID"],
)
def test_combined_probe_requires_its_own_environment_references(
    missing_name: str,
) -> None:
    """A selected combined probe validates every declaration it would execute."""
    mapping = _mapping()
    scenario = mapping["scenarios"][0]
    probe = scenario["probes"][0]
    probe["observations"] = [
        "bedrockInvocation",
        "retrievalCanary",
        "telemetryCanary",
    ]
    probe["canary"] = {
        "source": "environment",
        "name": "SYNTHETIC_TELEMETRY_CANARY",
    }
    probe["bedrock"] = {
        "modelId": {
            "source": "environment",
            "name": "SYNTHETIC_BEDROCK_MODEL_ID",
        },
        "modelAlias": {
            "source": "literal",
            "value": "synthetic-model",
            "sensitive": False,
        },
    }
    suite = VerificationSuite.model_validate(mapping)
    validated_scenario = suite.scenarios[0]
    object.__setattr__(
        validated_scenario,
        "actions",
        (validated_scenario.actions[0],),
    )
    object.__setattr__(
        validated_scenario,
        "probes",
        (validated_scenario.probes[0],),
    )
    object.__setattr__(
        validated_scenario,
        "assertions",
        (validated_scenario.assertions[0],),
    )
    environment = {
        **_ENVIRONMENT,
        "SYNTHETIC_TELEMETRY_CANARY": "synthetic-telemetry-canary",
        "SYNTHETIC_BEDROCK_MODEL_ID": "synthetic.model-v1",
    }
    environment.pop(missing_name)
    logs = _LogsClient()

    result = run_retrieval_doctor(
        suite,
        environment=environment,
        session_factory=cast("AwsSessionFactory", _factory(logs=logs)),
        clock=lambda: _NOW,
        monotonic=lambda: 2.0,
    )

    assert not result.ready
    assert RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_MISSING in (
        result.checks[0].issues
    )
    assert logs.calls == []


@pytest.mark.parametrize(
    ("change", "extra_issue"),
    [
        ({"type": "http"}, RetrievalDoctorIssueCode.UNSUPPORTED_ACTION),
        (
            {"service": "bedrock-runtime"},
            RetrievalDoctorIssueCode.UNSUPPORTED_ACTION,
        ),
        ({"region": "us-east-1"}, RetrievalDoctorIssueCode.INVALID_CONFIGURATION),
        ({"mutating": True}, RetrievalDoctorIssueCode.INVALID_CONFIGURATION),
    ],
)
def test_incompatible_actions_never_establish_correlation(
    change: dict[str, object],
    extra_issue: RetrievalDoctorIssueCode,
) -> None:
    """Unsigned, direct Bedrock, conflicting-region, and mutating actions fail."""
    suite = _single_chain_suite()
    action = suite.scenarios[0].actions[0]
    object.__setattr__(action, "type", change.get("type", action.type))
    for name, value in change.items():
        if name != "type":
            object.__setattr__(action, name, value)
    logs = _LogsClient()

    result = run_retrieval_doctor(
        suite,
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", _factory(logs=logs)),
        clock=lambda: _NOW,
        monotonic=lambda: 3.0,
    )

    check = result.checks[0]
    assert check.correlation_state is RetrievalCorrelationState.INCOMPATIBLE
    assert RetrievalDoctorIssueCode.CORRELATION_INCOMPATIBLE in check.issues
    assert extra_issue in check.issues
    assert logs.calls == []


def test_reserved_correlation_header_is_case_insensitively_incompatible() -> None:
    """Caller-defined application correlation cannot reach runtime preflight."""
    suite = _single_chain_suite()
    action = suite.scenarios[0].actions[0]
    reserved = ActionInput.model_validate(
        {
            "location": "header",
            "name": "x-CAI-cOrReLaTiOn-ID",
            "value": {
                "sensitive": False,
                "source": "literal",
                "value": "synthetic",
            },
        }
    )
    object.__setattr__(action, "inputs", (*action.inputs, reserved))
    logs = _LogsClient()

    result = run_retrieval_doctor(
        suite,
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", _factory(logs=logs)),
        clock=lambda: _NOW,
        monotonic=lambda: 3.0,
    )

    assert result.checks[0].correlation_state is (
        RetrievalCorrelationState.INCOMPATIBLE
    )
    assert RetrievalDoctorIssueCode.CORRELATION_INCOMPATIBLE in (
        result.checks[0].issues
    )
    assert logs.calls == []


def test_real_unsigned_remote_http_action_is_unsupported() -> None:
    """A concrete HTTP action cannot satisfy the SigV4 correlation contract."""
    suite = _single_chain_suite()
    action = suite.scenarios[0].actions[0]
    action_value = action.model_dump(mode="json", by_alias=True)
    action_value["type"] = "http"
    action_value.pop("region")
    action_value.pop("service")
    unsigned = HttpAction.model_validate(action_value)
    object.__setattr__(suite.scenarios[0], "actions", (unsigned,))

    result = run_retrieval_doctor(
        suite,
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", _factory(logs=_LogsClient())),
        clock=lambda: _NOW,
        monotonic=lambda: 3.0,
    )

    assert result.checks[0].correlation_state is RetrievalCorrelationState.INCOMPATIBLE
    assert RetrievalDoctorIssueCode.UNSUPPORTED_ACTION in result.checks[0].issues


@pytest.mark.parametrize(
    ("error", "issue"),
    [
        (
            _SdkError("AccessDeniedException"),
            RetrievalDoctorIssueCode.ACCESS_DENIED,
        ),
        (
            _SdkError("ResourceNotFoundException"),
            RetrievalDoctorIssueCode.SOURCE_NOT_FOUND,
        ),
        (TimeoutError("timeout-secret"), RetrievalDoctorIssueCode.SDK_TIMEOUT),
        (_SdkError("ThrottlingException"), RetrievalDoctorIssueCode.THROTTLED),
        (_SdkError("InternalFailure"), RetrievalDoctorIssueCode.SDK_ERROR),
    ],
)
def test_source_sdk_failures_use_stable_redacted_codes(
    error: Exception,
    issue: RetrievalDoctorIssueCode,
) -> None:
    """CloudWatch errors never expose exception text or request diagnostics."""
    logs = _LogsClient(error=error)
    result = run_retrieval_doctor(
        _single_chain_suite(),
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", _factory(logs=logs)),
        clock=lambda: _NOW,
        monotonic=lambda: 5.0,
    )

    assert not result.ready
    assert result.checks[0].issues == (issue,)
    assert (
        "secret" not in (result.to_json_bytes() + result.to_terminal_bytes()).decode()
    )


def test_sdk_unavailable_during_logs_client_creation_is_stable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing optional SDK support cannot expose import diagnostics."""
    logs = _LogsClient()

    def sdk_unavailable(**_kwargs: object) -> object:
        raise ModuleNotFoundError

    monkeypatch.setattr(
        "cai_verify.aws.identity._bounded_client_config",
        sdk_unavailable,
    )
    result = run_retrieval_doctor(
        _single_chain_suite(),
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", _factory(logs=logs)),
        clock=lambda: _NOW,
        monotonic=lambda: 5.0,
    )

    assert result.checks[0].issues == (RetrievalDoctorIssueCode.SDK_UNAVAILABLE,)
    assert logs.calls == []


def test_identity_acquisition_failure_and_closed_lease_are_not_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provider failures and already-closed leases never reach CloudWatch."""
    failed = run_retrieval_doctor(
        _single_chain_suite(),
        environment=_ENVIRONMENT,
        session_factory=cast(
            "AwsSessionFactory",
            _SessionFactory(base_sessions=[], lease_sessions=[]),
        ),
        clock=lambda: _NOW,
        monotonic=lambda: 5.0,
    )

    def closed_lease(
        _provider: object,
        request: IdentityRequest,
    ) -> AwsScopedIdentity:
        identity = request.identity
        return AwsScopedIdentity(
            _identity_id=identity.id,
            _account_id=None,
            _partition=None,
            _expires_at=None,
            _session=None,
            closed=True,
        )

    monkeypatch.setattr(
        "cai_verify.aws.retrieval_doctor.AssumedRoleAwsIdentityProvider."
        "provide_identity",
        closed_lease,
    )
    closed = run_retrieval_doctor(
        _single_chain_suite(),
        environment=_ENVIRONMENT,
        session_factory=cast(
            "AwsSessionFactory",
            _SessionFactory(base_sessions=[], lease_sessions=[]),
        ),
        clock=lambda: _NOW,
        monotonic=lambda: 5.0,
    )

    assert RetrievalDoctorIssueCode.IDENTITY_ACQUISITION_FAILED in (
        failed.checks[0].issues
    )
    assert RetrievalDoctorIssueCode.IDENTITY_ACQUISITION_FAILED in (
        closed.checks[0].issues
    )


@pytest.mark.parametrize(
    ("response", "issue"),
    [
        ([], RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE),
        (
            {"events": [], "unexpected": "value"},
            RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE,
        ),
        (
            {"events": [], "ResponseMetadata": {"HTTPStatusCode": True}},
            RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE,
        ),
        (
            {"events": [{}, {}]},
            RetrievalDoctorIssueCode.RESPONSE_OVERSIZED,
        ),
        (
            {"events": [{"message": "x" * 4097}]},
            RetrievalDoctorIssueCode.RESPONSE_OVERSIZED,
        ),
        (
            {"events": [], "nextToken": "x" * 8193},
            RetrievalDoctorIssueCode.RESPONSE_OVERSIZED,
        ),
    ],
)
def test_malformed_and_oversized_outer_responses_fail_closed(
    response: object,
    issue: RetrievalDoctorIssueCode,
) -> None:
    """Only the bounded installed FilterLogEvents outer shape is accepted."""
    logs = _LogsClient(response=response)
    result = run_retrieval_doctor(
        _single_chain_suite(),
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", _factory(logs=logs)),
        clock=lambda: _NOW,
        monotonic=lambda: 5.0,
    )

    assert result.checks[0].issues == (issue,)
    assert len(logs.calls) == 1


def test_expired_account_and_partition_boundaries_close_every_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unusable identity cannot create a Logs client and all leases close."""
    suite = _single_chain_suite()
    factory = _factory(
        logs=_LogsClient(),
        evidence_sts=_StsClient(expires_at=_NOW),
    )
    closed: list[str] = []
    original_close = AwsScopedIdentity.close

    def close(lease: AwsScopedIdentity) -> None:
        closed.append(lease.identity_id)
        original_close(lease)

    monkeypatch.setattr(AwsScopedIdentity, "close", close)
    result = run_retrieval_doctor(
        suite,
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", factory),
        clock=lambda: _NOW,
        monotonic=lambda: 6.0,
    )

    assert RetrievalDoctorIssueCode.IDENTITY_EXPIRED in result.checks[0].issues
    assert closed == ["evidence-reader", "requester-a"]
    assert factory.created_lease_sessions[0].services == ["sts"]


@pytest.mark.parametrize(
    ("evidence_sts", "issue"),
    [
        (
            _StsClient(account_id="999900001111"),
            RetrievalDoctorIssueCode.ACCOUNT_MISMATCH,
        ),
        (
            _StsClient(partition="aws-cn"),
            RetrievalDoctorIssueCode.PARTITION_MISMATCH,
        ),
    ],
)
def test_evidence_identity_must_match_target_boundary(
    evidence_sts: _StsClient,
    issue: RetrievalDoctorIssueCode,
) -> None:
    """Account and partition mismatches fail before a Logs client is created."""
    logs = _LogsClient()
    factory = _factory(logs=logs, evidence_sts=evidence_sts)

    result = run_retrieval_doctor(
        _single_chain_suite(),
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", factory),
        clock=lambda: _NOW,
        monotonic=lambda: 6.0,
    )

    assert issue in result.checks[0].issues
    assert logs.calls == []
    assert factory.created_lease_sessions[0].services == ["sts"]


def test_duration_exhaustion_stops_additional_sdk_work() -> None:
    """The injected monotonic limit preserves completed checks and stops calls."""
    values = iter((0.0, 0.0, 0.0, 31.0))
    factory = _factory(logs=_LogsClient())

    result = run_retrieval_doctor(
        _single_chain_suite(),
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", factory),
        clock=lambda: _NOW,
        monotonic=lambda: next(values, 31.0),
    )

    assert not result.ready
    assert result.issues == (RetrievalDoctorIssueCode.DURATION_EXCEEDED,)
    assert RetrievalDoctorIssueCode.NOT_CHECKED_DUE_TO_LIMIT in (
        result.checks[0].issues
    )
    assert len(factory.current_profiles) == 1


@pytest.mark.parametrize(
    ("limit_kind", "expected_checks"),
    [
        ("assertions", 32),
        ("identities", 17),
        ("sources", 17),
    ],
)
def test_configured_selection_identity_and_source_limits_stop_all_sdk_work(
    limit_kind: str,
    expected_checks: int,
) -> None:
    """Every one-beyond-limit declaration is rejected before AWS access."""
    if limit_kind == "assertions":
        suite = _expanded_suite(33)
    elif limit_kind == "identities":
        suite = _expanded_suite(17, unique_identities=True)
    else:
        suite = _expanded_suite(17, unique_sources=True)
    factory = _factory(logs=_LogsClient())

    result = run_retrieval_doctor(
        suite,
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", factory),
        clock=lambda: _NOW,
        monotonic=lambda: 1.0,
    )

    assert not result.ready
    assert len(result.checks) == expected_checks
    assert result.issues == (RetrievalDoctorIssueCode.LIMIT_EXCEEDED,)
    assert all(
        RetrievalDoctorIssueCode.NOT_CHECKED_DUE_TO_LIMIT in check.issues
        for check in result.checks
    )
    assert factory.current_profiles == []


@pytest.mark.parametrize(
    ("limit_kind", "session_count", "expected_source_calls"),
    [
        ("assertions", 3, 1),
        ("identities", 16, 1),
        ("sources", 3, 16),
    ],
)
def test_exact_selection_identity_and_source_limits_are_accepted(
    limit_kind: str,
    session_count: int,
    expected_source_calls: int,
) -> None:
    """Every documented assertion, identity, and source maximum is inclusive."""
    if limit_kind == "assertions":
        suite = _expanded_suite(32)
    elif limit_kind == "identities":
        suite = _expanded_suite(15, unique_identities=True)
    else:
        suite = _expanded_suite(16, unique_sources=True)
    logs = _LogsClient()

    result = run_retrieval_doctor(
        suite,
        environment=_ENVIRONMENT,
        session_factory=cast(
            "AwsSessionFactory",
            _factory(logs=logs, session_count=session_count),
        ),
        clock=lambda: _NOW,
        monotonic=lambda: 1.0,
    )

    assert result.ready
    assert len(logs.calls) == expected_source_calls


def test_exact_returned_text_message_event_and_token_limits_are_accepted() -> None:
    """The outer response accepts each inclusive bound and never paginates."""
    response: dict[str, Any] = {
        "events": [
            {
                "eventId": "synthetic-event",
                "message": "m" * 4096,
                "timestamp": 1,
            }
        ],
        "nextToken": "t" * 8192,
        "ResponseMetadata": {
            "HTTPHeaders": {"x-synthetic": "v"},
            "HTTPStatusCode": 200,
            "RetryAttempts": 0,
        },
    }
    current_size = _bounded_returned_text_bytes(response)
    assert isinstance(current_size, int)
    padding = MAX_RETRIEVAL_RETURNED_TEXT_BYTES - current_size
    response["ResponseMetadata"]["HTTPHeaders"]["x-padding"] = "p" * (
        padding - len("x-padding")
    )
    assert _bounded_returned_text_bytes(response) == (MAX_RETRIEVAL_RETURNED_TEXT_BYTES)
    logs = _LogsClient(response=response)

    result = run_retrieval_doctor(
        _single_chain_suite(),
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", _factory(logs=logs)),
        clock=lambda: _NOW,
        monotonic=lambda: 1.0,
    )

    assert result.ready
    assert len(logs.calls) == 1

    response["ResponseMetadata"]["HTTPHeaders"]["x-padding"] += "p"
    oversized = run_retrieval_doctor(
        _single_chain_suite(),
        environment=_ENVIRONMENT,
        session_factory=cast(
            "AwsSessionFactory",
            _factory(logs=_LogsClient(response=response)),
        ),
        clock=lambda: _NOW,
        monotonic=lambda: 1.0,
    )
    assert oversized.checks[0].issues == (RetrievalDoctorIssueCode.RESPONSE_OVERSIZED,)


def test_finding_limit_is_inclusive_and_one_beyond_stops_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The normalized finding budget accepts its edge and rejects the next."""
    suite = _single_chain_suite()
    object.__setattr__(
        suite.scenarios[0].assertions[0],
        "probe_ref",
        "missing-probe",
    )
    monkeypatch.setattr(
        "cai_verify.aws.retrieval_doctor.MAX_RETRIEVAL_FINDINGS",
        1,
    )
    exact_factory = _factory(logs=_LogsClient())
    exact = run_retrieval_doctor(
        suite,
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", exact_factory),
        clock=lambda: _NOW,
        monotonic=lambda: 1.0,
    )
    action = suite.scenarios[0].actions[0]
    object.__setattr__(action, "region", "us-east-1")
    exceeded_factory = _factory(logs=_LogsClient())
    exceeded = run_retrieval_doctor(
        suite,
        environment=_ENVIRONMENT,
        session_factory=cast("AwsSessionFactory", exceeded_factory),
        clock=lambda: _NOW,
        monotonic=lambda: 1.0,
    )

    assert exact.issues == ()
    assert exact.checks[0].issues == (RetrievalDoctorIssueCode.INVALID_CONFIGURATION,)
    assert exceeded.issues == (RetrievalDoctorIssueCode.LIMIT_EXCEEDED,)
    assert exceeded_factory.current_profiles == []


def _suite() -> VerificationSuite:
    return VerificationSuite.model_validate(_mapping())


def _single_chain_suite() -> VerificationSuite:
    suite = _suite()
    scenario = suite.scenarios[0]
    object.__setattr__(scenario, "actions", (scenario.actions[0],))
    object.__setattr__(scenario, "probes", (scenario.probes[0],))
    object.__setattr__(scenario, "assertions", (scenario.assertions[0],))
    return suite


def _mapping() -> dict[str, Any]:
    return cast("dict[str, Any]", yaml.safe_load(_FIXTURE.read_text(encoding="utf-8")))


def _expanded_suite(
    count: int,
    *,
    unique_identities: bool = False,
    unique_sources: bool = False,
) -> VerificationSuite:
    suite = _single_chain_suite()
    scenario = suite.scenarios[0]
    action_template = scenario.actions[0]
    probe_template = scenario.probes[0]
    assertion_template = scenario.assertions[0]
    assert isinstance(probe_template, CloudWatchLogsProbe)
    actions = []
    probes = []
    assertions = []
    identities = list(suite.identities)
    for index in range(count):
        action_id = f"retrieval-action-{index:02d}"
        probe_id = f"retrieval-probe-{index:02d}"
        identity_id = f"requester-{index:02d}"
        if unique_identities:
            identities.append(
                suite.identities[0].model_copy(update={"id": identity_id})
            )
        actions.append(
            action_template.model_copy(
                update={
                    "id": action_id,
                    "identity_ref": (
                        identity_id if unique_identities else "requester-a"
                    ),
                }
            )
        )
        probes.append(
            probe_template.model_copy(
                update={
                    "action_ref": action_id,
                    "id": probe_id,
                    "log_group": (
                        f"/aws/cai-verify/source-{index:02d}"
                        if unique_sources
                        else probe_template.log_group
                    ),
                }
            )
        )
        assertions.append(
            assertion_template.model_copy(
                update={
                    "action_ref": action_id,
                    "id": f"retrieval-assertion-{index:02d}",
                    "probe_ref": probe_id,
                }
            )
        )
    object.__setattr__(scenario, "actions", tuple(actions))
    object.__setattr__(scenario, "probes", tuple(probes))
    object.__setattr__(scenario, "assertions", tuple(assertions))
    object.__setattr__(suite, "identities", tuple(identities))
    return suite


def _factory(
    *,
    logs: _LogsClient,
    evidence_sts: _StsClient | None = None,
    session_count: int = 3,
) -> _SessionFactory:
    sts_values = [
        evidence_sts or _StsClient(),
        *(_StsClient() for _ in range(session_count - 1)),
    ]
    base_sessions = [_Session(sts=sts, logs=_LogsClient()) for sts in sts_values]
    lease_sessions = [_Session(sts=sts, logs=logs) for sts in sts_values]
    return _SessionFactory(
        base_sessions=base_sessions,
        lease_sessions=lease_sessions,
    )


def _botocore_client(service_name: str) -> object:
    return cast(
        "object",
        boto3.client(
            service_name,
            region_name="eu-west-2",
            aws_access_key_id="synthetic-source-key",
            aws_secret_access_key="synthetic-source-secret",  # noqa: S106
            aws_session_token="synthetic-source-token",  # noqa: S106
        ),
    )
