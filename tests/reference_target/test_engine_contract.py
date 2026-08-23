"""End-to-end network-isolated contract for the disposable AWS target."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

import pytest
from examples.aws.reference_target import handler
from examples.aws.reference_target.config import (
    REFERENCE_SCENARIO_ID,
    REQUESTER_A_SESSION_NAME,
    REQUESTER_B_SESSION_NAME,
    generate_configuration,
    load_deployment_description,
)

from cai_verify.assertions import RetrievalBoundaryEvaluator
from cai_verify.aws import (
    AwsScopedIdentity,
    AwsSession,
    CloudWatchLogsProbeAdapter,
    validated_aws_reciprocal_retrieval_slice,
)
from cai_verify.config import (
    AssumedRoleIdentity,
    AwsSigV4Action,
    CloudWatchLogsProbe,
    LiteralInput,
    RetrievalBoundaryAssertion,
    load_suite_bytes,
)
from cai_verify.core import AssertionStatus, RedactedValue, aggregate_results
from cai_verify.plugins import (
    ActionExecutionResult,
    ActionOutcome,
    AssertionEvaluationRequest,
    ExecutionContext,
    ProbeRequest,
)
from tests.reference_target.helpers import (
    ACCOUNT_ID,
    REGION,
    STACK_NAME,
    description_bytes,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cai_verify.plugins import ProbeResult

_CANARY_A = "synthetic_canary_requester_a_001"
_CANARY_B = "synthetic_canary_requester_b_002"
_EVENT_MILLISECONDS = 1_786_532_400_123
_EVENT_TIME = datetime.fromtimestamp(_EVENT_MILLISECONDS / 1000, tz=UTC)
_COLLECTED_AT = _EVENT_TIME + timedelta(seconds=10)
_LOG_STREAM = "retrieval-events"
_HTTP_OK = 200
_EXPECTED_VISIBILITY_CALLS = 2


@dataclass(slots=True)
class _DynamoDb:
    def get_item(self, **kwargs: object) -> Mapping[str, object]:
        """Return the exact two synthetic documents seeded by the fixture."""
        key = cast("dict[str, dict[str, str]]", kwargs["Key"])
        document_id = key["documentId"]["S"]
        suffix = "a" if document_id == "requester-a" else "b"
        return {
            "Item": {
                "content": {"S": _CANARY_A if suffix == "a" else _CANARY_B},
                "documentId": {"S": document_id},
                "syntheticQuery": {"S": f"requester-{suffix}-synthetic-topic"},
            },
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }


@dataclass(slots=True)
class _PutLogs:
    calls: list[dict[str, object]] = field(default_factory=list)

    def put_log_events(self, **kwargs: object) -> Mapping[str, object]:
        """Capture the handler's real PutLogEvents request without a socket."""
        self.calls.append(dict(kwargs))
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


@dataclass(slots=True)
class _FilterLogs:
    responses: list[Mapping[str, object]]
    calls: list[dict[str, object]] = field(default_factory=list)

    def filter_log_events(self, **kwargs: object) -> Mapping[str, object]:
        """Return queued SDK pages derived from a captured handler write."""
        self.calls.append(dict(kwargs))
        return self.responses.pop(0)


@dataclass(slots=True)
class _LogsSession:
    client_value: _FilterLogs
    regions: list[str] = field(default_factory=list)

    def client(self, service_name: str, **kwargs: object) -> object:
        """Expose only the injected regional CloudWatch Logs client."""
        assert service_name == "logs"
        assert set(kwargs) == {"config", "region_name"}
        self.regions.append(cast("str", kwargs["region_name"]))
        return self.client_value


@pytest.mark.parametrize(
    ("mode", "expected_status"),
    [
        ("isolated", AssertionStatus.PASS),
        ("vulnerable", AssertionStatus.FAIL),
    ],
)
def test_handler_telemetry_drives_reciprocal_engine_result(  # noqa: PLR0915
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected_status: AssertionStatus,
) -> None:
    """Real fixture messages produce PASS/PASS or FAIL/FAIL in the engine."""
    descriptor = load_deployment_description(
        description_bytes(mode=mode),
        expected_account_id=ACCOUNT_ID,
        expected_region=REGION,
        expected_stack_name=STACK_NAME,
    )
    suite = validated_aws_reciprocal_retrieval_slice(
        load_suite_bytes(generate_configuration(descriptor).suite),
        REFERENCE_SCENARIO_ID,
    )
    scenario = suite.scenarios[0]
    assert scenario.id == REFERENCE_SCENARIO_ID
    assert suite.evidence_policy.max_age == "PT5M"
    assert suite.evidence_policy.clock_skew_tolerance == "PT30S"

    captured_logs = _PutLogs()
    monkeypatch.setenv("DOCUMENTS_TABLE_NAME", descriptor.documents_table_name)
    monkeypatch.setenv("EXPECTED_ACCOUNT_ID", descriptor.account_id)
    monkeypatch.setenv("LOG_GROUP_NAME", descriptor.log_group_name)
    monkeypatch.setenv("LOG_STREAM_NAME", _LOG_STREAM)
    monkeypatch.setenv("REFERENCE_MODE", mode)
    monkeypatch.setenv("REQUESTER_A_ROLE_ARN", descriptor.requester_a_role_arn)
    monkeypatch.setenv("REQUESTER_A_SESSION_NAME", REQUESTER_A_SESSION_NAME)
    monkeypatch.setenv("REQUESTER_B_ROLE_ARN", descriptor.requester_b_role_arn)
    monkeypatch.setenv("REQUESTER_B_SESSION_NAME", REQUESTER_B_SESSION_NAME)
    monkeypatch.setattr(handler, "_clock_milliseconds", lambda: _EVENT_MILLISECONDS)
    monkeypatch.setattr(handler, "_DYNAMODB", _DynamoDb())
    monkeypatch.setattr(handler, "_LOGS", captured_logs)

    identities = {identity.id: identity for identity in suite.identities}
    actions = tuple(sorted(scenario.actions, key=lambda item: item.id))
    probes = {probe.action_ref: probe for probe in scenario.probes}
    context = ExecutionContext(
        run_id=f"reference-contract-{mode}",
        scenario_id=scenario.id,
        target=suite.target,
    )
    adapter = CloudWatchLogsProbeAdapter(
        environment={
            "CAI_REQUESTER_A_CANARY": _CANARY_A,
            "CAI_REQUESTER_B_CANARY": _CANARY_B,
        },
        suite_max_age=timedelta(minutes=5),
        clock_skew_tolerance=timedelta(seconds=30),
        clock=lambda: _COLLECTED_AT,
        monotonic=lambda: 0.0,
        sleep=lambda _delay: None,
    )
    action_results: list[ActionExecutionResult] = []
    probe_results: list[ProbeResult] = []

    for position, declared_action in enumerate(actions):
        assert isinstance(declared_action, AwsSigV4Action)
        requester = identities[cast("str", declared_action.identity_ref)]
        assert isinstance(requester, AssumedRoleIdentity)
        correlation = f"synthetic-contract-{declared_action.id}"

        response = handler.lambda_handler(
            _handler_event(declared_action, requester, correlation=correlation),
            object(),
        )

        assert response["statusCode"] == _HTTP_OK
        response_headers = cast("dict[str, str]", response["headers"])
        assert response_headers["X-Cai-Correlation-Id"] == correlation
        captured = captured_logs.calls[position]
        assert captured["logGroupName"] == descriptor.log_group_name
        assert captured["logStreamName"] == _LOG_STREAM

        action_result = ActionExecutionResult(
            action_id=declared_action.id,
            outcome=ActionOutcome.SUCCEEDED,
            started_at=_EVENT_TIME - timedelta(seconds=1),
            completed_at=_EVENT_TIME,
            observed=RedactedValue(
                {
                    "correlation_state": "MATCHED",
                    "service": "execute-api",
                    "signing_region": REGION,
                }
            ),
            correlation_ids=(correlation,),
            limitations=("Synthetic fixture action result.",),
        )
        action_results.append(action_result)

        declared_probe = probes[declared_action.id]
        assert isinstance(declared_probe, CloudWatchLogsProbe)
        filter_client = _FilterLogs(
            [
                _empty_filter_response(captured),
                _filter_response(
                    captured,
                    event_id=f"synthetic-event-{declared_action.id}",
                ),
            ],
        )
        session = _LogsSession(filter_client)
        evidence_identity = AwsScopedIdentity(
            _identity_id=cast("str", declared_probe.identity_ref),
            _account_id=ACCOUNT_ID,
            _partition="aws",
            _expires_at=_COLLECTED_AT + timedelta(minutes=10),
            _session=cast("AwsSession", session),
        )
        probe_result = adapter.collect_evidence(
            ProbeRequest(
                context=context,
                probe=declared_probe,
                action_result=action_result,
                identity=evidence_identity,
            )
        )
        evidence_identity.close()
        probe_results.append(probe_result)

        assert session.regions == [REGION]
        assert len(filter_client.calls) == _EXPECTED_VISIBILITY_CALLS
        assert filter_client.calls[0] == filter_client.calls[1]
        assert filter_client.calls[0]["logGroupName"] == descriptor.log_group_name
        assert filter_client.calls[0]["filterPattern"] == (
            f'{{ $.correlationId = "{correlation}" }}'
        )
        observed = cast(
            "dict[str, object]",
            probe_result.observations[0].observed.to_json_value(),
        )
        assert observed["baseline_canary_observed"] is True
        assert observed["boundary_canary_observed"] is (mode == "vulnerable")
        assert observed["evidence_complete"] is True

    assertions = tuple(sorted(scenario.assertions, key=lambda item: item.id))
    assert all(isinstance(item, RetrievalBoundaryAssertion) for item in assertions)
    evaluator = RetrievalBoundaryEvaluator(clock=lambda: _COLLECTED_AT)
    results = tuple(
        evaluator.evaluate_assertion(
            AssertionEvaluationRequest(
                assertion=assertion,
                action_results=tuple(action_results),
                probe_results=tuple(probe_results),
            )
        )
        for assertion in assertions
    )

    assert tuple(result.status for result in results) == (
        expected_status,
        expected_status,
    )
    assert aggregate_results(results) is expected_status
    serialized = b"".join(result.to_json_bytes() for result in results)
    assert _CANARY_A.encode() not in serialized
    assert _CANARY_B.encode() not in serialized
    assert all(
        action.correlation_ids[0].encode() not in serialized
        for action in action_results
    )


def _handler_event(
    action: AwsSigV4Action,
    requester: AssumedRoleIdentity,
    *,
    correlation: str,
) -> dict[str, object]:
    assert action.method == "POST"
    assert action.path == "/retrieve"
    assert len(action.inputs) == 1
    action_input = action.inputs[0]
    assert action_input.location == "json"
    assert isinstance(action_input.value, LiteralInput)
    assert isinstance(action_input.value.value, str)
    return {
        "body": json.dumps(
            {action_input.name: action_input.value.value},
            separators=(",", ":"),
        ),
        "headers": {
            "Content-Type": "application/json",
            "X-Cai-Correlation-Id": correlation,
        },
        "httpMethod": action.method.value,
        "isBase64Encoded": False,
        "path": action.path,
        "requestContext": {
            "identity": {
                "userArn": _assumed_role_arn(
                    requester.role_arn,
                    requester.session_name,
                )
            }
        },
        "resource": action.path,
    }


def _assumed_role_arn(role_arn: str, session_name: str) -> str:
    partition, separator, account_and_role = role_arn.partition(":iam::")
    assert separator
    account_id, separator, role_name = account_and_role.partition(":role/")
    assert separator
    return f"{partition}:sts::{account_id}:assumed-role/{role_name}/{session_name}"


def _filter_response(
    captured: Mapping[str, object],
    *,
    event_id: str,
) -> Mapping[str, object]:
    events = cast("list[dict[str, object]]", captured["logEvents"])
    assert len(events) == 1
    written = events[0]
    timestamp = cast("int", written["timestamp"])
    stream = cast("str", captured["logStreamName"])
    return {
        "ResponseMetadata": {"HTTPStatusCode": 200},
        "events": [
            {
                "eventId": event_id,
                "ingestionTime": timestamp,
                "logStreamName": stream,
                "message": written["message"],
                "timestamp": timestamp,
            }
        ],
        "searchedLogStreams": [
            {
                "logStreamName": stream,
                "searchedCompletely": True,
            }
        ],
    }


def _empty_filter_response(
    captured: Mapping[str, object],
) -> Mapping[str, object]:
    """Return a complete empty page representing delayed log visibility."""
    stream = cast("str", captured["logStreamName"])
    return {
        "ResponseMetadata": {"HTTPStatusCode": 200},
        "events": [],
        "searchedLogStreams": [
            {
                "logStreamName": stream,
                "searchedCompletely": True,
            }
        ],
    }
