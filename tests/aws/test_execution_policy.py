"""Tests for the strict operator-owned AWS execution-policy boundary."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Never

import pytest
import yaml

from cai_verify.aws import (
    AWS_EXECUTION_POLICY_SCHEMA_ID,
    AWS_EXECUTION_POLICY_SCHEMA_VERSION,
    MAX_AWS_EXECUTION_POLICY_BYTES,
    AwsExecutionPolicy,
    AwsExecutionPolicyError,
    AwsExecutionPolicyFailureCode,
    AwsRetrievalRunOptions,
    authorize_aws_execution,
    aws_execution_policy_json_schema,
    load_aws_execution_policy,
    load_aws_execution_policy_bytes,
    run_aws_doctor,
    run_aws_retrieval_chain,
    run_retrieval_doctor,
)
from cai_verify.config import (
    AssumedRoleIdentity,
    AwsSigV4Action,
    CurrentAwsIdentity,
    SyntheticLocalIdentity,
    Target,
    VerificationSuite,
)

if TYPE_CHECKING:
    from cai_verify.aws import AwsSession, AwsStsClient

_ACCOUNT_ID = "111122223333"
_OTHER_ACCOUNT_ID = "999900001111"
_REGION = "eu-west-2"
_ENDPOINT = "https://retrieval.sandbox.example.test/v1"
_LOG_GROUP = "/aws/cai-verify/synthetic-retrieval"
_REQUESTER_A_ROLE = "arn:aws:iam::111122223333:role/cai-verify-requester-a"
_REQUESTER_B_ROLE = "arn:aws:iam::111122223333:role/cai-verify-requester-b"
_EVIDENCE_ROLE = "arn:aws:iam::111122223333:role/cai-verify-read-only-evidence"
_FIXTURE = (
    Path(__file__).parents[1]
    / "fixtures"
    / "suites"
    / "valid"
    / "reciprocal-retrieval.yaml"
)


def _policy_payload() -> dict[str, object]:
    return {
        "actions": [
            {
                "method": "POST",
                "path": "/retrieve",
                "service": "execute-api",
            }
        ],
        "allowCurrentIdentity": False,
        "applicationEndpoint": _ENDPOINT,
        "assumedRoleArns": [
            _REQUESTER_A_ROLE,
            _REQUESTER_B_ROLE,
            _EVIDENCE_ROLE,
        ],
        "awsAccountId": _ACCOUNT_ID,
        "cloudwatchLogGroups": [_LOG_GROUP],
        "partition": "aws",
        "region": _REGION,
        "schemaVersion": AWS_EXECUTION_POLICY_SCHEMA_VERSION,
    }


def _policy_bytes() -> bytes:
    return json.dumps(
        _policy_payload(),
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _policy() -> AwsExecutionPolicy:
    return AwsExecutionPolicy.model_validate(_policy_payload())


def _target(**overrides: object) -> Target:
    payload: dict[str, object] = {
        "allowedHosts": ["retrieval.sandbox.example.test"],
        "awsAccountId": _ACCOUNT_ID,
        "awsRegion": _REGION,
        "endpoint": _ENDPOINT,
        "environment": "sandbox",
        "id": "synthetic-retrieval-application",
    }
    payload.update(overrides)
    return Target.model_validate(payload)


def _assumed_identity(identity_id: str, role_arn: str) -> AssumedRoleIdentity:
    return AssumedRoleIdentity.model_validate(
        {
            "id": identity_id,
            "roleArn": role_arn,
            "sessionName": "cai-verify-synthetic",
            "type": "awsAssumeRole",
        }
    )


def _action(**overrides: object) -> AwsSigV4Action:
    payload: dict[str, object] = {
        "id": "retrieve",
        "method": "POST",
        "mutating": False,
        "path": "/retrieve",
        "region": _REGION,
        "service": "execute-api",
        "type": "awsSigV4",
    }
    payload.update(overrides)
    return AwsSigV4Action.model_validate(payload)


def test_bounded_loader_accepts_one_exact_policy_at_the_size_limit(
    tmp_path: Path,
) -> None:
    """A duplicate-free UTF-8 policy may occupy exactly 64 KiB."""
    raw = _policy_bytes()
    padding = MAX_AWS_EXECUTION_POLICY_BYTES - len(raw)
    assert padding > 0
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(raw + (b" " * padding))

    policy = load_aws_execution_policy(policy_path)

    assert policy.schema_version == AWS_EXECUTION_POLICY_SCHEMA_VERSION
    assert policy.aws_account_id == _ACCOUNT_ID
    assert policy.partition == "aws"
    assert policy.region == _REGION
    assert str(policy.application_endpoint) == _ENDPOINT
    assert [(item.method, item.path, item.service) for item in policy.actions] == [
        ("POST", "/retrieve", "execute-api")
    ]
    assert policy.assumed_role_arns == (
        _REQUESTER_A_ROLE,
        _REQUESTER_B_ROLE,
        _EVIDENCE_ROLE,
    )
    assert policy.allow_current_identity is False
    assert policy.cloudwatch_log_groups == (_LOG_GROUP,)


def test_path_and_byte_loaders_share_the_exact_policy_contract() -> None:
    """The console upload and CLI path return the same strict policy model."""
    assert load_aws_execution_policy_bytes(_policy_bytes()) == _policy()


def test_byte_policy_loader_rejects_non_bytes_and_oversized_content() -> None:
    """The upload seam retains the existing fixed 64 KiB boundary."""
    with pytest.raises(AwsExecutionPolicyError) as wrong_type:
        load_aws_execution_policy_bytes("{}")  # type: ignore[arg-type]
    _assert_fixed_error(
        wrong_type.value,
        AwsExecutionPolicyFailureCode.INVALID_EXECUTION_POLICY,
    )

    with pytest.raises(AwsExecutionPolicyError) as oversized:
        load_aws_execution_policy_bytes(b" " * (MAX_AWS_EXECUTION_POLICY_BYTES + 1))
    _assert_fixed_error(
        oversized.value,
        AwsExecutionPolicyFailureCode.INVALID_EXECUTION_POLICY,
    )


@pytest.mark.parametrize(
    ("name", "content"),
    [
        pytest.param("empty", b"", id="empty"),
        pytest.param("truncated", b'{"schemaVersion":', id="malformed"),
        pytest.param("invalid-utf8", b"\xff", id="invalid-utf8"),
        pytest.param(
            "utf16-json",
            _policy_bytes().decode().encode("utf-16"),
            id="non-utf8-json-encoding",
        ),
        pytest.param(
            "non-finite",
            b'{"extra":NaN}',
            id="non-finite-number",
        ),
        pytest.param(
            "duplicate-root",
            b'{"schemaVersion":"1alpha1","schemaVersion":"1alpha1"}',
            id="duplicate-root-field",
        ),
        pytest.param(
            "duplicate-nested",
            (
                b'{"actions":[{"method":"POST","method":"POST",'
                b'"path":"/retrieve","service":"execute-api"}]}'
            ),
            id="duplicate-nested-field",
        ),
    ],
)
def test_loader_collapses_malformed_or_duplicate_json_to_one_fixed_error(
    tmp_path: Path,
    name: str,
    content: bytes,
) -> None:
    """Parser diagnostics and policy contents never cross the trust boundary."""
    policy_path = tmp_path / f"{name}-secret-policy.json"
    policy_path.write_bytes(content)

    with pytest.raises(AwsExecutionPolicyError) as captured:
        load_aws_execution_policy(policy_path)

    _assert_fixed_error(
        captured.value,
        AwsExecutionPolicyFailureCode.INVALID_EXECUTION_POLICY,
    )
    rendered = f"{captured.value!r} {captured.value}"
    assert name not in rendered
    assert str(policy_path) not in rendered
    assert "NaN" not in rendered
    assert captured.value.__cause__ is None


def test_loader_rejects_an_oversized_policy_without_parsing_it(
    tmp_path: Path,
) -> None:
    """The loader reads at most one byte beyond its 64 KiB boundary."""
    policy_path = tmp_path / "oversized.json"
    policy_path.write_bytes(b"{" + (b" " * (MAX_AWS_EXECUTION_POLICY_BYTES - 1)) + b"}")
    assert policy_path.stat().st_size == MAX_AWS_EXECUTION_POLICY_BYTES + 1

    with pytest.raises(AwsExecutionPolicyError) as captured:
        load_aws_execution_policy(policy_path)

    _assert_fixed_error(
        captured.value,
        AwsExecutionPolicyFailureCode.INVALID_EXECUTION_POLICY,
    )


def test_loader_rejects_unknown_fields_without_disclosing_them(
    tmp_path: Path,
) -> None:
    """The versioned contract is closed to unknown policy capabilities."""
    marker = "operator-secret-marker"
    payload = _policy_payload()
    payload[marker] = "must-not-escape"

    error = _load_invalid_payload(tmp_path, payload)

    _assert_fixed_error(error, AwsExecutionPolicyFailureCode.INVALID_EXECUTION_POLICY)
    rendered = f"{error!r} {error}"
    assert marker not in rendered
    assert "must-not-escape" not in rendered


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param(
            "actions",
            [
                {
                    "method": "POST",
                    "path": "/retrieve",
                    "service": "execute-api",
                },
                {
                    "method": "POST",
                    "path": "/retrieve",
                    "service": "execute-api",
                },
            ],
            id="duplicate-action",
        ),
        pytest.param(
            "assumedRoleArns",
            [_REQUESTER_A_ROLE, _REQUESTER_A_ROLE],
            id="duplicate-role",
        ),
        pytest.param(
            "cloudwatchLogGroups",
            [_LOG_GROUP, _LOG_GROUP],
            id="duplicate-log-group",
        ),
        pytest.param(
            "actions",
            [
                {
                    "method": "POST",
                    "path": "/retriev*",
                    "service": "execute-api",
                }
            ],
            id="wildcard-action-path",
        ),
        pytest.param(
            "actions",
            [
                {
                    "method": "POST",
                    "path": "/items/${tenant}",
                    "service": "execute-api",
                }
            ],
            id="expression-action-path",
        ),
        pytest.param(
            "cloudwatchLogGroups",
            ["/aws/cai-verify/*"],
            id="wildcard-log-group",
        ),
        pytest.param(
            "applicationEndpoint",
            "https://operator:secret@retrieval.sandbox.example.test/v1",
            id="endpoint-credentials",
        ),
        pytest.param(
            "applicationEndpoint",
            f"{_ENDPOINT}?tenant=synthetic",
            id="endpoint-query",
        ),
        pytest.param(
            "applicationEndpoint",
            f"{_ENDPOINT}#fragment",
            id="endpoint-fragment",
        ),
        pytest.param(
            "applicationEndpoint",
            "http://retrieval.sandbox.example.test/v1",
            id="non-https-endpoint",
        ),
        pytest.param(
            "applicationEndpoint",
            "https://RETRIEVAL.sandbox.example.test/v1",
            id="noncanonical-endpoint-host",
        ),
        pytest.param(
            "applicationEndpoint",
            "https://retrieval.sandbox.example.test:443/v1",
            id="noncanonical-endpoint-port",
        ),
        pytest.param(
            "applicationEndpoint",
            "https://retrieval.sandbox.example.test/*",
            id="wildcard-endpoint-path",
        ),
        pytest.param(
            "region",
            "${AWS_REGION}",
            id="environment-reference",
        ),
        pytest.param(
            "allowCurrentIdentity",
            1,
            id="non-boolean-current-identity-flag",
        ),
    ],
)
def test_loader_rejects_ambiguous_or_non_exact_policy_values(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    """Collections and authorization values remain exact and unambiguous."""
    payload = _policy_payload()
    payload[field] = value

    error = _load_invalid_payload(tmp_path, payload)

    _assert_fixed_error(error, AwsExecutionPolicyFailureCode.INVALID_EXECUTION_POLICY)


@pytest.mark.parametrize(
    ("region", "partition", "role_arn"),
    [
        pytest.param(
            "us-gov-west-1",
            "aws",
            _REQUESTER_A_ROLE,
            id="region-partition",
        ),
        pytest.param(
            _REGION,
            "aws",
            "arn:aws-cn:iam::111122223333:role/cai-verify-requester-a",
            id="role-partition",
        ),
        pytest.param(
            _REGION,
            "aws",
            "arn:aws:iam::999900001111:role/cai-verify-requester-a",
            id="role-account",
        ),
    ],
)
def test_loader_rejects_partition_or_account_inconsistency(
    tmp_path: Path,
    region: str,
    partition: str,
    role_arn: str,
) -> None:
    """The policy cannot span AWS partitions or accounts."""
    payload = _policy_payload()
    payload["region"] = region
    payload["partition"] = partition
    payload["assumedRoleArns"] = [role_arn]

    error = _load_invalid_payload(tmp_path, payload)

    _assert_fixed_error(error, AwsExecutionPolicyFailureCode.INVALID_EXECUTION_POLICY)


def test_authorizer_allows_only_the_complete_exact_plan() -> None:
    """Every declared account, region, endpoint, action, role, and source matches."""
    authorize_aws_execution(
        _policy(),
        target=_target(),
        identities=(
            _assumed_identity("requester-a", _REQUESTER_A_ROLE),
            _assumed_identity("requester-b", _REQUESTER_B_ROLE),
            _assumed_identity("evidence-reader", _EVIDENCE_ROLE),
        ),
        actions=(_action(),),
        cloudwatch_log_groups=(_LOG_GROUP,),
    )


def test_current_identity_requires_an_explicit_true_authorization() -> None:
    """Current process credentials remain denied by default and opt-in exactly."""
    payload = _policy_payload()
    payload["allowCurrentIdentity"] = True
    identity = CurrentAwsIdentity.model_validate(
        {"id": "current-reader", "type": "awsCurrent"}
    )

    authorize_aws_execution(
        AwsExecutionPolicy.model_validate(payload),
        target=_target(),
        identities=(identity,),
    )


@pytest.mark.parametrize(
    ("target", "identities", "actions", "log_groups", "expected"),
    [
        pytest.param(
            _target(awsAccountId=_OTHER_ACCOUNT_ID),
            (),
            (),
            (),
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_ACCOUNT,
            id="target-account",
        ),
        pytest.param(
            _target(awsRegion="us-east-1"),
            (),
            (),
            (),
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_REGION,
            id="target-region",
        ),
        pytest.param(
            _target(
                endpoint="https://other.sandbox.example.test/v1",
                allowedHosts=["other.sandbox.example.test"],
            ),
            (),
            (),
            (),
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_ENDPOINT,
            id="target-endpoint",
        ),
        pytest.param(
            _target(
                endpoint=f"{_ENDPOINT}?tenant=synthetic",
            ),
            (),
            (),
            (),
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_ENDPOINT,
            id="target-query",
        ),
        pytest.param(
            _target(),
            (
                _assumed_identity(
                    "wrong-account",
                    ("arn:aws:iam::999900001111:role/cai-verify-requester-a"),
                ),
            ),
            (),
            (),
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_ACCOUNT,
            id="identity-account",
        ),
        pytest.param(
            _target(),
            (
                _assumed_identity(
                    "wrong-partition",
                    ("arn:aws-cn:iam::111122223333:role/cai-verify-requester-a"),
                ),
            ),
            (),
            (),
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_PARTITION,
            id="identity-partition",
        ),
        pytest.param(
            _target(),
            (
                _assumed_identity(
                    "unlisted-role",
                    "arn:aws:iam::111122223333:role/unlisted",
                ),
            ),
            (),
            (),
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_IDENTITY,
            id="unlisted-role",
        ),
        pytest.param(
            _target(),
            (
                CurrentAwsIdentity.model_validate(
                    {"id": "current-reader", "type": "awsCurrent"}
                ),
            ),
            (),
            (),
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_IDENTITY,
            id="current-identity-default-deny",
        ),
        pytest.param(
            _target(),
            (
                SyntheticLocalIdentity.model_validate(
                    {
                        "id": "synthetic-local",
                        "type": "syntheticLocal",
                        "principal": "synthetic-principal",
                    }
                ),
            ),
            (),
            (),
            AwsExecutionPolicyFailureCode.EXECUTION_POLICY_DENIED,
            id="unsupported-identity-type",
        ),
        pytest.param(
            _target(),
            (),
            (_action(region="us-east-1"),),
            (),
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_REGION,
            id="action-region",
        ),
        pytest.param(
            _target(),
            (),
            (_action(method="GET"),),
            (),
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_ACTION,
            id="action-method",
        ),
        pytest.param(
            _target(),
            (),
            (_action(path="/other"),),
            (),
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_ACTION,
            id="action-path",
        ),
        pytest.param(
            _target(),
            (),
            (_action(service="bedrock-runtime"),),
            (),
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_ACTION,
            id="action-service",
        ),
        pytest.param(
            _target(),
            (),
            (),
            ("/aws/cai-verify/other",),
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_EVIDENCE_SOURCE,
            id="log-group",
        ),
    ],
)
def test_authorizer_returns_only_the_fixed_exact_denial_category(
    target: Target,
    identities: tuple[
        AssumedRoleIdentity | CurrentAwsIdentity | SyntheticLocalIdentity, ...
    ],
    actions: tuple[AwsSigV4Action, ...],
    log_groups: tuple[str, ...],
    expected: AwsExecutionPolicyFailureCode,
) -> None:
    """Every boundary mismatch fails closed without its rejected value."""
    with pytest.raises(AwsExecutionPolicyError) as captured:
        authorize_aws_execution(
            _policy(),
            target=target,
            identities=identities,
            actions=actions,
            cloudwatch_log_groups=log_groups,
        )

    _assert_fixed_error(captured.value, expected)
    rendered = f"{captured.value!r} {captured.value}"
    assert _ACCOUNT_ID not in rendered
    assert _OTHER_ACCOUNT_ID not in rendered
    assert "arn:" not in rendered
    assert "example.test" not in rendered
    assert "/aws/" not in rendered


def test_authorizer_rejects_a_non_policy_object_with_a_fixed_category() -> None:
    """A forged policy-shaped object is not accepted by duck typing."""
    with pytest.raises(AwsExecutionPolicyError) as captured:
        authorize_aws_execution(
            object(),  # type: ignore[arg-type]
            target=_target(),
            identities=(),
        )

    _assert_fixed_error(
        captured.value,
        AwsExecutionPolicyFailureCode.INVALID_EXECUTION_POLICY,
    )


def test_denial_precedes_aws_doctor_session_creation() -> None:
    """Doctor authorization completes before any SDK session seam is touched."""
    suite = VerificationSuite.model_validate(
        yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))
    )
    payload = _policy_payload()
    payload["applicationEndpoint"] = "https://denied.sandbox.example.test/v1"
    factory = _NeverSessionFactory()

    with pytest.raises(AwsExecutionPolicyError) as captured:
        run_aws_doctor(
            suite,
            execution_policy=AwsExecutionPolicy.model_validate(payload),
            environment={},
            session_factory=factory,
        )

    _assert_fixed_error(
        captured.value,
        AwsExecutionPolicyFailureCode.UNAUTHORIZED_ENDPOINT,
    )
    assert factory.calls == 0


@pytest.mark.parametrize("entrypoint", ["retrieval-doctor", "single-chain-runner"])
def test_denial_precedes_other_aws_session_and_target_seams(
    tmp_path: Path,
    entrypoint: str,
) -> None:
    """Every AWS execution API authorizes before SDK or target-capable work."""
    suite = VerificationSuite.model_validate(
        yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))
    )
    payload = _policy_payload()
    payload["applicationEndpoint"] = "https://denied.sandbox.example.test/v1"
    denied = AwsExecutionPolicy.model_validate(payload)
    factory = _NeverSessionFactory()
    environment = {
        "SYNTHETIC_REQUESTER_A_CANARY": "synthetic-canary-a",
        "SYNTHETIC_REQUESTER_B_CANARY": "synthetic-canary-b",
    }

    def operation() -> object:
        if entrypoint == "retrieval-doctor":
            return run_retrieval_doctor(
                suite,
                execution_policy=denied,
                environment=environment,
                session_factory=factory,
                clock=lambda: datetime(2026, 7, 28, tzinfo=UTC),
                monotonic=lambda: 0.0,
            )
        return run_aws_retrieval_chain(
            suite,
            AwsRetrievalRunOptions(
                run_id="policy-denied-single-chain",
                assertion_id="requester-a-retrieval-boundary",
                execution_policy=denied,
                environment=environment,
                session_factory=factory,
                clock=lambda: datetime(2026, 7, 28, tzinfo=UTC),
            ),
        )

    with pytest.raises(AwsExecutionPolicyError) as captured:
        operation()

    _assert_fixed_error(
        captured.value,
        AwsExecutionPolicyFailureCode.UNAUTHORIZED_ENDPOINT,
    )
    assert factory.calls == 0
    assert list(tmp_path.iterdir()) == []


def test_policy_schema_is_strict_versioned_and_uses_public_aliases() -> None:
    """The generated schema describes the closed standalone JSON contract."""
    schema = aws_execution_policy_json_schema()

    assert schema["$id"] == AWS_EXECUTION_POLICY_SCHEMA_ID
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "AWS Execution Policy 1alpha1"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        "actions",
        "applicationEndpoint",
        "assumedRoleArns",
        "awsAccountId",
        "cloudwatchLogGroups",
        "partition",
        "region",
        "schemaVersion",
    }
    properties = schema["properties"]
    assert "schemaVersion" in properties
    assert "schema_version" not in properties
    assert properties["allowCurrentIdentity"]["default"] is False
    assert properties["applicationEndpoint"]["pattern"].startswith("^https://")
    assert properties["actions"]["uniqueItems"] is True
    assert properties["assumedRoleArns"]["uniqueItems"] is True
    assert properties["cloudwatchLogGroups"]["uniqueItems"] is True
    action_schema = schema["$defs"]["AwsExecutionPolicyAction"]
    assert action_schema["additionalProperties"] is False
    assert set(action_schema["required"]) == {"method", "path", "service"}
    assert (
        schema["$defs"]["AwsPolicyActionPath"]["pattern"]
        == r"^/[A-Za-z0-9._~!:@&'+,;=%/-]*$"
    )
    encoded = json.dumps(schema, sort_keys=True)
    assert _ACCOUNT_ID not in encoded
    assert _ENDPOINT not in encoded
    assert _REQUESTER_A_ROLE not in encoded
    assert _LOG_GROUP not in encoded


def test_policy_and_action_repr_hide_every_operator_value() -> None:
    """Pydantic representations expose types but no policy contents."""
    policy = _policy()
    marker_values = (
        _ACCOUNT_ID,
        _REGION,
        _ENDPOINT,
        _REQUESTER_A_ROLE,
        _REQUESTER_B_ROLE,
        _EVIDENCE_ROLE,
        _LOG_GROUP,
        "/retrieve",
        "execute-api",
    )

    assert repr(policy) == "AwsExecutionPolicy()"
    assert repr(policy.actions[0]) == "AwsExecutionPolicyAction()"
    rendered = f"{policy!r} {policy.actions!r}"
    assert all(value not in rendered for value in marker_values)


class _NeverSessionFactory:
    """AWS session seam that makes any access observable and fatal."""

    def __init__(self) -> None:
        self.calls = 0

    def create_current_session(
        self,
        *,
        profile_name: str | None,
        region_name: str,
    ) -> Never:
        del profile_name, region_name
        self.calls += 1
        raise AssertionError

    def create_assumed_session(
        self,
        *,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        region_name: str,
    ) -> Never:
        del access_key_id, secret_access_key, session_token, region_name
        self.calls += 1
        raise AssertionError

    def create_sts_client(
        self,
        session: AwsSession,
        *,
        region_name: str,
    ) -> AwsStsClient:
        del session, region_name
        self.calls += 1
        raise AssertionError


def _load_invalid_payload(
    tmp_path: Path,
    payload: dict[str, object],
) -> AwsExecutionPolicyError:
    path = tmp_path / "invalid-policy.json"
    path.write_text(
        json.dumps(payload, allow_nan=False, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    with pytest.raises(AwsExecutionPolicyError) as captured:
        load_aws_execution_policy(path)
    return captured.value


def _assert_fixed_error(
    error: AwsExecutionPolicyError,
    expected: AwsExecutionPolicyFailureCode,
) -> None:
    assert error.code is expected
    assert str(error) == (
        f"AWS execution policy rejected the operation ({expected.value})"
    )
