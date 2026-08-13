"""Tests for fixed reference-target configuration generation and storage."""

from __future__ import annotations

import json
import stat
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from examples.aws.reference_target.config import (
    REFERENCE_SCENARIO_ID,
    ReferenceTargetError,
    ReferenceTargetFailureCode,
    generate_configuration,
    load_deployment_description,
    write_configuration,
)

from cai_verify.aws import (
    load_aws_execution_policy_bytes,
    validated_aws_reciprocal_retrieval_slice,
)
from cai_verify.config import (
    AssumedRoleIdentity,
    AwsSigV4Action,
    CloudWatchLogsProbe,
    load_suite_bytes,
)
from tests.reference_target.helpers import (
    ACCOUNT_ID,
    ENDPOINT,
    EVIDENCE_ROLE_ARN,
    HOST,
    LOG_GROUP,
    REGION,
    REQUESTER_A_ROLE_ARN,
    REQUESTER_B_ROLE_ARN,
    STACK_NAME,
    description_bytes,
)

if TYPE_CHECKING:
    from pathlib import Path

_SECRET = "synthetic_canary_must_not_be_generated_001"  # noqa: S105
_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600


def test_generated_pair_is_deterministic_and_authorized() -> None:
    """One deployment descriptor produces an executable reciprocal contract."""
    descriptor = load_deployment_description(
        description_bytes(),
        expected_account_id=ACCOUNT_ID,
        expected_region=REGION,
        expected_stack_name=STACK_NAME,
    )

    first = generate_configuration(descriptor)
    second = generate_configuration(descriptor)

    assert first == second
    suite = load_suite_bytes(first.suite)
    policy = load_aws_execution_policy_bytes(first.execution_policy)
    selected = validated_aws_reciprocal_retrieval_slice(
        suite,
        REFERENCE_SCENARIO_ID,
    )
    assert selected.target.aws_account_id == ACCOUNT_ID
    assert selected.target.aws_region == REGION
    assert str(selected.target.endpoint) == ENDPOINT
    assert selected.target.allowed_hosts == (HOST,)
    identities = tuple(
        identity
        for identity in selected.identities
        if isinstance(identity, AssumedRoleIdentity)
    )
    assert len(identities) == len(selected.identities)
    assert tuple(identity.role_arn for identity in identities) == (
        EVIDENCE_ROLE_ARN,
        REQUESTER_A_ROLE_ARN,
        REQUESTER_B_ROLE_ARN,
    )
    scenario = selected.scenarios[0]
    actions = tuple(
        action for action in scenario.actions if isinstance(action, AwsSigV4Action)
    )
    probes = tuple(
        probe for probe in scenario.probes if isinstance(probe, CloudWatchLogsProbe)
    )
    assert len(actions) == len(scenario.actions)
    assert len(probes) == len(scenario.probes)
    assert {action.region for action in actions} == {REGION}
    assert {probe.log_group for probe in probes} == {LOG_GROUP}
    assert policy.application_endpoint == selected.target.endpoint
    assert set(policy.assumed_role_arns) == {
        EVIDENCE_ROLE_ARN,
        REQUESTER_A_ROLE_ARN,
        REQUESTER_B_ROLE_ARN,
    }
    assert _SECRET.encode() not in first.suite
    assert _SECRET.encode() not in first.execution_policy


def test_isolated_and_vulnerable_modes_share_the_same_verification_contract() -> None:
    """Mode is a target behavior, never a suite-controlled request value."""
    isolated = generate_configuration(
        load_deployment_description(
            description_bytes(mode="isolated"),
            expected_account_id=ACCOUNT_ID,
            expected_region=REGION,
            expected_stack_name=STACK_NAME,
        )
    )
    vulnerable = generate_configuration(
        load_deployment_description(
            description_bytes(mode="vulnerable"),
            expected_account_id=ACCOUNT_ID,
            expected_region=REGION,
            expected_stack_name=STACK_NAME,
        )
    )

    assert isolated == vulnerable


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("duplicate", ReferenceTargetFailureCode.INVALID_DESCRIPTION),
        ("wrong-account", ReferenceTargetFailureCode.INVALID_DESCRIPTION),
        ("wrong-region", ReferenceTargetFailureCode.INVALID_DESCRIPTION),
        ("wrong-host", ReferenceTargetFailureCode.INVALID_DESCRIPTION),
        ("wrong-ownership", ReferenceTargetFailureCode.INVALID_DESCRIPTION),
        ("missing-output", ReferenceTargetFailureCode.INVALID_DESCRIPTION),
        ("extra-output", ReferenceTargetFailureCode.INVALID_DESCRIPTION),
        ("incomplete", ReferenceTargetFailureCode.INVALID_DESCRIPTION),
    ],
)
def test_malformed_deployment_descriptions_fail_closed(
    mutation: str,
    expected_code: ReferenceTargetFailureCode,
) -> None:
    """Stack output parsing accepts only one complete exact deployment."""
    if mutation == "duplicate":
        content = b'{"Stacks":[],"Stacks":[]}'
    else:
        decoded = json.loads(description_bytes())
        stack = decoded["Stacks"][0]
        outputs = {item["OutputKey"]: item for item in stack["Outputs"]}
        if mutation == "wrong-account":
            outputs["AccountId"]["OutputValue"] = "999900001111"
        elif mutation == "wrong-region":
            outputs["Region"]["OutputValue"] = "us-east-1"
        elif mutation == "wrong-host":
            outputs["AllowedHost"]["OutputValue"] = "example.test"
        elif mutation == "wrong-ownership":
            outputs["OwnershipMarker"]["OutputValue"] = "unrelated-stack"
        elif mutation == "missing-output":
            stack["Outputs"].remove(outputs["LogGroupName"])
        elif mutation == "extra-output":
            stack["Outputs"].append({"OutputKey": "Unexpected", "OutputValue": "value"})
        elif mutation == "incomplete":
            stack["StackStatus"] = "UPDATE_IN_PROGRESS"
        content = json.dumps(decoded).encode()

    with pytest.raises(ReferenceTargetError) as captured:
        load_deployment_description(
            content,
            expected_account_id=ACCOUNT_ID,
            expected_region=REGION,
            expected_stack_name=STACK_NAME,
        )

    assert captured.value.code is expected_code
    assert ACCOUNT_ID not in str(captured.value)
    assert REQUESTER_A_ROLE_ARN not in str(captured.value)


def test_descriptor_conflicts_are_rejected_before_generation() -> None:
    """A caller cannot mutate validated output values after parsing."""
    descriptor = load_deployment_description(
        description_bytes(),
        expected_account_id=ACCOUNT_ID,
        expected_region=REGION,
        expected_stack_name=STACK_NAME,
    )

    with pytest.raises(ReferenceTargetError) as captured:
        generate_configuration(replace(descriptor, endpoint="https://example.test"))

    assert captured.value.code is (
        ReferenceTargetFailureCode.INVALID_GENERATED_CONFIGURATION
    )


def test_generated_files_are_private_and_refuse_unapproved_overwrite(
    tmp_path: Path,
) -> None:
    """Generated account and role identifiers are stored only in private files."""
    root = tmp_path / "generated"
    descriptor = load_deployment_description(
        description_bytes(),
        expected_account_id=ACCOUNT_ID,
        expected_region=REGION,
        expected_stack_name=STACK_NAME,
    )
    generated = generate_configuration(descriptor)

    suite_path, policy_path = write_configuration(root, generated)

    assert suite_path.read_bytes() == generated.suite
    assert policy_path.read_bytes() == generated.execution_policy
    assert stat.S_IMODE(root.stat().st_mode) == _DIRECTORY_MODE
    assert stat.S_IMODE(suite_path.stat().st_mode) == _FILE_MODE
    assert stat.S_IMODE(policy_path.stat().st_mode) == _FILE_MODE
    with pytest.raises(ReferenceTargetError) as captured:
        write_configuration(root, generated)
    assert captured.value.code is ReferenceTargetFailureCode.OUTPUT_EXISTS
    assert write_configuration(root, generated, replace=True) == (
        suite_path,
        policy_path,
    )


def test_symlink_output_is_rejected(tmp_path: Path) -> None:
    """Generated configuration never follows an attacker-controlled symlink."""
    root = tmp_path
    real = root / "real"
    real.mkdir()
    linked = root / "linked"
    linked.symlink_to(real, target_is_directory=True)
    descriptor = load_deployment_description(
        description_bytes(),
        expected_account_id=ACCOUNT_ID,
        expected_region=REGION,
        expected_stack_name=STACK_NAME,
    )

    with pytest.raises(ReferenceTargetError) as captured:
        write_configuration(linked, generate_configuration(descriptor))

    assert captured.value.code is (ReferenceTargetFailureCode.INVALID_OUTPUT_DIRECTORY)
