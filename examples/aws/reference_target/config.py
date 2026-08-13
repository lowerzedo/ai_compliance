"""Strict configuration generation for the disposable AWS reference target."""

# ruff: noqa: BLE001, C901, PLR2004, PTH101, PTH105, SIM105, TRY300, TRY301

from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

from cai_verify.aws import (
    authorize_aws_execution,
    load_aws_execution_policy_bytes,
    validated_aws_reciprocal_retrieval_slice,
)
from cai_verify.config import AwsSigV4Action, CloudWatchLogsProbe, load_suite_bytes

if TYPE_CHECKING:
    from collections.abc import Mapping

REFERENCE_SCENARIO_ID = "reciprocal-requester-retrieval"
REFERENCE_TARGET_OWNERSHIP_MARKER = "cai-verify-reference-target/1"
REQUESTER_A_SESSION_NAME = "cai-verify-reference-requester-a"
REQUESTER_B_SESSION_NAME = "cai-verify-reference-requester-b"
EVIDENCE_READER_SESSION_NAME = "cai-verify-reference-evidence-reader"
MAX_DEPLOYMENT_DESCRIPTION_BYTES = 512 * 1024

_ROOT = Path(__file__).resolve().parent
_AWS_EXAMPLE_ROOT = _ROOT.parent
_SUITE_TEMPLATE = _AWS_EXAMPLE_ROOT / "reciprocal-retrieval-suite.json"
_POLICY_TEMPLATE = _AWS_EXAMPLE_ROOT / "reciprocal-retrieval-policy.json"
_STACK_PATTERN = re.compile(r"cai-verify-ref-[a-z0-9](?:[a-z0-9-]{0,31})\Z")
_ACCOUNT_PATTERN = re.compile(r"\d{12}\Z")
_REGION_PATTERN = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-\d\Z")
_API_HOST_PATTERN = re.compile(
    r"(?P<api>[a-z0-9]{10})\.execute-api\."
    r"(?P<region>[a-z0-9-]+)\.(?P<suffix>amazonaws\.com(?:\.cn)?)\Z"
)
_ROLE_ARN_PATTERN = re.compile(
    r"arn:(?P<partition>aws|aws-us-gov|aws-cn):iam::"
    r"(?P<account>\d{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}\Z"
)
_OUTPUT_KEYS = frozenset(
    {
        "AccountId",
        "AllowedHost",
        "ApplicationEndpoint",
        "DocumentsTableName",
        "EvidenceReaderRoleArn",
        "EvidenceReaderSessionName",
        "LogGroupName",
        "OwnershipMarker",
        "Partition",
        "ReferenceMode",
        "Region",
        "RequesterARoleArn",
        "RequesterASessionName",
        "RequesterBRoleArn",
        "RequesterBSessionName",
        "SchemaVersion",
        "StackName",
    }
)
_COMPLETE_STACK_STATUSES = frozenset({"CREATE_COMPLETE", "UPDATE_COMPLETE"})


class ReferenceTargetFailureCode(StrEnum):
    """Stable failures that never include configuration or AWS values."""

    APPROVAL_REQUIRED = "approval_required"
    AWS_CLI_UNAVAILABLE = "aws_cli_unavailable"
    AWS_COMMAND_FAILED = "aws_command_failed"
    AWS_IDENTITY_MISMATCH = "aws_identity_mismatch"
    CONSOLE_LAUNCH_FAILED = "console_launch_failed"
    INVALID_CANARY_ENVIRONMENT = "invalid_canary_environment"
    INVALID_CREDENTIAL_FILE = "invalid_credential_file"
    INVALID_DESCRIPTION = "invalid_description"
    INVALID_GENERATED_CONFIGURATION = "invalid_generated_configuration"
    INVALID_OUTPUT_DIRECTORY = "invalid_output_directory"
    INVALID_TEMPLATE = "invalid_template"
    OUTPUT_EXISTS = "output_exists"
    WRITE_FAILED = "write_failed"


class ReferenceTargetError(RuntimeError):
    """One redacted reference-target configuration failure."""

    def __init__(self, code: ReferenceTargetFailureCode) -> None:
        """Create an error that carries only a stable category."""
        self.code = code
        super().__init__(f"reference target operation failed ({code.value})")


@dataclass(frozen=True, slots=True, repr=False)
class DeploymentDescriptor:
    """Validated fixed CloudFormation outputs used to create both contracts."""

    stack_name: str
    account_id: str
    partition: str
    region: str
    endpoint: str
    allowed_host: str
    requester_a_role_arn: str
    requester_b_role_arn: str
    evidence_reader_role_arn: str
    log_group_name: str
    documents_table_name: str
    reference_mode: str


@dataclass(frozen=True, slots=True)
class GeneratedConfiguration:
    """Canonical validated suite and execution-policy bytes."""

    suite: bytes = field(repr=False)
    execution_policy: bytes = field(repr=False)


def load_deployment_description(
    content: bytes,
    *,
    expected_account_id: str,
    expected_region: str,
    expected_stack_name: str,
) -> DeploymentDescriptor:
    """Parse one bounded duplicate-free CloudFormation DescribeStacks result."""
    try:
        _validate_boundary_inputs(
            expected_account_id,
            expected_region,
            expected_stack_name,
        )
        decoded = _load_json_bytes(
            content,
            maximum=MAX_DEPLOYMENT_DESCRIPTION_BYTES,
        )
        if type(decoded) is not dict or set(decoded) != {"Stacks"}:
            raise ValueError
        stacks = decoded["Stacks"]
        if type(stacks) is not list or len(stacks) != 1 or type(stacks[0]) is not dict:
            raise ValueError
        stack = stacks[0]
        if (
            stack.get("StackName") != expected_stack_name
            or stack.get("StackStatus") not in _COMPLETE_STACK_STATUSES
        ):
            raise ValueError
        outputs = _output_map(stack.get("Outputs"))
        descriptor = _descriptor_from_outputs(outputs)
        _validate_descriptor(
            descriptor,
            expected_account_id=expected_account_id,
            expected_region=expected_region,
            expected_stack_name=expected_stack_name,
        )
        return descriptor
    except ReferenceTargetError:
        raise
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.INVALID_DESCRIPTION
        ) from None


def generate_configuration(
    descriptor: DeploymentDescriptor,
) -> GeneratedConfiguration:
    """Generate and validate the one fixed reciprocal suite/policy pair."""
    try:
        if type(descriptor) is not DeploymentDescriptor:
            raise TypeError
        _validate_descriptor(
            descriptor,
            expected_account_id=descriptor.account_id,
            expected_region=descriptor.region,
            expected_stack_name=descriptor.stack_name,
        )
        suite = _load_json_bytes(_SUITE_TEMPLATE.read_bytes(), maximum=1024 * 1024)
        policy = _load_json_bytes(_POLICY_TEMPLATE.read_bytes(), maximum=64 * 1024)
        if type(suite) is not dict or type(policy) is not dict:
            raise TypeError
        _apply_descriptor_to_suite(suite, descriptor)
        _apply_descriptor_to_policy(policy, descriptor)
        suite_bytes = _canonical_json(suite)
        policy_bytes = _canonical_json(policy)
        _validate_generated_pair(suite_bytes, policy_bytes)
        return GeneratedConfiguration(
            suite=suite_bytes,
            execution_policy=policy_bytes,
        )
    except ReferenceTargetError:
        raise
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.INVALID_GENERATED_CONFIGURATION
        ) from None


def write_configuration(
    output_directory: str | os.PathLike[str],
    generated: GeneratedConfiguration,
    *,
    replace: bool = False,
) -> tuple[Path, Path]:
    """Write only the two exact generated files with restrictive permissions."""
    try:
        if type(generated) is not GeneratedConfiguration or type(replace) is not bool:
            raise TypeError
        directory = _prepare_output_directory(Path(output_directory))
        suite_path = directory / "suite.json"
        policy_path = directory / "execution-policy.json"
        targets = (
            (suite_path, generated.suite),
            (policy_path, generated.execution_policy),
        )
        if not replace and any(
            path.exists() or path.is_symlink() for path, _ in targets
        ):
            raise ReferenceTargetError(ReferenceTargetFailureCode.OUTPUT_EXISTS)
        if any(path.is_symlink() for path, _ in targets):
            raise ReferenceTargetError(
                ReferenceTargetFailureCode.INVALID_OUTPUT_DIRECTORY
            )
        staged: list[tuple[Path, Path]] = []
        try:
            for target, content in targets:
                temporary = directory / f".{target.name}.{secrets.token_hex(8)}.tmp"
                _write_new_file(temporary, content)
                staged.append((temporary, target))
            for temporary, target in staged:
                os.replace(temporary, target)
                os.chmod(target, 0o600, follow_symlinks=False)
            _sync_directory(directory)
        finally:
            for temporary, _ in staged:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
        return suite_path, policy_path
    except ReferenceTargetError:
        raise
    except Exception:
        raise ReferenceTargetError(ReferenceTargetFailureCode.WRITE_FAILED) from None


def _validate_boundary_inputs(account_id: str, region: str, stack_name: str) -> None:
    if (
        type(account_id) is not str
        or _ACCOUNT_PATTERN.fullmatch(account_id) is None
        or type(region) is not str
        or _REGION_PATTERN.fullmatch(region) is None
        or type(stack_name) is not str
        or _STACK_PATTERN.fullmatch(stack_name) is None
    ):
        raise ValueError


def _output_map(value: object) -> dict[str, str]:
    if type(value) is not list or len(value) != len(_OUTPUT_KEYS):
        raise ValueError
    outputs: dict[str, str] = {}
    for item in value:
        if type(item) is not dict or set(item) != {"OutputKey", "OutputValue"}:
            raise ValueError
        key = item.get("OutputKey")
        output_value = item.get("OutputValue")
        if (
            type(key) is not str
            or key not in _OUTPUT_KEYS
            or key in outputs
            or type(output_value) is not str
            or not output_value
            or len(output_value.encode("utf-8")) > 4096
        ):
            raise ValueError
        outputs[key] = output_value
    if set(outputs) != _OUTPUT_KEYS:
        raise ValueError
    return outputs


def _descriptor_from_outputs(outputs: Mapping[str, str]) -> DeploymentDescriptor:
    if (
        outputs["SchemaVersion"] != "1"
        or outputs["OwnershipMarker"] != REFERENCE_TARGET_OWNERSHIP_MARKER
        or outputs["RequesterASessionName"] != REQUESTER_A_SESSION_NAME
        or outputs["RequesterBSessionName"] != REQUESTER_B_SESSION_NAME
        or outputs["EvidenceReaderSessionName"] != EVIDENCE_READER_SESSION_NAME
    ):
        raise ValueError
    return DeploymentDescriptor(
        stack_name=outputs["StackName"],
        account_id=outputs["AccountId"],
        partition=outputs["Partition"],
        region=outputs["Region"],
        endpoint=outputs["ApplicationEndpoint"],
        allowed_host=outputs["AllowedHost"],
        requester_a_role_arn=outputs["RequesterARoleArn"],
        requester_b_role_arn=outputs["RequesterBRoleArn"],
        evidence_reader_role_arn=outputs["EvidenceReaderRoleArn"],
        log_group_name=outputs["LogGroupName"],
        documents_table_name=outputs["DocumentsTableName"],
        reference_mode=outputs["ReferenceMode"],
    )


def _validate_descriptor(
    descriptor: DeploymentDescriptor,
    *,
    expected_account_id: str,
    expected_region: str,
    expected_stack_name: str,
) -> None:
    _validate_boundary_inputs(
        expected_account_id,
        expected_region,
        expected_stack_name,
    )
    partition = _partition_for_region(expected_region)
    if (
        descriptor.account_id != expected_account_id
        or descriptor.region != expected_region
        or descriptor.stack_name != expected_stack_name
        or descriptor.partition != partition
        or descriptor.reference_mode not in {"isolated", "vulnerable"}
        or descriptor.log_group_name
        != f"/aws/cai-verify/reference/{expected_stack_name}"
        or descriptor.documents_table_name != f"{expected_stack_name}-documents"
    ):
        raise ValueError
    endpoint = urlsplit(descriptor.endpoint)
    if (
        endpoint.scheme != "https"
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.port is not None
        or endpoint.path != "/sandbox"
        or endpoint.query
        or endpoint.fragment
        or endpoint.hostname != descriptor.allowed_host
        or descriptor.endpoint != f"https://{descriptor.allowed_host}/sandbox"
    ):
        raise ValueError
    host = _API_HOST_PATTERN.fullmatch(descriptor.allowed_host)
    suffix = "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com"
    if (
        host is None
        or host.group("region") != expected_region
        or host.group("suffix") != suffix
    ):
        raise ValueError
    roles = (
        (
            descriptor.requester_a_role_arn,
            f"{expected_stack_name}-requester-a",
        ),
        (
            descriptor.requester_b_role_arn,
            f"{expected_stack_name}-requester-b",
        ),
        (
            descriptor.evidence_reader_role_arn,
            f"{expected_stack_name}-evidence-reader",
        ),
    )
    if len({role_arn for role_arn, _ in roles}) != 3:
        raise ValueError
    for role_arn, expected_role_name in roles:
        match = _ROLE_ARN_PATTERN.fullmatch(role_arn)
        if (
            match is None
            or match.group("partition") != partition
            or match.group("account") != expected_account_id
            or role_arn.rsplit("/", 1)[-1] != expected_role_name
        ):
            raise ValueError


def _apply_descriptor_to_suite(
    suite: dict[str, Any],
    descriptor: DeploymentDescriptor,
) -> None:
    suite["metadata"] = {
        "description": (
            "Disposable synthetic reciprocal retrieval reference-target assessment."
        ),
        "name": "aws-reference-reciprocal-retrieval",
        "owners": ["reference-sandbox-operator@example.test"],
    }
    suite["target"] = {
        "allowedHosts": [descriptor.allowed_host],
        "awsAccountId": descriptor.account_id,
        "awsRegion": descriptor.region,
        "endpoint": descriptor.endpoint,
        "environment": "sandbox",
        "id": "cai-verify-reference-target",
    }
    identities = suite.get("identities")
    if type(identities) is not list:
        raise TypeError
    role_values = {
        "requester-a": (
            descriptor.requester_a_role_arn,
            REQUESTER_A_SESSION_NAME,
        ),
        "requester-b": (
            descriptor.requester_b_role_arn,
            REQUESTER_B_SESSION_NAME,
        ),
        "evidence-reader": (
            descriptor.evidence_reader_role_arn,
            EVIDENCE_READER_SESSION_NAME,
        ),
    }
    for identity in identities:
        if type(identity) is not dict or identity.get("id") not in role_values:
            raise ValueError
        role_arn, session_name = role_values[identity["id"]]
        identity["roleArn"] = role_arn
        identity["sessionName"] = session_name
    scenarios = suite.get("scenarios")
    if type(scenarios) is not list or len(scenarios) != 1:
        raise ValueError
    scenario = scenarios[0]
    if type(scenario) is not dict or scenario.get("id") != REFERENCE_SCENARIO_ID:
        raise ValueError
    actions = scenario.get("actions")
    probes = scenario.get("probes")
    if type(actions) is not list or type(probes) is not list:
        raise TypeError
    for action in actions:
        if type(action) is not dict:
            raise TypeError
        action["region"] = descriptor.region
    for probe in probes:
        if type(probe) is not dict:
            raise TypeError
        probe["logGroup"] = descriptor.log_group_name


def _apply_descriptor_to_policy(
    policy: dict[str, Any],
    descriptor: DeploymentDescriptor,
) -> None:
    policy.update(
        {
            "applicationEndpoint": descriptor.endpoint,
            "assumedRoleArns": [
                descriptor.requester_a_role_arn,
                descriptor.requester_b_role_arn,
                descriptor.evidence_reader_role_arn,
            ],
            "awsAccountId": descriptor.account_id,
            "cloudwatchLogGroups": [descriptor.log_group_name],
            "partition": descriptor.partition,
            "region": descriptor.region,
        }
    )


def _validate_generated_pair(suite_bytes: bytes, policy_bytes: bytes) -> None:
    suite = load_suite_bytes(suite_bytes)
    policy = load_aws_execution_policy_bytes(policy_bytes)
    selected = validated_aws_reciprocal_retrieval_slice(
        suite,
        REFERENCE_SCENARIO_ID,
    )
    scenario = selected.scenarios[0]
    authorize_aws_execution(
        policy,
        target=selected.target,
        identities=selected.identities,
        actions=cast("tuple[AwsSigV4Action, ...]", scenario.actions),
        cloudwatch_log_groups=(
            probe.log_group
            for probe in cast("tuple[CloudWatchLogsProbe, ...]", scenario.probes)
        ),
    )


def _prepare_output_directory(path: Path) -> Path:
    if not path.name or len(os.fsencode(path)) > 4096:
        raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_OUTPUT_DIRECTORY)
    absolute = path.absolute()
    if any(candidate.is_symlink() for candidate in (absolute, *absolute.parents)):
        raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_OUTPUT_DIRECTORY)
    existing = absolute
    while not existing.exists() and existing.parent != existing:
        existing = existing.parent
    if not existing.is_dir():
        raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_OUTPUT_DIRECTORY)
    absolute.mkdir(mode=0o700, parents=True, exist_ok=True)
    if absolute.is_symlink() or not absolute.is_dir():
        raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_OUTPUT_DIRECTORY)
    os.chmod(absolute, 0o700, follow_symlinks=False)
    return absolute.resolve(strict=True)


def _write_new_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _sync_directory(path: Path) -> None:
    if not hasattr(os, "O_DIRECTORY"):
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _load_json_bytes(content: bytes, *, maximum: int) -> object:
    if type(content) is not bytes or len(content) > maximum:
        raise ValueError
    return json.loads(
        content.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _partition_for_region(region: str) -> str:
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"
