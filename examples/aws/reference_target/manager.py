"""Guarded local manager for the disposable AWS reference target.

No command in this module runs implicitly. Deploy and destroy both require a
typed confirmation before even the read-only STS identity check is attempted.
"""

# ruff: noqa: BLE001, PLR0913, PLR2004, PTH101, TRY300, TRY301

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from cai_verify.aws import (
    authorize_aws_execution,
    load_aws_execution_policy_bytes,
    validated_aws_reciprocal_retrieval_slice,
)
from cai_verify.config import (
    AssumedRoleIdentity,
    AwsSigV4Action,
    CloudWatchLogsProbe,
    load_suite_bytes,
)
from examples.aws.reference_target.config import (
    EVIDENCE_READER_SESSION_NAME,
    MAX_DEPLOYMENT_DESCRIPTION_BYTES,
    REFERENCE_SCENARIO_ID,
    REQUESTER_A_SESSION_NAME,
    REQUESTER_B_SESSION_NAME,
    ReferenceTargetError,
    ReferenceTargetFailureCode,
    generate_configuration,
    load_deployment_description,
    write_configuration,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from typing import Never

MAX_CREDENTIAL_FILE_BYTES = 16 * 1024
MAX_AWS_COMMAND_OUTPUT_BYTES = 512 * 1024
MAX_HANDLER_BYTES = 64 * 1024
AWS_COMMAND_TIMEOUT_SECONDS = 60.0
AWS_DEPLOY_TIMEOUT_SECONDS = 10 * 60.0
AWS_DELETE_TIMEOUT_SECONDS = 15 * 60.0

_ROOT = Path(__file__).resolve().parent
_TEMPLATE_PATH = _ROOT / "template.json"
_HANDLER_PATH = _ROOT / "handler.py"
_TEMPLATE_PLACEHOLDER = "__CAI_VERIFY_REFERENCE_HANDLER__"
_ACCOUNT_PATTERN = re.compile(r"\d{12}\Z")
_REGION_PATTERN = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-\d\Z")
_STACK_PATTERN = re.compile(r"cai-verify-ref-[a-z0-9](?:[a-z0-9-]{0,31})\Z")
_ACCESS_KEY_PATTERN = re.compile(r"[A-Z0-9]{16,128}\Z")
_SECRET_KEY_PATTERN = re.compile(r"[A-Za-z0-9/+=]{32,128}\Z")
_CANARY_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
_IAM_USER_ARN_PATTERN = re.compile(
    r"arn:(?P<partition>aws|aws-us-gov|aws-cn):iam::"
    r"(?P<account>\d{12}):user/[A-Za-z0-9+=,.@_/-]{1,512}\Z"
)
_REFERENCE_API_HOST_PATTERN = re.compile(
    r"(?P<api>[a-z0-9]{10})\.execute-api\."
    r"(?P<region>[a-z0-9-]+)\.(?P<suffix>amazonaws\.com(?:\.cn)?)\Z"
)
_ALLOWED_CREDENTIAL_KEYS = frozenset({"ACCESS_KEY_ID", "SECRET_ACCESS_KEY"})
_SAFE_PARENT_ENVIRONMENT = frozenset(
    {"LANG", "LC_ALL", "PATH", "SSL_CERT_DIR", "SSL_CERT_FILE", "TMPDIR"}
)
_SANDBOX_ACKNOWLEDGEMENT = "I_ACKNOWLEDGE_SYNTHETIC_SANDBOX_ONLY"
_COMPLETE_STACK_STATUSES = frozenset({"CREATE_COMPLETE", "UPDATE_COMPLETE"})
_FAILED_TERMINAL_STACK_STATUSES = frozenset(
    {
        "DELETE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_ROLLBACK_FAILED",
    }
)
_FIXED_OWNERSHIP_TAGS = {
    "Environment": "sandbox",
    "Project": "cai-verify",
    "Purpose": "synthetic-reciprocal-retrieval",
}
_MAX_STACK_TAGS = 50
_SUITE_DIGEST_ENVIRONMENT = "CAI_VERIFY_UI_SUITE_SHA256"
_POLICY_DIGEST_ENVIRONMENT = "CAI_VERIFY_UI_POLICY_SHA256"
_AWS_CLI_ERROR_PREFIX = b"aws: [ERROR]: "


@dataclass(frozen=True, slots=True, repr=False)
class _AwsCredentials:
    access_key_id: str
    secret_access_key: str


@dataclass(frozen=True, slots=True, repr=False)
class _SyntheticCanaries:
    requester_a: str
    requester_b: str


@dataclass(frozen=True, slots=True, repr=False)
class _CallerIdentity:
    account_id: str
    arn: str


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Bounded command result used by the injected network-isolated tests."""

    returncode: int
    stdout: bytes = field(default=b"", repr=False)
    stderr: bytes = field(default=b"", repr=False)


class CommandRunner(Protocol):
    """Exact shell-free command seam for AWS CLI calls."""

    def __call__(
        self,
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
        timeout_seconds: float,
    ) -> CommandResult:
        """Run one already-fixed command without a shell."""
        ...


class ProcessExec(Protocol):
    """Exact process-replacement seam for the credential-contained console."""

    def __call__(
        self,
        executable: str,
        arguments: Sequence[str],
        environment: Mapping[str, str],
    ) -> Never:
        """Replace the manager with one fixed local console process."""
        ...


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: CommandRunner | None = None,
    input_fn: Callable[[str], str] = input,
    environment: Mapping[str, str] | None = None,
    exec_fn: ProcessExec | None = None,
) -> int:
    """Run the explicit reference-target management command."""
    parser = _parser()
    arguments = parser.parse_args(argv)
    command_runner = runner or _subprocess_runner
    process_environment = environment if environment is not None else os.environ
    try:
        if arguments.command == "check":
            rendered = render_template()
            if len(rendered) > 1024 * 1024:
                raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_TEMPLATE)
            sys.stdout.write("Reference target template check passed.\n")
            return 0
        if arguments.command == "generate":
            description = _read_bounded_file(
                Path(arguments.description),
                maximum=MAX_DEPLOYMENT_DESCRIPTION_BYTES,
            )
            descriptor = load_deployment_description(
                description,
                expected_account_id=arguments.account_id,
                expected_region=arguments.region,
                expected_stack_name=arguments.stack_name,
            )
            generated = generate_configuration(descriptor)
            write_configuration(
                arguments.output_dir,
                generated,
                replace=arguments.replace,
            )
            sys.stdout.write("Reference target configuration generated.\n")
            return 0
        if arguments.command == "deploy":
            _deploy(
                arguments,
                runner=command_runner,
                input_fn=input_fn,
                process_environment=process_environment,
            )
            sys.stdout.write("Reference target deployed and configuration generated.\n")
            return 0
        if arguments.command == "destroy":
            _destroy(
                arguments,
                runner=command_runner,
                input_fn=input_fn,
                process_environment=process_environment,
            )
            sys.stdout.write("Reference target stack deletion completed.\n")
            return 0
        if arguments.command == "ui":
            _launch_ui(
                arguments,
                input_fn=input_fn,
                process_environment=process_environment,
                exec_fn=exec_fn or _exec_process,
            )
        raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_TEMPLATE)
    except ReferenceTargetError as error:
        sys.stderr.write(f"{error}\n")
        return 2


def render_template() -> bytes:
    """Render the fixed inline Lambda source into the fixed JSON template."""
    try:
        template = _load_json(
            _read_bounded_file(_TEMPLATE_PATH, maximum=1024 * 1024),
            maximum=1024 * 1024,
        )
        handler = _read_bounded_file(_HANDLER_PATH, maximum=MAX_HANDLER_BYTES).decode(
            "utf-8"
        )
        if type(template) is not dict or _TEMPLATE_PLACEHOLDER in handler:
            raise ValueError
        resources = template.get("Resources")
        if type(resources) is not dict:
            raise ValueError
        function = resources.get("RetrievalFunction")
        if type(function) is not dict or type(function.get("Properties")) is not dict:
            raise ValueError
        code = function["Properties"].get("Code")
        if type(code) is not dict or code.get("ZipFile") != _TEMPLATE_PLACEHOLDER:
            raise ValueError
        code["ZipFile"] = handler
        rendered = _canonical_json(template)
        if _TEMPLATE_PLACEHOLDER.encode("utf-8") in rendered:
            raise ValueError
        return rendered
    except ReferenceTargetError:
        raise
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.INVALID_TEMPLATE
        ) from None


def load_credential_file(content: bytes) -> _AwsCredentials:
    """Parse only the two fixed literal credential keys without shell syntax."""
    try:
        if type(content) is not bytes or len(content) > MAX_CREDENTIAL_FILE_BYTES:
            raise ValueError
        text = content.decode("utf-8")
        if "\x00" in text or "\r" in text or text.startswith("\ufeff"):
            raise ValueError
        values: dict[str, str] = {}
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            if line.count("=") < 1:
                raise ValueError
            key, value = line.split("=", 1)
            if (
                key not in _ALLOWED_CREDENTIAL_KEYS
                or key in values
                or not value
                or value != value.strip()
            ):
                raise ValueError
            values[key] = value
        if set(values) != _ALLOWED_CREDENTIAL_KEYS:
            raise ValueError
        if (
            _ACCESS_KEY_PATTERN.fullmatch(values["ACCESS_KEY_ID"]) is None
            or _SECRET_KEY_PATTERN.fullmatch(values["SECRET_ACCESS_KEY"]) is None
        ):
            raise ValueError
        return _AwsCredentials(
            access_key_id=values["ACCESS_KEY_ID"],
            secret_access_key=values["SECRET_ACCESS_KEY"],
        )
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.INVALID_CREDENTIAL_FILE
        ) from None


def aws_environment(
    credentials: _AwsCredentials,
    *,
    region: str,
    parent: Mapping[str, str],
) -> dict[str, str]:
    """Build a child environment with no alternate AWS credential sources."""
    _validate_region(region)
    if type(credentials) is not _AwsCredentials:
        raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_CREDENTIAL_FILE)
    result = {
        key: value
        for key, value in parent.items()
        if key in _SAFE_PARENT_ENVIRONMENT and type(value) is str
    }
    result.update(
        {
            "AWS_ACCESS_KEY_ID": credentials.access_key_id,
            "AWS_CLI_AUTO_PROMPT": "off",
            "AWS_CONFIG_FILE": os.devnull,
            "AWS_DEFAULT_REGION": region,
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_PAGER": "",
            "AWS_REGION": region,
            "AWS_SECRET_ACCESS_KEY": credentials.secret_access_key,
            "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        }
    )
    return result


def _deploy(
    arguments: argparse.Namespace,
    *,
    runner: CommandRunner,
    input_fn: Callable[[str], str],
    process_environment: Mapping[str, str],
) -> None:
    _validate_boundary(arguments.account_id, arguments.region, arguments.stack_name)
    _confirm(
        "DEPLOY",
        arguments.account_id,
        arguments.region,
        arguments.stack_name,
        input_fn=input_fn,
    )
    _progress("[1/8] Validating local inputs")
    output_directory = _prepare_output_directory_before_mutation(
        arguments.output_dir,
        replace=arguments.replace,
    )
    credentials = load_credential_file(_read_credential_file(Path(arguments.env_file)))
    canaries = _canaries(process_environment)
    rendered_template = render_template()
    _progress("[2/8] Checking AWS CLI v2")
    aws_cli = _aws_cli_path()
    child_environment = aws_environment(
        credentials,
        region=arguments.region,
        parent=process_environment,
    )
    _require_aws_cli_v2(aws_cli, child_environment, runner)
    _progress("[3/8] Verifying caller account")
    caller = _caller_identity(
        aws_cli,
        child_environment,
        runner,
        expected_account_id=arguments.account_id,
        expected_region=arguments.region,
    )
    _progress("[4/8] Checking existing stack ownership")
    existing_description = _describe_existing_stack(
        aws_cli,
        child_environment,
        runner,
        account_id=arguments.account_id,
        region=arguments.region,
        stack_name=arguments.stack_name,
    )
    if existing_description is not None:
        _require_exact_stack_template(
            aws_cli,
            child_environment,
            runner,
            region=arguments.region,
            stack_name=arguments.stack_name,
            expected_template=rendered_template,
        )
        load_deployment_description(
            existing_description,
            expected_account_id=arguments.account_id,
            expected_region=arguments.region,
            expected_stack_name=arguments.stack_name,
        )
    _progress("[5/8] Deploying CloudFormation stack (up to 10 minutes)")
    with tempfile.TemporaryDirectory(prefix="cai-verify-reference-") as temporary:
        temporary_path = Path(temporary)
        os.chmod(temporary_path, 0o700)
        template_path = temporary_path / "template.json"
        _write_private_file(template_path, rendered_template)
        expires_on = (datetime.now(UTC).date() + timedelta(days=2)).isoformat()
        _aws_call(
            aws_cli,
            [
                "cloudformation",
                "deploy",
                "--template-file",
                str(template_path),
                "--stack-name",
                arguments.stack_name,
                "--capabilities",
                "CAPABILITY_NAMED_IAM",
                "--no-fail-on-empty-changeset",
                "--parameter-overrides",
                f"ExpectedAccountId={arguments.account_id}",
                f"ExpectedRegion={arguments.region}",
                f"OperatorPrincipalArn={caller.arn}",
                f"ReferenceMode={arguments.mode}",
                f"SandboxAcknowledgement={_SANDBOX_ACKNOWLEDGEMENT}",
                "--tags",
                "Project=cai-verify",
                "Environment=sandbox",
                "Purpose=synthetic-reciprocal-retrieval",
                f"ExpiresOn={expires_on}",
                "--region",
                arguments.region,
                "--output",
                "json",
            ],
            environment=child_environment,
            runner=runner,
            timeout_seconds=AWS_DEPLOY_TIMEOUT_SECONDS,
            failure_code=ReferenceTargetFailureCode.CLOUDFORMATION_DEPLOY_FAILED,
        )
        _progress("[6/8] Validating deployed outputs")
        description = _describe_stack(
            aws_cli,
            child_environment,
            runner,
            account_id=arguments.account_id,
            region=arguments.region,
            stack_name=arguments.stack_name,
        )
        descriptor = load_deployment_description(
            description,
            expected_account_id=arguments.account_id,
            expected_region=arguments.region,
            expected_stack_name=arguments.stack_name,
        )
        if descriptor.reference_mode != arguments.mode:
            raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_DESCRIPTION)
        generated = generate_configuration(descriptor)
        _progress("[7/8] Seeding synthetic documents")
        seed_path = temporary_path / "seed.json"
        _write_private_file(
            seed_path, _seed_bytes(descriptor.documents_table_name, canaries)
        )
        _aws_call(
            aws_cli,
            [
                "dynamodb",
                "transact-write-items",
                "--transact-items",
                seed_path.resolve(strict=True).as_uri(),
                "--return-consumed-capacity",
                "NONE",
                "--region",
                arguments.region,
                "--output",
                "json",
            ],
            environment=child_environment,
            runner=runner,
            timeout_seconds=AWS_COMMAND_TIMEOUT_SECONDS,
            failure_code=ReferenceTargetFailureCode.DYNAMODB_SEED_FAILED,
        )
        _progress("[8/8] Writing private configuration")
        write_configuration(
            output_directory,
            generated,
            replace=arguments.replace,
        )


def _destroy(
    arguments: argparse.Namespace,
    *,
    runner: CommandRunner,
    input_fn: Callable[[str], str],
    process_environment: Mapping[str, str],
) -> None:
    _validate_boundary(arguments.account_id, arguments.region, arguments.stack_name)
    _confirm(
        "DESTROY",
        arguments.account_id,
        arguments.region,
        arguments.stack_name,
        input_fn=input_fn,
    )
    _progress("[1/6] Validating local inputs")
    credentials = load_credential_file(_read_credential_file(Path(arguments.env_file)))
    _progress("[2/6] Checking AWS CLI v2")
    aws_cli = _aws_cli_path()
    child_environment = aws_environment(
        credentials,
        region=arguments.region,
        parent=process_environment,
    )
    _require_aws_cli_v2(aws_cli, child_environment, runner)
    _progress("[3/6] Verifying caller account")
    _caller_identity(
        aws_cli,
        child_environment,
        runner,
        expected_account_id=arguments.account_id,
        expected_region=arguments.region,
    )
    _progress("[4/6] Verifying stack ownership")
    description = _describe_existing_stack(
        aws_cli,
        child_environment,
        runner,
        account_id=arguments.account_id,
        region=arguments.region,
        stack_name=arguments.stack_name,
    )
    if description is None:
        raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_DESCRIPTION)
    _require_exact_stack_template(
        aws_cli,
        child_environment,
        runner,
        region=arguments.region,
        stack_name=arguments.stack_name,
        expected_template=render_template(),
    )
    _validate_destroyable_stack(
        description,
        expected_account_id=arguments.account_id,
        expected_region=arguments.region,
        expected_stack_name=arguments.stack_name,
    )
    _progress("[5/6] Requesting exact stack deletion")
    _aws_call(
        aws_cli,
        [
            "cloudformation",
            "delete-stack",
            "--stack-name",
            arguments.stack_name,
            "--region",
            arguments.region,
        ],
        environment=child_environment,
        runner=runner,
        timeout_seconds=AWS_COMMAND_TIMEOUT_SECONDS,
        failure_code=ReferenceTargetFailureCode.CLOUDFORMATION_DELETE_FAILED,
    )
    _progress("[6/6] Waiting for stack deletion (up to 15 minutes)")
    _aws_call(
        aws_cli,
        [
            "cloudformation",
            "wait",
            "stack-delete-complete",
            "--stack-name",
            arguments.stack_name,
            "--region",
            arguments.region,
        ],
        environment=child_environment,
        runner=runner,
        timeout_seconds=AWS_DELETE_TIMEOUT_SECONDS,
        failure_code=ReferenceTargetFailureCode.CLOUDFORMATION_DELETE_WAIT_FAILED,
    )


def _launch_ui(
    arguments: argparse.Namespace,
    *,
    input_fn: Callable[[str], str],
    process_environment: Mapping[str, str],
    exec_fn: ProcessExec,
) -> Never:
    _validate_boundary(arguments.account_id, arguments.region, arguments.stack_name)
    _confirm(
        "LAUNCH",
        arguments.account_id,
        arguments.region,
        arguments.stack_name,
        input_fn=input_fn,
    )
    config_directory = Path(arguments.config_dir)
    suite_content = _read_bounded_file(
        config_directory / "suite.json",
        maximum=1024 * 1024,
    )
    policy_content = _read_bounded_file(
        config_directory / "execution-policy.json",
        maximum=64 * 1024,
    )
    _validate_console_configuration(
        suite_content,
        policy_content,
        account_id=arguments.account_id,
        region=arguments.region,
        stack_name=arguments.stack_name,
    )
    credentials = load_credential_file(_read_credential_file(Path(arguments.env_file)))
    canaries = _canaries(process_environment)
    child_environment = aws_environment(
        credentials,
        region=arguments.region,
        parent=process_environment,
    )
    child_environment.update(
        {
            "CAI_REQUESTER_A_CANARY": canaries.requester_a,
            "CAI_REQUESTER_B_CANARY": canaries.requester_b,
            _SUITE_DIGEST_ENVIRONMENT: hashlib.sha256(suite_content).hexdigest(),
            _POLICY_DIGEST_ENVIRONMENT: hashlib.sha256(policy_content).hexdigest(),
        }
    )
    command = [
        sys.executable,
        "-m",
        "cai_verify",
        "ui",
        "--evidence-root",
        arguments.evidence_root,
        "--port",
        str(arguments.port),
        # The console process retains AWS credentials and canaries. Requiring
        # manual URL handoff prevents a spawned browser from inheriting them.
        "--no-open",
    ]
    try:
        exec_fn(sys.executable, command, child_environment)
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.CONSOLE_LAUNCH_FAILED
        ) from None
    raise ReferenceTargetError(ReferenceTargetFailureCode.CONSOLE_LAUNCH_FAILED)


def _validate_console_configuration(
    suite_content: bytes,
    policy_content: bytes,
    *,
    account_id: str,
    region: str,
    stack_name: str,
) -> None:
    try:
        suite = load_suite_bytes(suite_content)
        policy = load_aws_execution_policy_bytes(policy_content)
        selected = validated_aws_reciprocal_retrieval_slice(
            suite,
            REFERENCE_SCENARIO_ID,
        )
        expected_partition = _partition_for_region(region)
        expected_roles = {
            "requester-a": (
                f"arn:{expected_partition}:iam::{account_id}:role/"
                f"{stack_name}-requester-a",
                REQUESTER_A_SESSION_NAME,
            ),
            "requester-b": (
                f"arn:{expected_partition}:iam::{account_id}:role/"
                f"{stack_name}-requester-b",
                REQUESTER_B_SESSION_NAME,
            ),
            "evidence-reader": (
                f"arn:{expected_partition}:iam::{account_id}:role/"
                f"{stack_name}-evidence-reader",
                EVIDENCE_READER_SESSION_NAME,
            ),
        }
        identities = tuple(
            identity
            for identity in selected.identities
            if isinstance(identity, AssumedRoleIdentity)
        )
        scenario = selected.scenarios[0]
        actions = tuple(
            action for action in scenario.actions if isinstance(action, AwsSigV4Action)
        )
        probes = tuple(
            probe for probe in scenario.probes if isinstance(probe, CloudWatchLogsProbe)
        )
        endpoint = selected.target.endpoint
        endpoint_host = endpoint.host
        host_match = (
            _REFERENCE_API_HOST_PATTERN.fullmatch(endpoint_host)
            if type(endpoint_host) is str
            else None
        )
        expected_suffix = (
            "amazonaws.com.cn" if expected_partition == "aws-cn" else "amazonaws.com"
        )
        expected_log_group = f"/aws/cai-verify/reference/{stack_name}"
        observed_identities = {identity.id: identity for identity in identities}
        expected_action_contracts = (
            _reference_action_contract("a", region),
            _reference_action_contract("b", region),
        )
        expected_probe_contracts = (
            _reference_probe_contract("a", expected_log_group),
            _reference_probe_contract("b", expected_log_group),
        )
        expected_role_arns = tuple(
            expected_roles[identity_id][0]
            for identity_id in ("requester-a", "requester-b", "evidence-reader")
        )
        if (
            selected.target.aws_account_id != account_id
            or selected.target.aws_region != region
            or selected.target.id != "cai-verify-reference-target"
            or selected.target.environment.value != "sandbox"
            or host_match is None
            or host_match.group("region") != region
            or host_match.group("suffix") != expected_suffix
            or str(endpoint) != f"https://{endpoint_host}/sandbox"
            or selected.target.allowed_hosts != (endpoint_host,)
            or str(policy.application_endpoint) != str(endpoint)
            or policy.aws_account_id != account_id
            or policy.region != region
            or policy.partition != expected_partition
            or policy.allow_current_identity
            or tuple(policy.assumed_role_arns) != expected_role_arns
            or tuple((item.method, item.path, item.service) for item in policy.actions)
            != (("POST", "/retrieve", "execute-api"),)
            or tuple(policy.cloudwatch_log_groups) != (expected_log_group,)
            or len(identities) != 3
            or set(observed_identities) != set(expected_roles)
            or any(
                identity.role_arn != expected_roles[identity_id][0]
                or identity.session_name != expected_roles[identity_id][1]
                or identity.external_id is not None
                for identity_id, identity in observed_identities.items()
            )
            or scenario.identity_ref != "requester-a"
            or len(actions) != 2
            or tuple(
                action.model_dump(mode="json", by_alias=True) for action in actions
            )
            != expected_action_contracts
            or len(probes) != 2
            or tuple(probe.model_dump(mode="json", by_alias=True) for probe in probes)
            != expected_probe_contracts
            or selected.evidence_policy.max_age != "PT5M"
            or selected.evidence_policy.clock_skew_tolerance != "PT30S"
        ):
            raise ValueError
        authorize_aws_execution(
            policy,
            target=selected.target,
            identities=identities,
            actions=actions,
            cloudwatch_log_groups=(probe.log_group for probe in probes),
        )
    except ReferenceTargetError:
        raise
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.INVALID_GENERATED_CONFIGURATION
        ) from None


def _reference_action_contract(requester: str, region: str) -> dict[str, object]:
    requester_id = f"requester-{requester}"
    return {
        "id": f"retrieve-as-{requester_id}",
        "identityRef": requester_id,
        "method": "POST",
        "path": "/retrieve",
        "inputs": [
            {
                "location": "json",
                "name": "syntheticQuery",
                "value": {
                    "source": "literal",
                    "value": f"{requester_id}-synthetic-topic",
                    "sensitive": False,
                },
            }
        ],
        "timeoutSeconds": 15,
        "mutating": False,
        "type": "awsSigV4",
        "service": "execute-api",
        "region": region,
    }


def _reference_probe_contract(
    requester: str,
    log_group: str,
) -> dict[str, object]:
    requester_id = f"requester-{requester}"
    opposite = "b" if requester == "a" else "a"
    return {
        "id": f"{requester_id}-retrieval",
        "identityRef": "evidence-reader",
        "actionRef": f"retrieve-as-{requester_id}",
        "observations": ["retrievalCanary"],
        "maxAge": "PT3M",
        "type": "cloudWatchLogs",
        "logGroup": log_group,
        "canary": None,
        "bedrock": None,
        "retrieval": {
            "baselineCanary": {
                "source": "environment",
                "name": f"CAI_REQUESTER_{requester.upper()}_CANARY",
            },
            "boundaryCanary": {
                "source": "environment",
                "name": f"CAI_REQUESTER_{opposite.upper()}_CANARY",
            },
        },
    }


def _caller_identity(
    aws_cli: str,
    environment: Mapping[str, str],
    runner: CommandRunner,
    *,
    expected_account_id: str,
    expected_region: str,
) -> _CallerIdentity:
    content = _aws_call(
        aws_cli,
        [
            "sts",
            "get-caller-identity",
            "--region",
            expected_region,
            "--output",
            "json",
        ],
        environment=environment,
        runner=runner,
        timeout_seconds=AWS_COMMAND_TIMEOUT_SECONDS,
        failure_code=ReferenceTargetFailureCode.AWS_IDENTITY_CHECK_FAILED,
    )
    try:
        decoded = _load_json(content, maximum=64 * 1024)
        if type(decoded) is not dict or set(decoded) != {"Account", "Arn", "UserId"}:
            raise ValueError
        account = decoded["Account"]
        arn = decoded["Arn"]
        user_id = decoded["UserId"]
        match = _IAM_USER_ARN_PATTERN.fullmatch(arn) if type(arn) is str else None
        if (
            account != expected_account_id
            or type(user_id) is not str
            or not user_id
            or len(user_id) > 256
            or match is None
            or match.group("account") != expected_account_id
            or match.group("partition") != _partition_for_region(expected_region)
        ):
            raise ValueError
        return _CallerIdentity(account_id=account, arn=arn)
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.AWS_IDENTITY_MISMATCH
        ) from None


def _describe_stack(
    aws_cli: str,
    environment: Mapping[str, str],
    runner: CommandRunner,
    *,
    account_id: str,
    region: str,
    stack_name: str,
) -> bytes:
    _validate_boundary(account_id, region, stack_name)
    return _aws_call(
        aws_cli,
        [
            "cloudformation",
            "describe-stacks",
            "--stack-name",
            stack_name,
            "--region",
            region,
            "--output",
            "json",
        ],
        environment=environment,
        runner=runner,
        timeout_seconds=AWS_COMMAND_TIMEOUT_SECONDS,
        failure_code=ReferenceTargetFailureCode.CLOUDFORMATION_STACK_READ_FAILED,
    )


def _describe_existing_stack(
    aws_cli: str,
    environment: Mapping[str, str],
    runner: CommandRunner,
    *,
    account_id: str,
    region: str,
    stack_name: str,
) -> bytes | None:
    """Return one existing stack or an exact stack-not-found state."""
    _validate_boundary(account_id, region, stack_name)
    try:
        result = runner(
            [
                aws_cli,
                "cloudformation",
                "describe-stacks",
                "--stack-name",
                stack_name,
                "--region",
                region,
                "--output",
                "json",
                "--no-cli-pager",
                "--color",
                "off",
            ],
            environment=environment,
            timeout_seconds=AWS_COMMAND_TIMEOUT_SECONDS,
        )
        if (
            type(result) is not CommandResult
            or len(result.stdout) > MAX_AWS_COMMAND_OUTPUT_BYTES
            or len(result.stderr) > MAX_AWS_COMMAND_OUTPUT_BYTES
        ):
            raise ValueError
        if result.returncode == 0:
            return result.stdout
        expected_line = (
            "An error occurred (ValidationError) when calling the "
            "DescribeStacks operation: Stack with id "
            f"{stack_name} does not exist"
        ).encode()
        # AWS CLI v2 may place a blank line around an error and newer v2 builds
        # add one fixed severity prefix even when color is disabled. Ignore
        # only empty lines, then require the exact requested-stack error with
        # either known presentation. Additional diagnostics, changed text, or
        # any stdout remain failures and cannot authorize creation.
        error_lines = [line for line in result.stderr.splitlines() if line]
        accepted_error_lines = (
            expected_line,
            _AWS_CLI_ERROR_PREFIX + expected_line,
        )
        if (
            result.stdout == b""
            and len(error_lines) == 1
            and any(
                hmac.compare_digest(error_lines[0], accepted)
                for accepted in accepted_error_lines
            )
        ):
            return None
        raise ValueError
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.CLOUDFORMATION_STACK_LOOKUP_FAILED
        ) from None


def _require_exact_stack_template(
    aws_cli: str,
    environment: Mapping[str, str],
    runner: CommandRunner,
    *,
    region: str,
    stack_name: str,
    expected_template: bytes,
) -> None:
    """Require the original deployed template to equal the bundled template."""
    _validate_region(region)
    _validate_stack_name(stack_name)
    content = _aws_call(
        aws_cli,
        [
            "cloudformation",
            "get-template",
            "--stack-name",
            stack_name,
            "--template-stage",
            "Original",
            "--region",
            region,
            "--output",
            "json",
        ],
        environment=environment,
        runner=runner,
        timeout_seconds=AWS_COMMAND_TIMEOUT_SECONDS,
        failure_code=ReferenceTargetFailureCode.CLOUDFORMATION_TEMPLATE_READ_FAILED,
    )
    try:
        response = _load_json(content, maximum=MAX_AWS_COMMAND_OUTPUT_BYTES)
        if type(response) is not dict or set(response) not in (
            {"TemplateBody"},
            {"StagesAvailable", "TemplateBody"},
        ):
            raise ValueError
        stages = response.get("StagesAvailable")
        if stages is not None and (
            type(stages) is not list
            or not stages
            or len(stages) > 2
            or any(stage not in {"Original", "Processed"} for stage in stages)
            or len(set(stages)) != len(stages)
            or "Original" not in stages
        ):
            raise ValueError
        template_body = response["TemplateBody"]
        if type(template_body) is str:
            observed = _load_json(
                template_body.encode(),
                maximum=MAX_AWS_COMMAND_OUTPUT_BYTES,
            )
        elif type(template_body) is dict:
            observed = template_body
        else:
            raise ValueError
        expected = _load_json(
            expected_template,
            maximum=MAX_AWS_COMMAND_OUTPUT_BYTES,
        )
        if type(observed) is not dict or observed != expected:
            raise ValueError
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.INVALID_DESCRIPTION
        ) from None


def _validate_destroyable_stack(
    content: bytes,
    *,
    expected_account_id: str,
    expected_region: str,
    expected_stack_name: str,
) -> None:
    """Accept a complete owned stack or a tightly bounded failed owned stack."""
    try:
        decoded = _load_json(content, maximum=MAX_DEPLOYMENT_DESCRIPTION_BYTES)
        if type(decoded) is not dict or set(decoded) != {"Stacks"}:
            raise ValueError
        stacks = decoded["Stacks"]
        if type(stacks) is not list or len(stacks) != 1 or type(stacks[0]) is not dict:
            raise ValueError
        stack = stacks[0]
        if stack.get("StackName") != expected_stack_name:
            raise ValueError
        status = stack.get("StackStatus")
        if status in _COMPLETE_STACK_STATUSES:
            load_deployment_description(
                content,
                expected_account_id=expected_account_id,
                expected_region=expected_region,
                expected_stack_name=expected_stack_name,
            )
            return
        if status not in _FAILED_TERMINAL_STACK_STATUSES:
            raise ValueError
        _require_fixed_ownership_tags(stack.get("Tags"))
    except ReferenceTargetError:
        raise
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.INVALID_DESCRIPTION
        ) from None


def _require_fixed_ownership_tags(value: object) -> None:
    if type(value) is not list or not value or len(value) > _MAX_STACK_TAGS:
        raise ValueError
    observed: dict[str, str] = {}
    for item in value:
        if type(item) is not dict or set(item) != {"Key", "Value"}:
            raise ValueError
        key = item["Key"]
        tag_value = item["Value"]
        if (
            type(key) is not str
            or not key
            or len(key.encode()) > 128
            or key in observed
            or type(tag_value) is not str
            or len(tag_value.encode()) > 256
        ):
            raise ValueError
        observed[key] = tag_value
    if any(
        observed.get(key) != expected for key, expected in _FIXED_OWNERSHIP_TAGS.items()
    ):
        raise ValueError


def _aws_call(
    aws_cli: str,
    arguments: Sequence[str],
    *,
    environment: Mapping[str, str],
    runner: CommandRunner,
    timeout_seconds: float,
    failure_code: ReferenceTargetFailureCode,
) -> bytes:
    try:
        result = runner(
            [aws_cli, *arguments, "--no-cli-pager", "--color", "off"],
            environment=environment,
            timeout_seconds=timeout_seconds,
        )
        if (
            type(result) is not CommandResult
            or result.returncode != 0
            or len(result.stdout) > MAX_AWS_COMMAND_OUTPUT_BYTES
            or len(result.stderr) > MAX_AWS_COMMAND_OUTPUT_BYTES
        ):
            raise ValueError
        return result.stdout
    except Exception:
        raise ReferenceTargetError(failure_code) from None


def _progress(message: str) -> None:
    """Write one fixed non-sensitive operator stage immediately."""
    sys.stdout.write(f"{message}\n")
    sys.stdout.flush()


def _require_aws_cli_v2(
    aws_cli: str,
    environment: Mapping[str, str],
    runner: CommandRunner,
) -> None:
    try:
        result = runner(
            [aws_cli, "--version"],
            environment=environment,
            timeout_seconds=AWS_COMMAND_TIMEOUT_SECONDS,
        )
        if type(result) is not CommandResult:
            raise ValueError
        combined = result.stdout + result.stderr
        if (
            result.returncode != 0
            or len(combined) > 4096
            or not combined.startswith(b"aws-cli/2.")
        ):
            raise ValueError
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.AWS_CLI_UNAVAILABLE
        ) from None


def _aws_cli_path() -> str:
    path = shutil.which("aws")
    if path is None:
        raise ReferenceTargetError(ReferenceTargetFailureCode.AWS_CLI_UNAVAILABLE)
    resolved = Path(path).resolve(strict=True)
    if not resolved.is_file():
        raise ReferenceTargetError(ReferenceTargetFailureCode.AWS_CLI_UNAVAILABLE)
    return str(resolved)


def _canaries(environment: Mapping[str, str]) -> _SyntheticCanaries:
    try:
        requester_a = environment["CAI_REQUESTER_A_CANARY"]
        requester_b = environment["CAI_REQUESTER_B_CANARY"]
        if (
            type(requester_a) is not str
            or type(requester_b) is not str
            or _CANARY_PATTERN.fullmatch(requester_a) is None
            or _CANARY_PATTERN.fullmatch(requester_b) is None
            or hmac.compare_digest(requester_a, requester_b)
        ):
            raise ValueError
        return _SyntheticCanaries(
            requester_a=requester_a,
            requester_b=requester_b,
        )
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.INVALID_CANARY_ENVIRONMENT
        ) from None


def _seed_bytes(table_name: str, canaries: _SyntheticCanaries) -> bytes:
    if type(table_name) is not str or not table_name or len(table_name) > 255:
        raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_DESCRIPTION)
    entries = []
    for requester, query, canary in (
        (
            "requester-a",
            "requester-a-synthetic-topic",
            canaries.requester_a,
        ),
        (
            "requester-b",
            "requester-b-synthetic-topic",
            canaries.requester_b,
        ),
    ):
        entries.append(
            {
                "Put": {
                    "Item": {
                        "content": {"S": canary},
                        "documentId": {"S": requester},
                        "syntheticQuery": {"S": query},
                    },
                    "TableName": table_name,
                }
            }
        )
    return _canonical_json(entries)


def _confirm(
    operation: str,
    account_id: str,
    region: str,
    stack_name: str,
    *,
    input_fn: Callable[[str], str],
) -> None:
    phrase = f"{operation} {account_id} {region} {stack_name}"
    observed = input_fn(f"Type '{phrase}' to continue: ")
    if observed != phrase:
        raise ReferenceTargetError(ReferenceTargetFailureCode.APPROVAL_REQUIRED)


def _validate_boundary(account_id: str, region: str, stack_name: str) -> None:
    if type(account_id) is not str or _ACCOUNT_PATTERN.fullmatch(account_id) is None:
        raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_DESCRIPTION)
    _validate_region(region)
    _validate_stack_name(stack_name)


def _validate_region(region: str) -> None:
    if type(region) is not str or _REGION_PATTERN.fullmatch(region) is None:
        raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_DESCRIPTION)


def _validate_stack_name(stack_name: str) -> None:
    if type(stack_name) is not str or _STACK_PATTERN.fullmatch(stack_name) is None:
        raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_DESCRIPTION)


def _partition_for_region(region: str) -> str:
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


def _prepare_output_directory_before_mutation(
    path_value: str,
    *,
    replace: bool,
) -> Path:
    """Create and secure the exact configuration directory before AWS mutation."""
    path = Path(path_value).absolute()
    if (
        not path.name
        or len(os.fsencode(path)) > 4096
        or any(candidate.is_symlink() for candidate in (path, *path.parents))
        or (path.exists() and not path.is_dir())
    ):
        raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_OUTPUT_DIRECTORY)
    existing = path
    while not existing.exists() and existing.parent != existing:
        existing = existing.parent
    if not existing.is_dir():
        raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_OUTPUT_DIRECTORY)
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink() or not path.is_dir():
            raise ValueError
        os.chmod(path, 0o700, follow_symlinks=False)
        prepared = path.resolve(strict=True)
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.INVALID_OUTPUT_DIRECTORY
        ) from None
    targets = tuple(
        prepared / filename for filename in ("suite.json", "execution-policy.json")
    )
    if any(target.is_symlink() for target in targets):
        raise ReferenceTargetError(ReferenceTargetFailureCode.INVALID_OUTPUT_DIRECTORY)
    if not replace and any(target.exists() for target in targets):
        raise ReferenceTargetError(ReferenceTargetFailureCode.OUTPUT_EXISTS)
    return prepared


def _read_credential_file(path: Path) -> bytes:
    """Read one owner-only regular credential file without following links."""
    try:
        absolute = path.absolute()
        if (
            any(candidate.is_symlink() for candidate in (absolute, *absolute.parents))
            or not absolute.is_file()
        ):
            raise ValueError
        before = absolute.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            raise ValueError
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(absolute, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise ValueError
            content = stream.read(MAX_CREDENTIAL_FILE_BYTES + 1)
        if len(content) > MAX_CREDENTIAL_FILE_BYTES:
            raise ValueError
        return content
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.INVALID_CREDENTIAL_FILE
        ) from None


def _read_bounded_file(path: Path, *, maximum: int) -> bytes:
    try:
        absolute = path.absolute()
        if (
            any(candidate.is_symlink() for candidate in (absolute, *absolute.parents))
            or not absolute.is_file()
        ):
            raise ValueError
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(absolute, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            content = stream.read(maximum + 1)
        if len(content) > maximum:
            raise ValueError
        return content
    except ReferenceTargetError:
        raise
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.INVALID_DESCRIPTION
        ) from None


def _write_private_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb", closefd=True) as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _load_json(content: bytes, *, maximum: int) -> object:
    if type(content) is not bytes or len(content) > maximum:
        raise ValueError
    return json.loads(
        content.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _reject_constant(_value: str) -> None:
    raise ValueError


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _subprocess_runner(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> CommandResult:
    try:
        result = subprocess.run(  # noqa: S603 - argv is fixed and shell-free.
            list(command),
            check=False,
            capture_output=True,
            env=dict(environment),
            shell=False,
            timeout=timeout_seconds,
        )
        return CommandResult(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )
    except Exception:
        raise ReferenceTargetError(
            ReferenceTargetFailureCode.AWS_COMMAND_FAILED
        ) from None


def _exec_process(
    executable: str,
    arguments: Sequence[str],
    environment: Mapping[str, str],
) -> Never:
    # The exact interpreter/module argv avoids both a shell and PATH lookup.
    os.execve(  # noqa: S606
        executable,
        list(arguments),
        dict(environment),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Manage the fixed disposable CAI Verify AWS reference target. "
            "No AWS operation runs without explicit typed confirmation."
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="validate local template composition only")

    generate = commands.add_parser(
        "generate",
        help="generate configs from a saved DescribeStacks JSON response",
    )
    _boundary_arguments(generate)
    generate.add_argument("--description", required=True)
    generate.add_argument("--output-dir", required=True)
    generate.add_argument("--replace", action="store_true")

    deploy = commands.add_parser(
        "deploy",
        help="confirm, deploy/update, seed, and generate exact configs",
    )
    _boundary_arguments(deploy)
    deploy.add_argument("--mode", choices=("isolated", "vulnerable"), required=True)
    deploy.add_argument("--env-file", default=".env")
    deploy.add_argument("--output-dir", required=True)
    deploy.add_argument("--replace", action="store_true")

    destroy = commands.add_parser(
        "destroy",
        help="confirm and delete only the exact named reference stack",
    )
    _boundary_arguments(destroy)
    destroy.add_argument("--env-file", default=".env")

    ui = commands.add_parser(
        "ui",
        help="launch the local console with only the validated .env AWS user",
    )
    _boundary_arguments(ui)
    ui.add_argument("--env-file", default=".env")
    ui.add_argument("--config-dir", required=True)
    ui.add_argument("--evidence-root", default=".cai-verify/runs")
    ui.add_argument("--port", type=int, default=0, choices=range(65536))
    ui.add_argument("--no-open", action="store_true")
    return parser


def _boundary_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--stack-name", default="cai-verify-ref-sandbox")


if __name__ == "__main__":
    raise SystemExit(main())
