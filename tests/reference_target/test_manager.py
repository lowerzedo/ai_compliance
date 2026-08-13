"""Network-isolated tests for guarded reference-target management."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlparse

import pytest
from examples.aws.reference_target import manager
from examples.aws.reference_target.config import (
    ReferenceTargetError,
    ReferenceTargetFailureCode,
    generate_configuration,
    load_deployment_description,
    write_configuration,
)
from examples.aws.reference_target.manager import CommandResult

from tests.reference_target.helpers import (
    ACCOUNT_ID,
    REGION,
    STACK_NAME,
    caller_identity_bytes,
    description_bytes,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from typing import Never

_ACCESS_KEY = "AKIASYNTHETIC000001"
_SECRET_KEY = "syntheticSecretKeyMaterial0000000000000000"  # noqa: S105
_CANARY_A = "synthetic_canary_requester_a_001"
_CANARY_B = "synthetic_canary_requester_b_002"
_AWS_PATH = "/synthetic/bin/aws"
_OPERATIONAL_FAILURE = 2
_EXEC_SENTINEL = 73
_PRIVATE_DIRECTORY_MODE = 0o700
_CREDENTIAL_BYTES = (
    f"ACCESS_KEY_ID={_ACCESS_KEY}\nSECRET_ACCESS_KEY={_SECRET_KEY}\n"
).encode()
_DEPLOY_PROGRESS = (
    "[1/8] Validating local inputs",
    "[2/8] Checking AWS CLI v2",
    "[3/8] Verifying caller account",
    "[4/8] Checking existing stack ownership",
    "[5/8] Deploying CloudFormation stack (up to 10 minutes)",
    "[6/8] Validating deployed outputs",
    "[7/8] Seeding synthetic documents",
    "[8/8] Writing private configuration",
)
_DESTROY_PROGRESS = (
    "[1/6] Validating local inputs",
    "[2/6] Checking AWS CLI v2",
    "[3/6] Verifying caller account",
    "[4/6] Verifying stack ownership",
    "[5/6] Requesting exact stack deletion",
    "[6/6] Waiting for stack deletion (up to 15 minutes)",
)


def _stack_not_found_stderr(*, stack_name: str = STACK_NAME) -> bytes:
    return (
        "An error occurred (ValidationError) when calling the "
        "DescribeStacks operation: Stack with id "
        f"{stack_name} does not exist\n"
    ).encode()


@dataclass(slots=True)
class _AwsRunner:
    mode: str = "isolated"
    fail_operation: str | None = None
    stack_exists: bool = False
    stack_description: bytes | None = field(default=None, repr=False)
    stack_template: bytes | None = field(default=None, repr=False)
    get_template_response: bytes | None = field(default=None, repr=False)
    missing_stack_stderr: bytes | None = field(default=None, repr=False)
    calls: list[tuple[tuple[str, ...], dict[str, str], float]] = field(
        default_factory=list
    )
    seed_content: bytes | None = field(default=None, repr=False)

    def __call__(  # noqa: PLR0911
        self,
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
        timeout_seconds: float,
    ) -> CommandResult:
        """Return fixed AWS CLI responses without starting a process."""
        argv = tuple(command)
        child = dict(environment)
        self.calls.append((argv, child, timeout_seconds))
        operation = _operation(argv)
        if operation == self.fail_operation:
            return CommandResult(
                returncode=255,
                stderr=b"synthetic SDK secret diagnostic",
            )
        if argv == (_AWS_PATH, "--version"):
            return CommandResult(returncode=0, stdout=b"aws-cli/2.31.0 synthetic\n")
        if operation == "get-caller-identity":
            return CommandResult(returncode=0, stdout=caller_identity_bytes())
        if operation == "describe-stacks":
            if not self.stack_exists:
                return CommandResult(
                    returncode=255,
                    stderr=(
                        self.missing_stack_stderr
                        if self.missing_stack_stderr is not None
                        else _stack_not_found_stderr()
                    ),
                )
            return CommandResult(
                returncode=0,
                stdout=self.stack_description or description_bytes(mode=self.mode),
            )
        if operation == "get-template":
            if self.get_template_response is not None:
                return CommandResult(
                    returncode=0,
                    stdout=self.get_template_response,
                )
            template = self.stack_template or manager.render_template()
            return CommandResult(
                returncode=0,
                stdout=json.dumps(
                    {
                        "StagesAvailable": ["Original", "Processed"],
                        "TemplateBody": json.loads(template),
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode(),
            )
        if operation == "deploy":
            self.stack_exists = True
            return CommandResult(returncode=0, stdout=b"{}")
        if operation == "transact-write-items":
            uri = argv[argv.index("--transact-items") + 1]
            parsed = urlparse(uri)
            self.seed_content = Path(parsed.path).read_bytes()
            return CommandResult(returncode=0, stdout=b"{}")
        return CommandResult(returncode=0, stdout=b"{}")


@dataclass(slots=True)
class _ConsoleExec:
    calls: list[tuple[str, tuple[str, ...], dict[str, str]]] = field(
        default_factory=list
    )

    def __call__(
        self,
        executable: str,
        arguments: Sequence[str],
        environment: Mapping[str, str],
    ) -> Never:
        """Capture the fixed replacement plan without starting a server."""
        self.calls.append((executable, tuple(arguments), dict(environment)))
        raise SystemExit(_EXEC_SENTINEL)


def test_credential_file_accepts_only_two_literal_bounded_keys() -> None:
    """The existing nonstandard `.env` names are mapped without sourcing it."""
    credentials = manager.load_credential_file(_credential_bytes())

    assert _ACCESS_KEY not in repr(credentials)
    assert _SECRET_KEY not in repr(credentials)
    child = manager.aws_environment(
        credentials,
        region=REGION,
        parent={
            "AWS_PROFILE": "must-not-survive",
            "AWS_SESSION_TOKEN": "must-not-survive",
            "AWS_WEB_IDENTITY_TOKEN_FILE": "/must/not/survive",
            "HOME": "/must/not/survive",
            "LANG": "C.UTF-8",
            "PATH": "/synthetic/bin",
        },
    )
    assert child == {
        "AWS_ACCESS_KEY_ID": _ACCESS_KEY,
        "AWS_CLI_AUTO_PROMPT": "off",
        "AWS_CONFIG_FILE": "/dev/null",
        "AWS_DEFAULT_REGION": REGION,
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_PAGER": "",
        "AWS_REGION": REGION,
        "AWS_SECRET_ACCESS_KEY": _SECRET_KEY,
        "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
        "LANG": "C.UTF-8",
        "PATH": "/synthetic/bin",
    }


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"ACCESS_KEY_ID=one\n",
        _CREDENTIAL_BYTES + b"AWS_PROFILE=personal\n",
        _CREDENTIAL_BYTES + b"ACCESS_KEY_ID=duplicate\n",
        b"export ACCESS_KEY_ID=value\nSECRET_ACCESS_KEY=value\n",
        b"ACCESS_KEY_ID=$(command)\nSECRET_ACCESS_KEY=value\n",
        b"ACCESS_KEY_ID='quoted'\nSECRET_ACCESS_KEY=value\n",
        b"ACCESS_KEY_ID=value\r\nSECRET_ACCESS_KEY=value\r\n",
        b"ACCESS_KEY_ID=value\nSECRET_ACCESS_KEY=value\x00\n",
    ],
)
def test_malformed_credential_files_are_redacted(content: bytes) -> None:
    """Shell syntax, alternate sources, duplicates, and malformed values fail."""
    with pytest.raises(ReferenceTargetError) as captured:
        manager.load_credential_file(content)

    assert captured.value.code is ReferenceTargetFailureCode.INVALID_CREDENTIAL_FILE
    assert _ACCESS_KEY not in str(captured.value)
    assert _SECRET_KEY not in str(captured.value)


def test_deploy_requires_confirmation_before_any_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Even read-only STS is not called before exact typed approval."""
    runner = _AwsRunner()
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)

    exit_code = manager.main(
        _deploy_argv(tmp_path, env_file),
        runner=runner,
        input_fn=lambda _prompt: "no",
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    assert runner.calls == []
    output = capsys.readouterr()
    assert output.out == ""
    assert "approval_required" in output.err
    _assert_redacted(output.err)


def test_deploy_rejects_symlinked_output_before_any_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A configuration path race cannot occur after cloud mutation begins."""
    runner = _AwsRunner()
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    arguments = _deploy_argv(tmp_path, env_file)
    arguments[arguments.index("--output-dir") + 1] = str(linked / "generated")

    exit_code = manager.main(
        arguments,
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DEPLOY"),
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    assert runner.calls == []


def test_deploy_uses_fixed_commands_scrubbed_credentials_and_private_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Deploy/update, seed, and config generation have one fixed command plan."""
    runner = _AwsRunner()
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)
    output_dir = tmp_path / "generated"

    exit_code = manager.main(
        _deploy_argv(tmp_path, env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DEPLOY"),
        environment=_process_environment(),
    )

    assert exit_code == 0
    assert [_operation(call[0]) for call in runner.calls] == [
        "version",
        "get-caller-identity",
        "describe-stacks",
        "deploy",
        "describe-stacks",
        "transact-write-items",
    ]
    for command, child, _timeout in runner.calls:
        serialized = " ".join(command)
        assert _ACCESS_KEY not in serialized
        assert _SECRET_KEY not in serialized
        assert _CANARY_A not in serialized
        assert _CANARY_B not in serialized
        assert child["AWS_ACCESS_KEY_ID"] == _ACCESS_KEY
        assert child["AWS_SECRET_ACCESS_KEY"] == _SECRET_KEY
        assert "AWS_PROFILE" not in child
        assert "AWS_SESSION_TOKEN" not in child
        assert "AWS_WEB_IDENTITY_TOKEN_FILE" not in child
        assert child["AWS_CONFIG_FILE"] == "/dev/null"
        assert child["AWS_SHARED_CREDENTIALS_FILE"] == "/dev/null"
    assert runner.seed_content is not None
    seed = json.loads(runner.seed_content)
    assert [item["Put"]["Item"]["content"]["S"] for item in seed] == [
        _CANARY_A,
        _CANARY_B,
    ]
    suite = (output_dir / "suite.json").read_text(encoding="utf-8")
    policy = (output_dir / "execution-policy.json").read_text(encoding="utf-8")
    assert _CANARY_A not in suite + policy
    assert _CANARY_B not in suite + policy
    captured = capsys.readouterr()
    assert captured.out.splitlines() == [
        *_DEPLOY_PROGRESS,
        "Reference target deployed and configuration generated.",
    ]
    assert captured.err == ""
    _assert_redacted(captured.out)


@pytest.mark.parametrize(
    "prefix",
    [
        b"",
        b"aws: [ERROR]: ",
    ],
)
def test_deploy_accepts_exact_stack_not_found_with_cli_formatting(
    prefix: bytes,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Known CLI presentation cannot hide the exact not-found condition."""
    runner = _AwsRunner(missing_stack_stderr=b"\n" + prefix + _stack_not_found_stderr())
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)

    exit_code = manager.main(
        _deploy_argv(tmp_path, env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DEPLOY"),
        environment=_process_environment(),
    )

    assert exit_code == 0
    describe_command = runner.calls[2][0]
    assert describe_command[-3:] == ("--no-cli-pager", "--color", "off")


@pytest.mark.parametrize(
    "stderr",
    [
        b"",
        b"synthetic access denied",
        _stack_not_found_stderr(stack_name="cai-verify-ref-other"),
        _stack_not_found_stderr() + b"additional diagnostic\n",
        b"aws: [WARNING]: " + _stack_not_found_stderr(),
        b"aws: [ERROR]: synthetic prefix diagnostic\n" + _stack_not_found_stderr(),
        b"\x1b[31m" + _stack_not_found_stderr().rstrip(b"\n") + b"\x1b[0m\n",
    ],
)
def test_deploy_rejects_every_non_exact_stack_not_found_response(
    stderr: bytes,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only one uncolored exact-name not-found line authorizes creation."""
    runner = _AwsRunner(missing_stack_stderr=stderr)
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)

    exit_code = manager.main(
        _deploy_argv(tmp_path, env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DEPLOY"),
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    assert "deploy" not in [_operation(call[0]) for call in runner.calls]


def test_deploy_failure_discards_aws_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI stderr and exception details never become manager output."""
    runner = _AwsRunner(fail_operation="deploy")
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)

    exit_code = manager.main(
        _deploy_argv(tmp_path, env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DEPLOY"),
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    captured = capsys.readouterr()
    assert captured.out.splitlines() == list(_DEPLOY_PROGRESS[:5])
    assert "cloudformation_deploy_failed" in captured.err
    assert "synthetic SDK secret diagnostic" not in captured.err
    _assert_redacted(captured.out)
    _assert_redacted(captured.err)


def test_deploy_rejects_non_not_found_describe_failure_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Only the exact bounded AWS not-found result authorizes stack creation."""
    runner = _AwsRunner(fail_operation="describe-stacks")
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)

    exit_code = manager.main(
        _deploy_argv(tmp_path, env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DEPLOY"),
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    assert [_operation(call[0]) for call in runner.calls] == [
        "version",
        "get-caller-identity",
        "describe-stacks",
    ]
    captured = capsys.readouterr()
    assert captured.out.splitlines() == list(_DEPLOY_PROGRESS[:4])
    assert "cloudformation_stack_lookup_failed" in captured.err
    assert "synthetic SDK secret diagnostic" not in captured.err
    _assert_redacted(captured.out)


@pytest.mark.parametrize(
    "case",
    [
        (
            "get-caller-identity",
            "aws_identity_check_failed",
            _DEPLOY_PROGRESS[:3],
        ),
        (
            "transact-write-items",
            "dynamodb_seed_failed",
            _DEPLOY_PROGRESS[:7],
        ),
    ],
)
def test_deploy_reports_safe_stage_specific_failures(
    case: tuple[str, str, tuple[str, ...]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AWS failures identify the safe stage without returning diagnostics."""
    operation, expected_code, expected_progress = case
    runner = _AwsRunner(fail_operation=operation)
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)

    exit_code = manager.main(
        _deploy_argv(tmp_path, env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DEPLOY"),
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    captured = capsys.readouterr()
    assert captured.out.splitlines() == list(expected_progress)
    assert expected_code in captured.err
    assert "synthetic SDK secret diagnostic" not in captured.err
    _assert_redacted(captured.out + captured.err)


def test_deploy_rejects_unowned_existing_stack_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An existing name is updated only for the exact owned output contract."""
    decoded = json.loads(description_bytes())
    outputs = decoded["Stacks"][0]["Outputs"]
    marker = next(item for item in outputs if item["OutputKey"] == "OwnershipMarker")
    marker["OutputValue"] = "unrelated-stack"
    runner = _AwsRunner(
        stack_exists=True,
        stack_description=json.dumps(decoded).encode(),
    )
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)

    exit_code = manager.main(
        _deploy_argv(tmp_path, env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DEPLOY"),
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    assert [_operation(call[0]) for call in runner.calls] == [
        "version",
        "get-caller-identity",
        "describe-stacks",
        "get-template",
    ]
    assert "invalid_description" in capsys.readouterr().err


def test_deploy_updates_only_existing_stack_with_exact_template_and_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exact template proof precedes every existing-stack update."""
    runner = _AwsRunner(stack_exists=True)
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)

    exit_code = manager.main(
        _deploy_argv(tmp_path, env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DEPLOY"),
        environment=_process_environment(),
    )

    assert exit_code == 0
    assert [_operation(call[0]) for call in runner.calls] == [
        "version",
        "get-caller-identity",
        "describe-stacks",
        "get-template",
        "deploy",
        "describe-stacks",
        "transact-write-items",
    ]


def test_deploy_rejects_existing_stack_with_different_template(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Matching outputs cannot authorize an update to a different template."""
    observed_template = json.loads(manager.render_template())
    observed_template["Description"] = "unrelated stack"
    runner = _AwsRunner(
        stack_exists=True,
        stack_template=json.dumps(observed_template).encode(),
    )
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)

    exit_code = manager.main(
        _deploy_argv(tmp_path, env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DEPLOY"),
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    assert [_operation(call[0]) for call in runner.calls] == [
        "version",
        "get-caller-identity",
        "describe-stacks",
        "get-template",
    ]


@pytest.mark.parametrize("unsafe_mode", [0o640, 0o644, 0o666])
def test_deploy_rejects_credential_file_permissions_before_any_command(
    unsafe_mode: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Credential files must already be owner-only; the manager never chmods them."""
    runner = _AwsRunner()
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)
    env_file.chmod(unsafe_mode)

    exit_code = manager.main(
        _deploy_argv(tmp_path, env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DEPLOY"),
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    assert runner.calls == []
    assert env_file.stat().st_mode & 0o777 == unsafe_mode


def test_deploy_rejects_non_owner_credential_file_before_any_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A credential lease owned by another local user is never read or repaired."""
    runner = _AwsRunner()
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)
    monkeypatch.setattr(os, "getuid", lambda: env_file.stat().st_uid + 1)

    exit_code = manager.main(
        _deploy_argv(tmp_path, env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DEPLOY"),
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    assert runner.calls == []


@pytest.mark.parametrize("kind", ["directory", "symlink"])
def test_deploy_rejects_non_regular_credential_path_before_any_command(
    kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Credential loading never follows a link or accepts a non-file object."""
    runner = _AwsRunner()
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = tmp_path / ".env"
    if kind == "directory":
        env_file.mkdir(mode=0o700)
    else:
        target = tmp_path / "credentials"
        target.write_bytes(_credential_bytes())
        target.chmod(0o600)
        env_file.symlink_to(target)

    exit_code = manager.main(
        _deploy_argv(tmp_path, env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DEPLOY"),
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    assert runner.calls == []


def test_deploy_prepares_private_output_directory_before_aws_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A later AWS failure cannot reveal that the local output target was unusable."""
    runner = _AwsRunner(fail_operation="deploy")
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)
    output_directory = tmp_path / "generated"

    exit_code = manager.main(
        _deploy_argv(tmp_path, env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DEPLOY"),
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    assert output_directory.is_dir()
    assert output_directory.stat().st_mode & 0o777 == _PRIVATE_DIRECTORY_MODE


def test_destroy_checks_identity_and_exact_stack_before_deletion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Destroy targets only one confirmed stack and waits for its deletion."""
    runner = _AwsRunner(stack_exists=True)
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)

    exit_code = manager.main(
        [
            "destroy",
            "--account-id",
            ACCOUNT_ID,
            "--region",
            REGION,
            "--stack-name",
            STACK_NAME,
            "--env-file",
            str(env_file),
        ],
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DESTROY"),
        environment=_process_environment(),
    )

    assert exit_code == 0
    assert [_operation(call[0]) for call in runner.calls] == [
        "version",
        "get-caller-identity",
        "describe-stacks",
        "get-template",
        "delete-stack",
        "wait",
    ]
    delete_command = runner.calls[-2][0]
    assert delete_command[delete_command.index("--stack-name") + 1] == STACK_NAME
    assert "--no-cli-pager" in delete_command


@pytest.mark.parametrize("case", ["missing", "unowned"])
def test_destroy_rejects_missing_or_unowned_stack_before_deletion(
    case: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Destroy never adopts a missing name or an unrelated existing stack."""
    stack_exists = case == "unowned"
    stack_description = None
    if stack_exists:
        decoded = json.loads(description_bytes())
        outputs = decoded["Stacks"][0]["Outputs"]
        marker = next(
            item for item in outputs if item["OutputKey"] == "OwnershipMarker"
        )
        marker["OutputValue"] = "unrelated-stack"
        stack_description = json.dumps(decoded).encode()
    runner = _AwsRunner(
        stack_exists=stack_exists,
        stack_description=stack_description,
    )
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)

    exit_code = manager.main(
        [
            "destroy",
            "--account-id",
            ACCOUNT_ID,
            "--region",
            REGION,
            "--stack-name",
            STACK_NAME,
            "--env-file",
            str(env_file),
        ],
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DESTROY"),
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    expected_operations = [
        "version",
        "get-caller-identity",
        "describe-stacks",
    ]
    if stack_exists:
        expected_operations.append("get-template")
    assert [_operation(call[0]) for call in runner.calls] == expected_operations
    assert "invalid_description" in capsys.readouterr().err


def test_destroy_accepts_failed_terminal_owned_stack_with_exact_template(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failed creation can be cleaned up only with both independent ownership proofs."""
    decoded = json.loads(description_bytes())
    stack = decoded["Stacks"][0]
    stack["StackStatus"] = "ROLLBACK_COMPLETE"
    stack["Outputs"] = []
    stack["Tags"] = [
        {"Key": "Environment", "Value": "sandbox"},
        {"Key": "ExpiresOn", "Value": "2026-08-14"},
        {"Key": "Project", "Value": "cai-verify"},
        {"Key": "Purpose", "Value": "synthetic-reciprocal-retrieval"},
    ]
    runner = _AwsRunner(
        stack_exists=True,
        stack_description=json.dumps(decoded).encode(),
    )
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)

    exit_code = manager.main(
        _destroy_argv(env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DESTROY"),
        environment=_process_environment(),
    )

    assert exit_code == 0
    assert [_operation(call[0]) for call in runner.calls] == [
        "version",
        "get-caller-identity",
        "describe-stacks",
        "get-template",
        "delete-stack",
        "wait",
    ]


@pytest.mark.parametrize(
    "case",
    [
        "wrong-template",
        "duplicate-template-field",
        "partial-template-response",
        "missing-tag",
        "wrong-tag",
        "duplicate-tag",
        "nonterminal-status",
    ],
)
def test_destroy_rejects_failed_stack_without_exact_ownership_proofs(
    case: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Neither a matching name nor a failed state is sufficient deletion authority."""
    decoded = json.loads(description_bytes())
    stack = decoded["Stacks"][0]
    stack["StackStatus"] = (
        "ROLLBACK_IN_PROGRESS" if case == "nonterminal-status" else "ROLLBACK_COMPLETE"
    )
    stack["Outputs"] = []
    stack["Tags"] = [
        {"Key": "Environment", "Value": "sandbox"},
        {"Key": "Project", "Value": "cai-verify"},
        {"Key": "Purpose", "Value": "synthetic-reciprocal-retrieval"},
    ]
    if case == "missing-tag":
        stack["Tags"].pop()
    elif case == "wrong-tag":
        stack["Tags"][0]["Value"] = "production"
    elif case == "duplicate-tag":
        stack["Tags"].append({"Key": "Project", "Value": "cai-verify"})
    stack_template = None
    get_template_response = None
    if case == "wrong-template":
        stack_template_decoded = json.loads(manager.render_template())
        stack_template_decoded["Description"] = "unrelated stack"
        stack_template = json.dumps(stack_template_decoded).encode()
    elif case == "duplicate-template-field":
        get_template_response = (
            b'{"TemplateBody":"{\\"Resources\\":{},\\"Resources\\":{}}"}'
        )
    elif case == "partial-template-response":
        get_template_response = b"{}"
    runner = _AwsRunner(
        stack_exists=True,
        stack_description=json.dumps(decoded).encode(),
        stack_template=stack_template,
        get_template_response=get_template_response,
    )
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)

    exit_code = manager.main(
        _destroy_argv(env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DESTROY"),
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    assert "delete-stack" not in [_operation(call[0]) for call in runner.calls]


def test_destroy_redacts_get_template_failure_before_deletion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Template-read diagnostics are never emitted or treated as ownership proof."""
    runner = _AwsRunner(stack_exists=True, fail_operation="get-template")
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)

    exit_code = manager.main(
        _destroy_argv(env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DESTROY"),
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    assert "delete-stack" not in [_operation(call[0]) for call in runner.calls]
    captured = capsys.readouterr()
    assert captured.out.splitlines() == list(_DESTROY_PROGRESS[:4])
    assert "cloudformation_template_read_failed" in captured.err
    assert "synthetic SDK secret diagnostic" not in captured.err


@pytest.mark.parametrize(
    "case",
    [
        ("delete-stack", "cloudformation_delete_failed", _DESTROY_PROGRESS[:5]),
        (
            "wait",
            "cloudformation_delete_wait_failed",
            _DESTROY_PROGRESS,
        ),
    ],
)
def test_destroy_reports_safe_stage_specific_failures(
    case: tuple[str, str, tuple[str, ...]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Deletion failures remain redacted while identifying their safe stage."""
    operation, expected_code, expected_progress = case
    runner = _AwsRunner(stack_exists=True, fail_operation=operation)
    monkeypatch.setattr(manager, "_aws_cli_path", lambda: _AWS_PATH)
    env_file = _env_file(tmp_path)

    exit_code = manager.main(
        _destroy_argv(env_file),
        runner=runner,
        input_fn=lambda _prompt: _confirmation("DESTROY"),
        environment=_process_environment(),
    )

    assert exit_code == _OPERATIONAL_FAILURE
    captured = capsys.readouterr()
    assert captured.out.splitlines() == list(expected_progress)
    assert expected_code in captured.err
    assert "synthetic SDK secret diagnostic" not in captured.err
    _assert_redacted(captured.out + captured.err)


def test_generate_is_local_and_never_calls_runner(tmp_path: Path) -> None:
    """Saved stack-output normalization is entirely offline."""
    description = tmp_path / "description.json"
    description.write_bytes(description_bytes())
    runner = _AwsRunner()

    exit_code = manager.main(
        [
            "generate",
            "--account-id",
            ACCOUNT_ID,
            "--region",
            REGION,
            "--stack-name",
            STACK_NAME,
            "--description",
            str(description),
            "--output-dir",
            str(tmp_path / "generated"),
        ],
        runner=runner,
    )

    assert exit_code == 0
    assert runner.calls == []


def test_ui_launch_contains_credentials_without_exposing_them_in_argv(
    tmp_path: Path,
) -> None:
    """The credentialed console always requires a manual browser handoff."""
    env_file = _env_file(tmp_path)
    config_directory = tmp_path / "generated"
    descriptor = load_deployment_description(
        description_bytes(),
        expected_account_id=ACCOUNT_ID,
        expected_region=REGION,
        expected_stack_name=STACK_NAME,
    )
    write_configuration(config_directory, generate_configuration(descriptor))
    console_exec = _ConsoleExec()

    with pytest.raises(SystemExit) as captured:
        manager.main(
            [
                "ui",
                "--account-id",
                ACCOUNT_ID,
                "--region",
                REGION,
                "--stack-name",
                STACK_NAME,
                "--env-file",
                str(env_file),
                "--config-dir",
                str(config_directory),
                "--evidence-root",
                str(tmp_path / "runs"),
                "--port",
                "0",
            ],
            input_fn=lambda _prompt: _confirmation("LAUNCH"),
            environment=_process_environment(),
            exec_fn=console_exec,
        )

    assert captured.value.code == _EXEC_SENTINEL
    assert len(console_exec.calls) == 1
    executable, arguments, child = console_exec.calls[0]
    assert executable == arguments[0]
    assert arguments[1:4] == ("-m", "cai_verify", "ui")
    assert arguments.count("--no-open") == 1
    serialized = " ".join(arguments)
    assert _ACCESS_KEY not in serialized
    assert _SECRET_KEY not in serialized
    assert _CANARY_A not in serialized
    assert _CANARY_B not in serialized
    assert child["AWS_ACCESS_KEY_ID"] == _ACCESS_KEY
    assert child["AWS_SECRET_ACCESS_KEY"] == _SECRET_KEY
    assert child["CAI_REQUESTER_A_CANARY"] == _CANARY_A
    assert child["CAI_REQUESTER_B_CANARY"] == _CANARY_B
    suite_bytes = (config_directory / "suite.json").read_bytes()
    policy_bytes = (config_directory / "execution-policy.json").read_bytes()
    assert (
        child["CAI_VERIFY_UI_SUITE_SHA256"] == hashlib.sha256(suite_bytes).hexdigest()
    )
    assert (
        child["CAI_VERIFY_UI_POLICY_SHA256"] == hashlib.sha256(policy_bytes).hexdigest()
    )
    assert suite_bytes.decode() not in serialized
    assert policy_bytes.decode() not in serialized
    assert "AWS_PROFILE" not in child
    assert "AWS_SESSION_TOKEN" not in child


@pytest.mark.parametrize(
    "case",
    [
        "endpoint-host",
        "endpoint-path",
        "session-name",
        "log-group",
        "action-contract",
        "probe-contract",
    ],
)
def test_ui_rejects_configuration_outside_fixed_reference_contract(
    case: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Self-authorized files cannot widen the deterministic stack contract."""
    env_file = _env_file(tmp_path)
    config_directory = tmp_path / "generated"
    suite, policy = _generated_configuration_payloads()
    target = cast("dict[str, Any]", suite["target"])
    identities = cast("list[dict[str, Any]]", suite["identities"])
    scenario = cast("list[dict[str, Any]]", suite["scenarios"])[0]
    actions = cast("list[dict[str, Any]]", scenario["actions"])
    probes = cast("list[dict[str, Any]]", scenario["probes"])
    if case == "endpoint-host":
        target["endpoint"] = "https://example.test/sandbox"
        target["allowedHosts"] = ["example.test"]
        policy["applicationEndpoint"] = "https://example.test/sandbox"
    elif case == "endpoint-path":
        host = cast("list[str]", target["allowedHosts"])[0]
        target["endpoint"] = f"https://{host}/different-stage"
        policy["applicationEndpoint"] = f"https://{host}/different-stage"
    elif case == "session-name":
        identities[0]["sessionName"] = "different-fixed-session"
    elif case == "log-group":
        wrong_log_group = f"/aws/cai-verify/reference/{STACK_NAME}-other"
        for probe in probes:
            probe["logGroup"] = wrong_log_group
        policy["cloudwatchLogGroups"] = [wrong_log_group]
    elif case == "action-contract":
        actions[0]["timeoutSeconds"] = 14
    elif case == "probe-contract":
        probes[0]["maxAge"] = "PT2M"
    else:  # pragma: no cover - the parameter list is closed above.
        raise AssertionError
    _write_configuration_payloads(config_directory, suite=suite, policy=policy)
    console_exec = _ConsoleExec()

    exit_code = manager.main(
        [
            "ui",
            "--account-id",
            ACCOUNT_ID,
            "--region",
            REGION,
            "--stack-name",
            STACK_NAME,
            "--env-file",
            str(env_file),
            "--config-dir",
            str(config_directory),
            "--evidence-root",
            str(tmp_path / "runs"),
        ],
        input_fn=lambda _prompt: _confirmation("LAUNCH"),
        environment=_process_environment(),
        exec_fn=console_exec,
    )

    assert exit_code == _OPERATIONAL_FAILURE
    assert console_exec.calls == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "invalid_generated_configuration" in captured.err
    _assert_redacted(captured.err)


def _credential_bytes() -> bytes:
    return _CREDENTIAL_BYTES


def _env_file(tmp_path: Path) -> Path:
    path = tmp_path / ".env"
    path.write_bytes(_credential_bytes())
    path.chmod(0o600)
    return path


def _generated_configuration_payloads() -> tuple[dict[str, object], dict[str, object]]:
    descriptor = load_deployment_description(
        description_bytes(),
        expected_account_id=ACCOUNT_ID,
        expected_region=REGION,
        expected_stack_name=STACK_NAME,
    )
    generated = generate_configuration(descriptor)
    suite = json.loads(generated.suite)
    policy = json.loads(generated.execution_policy)
    assert isinstance(suite, dict)
    assert isinstance(policy, dict)
    return suite, policy


def _write_configuration_payloads(
    directory: Path,
    *,
    suite: dict[str, object],
    policy: dict[str, object],
) -> None:
    directory.mkdir(mode=0o700)
    for name, payload in (
        ("suite.json", suite),
        ("execution-policy.json", policy),
    ):
        path = directory / name
        path.write_text(
            json.dumps(payload, allow_nan=False, separators=(",", ":")),
            encoding="utf-8",
        )
        path.chmod(0o600)


def _process_environment() -> dict[str, str]:
    return {
        "AWS_PROFILE": "ambient-profile-must-not-survive",
        "AWS_SESSION_TOKEN": "ambient-token-must-not-survive",
        "AWS_WEB_IDENTITY_TOKEN_FILE": "/ambient/must/not/survive",
        "CAI_REQUESTER_A_CANARY": _CANARY_A,
        "CAI_REQUESTER_B_CANARY": _CANARY_B,
        "LANG": "C.UTF-8",
        "PATH": "/synthetic/bin",
    }


def _deploy_argv(tmp_path: Path, env_file: Path) -> list[str]:
    return [
        "deploy",
        "--account-id",
        ACCOUNT_ID,
        "--region",
        REGION,
        "--stack-name",
        STACK_NAME,
        "--mode",
        "isolated",
        "--env-file",
        str(env_file),
        "--output-dir",
        str(tmp_path / "generated"),
    ]


def _destroy_argv(env_file: Path) -> list[str]:
    return [
        "destroy",
        "--account-id",
        ACCOUNT_ID,
        "--region",
        REGION,
        "--stack-name",
        STACK_NAME,
        "--env-file",
        str(env_file),
    ]


def _confirmation(operation: str) -> str:
    return f"{operation} {ACCOUNT_ID} {REGION} {STACK_NAME}"


def _operation(command: Sequence[str]) -> str:
    if command == (_AWS_PATH, "--version"):
        return "version"
    if "sts" in command:
        return command[command.index("sts") + 1]
    if "cloudformation" in command:
        return command[command.index("cloudformation") + 1]
    if "dynamodb" in command:
        return command[command.index("dynamodb") + 1]
    return "unknown"


def _assert_redacted(value: str) -> None:
    assert _ACCESS_KEY not in value
    assert _SECRET_KEY not in value
    assert _CANARY_A not in value
    assert _CANARY_B not in value
    assert ACCOUNT_ID not in value
    assert STACK_NAME not in value
