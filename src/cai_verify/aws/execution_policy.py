"""Strict operator-owned authorization for the bounded AWS execution surface."""

from __future__ import annotations

import json
import re
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal, Self, final

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from cai_verify.aws.identity import _partition_for_region
from cai_verify.config import AssumedRoleIdentity, CurrentAwsIdentity

if TYPE_CHECKING:
    import os
    from collections.abc import Iterable

    from cai_verify.config import AwsSigV4Action, Identity, Target

AWS_EXECUTION_POLICY_SCHEMA_VERSION = "1alpha1"
AWS_EXECUTION_POLICY_SCHEMA_ID = (
    "https://schemas.cai-verify.dev/aws-execution-policy/1alpha1/schema.json"
)
MAX_AWS_EXECUTION_POLICY_BYTES = 64 * 1024

_AWS_REGION_PATTERN = r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$"
_AWS_ACCOUNT_PATTERN = r"^\d{12}$"
_AWS_ROLE_ARN_PATTERN = (
    r"^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/"
    r"[A-Za-z0-9+=,.@_/-]{1,512}$"
)
_ACTION_PATH_PATTERN = r"^/[A-Za-z0-9._~!:@&'+,;=%/-]*$"
_HTTPS_ENDPOINT_SCHEMA_PATTERN = r"^https://[^/?#@]+(?:/[^?#]*)?$"
_LOG_GROUP_PATTERN = r"^[A-Za-z0-9_./#-]{1,512}$"
_ROLE_ARN = re.compile(
    r"arn:(?P<partition>aws|aws-us-gov|aws-cn):iam::"
    r"(?P<account>\d{12}):role/.+\Z"
)
_FORBIDDEN_EXACT_SYNTAX = re.compile(r"[*?\[\]{}()|\\^$]")

type AwsPolicyRegion = Annotated[
    str,
    StringConstraints(strict=True, pattern=_AWS_REGION_PATTERN),
]
type AwsPolicyAccountId = Annotated[
    str,
    StringConstraints(strict=True, pattern=_AWS_ACCOUNT_PATTERN),
]
type AwsPolicyRoleArn = Annotated[
    str,
    StringConstraints(strict=True, pattern=_AWS_ROLE_ARN_PATTERN),
]
type AwsPolicyActionPath = Annotated[
    str,
    StringConstraints(strict=True, pattern=_ACTION_PATH_PATTERN, max_length=2048),
]
type AwsPolicyLogGroup = Annotated[
    str,
    StringConstraints(strict=True, pattern=_LOG_GROUP_PATTERN),
]


def _to_camel(name: str) -> str:
    first, *rest = name.split("_")
    return first + "".join(part.capitalize() for part in rest)


class _StrictPolicyModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=_to_camel,
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        validate_default=True,
    )

    def __repr_args__(self) -> list[tuple[str | None, object]]:
        """Keep operator policy values out of incidental representations."""
        return []


@final
class AwsExecutionPolicyAction(_StrictPolicyModel):
    """One exact non-mutating application action authorization."""

    method: Literal["GET", "POST"] = Field(repr=False)
    path: AwsPolicyActionPath = Field(repr=False)
    service: Literal["execute-api", "bedrock-runtime"] = Field(repr=False)

    @field_validator("path")
    @classmethod
    def require_exact_path(cls, value: str) -> str:
        """Reject expression, glob, wildcard, and regex-shaped paths."""
        if _FORBIDDEN_EXACT_SYNTAX.search(value) is not None:
            message = "execution-policy action paths must be exact"
            raise ValueError(message)
        return value


@final
class AwsExecutionPolicy(_StrictPolicyModel):
    """Versioned exact-match boundary independently owned by the operator."""

    model_config = ConfigDict(
        alias_generator=_to_camel,
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "$id": AWS_EXECUTION_POLICY_SCHEMA_ID,
            "$schema": "https://json-schema.org/draft/2020-12/schema",
        },
        populate_by_name=False,
        serialize_by_alias=True,
        title="AWS Execution Policy 1alpha1",
        validate_default=True,
    )

    schema_version: Literal["1alpha1"] = Field(repr=False)
    aws_account_id: AwsPolicyAccountId = Field(repr=False)
    partition: Literal["aws", "aws-us-gov", "aws-cn"] = Field(repr=False)
    region: AwsPolicyRegion = Field(repr=False)
    application_endpoint: AnyHttpUrl = Field(
        repr=False,
        json_schema_extra={"pattern": _HTTPS_ENDPOINT_SCHEMA_PATTERN},
    )
    actions: tuple[AwsExecutionPolicyAction, ...] = Field(
        json_schema_extra={"uniqueItems": True},
        min_length=1,
        repr=False,
    )
    assumed_role_arns: tuple[AwsPolicyRoleArn, ...] = Field(
        repr=False,
        json_schema_extra={"uniqueItems": True},
    )
    allow_current_identity: bool = Field(default=False, repr=False, strict=True)
    cloudwatch_log_groups: tuple[AwsPolicyLogGroup, ...] = Field(
        json_schema_extra={"uniqueItems": True},
        min_length=1,
        repr=False,
    )

    @field_validator("application_endpoint")
    @classmethod
    def require_normalized_https_endpoint(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        """Accept only one normalized HTTPS endpoint without request data."""
        if (
            value.scheme != "https"
            or value.username is not None
            or value.password is not None
            or value.query is not None
            or value.fragment is not None
            or _FORBIDDEN_EXACT_SYNTAX.search(str(value)) is not None
        ):
            message = "execution-policy endpoint must be normalized HTTPS"
            raise ValueError(message)
        return value

    @field_validator("application_endpoint", mode="before")
    @classmethod
    def reject_noncanonical_endpoint_text(cls, value: object) -> object:
        """Require the JSON string itself to equal its normalized URL form."""
        if type(value) is not str:
            return value
        try:
            normalized = str(AnyHttpUrl(value))
        except ValueError:
            return value
        if value != normalized:
            message = "execution-policy endpoint must use canonical URL text"
            raise ValueError(message)
        return value

    @field_validator("assumed_role_arns")
    @classmethod
    def role_arns_are_unique(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Keep the exact role authorization set unambiguous."""
        _require_unique(values)
        return values

    @field_validator("actions")
    @classmethod
    def actions_are_unique(
        cls,
        values: tuple[AwsExecutionPolicyAction, ...],
    ) -> tuple[AwsExecutionPolicyAction, ...]:
        """Reject duplicate exact action authorizations."""
        keys = tuple((item.method, item.path, item.service) for item in values)
        _require_unique(keys)
        return values

    @field_validator("cloudwatch_log_groups")
    @classmethod
    def log_groups_are_unique_and_exact(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Reject duplicate or expression-shaped evidence sources."""
        _require_unique(values)
        if any(_FORBIDDEN_EXACT_SYNTAX.search(value) is not None for value in values):
            message = "execution-policy log groups must be exact"
            raise ValueError(message)
        return values

    @model_validator(mode="after")
    def require_one_account_and_partition(self) -> Self:
        """Bind the region and every role to the policy's exact AWS boundary."""
        if self.partition != _partition_for_region(self.region):
            message = "execution-policy partition does not match its region"
            raise ValueError(message)
        for role_arn in self.assumed_role_arns:
            match = _ROLE_ARN.fullmatch(role_arn)
            if (
                match is None
                or match.group("partition") != self.partition
                or match.group("account") != self.aws_account_id
            ):
                message = "execution-policy role is outside its AWS boundary"
                raise ValueError(message)
        return self


class AwsExecutionPolicyFailureCode(StrEnum):
    """Fixed categories that never include operator policy values."""

    INVALID_EXECUTION_POLICY = "invalid_execution_policy"
    EXECUTION_POLICY_DENIED = "execution_policy_denied"
    UNAUTHORIZED_ACCOUNT = "unauthorized_account"
    UNAUTHORIZED_PARTITION = "unauthorized_partition"
    UNAUTHORIZED_REGION = "unauthorized_region"
    UNAUTHORIZED_ENDPOINT = "unauthorized_endpoint"
    UNAUTHORIZED_ACTION = "unauthorized_action"
    UNAUTHORIZED_IDENTITY = "unauthorized_identity"
    UNAUTHORIZED_EVIDENCE_SOURCE = "unauthorized_evidence_source"


class AwsExecutionPolicyError(RuntimeError):
    """One redacted execution-policy validation or authorization failure."""

    def __init__(self, code: AwsExecutionPolicyFailureCode) -> None:
        """Construct an error containing only its stable category."""
        self.code = code
        super().__init__(f"AWS execution policy rejected the operation ({code.value})")


def load_aws_execution_policy(
    path: str | os.PathLike[str],
) -> AwsExecutionPolicy:
    """Load bounded duplicate-free UTF-8 JSON without leaking its contents."""
    try:
        policy_path = Path(path)
        with policy_path.open("rb") as stream:
            content = stream.read(MAX_AWS_EXECUTION_POLICY_BYTES + 1)
        _require_policy_size(content)
        utf8 = content.decode("utf-8")
        decoded = json.loads(
            utf8,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
        return AwsExecutionPolicy.model_validate(decoded)
    except Exception:  # noqa: BLE001 - paths, values, and parser text are sensitive.
        raise AwsExecutionPolicyError(
            AwsExecutionPolicyFailureCode.INVALID_EXECUTION_POLICY
        ) from None


def authorize_aws_execution(  # noqa: C901, PLR0912 - exact checks stay explicit.
    policy: AwsExecutionPolicy,
    *,
    target: Target,
    identities: Iterable[Identity],
    actions: Iterable[AwsSigV4Action] = (),
    cloudwatch_log_groups: Iterable[str] = (),
) -> None:
    """Authorize one fixed AWS plan using exact comparisons only."""
    if type(policy) is not AwsExecutionPolicy:
        raise AwsExecutionPolicyError(
            AwsExecutionPolicyFailureCode.INVALID_EXECUTION_POLICY
        )
    account_id = target.aws_account_id
    if account_id is None or account_id != policy.aws_account_id:
        raise AwsExecutionPolicyError(
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_ACCOUNT
        )
    region = target.aws_region
    if region is None or region != policy.region:
        raise AwsExecutionPolicyError(AwsExecutionPolicyFailureCode.UNAUTHORIZED_REGION)
    expected_partition = _partition_for_region(region)
    if expected_partition != policy.partition:
        raise AwsExecutionPolicyError(
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_PARTITION
        )
    endpoint = target.endpoint
    if (
        endpoint.scheme != "https"
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.query is not None
        or endpoint.fragment is not None
        or str(endpoint) != str(policy.application_endpoint)
    ):
        raise AwsExecutionPolicyError(
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_ENDPOINT
        )

    permitted_roles = frozenset(policy.assumed_role_arns)
    for identity in identities:
        if isinstance(identity, CurrentAwsIdentity):
            if not policy.allow_current_identity:
                raise AwsExecutionPolicyError(
                    AwsExecutionPolicyFailureCode.UNAUTHORIZED_IDENTITY
                )
            continue
        if not isinstance(identity, AssumedRoleIdentity):
            raise AwsExecutionPolicyError(
                AwsExecutionPolicyFailureCode.EXECUTION_POLICY_DENIED
            )
        match = _ROLE_ARN.fullmatch(identity.role_arn)
        if match is None or match.group("account") != account_id:
            raise AwsExecutionPolicyError(
                AwsExecutionPolicyFailureCode.UNAUTHORIZED_ACCOUNT
            )
        if match.group("partition") != expected_partition:
            raise AwsExecutionPolicyError(
                AwsExecutionPolicyFailureCode.UNAUTHORIZED_PARTITION
            )
        if identity.role_arn not in permitted_roles:
            raise AwsExecutionPolicyError(
                AwsExecutionPolicyFailureCode.UNAUTHORIZED_IDENTITY
            )

    permitted_actions = frozenset(
        (item.method, item.path, item.service) for item in policy.actions
    )
    for action in actions:
        if action.region is not None and action.region != region:
            raise AwsExecutionPolicyError(
                AwsExecutionPolicyFailureCode.UNAUTHORIZED_REGION
            )
        key = (action.method.value, action.path, action.service)
        if key not in permitted_actions:
            raise AwsExecutionPolicyError(
                AwsExecutionPolicyFailureCode.UNAUTHORIZED_ACTION
            )

    permitted_log_groups = frozenset(policy.cloudwatch_log_groups)
    if any(
        log_group not in permitted_log_groups for log_group in cloudwatch_log_groups
    ):
        raise AwsExecutionPolicyError(
            AwsExecutionPolicyFailureCode.UNAUTHORIZED_EVIDENCE_SOURCE
        )


def aws_execution_policy_json_schema() -> dict[str, Any]:
    """Return the canonical Draft 2020-12 execution-policy schema."""
    return AwsExecutionPolicy.model_json_schema(by_alias=True, mode="validation")


def _require_unique(values: Iterable[object]) -> None:
    seen: set[object] = set()
    for value in values:
        if value in seen:
            message = "execution-policy collections must not contain duplicates"
            raise ValueError(message)
        seen.add(value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            message = "execution-policy JSON fields must be unique"
            raise ValueError(message)
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def _require_policy_size(content: bytes) -> None:
    if len(content) > MAX_AWS_EXECUTION_POLICY_BYTES:
        raise ValueError
