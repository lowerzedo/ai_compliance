"""Pydantic models for verification-suite schema version ``1alpha1``.

Suite files are untrusted input. These models consequently forbid unknown
fields, avoid credential-shaped scalar fields, expose only fixed action and
assertion vocabularies, and perform reference validation before a future
planner or executor can consume the configuration.
"""

from __future__ import annotations

import json
import re
from datetime import date  # noqa: TC003 - Pydantic resolves model fields at runtime.
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Any, Literal, Self, final

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StrictBool,
    StrictInt,
    StringConstraints,
    field_validator,
    model_validator,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

SUITE_SCHEMA_VERSION = "1alpha1"
SUITE_SCHEMA_ID = (
    "https://schemas.cai-verify.dev/verification-suite/1alpha1/schema.json"
)
REDACTED = "[REDACTED]"
_SECONDS_PER_MINUTE = 60
_MAX_CLOCK_SKEW_SECONDS = 5 * _SECONDS_PER_MINUTE
_MAX_FRESHNESS_SECONDS = 24 * 60 * _SECONDS_PER_MINUTE

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"
_ENVIRONMENT_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]{0,127}$"
_AWS_REGION_PATTERN = r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$"
_AWS_ACCOUNT_PATTERN = r"^\d{12}$"
_AWS_ROLE_ARN_PATTERN = (
    r"^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/"
    r"[A-Za-z0-9+=,.@_/-]{1,512}$"
)
_HOST_PATTERN = (
    r"^(?:localhost|(?:[a-z0-9](?:[a-z0-9-]{0,61}"
    r"[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$"
)
_PATH_PATTERN = r"^/(?:$|[^/\s?#][^\s?#]*)$"
_HEADER_NAME_PATTERN = r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$"
_INPUT_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
_FRESHNESS_PATTERN = re.compile(
    r"PT(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?\Z"
)
_SENSITIVE_NAME_PATTERN = re.compile(
    r"(?:authorization|cookie|credential|password|private[-_.]?key|secret|token|"
    r"api[-_.]?key)",
    re.IGNORECASE,
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"bearer\s+\S+", re.IGNORECASE),
    re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
)
_SENSITIVE_ALIAS_PATTERN = re.compile(
    r"(?:^|-)(?:account|arn|credential|password|secret|tenant|token)(?:-|$)"
    r"|\d{12}",
)

type Identifier = Annotated[
    str,
    StringConstraints(strict=True, pattern=_IDENTIFIER_PATTERN),
]
type NonEmptyString = Annotated[
    str,
    StringConstraints(
        strict=True, strip_whitespace=True, min_length=1, max_length=4096
    ),
]
type FreshnessString = Annotated[
    str,
    StringConstraints(
        strict=True,
        pattern=r"^PT(?:\d+H)?(?:\d+M)?(?:\d+S)?$",
        max_length=32,
    ),
]
type EnvironmentName = Annotated[
    str,
    StringConstraints(strict=True, pattern=_ENVIRONMENT_PATTERN),
]
type AwsRegion = Annotated[
    str,
    StringConstraints(strict=True, pattern=_AWS_REGION_PATTERN),
]
type AwsAccountId = Annotated[
    str,
    StringConstraints(strict=True, pattern=_AWS_ACCOUNT_PATTERN),
]
type AwsRoleArn = Annotated[
    str,
    StringConstraints(strict=True, pattern=_AWS_ROLE_ARN_PATTERN),
]
type Hostname = Annotated[
    str,
    StringConstraints(
        strict=True,
        to_lower=True,
        pattern=_HOST_PATTERN,
        max_length=253,
    ),
]
type RelativeHttpPath = Annotated[
    str,
    StringConstraints(strict=True, pattern=_PATH_PATTERN, max_length=2048),
]
type InputName = Annotated[
    str,
    StringConstraints(strict=True, pattern=_INPUT_NAME_PATTERN),
]
type HeaderName = Annotated[
    str,
    StringConstraints(strict=True, pattern=_HEADER_NAME_PATTERN),
]
type PositiveTimeout = Annotated[StrictInt, Field(ge=1, le=60)]
type SafeModelAliasValue = Annotated[
    str,
    StringConstraints(
        strict=True,
        pattern=r"^[a-z][a-z0-9-]{0,63}$",
    ),
]


def _to_camel(name: str) -> str:
    first, *rest = name.split("_")
    return first + "".join(part.capitalize() for part in rest)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=_to_camel,
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        validate_default=True,
    )


class DeploymentEnvironment(StrEnum):
    """Explicit deployment classes accepted by the alpha schema."""

    LOCAL = "local"
    SANDBOX = "sandbox"
    DEVELOPMENT = "development"
    STAGING = "staging"


class HttpMethod(StrEnum):
    """Application methods supported by the non-executing schema."""

    GET = "GET"
    POST = "POST"


class InputLocation(StrEnum):
    """Fixed request locations for declared action inputs."""

    HEADER = "header"
    QUERY = "query"
    JSON = "json"


class ObservationKind(StrEnum):
    """Normalized observations that an alpha probe may request."""

    BEDROCK_INVOCATION = "bedrockInvocation"
    PROVIDER_INVOCATION = "providerInvocation"
    TELEMETRY_CANARY = "telemetryCanary"
    AUDIT_EVENT = "auditEvent"
    ENCRYPTION_STATE = "encryptionState"


class EncryptionScope(StrEnum):
    """Encryption conditions supported by the fixed evaluator vocabulary."""

    AT_REST = "atRest"
    IN_TRANSIT = "inTransit"


class ResponsibleParty(StrEnum):
    """Parties whose responsibilities bound a control mapping."""

    VERIFIER = "verifier"
    CLOUD_PROVIDER = "cloudProvider"
    CUSTOMER = "customer"


class EnvironmentReference(_StrictModel):
    """An explicit reference to a value supplied through the environment."""

    source: Literal["environment"]
    name: EnvironmentName


class LiteralInput(_StrictModel):
    """A declared non-secret, JSON-compatible action input."""

    source: Literal["literal"]
    value: JsonValue
    sensitive: Literal[False]

    @field_validator("value")
    @classmethod
    def reject_credential_shaped_values(cls, value: JsonValue) -> JsonValue:
        """Reject common credential encodings even when mislabeled public."""
        try:
            encoded = json.dumps(value, allow_nan=False, ensure_ascii=False)
        except (TypeError, ValueError) as error:
            message = "literal input must contain a finite JSON value"
            raise ValueError(message) from error
        if any(pattern.search(encoded) for pattern in _SECRET_VALUE_PATTERNS):
            message = "credential-shaped values must use an environment reference"
            raise ValueError(message)
        return value


class SafeModelAlias(_StrictModel):
    """An explicitly public bounded label for a sensitive Bedrock model ID."""

    source: Literal["literal"]
    value: SafeModelAliasValue
    sensitive: Literal[False]

    @field_validator("value")
    @classmethod
    def reject_identifier_shaped_aliases(cls, value: str) -> str:
        """Reject obvious tenant and secret identifiers from normalized aliases."""
        if _SENSITIVE_ALIAS_PATTERN.search(value) is not None:
            message = "model alias must not contain sensitive identifier material"
            raise ValueError(message)
        return value


class BedrockInvocationDeclaration(_StrictModel):
    """Declare an opaque Bedrock model comparison and optional safe alias."""

    model_id: EnvironmentReference
    model_alias: SafeModelAlias | None = None


type InputValue = Annotated[
    LiteralInput | EnvironmentReference,
    Field(discriminator="source"),
]


class ActionInput(_StrictModel):
    """One explicitly sourced input for an HTTP-family action."""

    location: InputLocation
    name: InputName | HeaderName
    value: InputValue

    @model_validator(mode="after")
    def require_environment_for_sensitive_names(self) -> Self:
        """Prevent secret-bearing request fields from accepting literals."""
        if _SENSITIVE_NAME_PATTERN.search(self.name) and isinstance(
            self.value, LiteralInput
        ):
            message = f"sensitive input {self.name!r} must use an environment reference"
            raise ValueError(message)
        return self


class SuiteMetadata(_StrictModel):
    """Human-readable identity for one verification suite."""

    name: Identifier
    description: NonEmptyString
    owners: tuple[NonEmptyString, ...] = Field(min_length=1)

    @field_validator("owners")
    @classmethod
    def owners_are_unique(
        cls,
        owners: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Keep ownership metadata unambiguous."""
        _require_unique(owners, item_kind="metadata owner")
        return owners


class Target(_StrictModel):
    """A bounded application endpoint and optional AWS deployment context."""

    id: Identifier
    environment: DeploymentEnvironment
    endpoint: AnyHttpUrl
    allowed_hosts: tuple[Hostname, ...] = Field(min_length=1)
    aws_region: AwsRegion | None = None
    aws_account_id: AwsAccountId | None = None

    @field_validator("endpoint")
    @classmethod
    def require_https_except_local(cls, endpoint: AnyHttpUrl) -> AnyHttpUrl:
        """Disallow cleartext remote endpoints and literal URL credentials."""
        if endpoint.username is not None or endpoint.password is not None:
            message = "target endpoint must not contain literal credentials"
            raise ValueError(message)
        if endpoint.scheme == "http" and endpoint.host != "localhost":
            message = "target endpoint must use HTTPS unless it is localhost"
            raise ValueError(message)
        return endpoint

    @model_validator(mode="after")
    def require_endpoint_allowlist_match(self) -> Self:
        """Require the endpoint host to be declared in the target allowlist."""
        if self.endpoint.host not in self.allowed_hosts:
            message = "target endpoint host must appear in allowedHosts"
            raise ValueError(message)
        if self.environment is DeploymentEnvironment.LOCAL:
            if self.endpoint.host != "localhost":
                message = "local targets must use the localhost hostname"
                raise ValueError(message)
            if self.aws_region is not None or self.aws_account_id is not None:
                message = "local targets must not declare AWS deployment fields"
                raise ValueError(message)
        elif self.aws_region is None or self.aws_account_id is None:
            message = "non-local targets must declare awsRegion and awsAccountId"
            raise ValueError(message)
        return self


class CurrentAwsIdentity(_StrictModel):
    """Use the process's already-scoped AWS credential provider chain."""

    id: Identifier
    type: Literal["awsCurrent"]
    profile: EnvironmentReference | None = None


class AssumedRoleIdentity(_StrictModel):
    """Assume one declared AWS role without accepting literal credentials."""

    id: Identifier
    type: Literal["awsAssumeRole"]
    role_arn: AwsRoleArn
    session_name: Annotated[
        str,
        StringConstraints(
            strict=True,
            pattern=r"^[\w+=,.@-]{2,64}$",
        ),
    ]
    external_id: EnvironmentReference | None = None


class SyntheticLocalIdentity(_StrictModel):
    """A non-secret principal for the loopback-only synthetic application."""

    id: Identifier
    type: Literal["syntheticLocal"]
    principal: Identifier


type Identity = Annotated[
    CurrentAwsIdentity | AssumedRoleIdentity | SyntheticLocalIdentity,
    Field(discriminator="type"),
]


class EvidencePolicy(_StrictModel):
    """Suite-wide freshness and source-clock constraints."""

    max_age: FreshnessString
    clock_skew_tolerance: FreshnessString = "PT30S"

    @field_validator("max_age")
    @classmethod
    def validate_max_age(cls, value: str) -> str:
        """Require a positive freshness duration no longer than one day."""
        _freshness_seconds(value, allow_zero=False)
        return value

    @field_validator("clock_skew_tolerance")
    @classmethod
    def validate_clock_skew(cls, value: str) -> str:
        """Require a bounded, non-negative source-clock tolerance."""
        seconds = _freshness_seconds(value, allow_zero=True)
        if seconds > _MAX_CLOCK_SKEW_SECONDS:
            message = "clockSkewTolerance cannot exceed PT5M"
            raise ValueError(message)
        return value


class _BaseAction(_StrictModel):
    id: Identifier
    identity_ref: Identifier | None = None
    method: HttpMethod
    path: RelativeHttpPath
    inputs: tuple[ActionInput, ...] = ()
    timeout_seconds: PositiveTimeout = 30
    mutating: StrictBool = False

    @field_validator("inputs")
    @classmethod
    def input_destinations_are_unique(
        cls,
        inputs: tuple[ActionInput, ...],
    ) -> tuple[ActionInput, ...]:
        keys = (f"{item.location.value}:{item.name.lower()}" for item in inputs)
        _require_unique(keys, item_kind="action input destination")
        return inputs


class HttpAction(_BaseAction):
    """A bounded unsigned HTTP application request declaration."""

    type: Literal["http"]


class AwsSigV4Action(_BaseAction):
    """An HTTP application request signed for one allowed AWS service."""

    type: Literal["awsSigV4"]
    service: Literal["execute-api", "bedrock-runtime"]
    region: AwsRegion | None = None


type Action = Annotated[
    HttpAction | AwsSigV4Action,
    Field(discriminator="type"),
]


class _BaseProbe(_StrictModel):
    id: Identifier
    identity_ref: Identifier | None = None
    action_ref: Identifier
    observations: tuple[ObservationKind, ...] = Field(min_length=1)
    max_age: FreshnessString | None = None

    @field_validator("observations")
    @classmethod
    def observations_are_unique(
        cls,
        observations: tuple[ObservationKind, ...],
    ) -> tuple[ObservationKind, ...]:
        _require_unique(observations, item_kind="probe observation")
        return observations

    @field_validator("max_age")
    @classmethod
    def validate_freshness_override(cls, value: str | None) -> str | None:
        if value is not None:
            _freshness_seconds(value, allow_zero=False)
        return value


class CloudWatchLogsProbe(_BaseProbe):
    """Collect normalized observations from one CloudWatch log group."""

    type: Literal["cloudWatchLogs"]
    log_group: Annotated[
        str,
        StringConstraints(strict=True, pattern=r"^[A-Za-z0-9_./#-]{1,512}$"),
    ]
    canary: EnvironmentReference | None = None
    bedrock: BedrockInvocationDeclaration | None = None

    @field_validator("observations")
    @classmethod
    def observations_are_cloudwatch_logs(
        cls,
        observations: tuple[ObservationKind, ...],
    ) -> tuple[ObservationKind, ...]:
        """Keep the built-in CloudWatch normalization surface fixed."""
        supported = {
            ObservationKind.BEDROCK_INVOCATION,
            ObservationKind.PROVIDER_INVOCATION,
            ObservationKind.TELEMETRY_CANARY,
        }
        if not set(observations) <= supported:
            message = (
                "cloudWatchLogs supports bedrockInvocation, providerInvocation, "
                "and telemetryCanary only"
            )
            raise ValueError(message)
        return observations

    @model_validator(mode="after")
    def require_only_explicit_sensitive_references(self) -> Self:
        """Bind sensitive comparisons to declarations owned by this probe."""
        requests_canary = ObservationKind.TELEMETRY_CANARY in self.observations
        if requests_canary and self.canary is None:
            message = "cloudWatchLogs telemetryCanary requires a canary reference"
            raise ValueError(message)
        if not requests_canary and self.canary is not None:
            message = (
                "cloudWatchLogs canary is valid only when telemetryCanary is requested"
            )
            raise ValueError(message)
        requests_bedrock = ObservationKind.BEDROCK_INVOCATION in self.observations
        if requests_bedrock and self.bedrock is None:
            message = "cloudWatchLogs bedrockInvocation requires a bedrock declaration"
            raise ValueError(message)
        if not requests_bedrock and self.bedrock is not None:
            message = (
                "cloudWatchLogs bedrock is valid only when bedrockInvocation "
                "is requested"
            )
            raise ValueError(message)
        return self


class CloudTrailProbe(_BaseProbe):
    """Collect normalized events from CloudTrail's fixed lookup surface."""

    type: Literal["cloudTrail"]
    event_source: Literal[
        "bedrock.amazonaws.com",
        "execute-api.amazonaws.com",
        "kms.amazonaws.com",
        "s3.amazonaws.com",
        "sts.amazonaws.com",
    ]
    event_names: tuple[Identifier, ...] = Field(min_length=1)

    @field_validator("event_names")
    @classmethod
    def event_names_are_unique(
        cls,
        event_names: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Reject duplicate CloudTrail lookup names."""
        _require_unique(event_names, item_kind="CloudTrail event name")
        return event_names


class LocalTelemetryProbe(_BaseProbe):
    """Read normalized records from the in-process synthetic telemetry sink."""

    type: Literal["localTelemetry"]

    @field_validator("observations")
    @classmethod
    def observations_are_local(
        cls,
        observations: tuple[ObservationKind, ...],
    ) -> tuple[ObservationKind, ...]:
        """Keep the local probe's normalization surface deliberately narrow."""
        supported = {
            ObservationKind.TELEMETRY_CANARY,
            ObservationKind.AUDIT_EVENT,
        }
        if not set(observations) <= supported:
            message = "localTelemetry supports telemetryCanary and auditEvent only"
            raise ValueError(message)
        return observations


type Probe = Annotated[
    CloudWatchLogsProbe | CloudTrailProbe | LocalTelemetryProbe,
    Field(discriminator="type"),
]


class Limitation(_StrictModel):
    """A mandatory, stable statement bounding an assessment claim."""

    id: Identifier
    description: NonEmptyString


class Responsibility(_StrictModel):
    """One party's responsibility within a control mapping."""

    party: ResponsibleParty
    description: NonEmptyString


class ReviewMetadata(_StrictModel):
    """Human review provenance for a compliance mapping."""

    reviewed_by: NonEmptyString
    reviewed_at: date


class ControlReference(_StrictModel):
    """A versioned, bounded relationship to an external control source."""

    source: NonEmptyString
    source_version: NonEmptyString
    reference: Identifier
    relationship: Literal["supports-assessment"]
    rationale: NonEmptyString
    scope: NonEmptyString
    limitations: tuple[Limitation, ...] = Field(min_length=1)
    responsibilities: tuple[Responsibility, ...] = Field(min_length=3, max_length=3)
    review: ReviewMetadata

    @model_validator(mode="after")
    def validate_mapping_completeness(self) -> Self:
        """Require unique limitations and all three responsibility parties."""
        _require_unique(
            (limitation.id for limitation in self.limitations),
            item_kind="control-reference limitation id",
        )
        parties = {responsibility.party for responsibility in self.responsibilities}
        if parties != set(ResponsibleParty):
            message = (
                "control reference responsibilities must cover verifier, "
                "cloudProvider, and customer exactly once"
            )
            raise ValueError(message)
        return self


class _BaseAssertion(_StrictModel):
    id: Identifier
    control_refs: tuple[ControlReference, ...] = Field(min_length=1)
    limitations: tuple[Limitation, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_claim_boundaries(self) -> Self:
        _require_unique(
            (limitation.id for limitation in self.limitations),
            item_kind="assertion limitation id",
        )
        mapping_keys = (
            f"{mapping.source}@{mapping.source_version}:{mapping.reference}"
            for mapping in self.control_refs
        )
        _require_unique(mapping_keys, item_kind="assertion control reference")
        return self


class UnauthorizedIdentityAssertion(_BaseAssertion):
    """Require an application action under an unauthorized identity to fail."""

    type: Literal["unauthorizedIdentityDenied"]
    action_ref: Identifier


class ProviderBoundaryAssertion(_BaseAssertion):
    """Require evidence to name only explicitly permitted model providers."""

    type: Literal["providerBoundary"]
    probe_ref: Identifier
    allowed_providers: tuple[Identifier, ...] = Field(min_length=1)

    @field_validator("allowed_providers")
    @classmethod
    def providers_are_unique(
        cls,
        providers: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Reject duplicate provider allowlist entries."""
        _require_unique(providers, item_kind="allowed provider")
        return providers


class TelemetryCanaryAssertion(_BaseAssertion):
    """Require a secret canary to be correlated through normalized telemetry."""

    type: Literal["telemetryCanary"]
    action_ref: Identifier
    probe_ref: Identifier
    canary: EnvironmentReference


class AuditCorrelationAssertion(_BaseAssertion):
    """Require an action to correlate with a normalized audit observation."""

    type: Literal["auditCorrelation"]
    action_ref: Identifier
    probe_ref: Identifier


class EncryptionAssertion(_BaseAssertion):
    """Require evidence for one or more fixed encryption scopes."""

    type: Literal["encryption"]
    probe_ref: Identifier
    scopes: tuple[EncryptionScope, ...] = Field(min_length=1)

    @field_validator("scopes")
    @classmethod
    def scopes_are_unique(
        cls,
        scopes: tuple[EncryptionScope, ...],
    ) -> tuple[EncryptionScope, ...]:
        """Reject duplicate encryption scopes."""
        _require_unique(scopes, item_kind="encryption scope")
        return scopes


class ApplicationStatusAssertion(_BaseAssertion):
    """Require one HTTP action to return an exact status code."""

    type: Literal["application.status"]
    action_ref: Identifier
    expected_status: Annotated[StrictInt, Field(ge=100, le=599)]


class TelemetryCanaryAbsentAssertion(_BaseAssertion):
    """Require a synthetic canary to be absent from application telemetry."""

    type: Literal["telemetry.canary-absent"]
    probe_ref: Identifier


class AuditEventPresentAssertion(_BaseAssertion):
    """Require a named audit event correlated to a completed action."""

    type: Literal["audit.event-present"]
    action_ref: Identifier
    probe_ref: Identifier
    event_name: Identifier


class AuditPrincipalCorrelatedAssertion(_BaseAssertion):
    """Require an audit event principal to match the action principal."""

    type: Literal["audit.principal-correlated"]
    action_ref: Identifier
    probe_ref: Identifier


type Assertion = Annotated[
    UnauthorizedIdentityAssertion
    | ProviderBoundaryAssertion
    | TelemetryCanaryAssertion
    | AuditCorrelationAssertion
    | EncryptionAssertion
    | ApplicationStatusAssertion
    | TelemetryCanaryAbsentAssertion
    | AuditEventPresentAssertion
    | AuditPrincipalCorrelatedAssertion,
    Field(discriminator="type"),
]


class Scenario(_StrictModel):
    """A bounded group of declared actions, probes, and assertions."""

    id: Identifier
    description: NonEmptyString
    identity_ref: Identifier
    actions: tuple[Action, ...] = Field(min_length=1)
    probes: tuple[Probe, ...] = Field(min_length=1)
    assertions: tuple[Assertion, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def component_ids_are_unique(self) -> Self:
        """Keep all scenario-local reference namespaces deterministic."""
        _require_unique(
            (action.id for action in self.actions),
            item_kind=f"action id in scenario {self.id!r}",
        )
        _require_unique(
            (probe.id for probe in self.probes),
            item_kind=f"probe id in scenario {self.id!r}",
        )
        _require_unique(
            (assertion.id for assertion in self.assertions),
            item_kind=f"assertion id in scenario {self.id!r}",
        )
        return self


@final
class VerificationSuite(_StrictModel):
    """Root model for immutable verification-suite schema ``1alpha1``."""

    model_config = ConfigDict(
        alias_generator=_to_camel,
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "$id": SUITE_SCHEMA_ID,
            "$schema": "https://json-schema.org/draft/2020-12/schema",
        },
        populate_by_name=False,
        serialize_by_alias=True,
        title="VerificationSuite 1alpha1",
        validate_default=True,
    )

    schema_version: Literal["1alpha1"]
    metadata: SuiteMetadata
    target: Target
    identities: tuple[Identity, ...] = Field(min_length=1)
    evidence_policy: EvidencePolicy
    scenarios: tuple[Scenario, ...] = Field(min_length=1)
    limitations: tuple[Limitation, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_suite_semantics(self) -> Self:
        """Validate IDs, references, mutations, and action/probe links."""
        _require_unique(
            (identity.id for identity in self.identities),
            item_kind="identity id",
        )
        _require_unique(
            (scenario.id for scenario in self.scenarios),
            item_kind="scenario id",
        )
        _require_unique(
            (limitation.id for limitation in self.limitations),
            item_kind="suite limitation id",
        )
        _require_unique(
            (action.id for scenario in self.scenarios for action in scenario.actions),
            item_kind="action id across suite",
        )
        _require_unique(
            (probe.id for scenario in self.scenarios for probe in scenario.probes),
            item_kind="probe id across suite",
        )
        _require_unique(
            (
                assertion.id
                for scenario in self.scenarios
                for assertion in scenario.assertions
            ),
            item_kind="assertion id across suite",
        )

        identity_ids = {identity.id for identity in self.identities}
        local_identity_ids = {
            identity.id
            for identity in self.identities
            if isinstance(identity, SyntheticLocalIdentity)
        }
        if self.target.environment is DeploymentEnvironment.LOCAL:
            if local_identity_ids != identity_ids:
                message = "local targets require only syntheticLocal identities"
                raise ValueError(message)
        elif local_identity_ids:
            message = "syntheticLocal identities require a local target"
            raise ValueError(message)
        for scenario in self.scenarios:
            self._validate_scenario_references(scenario, identity_ids)
            self._validate_local_components(scenario)
            conflicting_regions = sorted(
                action.id
                for action in scenario.actions
                if isinstance(action, AwsSigV4Action)
                and action.region is not None
                and action.region != self.target.aws_region
            )
            if conflicting_regions:
                joined = ", ".join(conflicting_regions)
                message = (
                    f"awsSigV4 action regions must match target awsRegion: {joined}"
                )
                raise ValueError(message)
        return self

    def _validate_local_components(self, scenario: Scenario) -> None:
        local_probes = [
            probe for probe in scenario.probes if isinstance(probe, LocalTelemetryProbe)
        ]
        local_assertions = [
            assertion
            for assertion in scenario.assertions
            if isinstance(
                assertion,
                ApplicationStatusAssertion
                | TelemetryCanaryAbsentAssertion
                | AuditEventPresentAssertion
                | AuditPrincipalCorrelatedAssertion,
            )
        ]
        if (local_probes or local_assertions) and (
            self.target.environment is not DeploymentEnvironment.LOCAL
        ):
            message = "local probes and assertions require a local target"
            raise ValueError(message)
        if self.target.environment is DeploymentEnvironment.LOCAL:
            if any(not isinstance(action, HttpAction) for action in scenario.actions):
                message = "local scenarios support only http actions"
                raise ValueError(message)
            if any(
                not isinstance(probe, LocalTelemetryProbe) for probe in scenario.probes
            ):
                message = "local scenarios support only localTelemetry probes"
                raise ValueError(message)
            if len(local_assertions) != len(scenario.assertions):
                message = "local scenarios support only local assertion types"
                raise ValueError(message)
            probes_by_id = {probe.id: probe for probe in scenario.probes}
            for assertion in scenario.assertions:
                if isinstance(assertion, TelemetryCanaryAbsentAssertion):
                    required = ObservationKind.TELEMETRY_CANARY
                elif isinstance(
                    assertion,
                    AuditEventPresentAssertion | AuditPrincipalCorrelatedAssertion,
                ):
                    required = ObservationKind.AUDIT_EVENT
                else:
                    continue
                probe = probes_by_id[assertion.probe_ref]
                if required not in probe.observations:
                    message = (
                        f"local assertion {assertion.id!r} requires "
                        f"{required.value} from probe {probe.id!r}"
                    )
                    raise ValueError(message)
            return
        self._validate_cloud_components(scenario)

    @staticmethod
    def _validate_cloud_components(scenario: Scenario) -> None:
        probes_by_id = {probe.id: probe for probe in scenario.probes}
        for assertion in scenario.assertions:
            if not isinstance(assertion, TelemetryCanaryAssertion):
                continue
            probe = probes_by_id[assertion.probe_ref]
            if not isinstance(probe, CloudWatchLogsProbe):
                message = (
                    f"telemetry canary assertion {assertion.id!r} requires "
                    "a cloudWatchLogs probe"
                )
                raise ValueError(message)  # noqa: TRY004 - semantic validation.
            if (
                assertion.action_ref != probe.action_ref
                or ObservationKind.TELEMETRY_CANARY not in probe.observations
                or assertion.canary != probe.canary
            ):
                message = (
                    f"telemetry canary assertion {assertion.id!r} must match "
                    f"the action, observation, and canary declared by probe "
                    f"{probe.id!r}"
                )
                raise ValueError(message)

    def render_resolved_redacted(self, environment: Mapping[str, str]) -> str:
        """Validate environment resolution and render only redacted JSON.

        Environment values are checked but never retained, returned, or placed
        in exception messages. The unresolved suite remains independently safe
        to serialize because it contains variable names rather than values.
        """
        environment_names = _environment_reference_names(self)
        missing = sorted(name for name in environment_names if name not in environment)
        if missing:
            joined = ", ".join(missing)
            message = f"missing environment values: {joined}"
            raise ValueError(message)
        invalid = sorted(
            name for name in environment_names if not isinstance(environment[name], str)
        )
        if invalid:
            joined = ", ".join(invalid)
            message = f"environment values must be strings: {joined}"
            raise TypeError(message)
        empty = sorted(name for name in environment_names if not environment[name])
        if empty:
            joined = ", ".join(empty)
            message = f"environment values must not be empty: {joined}"
            raise ValueError(message)

        dumped = self.model_dump(mode="json", by_alias=True)
        redacted = _redact_environment_references(dumped)
        return json.dumps(
            redacted,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    @staticmethod
    def _validate_scenario_references(
        scenario: Scenario,
        identity_ids: set[str],
    ) -> None:
        identity_references = [scenario.identity_ref]
        identity_references.extend(
            action.identity_ref
            for action in scenario.actions
            if action.identity_ref is not None
        )
        identity_references.extend(
            probe.identity_ref
            for probe in scenario.probes
            if probe.identity_ref is not None
        )
        missing_identities = sorted(set(identity_references) - identity_ids)
        if missing_identities:
            joined = ", ".join(missing_identities)
            message = (
                f"scenario {scenario.id!r} references missing identities: {joined}"
            )
            raise ValueError(message)

        mutating_actions = sorted(
            action.id for action in scenario.actions if action.mutating
        )
        if mutating_actions:
            joined = ", ".join(mutating_actions)
            message = (
                f"mutating actions are unsupported in schemaVersion 1alpha1: {joined}"
            )
            raise ValueError(message)

        action_ids = {action.id for action in scenario.actions}
        probe_ids = {probe.id for probe in scenario.probes}
        missing_probe_actions = sorted(
            {probe.action_ref for probe in scenario.probes} - action_ids
        )
        if missing_probe_actions:
            joined = ", ".join(missing_probe_actions)
            message = (
                f"scenario {scenario.id!r} probes reference missing actions: {joined}"
            )
            raise ValueError(message)

        missing_assertion_actions: set[str] = set()
        missing_assertion_probes: set[str] = set()
        for assertion in scenario.assertions:
            action_ref = getattr(assertion, "action_ref", None)
            probe_ref = getattr(assertion, "probe_ref", None)
            if action_ref is not None and action_ref not in action_ids:
                missing_assertion_actions.add(action_ref)
            if probe_ref is not None and probe_ref not in probe_ids:
                missing_assertion_probes.add(probe_ref)
        if missing_assertion_actions:
            joined = ", ".join(sorted(missing_assertion_actions))
            message = (
                f"scenario {scenario.id!r} assertions reference missing actions: "
                f"{joined}"
            )
            raise ValueError(message)
        if missing_assertion_probes:
            joined = ", ".join(sorted(missing_assertion_probes))
            message = (
                f"scenario {scenario.id!r} assertions reference missing probes: "
                f"{joined}"
            )
            raise ValueError(message)


def verification_suite_json_schema() -> dict[str, Any]:
    """Return the canonical JSON Schema for suite version ``1alpha1``."""
    return VerificationSuite.model_json_schema(by_alias=True, mode="validation")


def _require_unique(values: Iterable[object], *, item_kind: str) -> None:
    seen: set[object] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(str(value))
        seen.add(value)
    if duplicates:
        joined = ", ".join(sorted(duplicates))
        message = f"duplicate {item_kind}: {joined}"
        raise ValueError(message)


def _freshness_seconds(value: str, *, allow_zero: bool) -> int:
    match = _FRESHNESS_PATTERN.fullmatch(value)
    if match is None or not any(match.groupdict().values()):
        message = (
            "freshness values must be ISO-8601 hour/minute/second durations "
            "such as PT5M"
        )
        raise ValueError(message)
    hours = int(match.group("hours") or 0)
    minutes = int(match.group("minutes") or 0)
    seconds = int(match.group("seconds") or 0)
    if minutes >= _SECONDS_PER_MINUTE or seconds >= _SECONDS_PER_MINUTE:
        message = "freshness minutes and seconds must each be less than 60"
        raise ValueError(message)
    total = hours * 3600 + minutes * _SECONDS_PER_MINUTE + seconds
    if (not allow_zero and total == 0) or total > _MAX_FRESHNESS_SECONDS:
        message = "freshness values must be positive and no longer than PT24H"
        raise ValueError(message)
    return total


def _environment_reference_names(model: BaseModel) -> set[str]:
    names: set[str] = set()

    def visit(value: object) -> None:
        if isinstance(value, EnvironmentReference):
            names.add(value.name)
            return
        if isinstance(value, BaseModel):
            for field_name in type(value).model_fields:
                visit(getattr(value, field_name))
            return
        if isinstance(value, tuple):
            for item in value:
                visit(item)

    visit(model)
    return names


def _redact_environment_references(value: JsonValue) -> JsonValue:
    if isinstance(value, list):
        return [_redact_environment_references(item) for item in value]
    if isinstance(value, dict):
        if value.get("source") == "environment" and isinstance(
            value.get("name"),
            str,
        ):
            return {
                "name": value["name"],
                "resolvedValue": REDACTED,
                "source": "environment",
            }
        return {
            key: _redact_environment_references(item) for key, item in value.items()
        }
    return value
