"""Read-only AWS identity providers with redacted failure boundaries."""

from __future__ import annotations

import importlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, cast, final

from cai_verify.config import (
    AssumedRoleIdentity,
    CurrentAwsIdentity,
    EnvironmentReference,
)
from cai_verify.plugins import (
    PLUGIN_API_VERSION,
    IdentityRequest,
    PluginMetadata,
)

if TYPE_CHECKING:
    from cai_verify.config import Identity, Target

_CALLER_ARN_PATTERN = re.compile(
    r"arn:(?P<partition>aws|aws-us-gov|aws-cn):(?:iam|sts)::"
    r"(?P<account>\d{12}):.+\Z"
)
_ROLE_ARN_PATTERN = re.compile(
    r"arn:(?P<partition>aws|aws-us-gov|aws-cn):iam::"
    r"(?P<account>\d{12}):role/.+\Z"
)
_ASSUMED_ROLE_CALLER_ARN_PATTERN = re.compile(
    r"arn:(?P<partition>aws|aws-us-gov|aws-cn):sts::"
    r"(?P<account>\d{12}):assumed-role/"
    r"(?P<role_name>[\w+=,.@-]{1,64})/"
    r"(?P<session_name>[\w+=,.@-]{2,64})\Z"
)
_HEADER_PAIR_SIZE = 2
_AWS_CONNECT_TIMEOUT_SECONDS = 3
_AWS_READ_TIMEOUT_SECONDS = 5
_AWS_MAX_ATTEMPTS = 2


class AwsIdentityFailureCode(StrEnum):
    """Stable, non-secret categories for identity acquisition failures."""

    ACCOUNT_MISMATCH = "account_mismatch"
    ACQUISITION_FAILED = "identity_acquisition_failed"
    ENVIRONMENT_VALUE_INVALID = "environment_value_invalid"
    INVALID_RESPONSE = "invalid_aws_response"
    PARTITION_MISMATCH = "partition_mismatch"
    SDK_UNAVAILABLE = "aws_sdk_unavailable"


class AwsIdentityError(RuntimeError):
    """An AWS identity failure whose public text excludes SDK diagnostics."""

    def __init__(self, code: AwsIdentityFailureCode, identity_id: str) -> None:
        """Create an error from validated non-secret identity metadata."""
        self.code = code
        message = f"AWS identity {identity_id!r} is unavailable ({code.value})"
        super().__init__(message)


class _AwsSdkUnavailableError(RuntimeError):
    """The optional AWS SDK is not installed or cannot be imported."""


class _InvalidAwsResponseError(ValueError):
    """An AWS response did not contain the normalized fields we require."""


class AwsStsClient(Protocol):
    """Narrow STS surface used by the built-in identity providers."""

    def get_caller_identity(self) -> Mapping[str, object]:
        """Return the caller identity response."""
        ...

    def assume_role(self, **kwargs: str) -> Mapping[str, object]:
        """Return temporary credentials for one declared role."""
        ...


class _AwsCloudWatchLogsClient(Protocol):
    """Exact read-only CloudWatch Logs surface used by the built-in probe."""

    def filter_log_events(self, **kwargs: object) -> Mapping[str, object]:
        """Return one bounded page from one declared log group."""
        ...


class _AwsCloudTrailClient(Protocol):
    """Exact read-only CloudTrail surface used by the built-in probe."""

    def lookup_events(self, **kwargs: object) -> Mapping[str, object]:
        """Return one bounded page from regional CloudTrail event history."""
        ...


class AwsSession(Protocol):
    """Opaque SDK session retained only for the lifetime of an identity lease."""

    def client(self, service_name: str, **kwargs: object) -> object:
        """Create a service client from the session's scoped credentials."""
        ...


class AwsSessionFactory(Protocol):
    """Construct bounded SDK sessions and STS clients."""

    def create_current_session(
        self,
        *,
        profile_name: str | None,
        region_name: str,
    ) -> AwsSession:
        """Create a session from the normal AWS credential provider chain."""
        ...

    def create_assumed_session(
        self,
        *,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        region_name: str,
    ) -> AwsSession:
        """Create a session from temporary AssumeRole credentials."""
        ...

    def create_sts_client(
        self,
        session: AwsSession,
        *,
        region_name: str,
    ) -> AwsStsClient:
        """Create an STS client with bounded retry and timeout policy."""
        ...


class _Boto3Module(Protocol):
    def Session(self, **kwargs: object) -> AwsSession:  # noqa: N802
        """Construct a boto3 session."""
        ...


class _BotocoreConfigModule(Protocol):
    def Config(self, **kwargs: object) -> object:  # noqa: N802
        """Construct a botocore client configuration."""
        ...


class _AwsCredentials(Protocol):
    def get_frozen_credentials(self) -> object:
        """Return an immutable SDK credential snapshot for one signature."""
        ...


class _AwsSigningSession(Protocol):
    def get_credentials(self) -> object | None:
        """Return the SDK's opaque credential provider result."""
        ...


class _AwsRequest(Protocol):
    context: dict[str, object]
    headers: Mapping[str, object]


class _SigV4Signer(Protocol):
    def _modify_request_before_signing(self, request: _AwsRequest) -> None:
        """Apply Botocore-owned date and session-token signing headers."""
        ...

    def canonical_request(self, request: _AwsRequest) -> str:
        """Build Botocore's canonical request."""
        ...

    def string_to_sign(self, request: _AwsRequest, canonical_request: str) -> str:
        """Build Botocore's string to sign."""
        ...

    def signature(self, string_to_sign: str, request: _AwsRequest) -> str:
        """Calculate Botocore's SigV4 signature."""
        ...

    def _inject_signature_to_request(
        self,
        request: _AwsRequest,
        signature: str,
    ) -> None:
        """Place Botocore's authorization header on the request."""
        ...


class _BotocoreAuthModule(Protocol):
    def SigV4Auth(  # noqa: N802
        self,
        credentials: object,
        service_name: str,
        region_name: str,
    ) -> _SigV4Signer:
        """Construct Botocore's SigV4 signer."""
        ...


class _BotocoreAwsRequestModule(Protocol):
    def AWSRequest(  # noqa: N802
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        data: bytes,
    ) -> _AwsRequest:
        """Construct Botocore's signable request."""
        ...


@final
@dataclass(frozen=True, slots=True)
class Boto3AwsSessionFactory:
    """Load the optional AWS SDK and apply conservative client bounds."""

    connect_timeout_seconds: int = _AWS_CONNECT_TIMEOUT_SECONDS
    read_timeout_seconds: int = _AWS_READ_TIMEOUT_SECONDS
    max_attempts: int = _AWS_MAX_ATTEMPTS

    def create_current_session(
        self,
        *,
        profile_name: str | None,
        region_name: str,
    ) -> AwsSession:
        """Create a boto3 session without accepting literal credentials."""
        boto3 = _boto3_module()
        arguments: dict[str, object] = {"region_name": region_name}
        if profile_name is not None:
            arguments["profile_name"] = profile_name
        return boto3.Session(**arguments)

    def create_assumed_session(
        self,
        *,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        region_name: str,
    ) -> AwsSession:
        """Create a boto3 session from one in-memory temporary lease."""
        boto3 = _boto3_module()
        return boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            aws_session_token=session_token,
            region_name=region_name,
        )

    def create_sts_client(
        self,
        session: AwsSession,
        *,
        region_name: str,
    ) -> AwsStsClient:
        """Create a regional STS client with bounded retries and timeouts."""
        config = _bounded_client_config(
            connect_timeout_seconds=self.connect_timeout_seconds,
            read_timeout_seconds=self.read_timeout_seconds,
            max_attempts=self.max_attempts,
        )
        return cast(
            "AwsStsClient",
            session.client("sts", config=config, region_name=region_name),
        )


@final
@dataclass(slots=True)
class AwsScopedIdentity:
    """Hold an opaque AWS SDK session and normalized non-secret lease metadata."""

    _identity_id: str
    _account_id: str | None = field(repr=False)
    _partition: str | None = field(repr=False)
    _expires_at: datetime | None
    _session: AwsSession | None = field(repr=False)
    closed: bool = False

    @property
    def identity_id(self) -> str:
        """Return the configured identity identifier."""
        return self._identity_id

    @property
    def expires_at(self) -> datetime | None:
        """Return the SDK-supplied expiry when one is available."""
        return self._expires_at

    def matches_account(self, expected_account_id: str) -> bool:
        """Compare an expected account without returning the observed account."""
        return self._account_id == expected_account_id

    def matches_partition(self, expected_partition: str) -> bool:
        """Compare an expected partition without returning the observed ARN."""
        return self._partition == expected_partition

    def _cloudwatch_logs_client(
        self,
        *,
        region: str,
        evaluated_at: datetime,
    ) -> _AwsCloudWatchLogsClient:
        """Create only the bounded CloudWatch Logs client needed by the probe."""
        now = _normalized_datetime(evaluated_at)
        expires_at = self._expires_at
        if (
            self.closed
            or self._session is None
            or (
                expires_at is not None
                and (
                    expires_at.tzinfo is None
                    or expires_at.utcoffset() is None
                    or expires_at.astimezone(UTC) <= now
                )
            )
        ):
            message = "AWS identity lease cannot create a CloudWatch Logs client"
            raise RuntimeError(message)
        config = _bounded_client_config(
            connect_timeout_seconds=_AWS_CONNECT_TIMEOUT_SECONDS,
            read_timeout_seconds=_AWS_READ_TIMEOUT_SECONDS,
            max_attempts=_AWS_MAX_ATTEMPTS,
        )
        return cast(
            "_AwsCloudWatchLogsClient",
            self._session.client(
                "logs",
                config=config,
                region_name=region,
            ),
        )

    def _cloudtrail_client(
        self,
        *,
        region: str,
        evaluated_at: datetime,
    ) -> _AwsCloudTrailClient:
        """Create only the bounded CloudTrail client needed by the audit probe."""
        now = _normalized_datetime(evaluated_at)
        expires_at = self._expires_at
        if (
            self.closed
            or self._session is None
            or (
                expires_at is not None
                and (
                    expires_at.tzinfo is None
                    or expires_at.utcoffset() is None
                    or expires_at.astimezone(UTC) <= now
                )
            )
        ):
            message = "AWS identity lease cannot create a CloudTrail client"
            raise RuntimeError(message)
        config = _bounded_client_config(
            connect_timeout_seconds=_AWS_CONNECT_TIMEOUT_SECONDS,
            read_timeout_seconds=_AWS_READ_TIMEOUT_SECONDS,
            max_attempts=_AWS_MAX_ATTEMPTS,
        )
        return cast(
            "_AwsCloudTrailClient",
            self._session.client(
                "cloudtrail",
                config=config,
                region_name=region,
            ),
        )

    def _sign_request(  # noqa: PLR0913 - exact signing fields remain explicit.
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        service: str,
        region: str,
        signing_time: datetime,
    ) -> tuple[tuple[str, str], ...]:
        """Sign one request without returning credentials or credential objects."""
        if self.closed or self._session is None:
            message = "AWS identity lease is closed"
            raise RuntimeError(message)
        credentials = cast(
            "_AwsCredentials | None",
            cast("_AwsSigningSession", self._session).get_credentials(),
        )
        if credentials is None:
            message = "AWS identity lease has no signing credentials"
            raise RuntimeError(message)
        frozen_credentials = credentials.get_frozen_credentials()
        auth_module = _botocore_auth_module()
        request_module = _botocore_awsrequest_module()
        aws_request = request_module.AWSRequest(
            method=method,
            url=url,
            headers=headers,
            data=body,
        )
        aws_request.context["timestamp"] = signing_time.astimezone(UTC).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        signer = auth_module.SigV4Auth(
            frozen_credentials,
            service,
            region,
        )
        # Botocore's public add_auth() owns its wall clock. Calling the same
        # Botocore primitives with an injected timestamp keeps tests
        # deterministic without reimplementing any signing cryptography.
        signer._modify_request_before_signing(aws_request)  # noqa: SLF001
        canonical_request = signer.canonical_request(aws_request)
        string_to_sign = signer.string_to_sign(aws_request, canonical_request)
        signature = signer.signature(string_to_sign, aws_request)
        signer._inject_signature_to_request(  # noqa: SLF001
            aws_request,
            signature,
        )
        return _normalized_header_items(aws_request.headers.items())

    def close(self) -> None:
        """Release references to the SDK session and normalized principal data."""
        self._session = None
        self._account_id = None
        self._partition = None
        self.closed = True


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class CurrentAwsIdentityProvider:
    """Acquire an identity through the normal AWS credential provider chain."""

    environment: Mapping[str, str] = field(repr=False)
    session_factory: AwsSessionFactory = field(
        default_factory=Boto3AwsSessionFactory,
        repr=False,
    )

    @property
    def metadata(self) -> PluginMetadata:
        """Declare the built-in current-identity capability."""
        return PluginMetadata(
            name="aws-current-identity",
            api_version=PLUGIN_API_VERSION,
            capabilities=("identity.aws-current",),
        )

    def provide_identity(self, request: IdentityRequest, /) -> AwsScopedIdentity:
        """Resolve a current AWS identity and validate it with read-only STS."""
        identity = request.identity
        if not isinstance(identity, CurrentAwsIdentity):
            message = "current AWS provider requires an awsCurrent identity"
            raise TypeError(message)
        region = _target_region(request.context.target, identity.id)
        try:
            profile_name = _optional_environment_value(
                identity.profile,
                self.environment,
                identity_id=identity.id,
            )
            session = self.session_factory.create_current_session(
                profile_name=profile_name,
                region_name=region,
            )
            return _validated_lease(
                identity_id=identity.id,
                session=session,
                session_factory=self.session_factory,
                region=region,
                expires_at=None,
            )
        except AwsIdentityError:
            raise
        except _AwsSdkUnavailableError:
            raise AwsIdentityError(
                AwsIdentityFailureCode.SDK_UNAVAILABLE,
                identity.id,
            ) from None
        except _InvalidAwsResponseError:
            raise AwsIdentityError(
                AwsIdentityFailureCode.INVALID_RESPONSE,
                identity.id,
            ) from None
        except Exception:  # noqa: BLE001 - SDK and credential errors are redacted.
            raise AwsIdentityError(
                AwsIdentityFailureCode.ACQUISITION_FAILED,
                identity.id,
            ) from None


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class AssumedRoleAwsIdentityProvider:
    """Acquire one explicitly declared AWS role through read-only STS calls."""

    environment: Mapping[str, str] = field(repr=False)
    session_factory: AwsSessionFactory = field(
        default_factory=Boto3AwsSessionFactory,
        repr=False,
    )

    @property
    def metadata(self) -> PluginMetadata:
        """Declare the built-in AssumeRole capability."""
        return PluginMetadata(
            name="aws-assumed-role-identity",
            api_version=PLUGIN_API_VERSION,
            capabilities=("identity.aws-assume-role",),
        )

    def provide_identity(self, request: IdentityRequest, /) -> AwsScopedIdentity:
        """Assume a declared role and validate the resulting principal with STS."""
        identity = request.identity
        if not isinstance(identity, AssumedRoleIdentity):
            message = "assumed-role provider requires an awsAssumeRole identity"
            raise TypeError(message)
        region = _target_region(request.context.target, identity.id)
        try:
            base_session = self.session_factory.create_current_session(
                profile_name=None,
                region_name=region,
            )
            base_sts = self.session_factory.create_sts_client(
                base_session,
                region_name=region,
            )
            arguments = {
                "RoleArn": identity.role_arn,
                "RoleSessionName": identity.session_name,
            }
            external_id = _optional_environment_value(
                identity.external_id,
                self.environment,
                identity_id=identity.id,
            )
            if external_id is not None:
                arguments["ExternalId"] = external_id
            response = base_sts.assume_role(**arguments)
            access_key, secret_key, session_token, expires_at = _temporary_credentials(
                response
            )
            assumed_session = self.session_factory.create_assumed_session(
                access_key_id=access_key,
                secret_access_key=secret_key,
                session_token=session_token,
                region_name=region,
            )
            return _validated_lease(
                identity_id=identity.id,
                session=assumed_session,
                session_factory=self.session_factory,
                region=region,
                expires_at=expires_at,
                expected_assumed_role_arn=identity.role_arn,
                expected_session_name=identity.session_name,
            )
        except AwsIdentityError:
            raise
        except _AwsSdkUnavailableError:
            raise AwsIdentityError(
                AwsIdentityFailureCode.SDK_UNAVAILABLE,
                identity.id,
            ) from None
        except _InvalidAwsResponseError:
            raise AwsIdentityError(
                AwsIdentityFailureCode.INVALID_RESPONSE,
                identity.id,
            ) from None
        except Exception:  # noqa: BLE001 - SDK and credential errors are redacted.
            raise AwsIdentityError(
                AwsIdentityFailureCode.ACQUISITION_FAILED,
                identity.id,
            ) from None


def _validated_lease(  # noqa: PLR0913 - role binding inputs stay explicit.
    *,
    identity_id: str,
    session: AwsSession,
    session_factory: AwsSessionFactory,
    region: str,
    expires_at: datetime | None,
    expected_assumed_role_arn: str | None = None,
    expected_session_name: str | None = None,
) -> AwsScopedIdentity:
    sts = session_factory.create_sts_client(session, region_name=region)
    account_id, partition, caller_arn = _caller_identity(sts.get_caller_identity())
    if expected_assumed_role_arn is not None or expected_session_name is not None:
        if expected_assumed_role_arn is None or expected_session_name is None:
            raise _InvalidAwsResponseError
        binding_failure = _assumed_role_binding_failure(
            caller_arn,
            role_arn=expected_assumed_role_arn,
            session_name=expected_session_name,
        )
        if binding_failure is not None:
            raise AwsIdentityError(binding_failure, identity_id)
    return AwsScopedIdentity(
        _identity_id=identity_id,
        _account_id=account_id,
        _partition=partition,
        _expires_at=expires_at,
        _session=session,
    )


def _caller_identity(response: Mapping[str, object]) -> tuple[str, str, str]:
    account_id = response.get("Account")
    arn = response.get("Arn")
    if not isinstance(account_id, str) or not isinstance(arn, str):
        raise _InvalidAwsResponseError
    match = _CALLER_ARN_PATTERN.fullmatch(arn)
    if match is None or match.group("account") != account_id:
        raise _InvalidAwsResponseError
    return account_id, match.group("partition"), arn


def _assumed_role_binding_failure(
    caller_arn: str,
    *,
    role_arn: str,
    session_name: str,
) -> AwsIdentityFailureCode | None:
    """Bind an STS principal to the exact declared role and session."""
    role_match = _ROLE_ARN_PATTERN.fullmatch(role_arn)
    caller_match = _ASSUMED_ROLE_CALLER_ARN_PATTERN.fullmatch(caller_arn)
    if role_match is None or caller_match is None:
        return AwsIdentityFailureCode.INVALID_RESPONSE
    role_name = role_arn.rsplit("/", maxsplit=1)[-1]
    if (
        caller_match.group("role_name") != role_name
        or caller_match.group("session_name") != session_name
    ):
        return AwsIdentityFailureCode.INVALID_RESPONSE
    if caller_match.group("partition") != role_match.group("partition"):
        return AwsIdentityFailureCode.PARTITION_MISMATCH
    if caller_match.group("account") != role_match.group("account"):
        return AwsIdentityFailureCode.ACCOUNT_MISMATCH
    return None


def _temporary_credentials(
    response: Mapping[str, object],
) -> tuple[str, str, str, datetime]:
    credentials = response.get("Credentials")
    if not isinstance(credentials, Mapping):
        raise _InvalidAwsResponseError
    access_key = credentials.get("AccessKeyId")
    secret_key = credentials.get("SecretAccessKey")
    session_token = credentials.get("SessionToken")
    expires_at = credentials.get("Expiration")
    if (
        not isinstance(access_key, str)
        or not access_key
        or not isinstance(secret_key, str)
        or not secret_key
        or not isinstance(session_token, str)
        or not session_token
        or not isinstance(expires_at, datetime)
        or expires_at.tzinfo is None
        or expires_at.utcoffset() is None
    ):
        raise _InvalidAwsResponseError
    return (
        access_key,
        secret_key,
        session_token,
        expires_at.astimezone(UTC),
    )


def _optional_environment_value(
    reference: EnvironmentReference | None,
    environment: Mapping[str, str],
    *,
    identity_id: str,
) -> str | None:
    if reference is None:
        return None
    try:
        value: object = environment[reference.name]
    except Exception:  # noqa: BLE001 - environment mappings are untrusted.
        raise AwsIdentityError(
            AwsIdentityFailureCode.ENVIRONMENT_VALUE_INVALID,
            identity_id,
        ) from None
    if not isinstance(value, str) or not value:
        raise AwsIdentityError(
            AwsIdentityFailureCode.ENVIRONMENT_VALUE_INVALID,
            identity_id,
        )
    return value


def _target_region(target: Target, identity_id: str) -> str:
    if target.aws_region is None:
        raise AwsIdentityError(
            AwsIdentityFailureCode.ACQUISITION_FAILED,
            identity_id,
        )
    return target.aws_region


def _expected_account(identity: Identity, target: Target) -> str | None:
    """Return the explicit account boundary for one declared identity."""
    if isinstance(identity, AssumedRoleIdentity):
        match = _ROLE_ARN_PATTERN.fullmatch(identity.role_arn)
        return match.group("account") if match is not None else None
    if isinstance(identity, CurrentAwsIdentity):
        return target.aws_account_id
    return None


def _expected_partition(identity: Identity, target: Target) -> str | None:
    """Return the explicit partition boundary for one declared identity."""
    if isinstance(identity, AssumedRoleIdentity):
        match = _ROLE_ARN_PATTERN.fullmatch(identity.role_arn)
        return match.group("partition") if match is not None else None
    if isinstance(identity, CurrentAwsIdentity) and target.aws_region is not None:
        return _partition_for_region(target.aws_region)
    return None


def _partition_for_region(region: str) -> str:
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if region.startswith("cn-"):
        return "aws-cn"
    return "aws"


def _boto3_module() -> _Boto3Module:
    try:
        module = importlib.import_module("boto3")
    except ModuleNotFoundError:
        raise _AwsSdkUnavailableError from None
    return cast("_Boto3Module", module)


def _botocore_config_module() -> _BotocoreConfigModule:
    try:
        module = importlib.import_module("botocore.config")
    except ModuleNotFoundError:
        raise _AwsSdkUnavailableError from None
    return cast("_BotocoreConfigModule", module)


def _bounded_client_config(
    *,
    connect_timeout_seconds: int,
    read_timeout_seconds: int,
    max_attempts: int,
) -> object:
    """Return one SDK configuration that ignores endpoint URL overrides."""
    config_module = _botocore_config_module()
    return config_module.Config(
        connect_timeout=connect_timeout_seconds,
        ignore_configured_endpoint_urls=True,
        read_timeout=read_timeout_seconds,
        retries={
            "mode": "standard",
            "total_max_attempts": max_attempts,
        },
    )


def _botocore_auth_module() -> _BotocoreAuthModule:
    try:
        module = importlib.import_module("botocore.auth")
    except ModuleNotFoundError:
        raise _AwsSdkUnavailableError from None
    return cast("_BotocoreAuthModule", module)


def _botocore_awsrequest_module() -> _BotocoreAwsRequestModule:
    try:
        module = importlib.import_module("botocore.awsrequest")
    except ModuleNotFoundError:
        raise _AwsSdkUnavailableError from None
    return cast("_BotocoreAwsRequestModule", module)


def _normalized_datetime(value: object) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        message = "AWS identity evaluation time must include a UTC offset"
        raise ValueError(message)
    return value.astimezone(UTC)


def _normalized_header_items(
    items: Iterable[tuple[str, object]],
) -> tuple[tuple[str, str], ...]:
    normalized: list[tuple[str, str]] = []
    for item in items:
        if (
            not isinstance(item, tuple)
            or len(item) != _HEADER_PAIR_SIZE
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
        ):
            message = "Botocore returned invalid signing headers"
            raise TypeError(message)
        normalized.append((item[0], item[1]))
    return tuple(sorted(normalized, key=lambda item: (item[0].lower(), item[0])))
