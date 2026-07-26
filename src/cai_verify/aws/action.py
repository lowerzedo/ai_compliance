"""Bounded AWS SigV4 application action execution."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, final
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from cai_verify.adapters._limits import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
from cai_verify.aws.identity import AwsScopedIdentity, _partition_for_region
from cai_verify.config import AwsSigV4Action, EnvironmentReference, LiteralInput
from cai_verify.config.models import DeploymentEnvironment, HttpMethod, InputLocation
from cai_verify.core import RedactedValue
from cai_verify.plugins import (
    PLUGIN_API_VERSION,
    ActionExecutionResult,
    ActionOutcome,
    ActionRequest,
    PluginMetadata,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from cai_verify.config import Target
    from cai_verify.core import JsonValue

_AWS_REGION_PATTERN = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-\d\Z")
_HTTP_SUCCESS_MIN = 200
_HTTP_SUCCESS_MAX = 300
_HTTP_STATUS_MIN = 100
_HTTP_STATUS_MAX = 599
_HTTPS_PORT = 443
_MAX_TIMEOUT_SECONDS = 60
_SUPPORTED_SERVICES = frozenset({"bedrock-runtime", "execute-api"})
_RESERVED_HEADERS = frozenset(
    {
        "authorization",
        "connection",
        "content-length",
        "host",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-amz-content-sha256",
        "x-amz-date",
        "x-amz-security-token",
        "x-cai-correlation-id",
    },
)
_LIMITATIONS = (
    "Request and response bodies, credentials, and signing headers are excluded "
    "from normalized evidence.",
    "The result reports one bounded application response; it does not establish "
    "service permission coverage or compliance.",
)


class AwsActionFailureCode(StrEnum):
    """Stable, non-secret failure categories for SigV4 action execution."""

    ENVIRONMENT_VALUE_INVALID = "environment_value_invalid"
    IDENTITY_BOUNDARY_INVALID = "identity_boundary_invalid"
    INVALID_CONFIGURATION = "invalid_configuration"
    INVALID_CORRELATION = "invalid_correlation"
    INVALID_RESPONSE = "invalid_response"
    REQUEST_TOO_LARGE = "request_too_large"
    RESERVED_HEADER = "reserved_header"
    RESPONSE_TOO_LARGE = "response_too_large"
    SIGNING_ERROR = "signing_error"
    TRANSPORT_ERROR = "transport_error"
    UNEXPECTED_HTTP_STATUS = "unexpected_http_status"


class _CorrelationState(StrEnum):
    MATCHED = "MATCHED"
    MISMATCHED = "MISMATCHED"
    NOT_CHECKED = "NOT_CHECKED"
    NOT_RETURNED = "NOT_RETURNED"


@dataclass(frozen=True, slots=True, kw_only=True)
class _AwsHttpRequest:
    """One already-signed request passed across the injected transport seam."""

    method: str
    hostname: str
    port: int
    target: str = field(repr=False)
    url: str = field(repr=False)
    timeout_seconds: int
    service: str
    region: str
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    body: bytes = field(repr=False)

    def header_map(self) -> dict[str, str]:
        """Return a detached header mapping for the concrete transport."""
        return dict(self.headers)


@dataclass(frozen=True, slots=True, kw_only=True)
class _AwsHttpResponse:
    """Bounded transport response retained only during result normalization."""

    status: int
    correlation_id: str | None = field(repr=False)
    too_large: bool


class _AwsActionTransport(Protocol):
    """Structural transport seam used for deterministic, network-free tests."""

    def send(self, request: _AwsHttpRequest, /) -> _AwsHttpResponse:
        """Send one request without redirects, proxies, or retries."""
        ...


@final
@dataclass(frozen=True, slots=True)
class _DirectHttpsTransport(_AwsActionTransport):
    """Direct standard-library HTTPS transport with no proxy integration."""

    def send(self, request: _AwsHttpRequest, /) -> _AwsHttpResponse:
        """Perform one HTTPS request and read at most one byte past the limit."""
        connection = http.client.HTTPSConnection(
            request.hostname,
            request.port,
            timeout=request.timeout_seconds,
            context=ssl.create_default_context(),
        )
        try:
            connection.request(
                request.method,
                request.target,
                request.body,
                request.header_map(),
                encode_chunked=False,
            )
            response = connection.getresponse()
            body = response.read(MAX_RESPONSE_BYTES + 1)
            return _AwsHttpResponse(
                status=response.status,
                correlation_id=response.getheader("X-Cai-Correlation-Id"),
                too_large=len(body) > MAX_RESPONSE_BYTES,
            )
        finally:
            connection.close()


class _ActionRejectedError(ValueError):
    """Internal fail-closed signal that carries only a stable category."""

    def __init__(self, code: AwsActionFailureCode) -> None:
        self.code = code
        super().__init__(code.value)


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class AwsSigV4ActionAdapter:
    """Execute validated SigV4 actions through an acquired AWS identity."""

    environment: Mapping[str, str] = field(repr=False)
    transport: _AwsActionTransport = field(
        default_factory=_DirectHttpsTransport,
        repr=False,
    )
    clock: Callable[[], datetime] = field(
        default=lambda: datetime.now(UTC),
        repr=False,
    )

    @property
    def metadata(self) -> PluginMetadata:
        """Declare the two fixed SigV4 application capabilities."""
        return PluginMetadata(
            name="aws-sigv4-action",
            api_version=PLUGIN_API_VERSION,
            capabilities=(
                "action.aws-sigv4.bedrock-runtime",
                "action.aws-sigv4.execute-api",
            ),
        )

    def execute_action(self, request: ActionRequest, /) -> ActionExecutionResult:
        """Sign, send, and safely normalize one bounded declared action."""
        action = request.action
        if not isinstance(action, AwsSigV4Action):
            message = "AWS SigV4 adapter requires an awsSigV4 action declaration"
            raise TypeError(message)
        identity = request.identity
        if type(identity) is not AwsScopedIdentity:
            message = "AWS SigV4 actions require an AWS scoped identity"
            raise TypeError(message)

        started_at = _normalized_time(self.clock())
        service = action.service
        region: str | None = None
        try:
            region = _signing_region(action, request.context.target)
            endpoint = _validated_endpoint(request.context.target)
            _validate_action(action)
            _validate_identity(
                identity,
                request.context.target,
                region=region,
                evaluated_at=started_at,
            )
            correlation_id = _correlation_id(
                request.context.run_id,
                request.context.scenario_id,
                action.id,
            )
            headers, query, body = self._resolve_inputs(action)
            _set_default_header(headers, "Content-Type", "application/json")
            headers["Host"] = endpoint.authority
            headers["X-Cai-Correlation-Id"] = correlation_id
            encoded_body = _encode_body(body)
            _enforce_request_size(encoded_body)
            path = _request_path(endpoint.base_path, action.path)
            target = _request_target(path, query)
            _enforce_request_size(target.value.encode("utf-8"))
            url = urlunsplit(("https", endpoint.authority, path, target.query, ""))
            try:
                signed_headers = identity._sign_request(  # noqa: SLF001
                    method=action.method.value,
                    url=url,
                    headers=headers,
                    body=encoded_body,
                    service=service,
                    region=region,
                    signing_time=started_at,
                )
            except Exception:  # noqa: BLE001 - SDK diagnostics are always redacted.
                return self._error_result(
                    action.id,
                    service=service,
                    region=region,
                    started_at=started_at,
                    code=AwsActionFailureCode.SIGNING_ERROR,
                )
            transport_request = _AwsHttpRequest(
                method=action.method.value,
                hostname=endpoint.hostname,
                port=endpoint.port,
                target=target.value,
                url=url,
                timeout_seconds=action.timeout_seconds,
                service=service,
                region=region,
                headers=signed_headers,
                body=encoded_body,
            )
            try:
                response = self.transport.send(transport_request)
            except Exception:  # noqa: BLE001 - transport details are always redacted.
                return self._error_result(
                    action.id,
                    service=service,
                    region=region,
                    started_at=started_at,
                    code=AwsActionFailureCode.TRANSPORT_ERROR,
                )
            return self._response_result(
                action.id,
                service=service,
                region=region,
                started_at=started_at,
                correlation_id=correlation_id,
                response=response,
            )
        except _ActionRejectedError as error:
            return self._error_result(
                action.id,
                service=service,
                region=region,
                started_at=started_at,
                code=error.code,
            )

    def _resolve_inputs(
        self,
        action: AwsSigV4Action,
    ) -> tuple[dict[str, str], list[tuple[str, str]], dict[str, JsonValue]]:
        headers: dict[str, str] = {}
        query: list[tuple[str, str]] = []
        body: dict[str, JsonValue] = {}
        for item in action.inputs:
            if (
                item.location is InputLocation.HEADER
                and item.name.lower() in _RESERVED_HEADERS
            ):
                raise _ActionRejectedError(
                    AwsActionFailureCode.RESERVED_HEADER,
                )
            value = item.value
            if isinstance(value, EnvironmentReference):
                try:
                    resolved: JsonValue = self.environment[value.name]
                except Exception:  # noqa: BLE001 - mappings are untrusted.
                    raise _ActionRejectedError(
                        AwsActionFailureCode.ENVIRONMENT_VALUE_INVALID,
                    ) from None
                if not isinstance(resolved, str) or not resolved:
                    raise _ActionRejectedError(
                        AwsActionFailureCode.ENVIRONMENT_VALUE_INVALID,
                    )
            elif isinstance(value, LiteralInput):
                resolved = value.value
            else:
                raise _ActionRejectedError(
                    AwsActionFailureCode.INVALID_CONFIGURATION,
                )
            _place_input(item.location, item.name, resolved, headers, query, body)
        return headers, sorted(query), body

    def _response_result(  # noqa: PLR0913 - normalization inputs are explicit.
        self,
        action_id: str,
        *,
        service: str,
        region: str,
        started_at: datetime,
        correlation_id: str,
        response: _AwsHttpResponse,
    ) -> ActionExecutionResult:
        if (
            type(response) is not _AwsHttpResponse
            or type(response.status) is not int
            or not _HTTP_STATUS_MIN <= response.status <= _HTTP_STATUS_MAX
            or type(response.too_large) is not bool
            or (
                response.correlation_id is not None
                and not isinstance(response.correlation_id, str)
            )
        ):
            return self._error_result(
                action_id,
                service=service,
                region=region,
                started_at=started_at,
                code=AwsActionFailureCode.INVALID_RESPONSE,
            )
        correlation_state = _correlation_state(
            expected=correlation_id,
            observed=response.correlation_id,
        )
        outcome, error = _outcome(
            response.status,
            too_large=response.too_large,
            correlation_state=correlation_state,
        )
        correlations = (
            (correlation_id,) if correlation_state is _CorrelationState.MATCHED else ()
        )
        observed: dict[str, JsonValue] = {
            "correlation_state": correlation_state.value,
            "http_status": response.status,
            "response_too_large": response.too_large,
            "service": service,
            "signing_region": region,
        }
        if error is not None:
            observed["error"] = error.value
        return ActionExecutionResult(
            action_id=action_id,
            outcome=outcome,
            started_at=started_at,
            completed_at=self._completed_at(started_at),
            observed=RedactedValue(observed),
            correlation_ids=correlations,
            limitations=_LIMITATIONS,
        )

    def _error_result(
        self,
        action_id: str,
        *,
        service: str,
        region: str | None,
        started_at: datetime,
        code: AwsActionFailureCode,
    ) -> ActionExecutionResult:
        return ActionExecutionResult(
            action_id=action_id,
            outcome=ActionOutcome.ERROR,
            started_at=started_at,
            completed_at=self._completed_at(started_at),
            observed=RedactedValue(
                {
                    "correlation_state": _CorrelationState.NOT_CHECKED.value,
                    "error": code.value,
                    "http_status": None,
                    "response_too_large": False,
                    "service": service,
                    "signing_region": region,
                },
            ),
            correlation_ids=(),
            limitations=_LIMITATIONS,
        )

    def _completed_at(self, started_at: datetime) -> datetime:
        completed_at = _normalized_time(self.clock())
        return max(started_at, completed_at)


@dataclass(frozen=True, slots=True)
class _Endpoint:
    hostname: str
    authority: str
    port: int
    base_path: str


@dataclass(frozen=True, slots=True)
class _RequestTarget:
    value: str = field(repr=False)
    query: str = field(repr=False)


def _signing_region(action: AwsSigV4Action, target: Target) -> str:
    target_region = target.aws_region
    action_region = action.region
    if (
        not isinstance(target_region, str)
        or _AWS_REGION_PATTERN.fullmatch(target_region) is None
        or (
            action_region is not None
            and (
                not isinstance(action_region, str)
                or _AWS_REGION_PATTERN.fullmatch(action_region) is None
                or action_region != target_region
            )
        )
    ):
        raise _ActionRejectedError(AwsActionFailureCode.INVALID_CONFIGURATION)
    return action_region or target_region


def _validated_endpoint(target: Target) -> _Endpoint:
    endpoint = urlsplit(str(target.endpoint))
    hostname = endpoint.hostname
    if (
        target.environment is DeploymentEnvironment.LOCAL
        or endpoint.scheme != "https"
        or hostname is None
        or hostname not in target.allowed_hosts
        or _is_local_hostname(hostname)
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.query
        or endpoint.fragment
    ):
        raise _ActionRejectedError(AwsActionFailureCode.INVALID_CONFIGURATION)
    port = endpoint.port
    if port is None:
        port = _HTTPS_PORT
    authority = hostname if port == _HTTPS_PORT else f"{hostname}:{port}"
    return _Endpoint(
        hostname=hostname,
        authority=authority,
        port=port,
        base_path=endpoint.path or "/",
    )


def _is_local_hostname(hostname: str) -> bool:
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return not address.is_global


def _validate_action(action: AwsSigV4Action) -> None:
    if (
        action.service not in _SUPPORTED_SERVICES
        or action.method not in {HttpMethod.GET, HttpMethod.POST}
        or type(action.timeout_seconds) is not int
        or not 1 <= action.timeout_seconds <= _MAX_TIMEOUT_SECONDS
        or action.mutating is not False
        or not isinstance(action.path, str)
        or not action.path.startswith("/")
        or any(character in action.path for character in ("\r", "\n", "?", "#"))
    ):
        raise _ActionRejectedError(AwsActionFailureCode.INVALID_CONFIGURATION)


def _validate_identity(
    identity: AwsScopedIdentity,
    target: Target,
    *,
    region: str,
    evaluated_at: datetime,
) -> None:
    if (
        identity.closed
        or target.aws_account_id is None
        or not identity.matches_account(target.aws_account_id)
        or not identity.matches_partition(_partition_for_region(region))
        or (identity.expires_at is not None and identity.expires_at <= evaluated_at)
    ):
        raise _ActionRejectedError(AwsActionFailureCode.IDENTITY_BOUNDARY_INVALID)


def _place_input(  # noqa: PLR0913 - destinations are explicit trust boundaries.
    location: InputLocation,
    name: str,
    value: JsonValue,
    headers: dict[str, str],
    query: list[tuple[str, str]],
    body: dict[str, JsonValue],
) -> None:
    if location is InputLocation.HEADER:
        if name.lower() in _RESERVED_HEADERS:
            raise _ActionRejectedError(AwsActionFailureCode.RESERVED_HEADER)
        if (
            not isinstance(value, str)
            or "\r" in value
            or "\n" in value
            or len(value.encode("utf-8")) > MAX_REQUEST_BYTES
        ):
            raise _ActionRejectedError(
                AwsActionFailureCode.INVALID_CONFIGURATION,
            )
        headers[name] = value
    elif location is InputLocation.QUERY:
        if (
            not isinstance(value, str | int | float | bool)
            or len(str(value).encode("utf-8")) > MAX_REQUEST_BYTES
        ):
            raise _ActionRejectedError(
                AwsActionFailureCode.INVALID_CONFIGURATION,
            )
        query.append((name, str(value)))
    elif location is InputLocation.JSON:
        body[name] = value
    else:
        raise _ActionRejectedError(AwsActionFailureCode.INVALID_CONFIGURATION)


def _set_default_header(headers: dict[str, str], name: str, value: str) -> None:
    if name.lower() not in {key.lower() for key in headers}:
        headers[name] = value


def _encode_body(body: dict[str, JsonValue]) -> bytes:
    try:
        return json.dumps(
            body,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except TypeError, ValueError:
        raise _ActionRejectedError(
            AwsActionFailureCode.INVALID_CONFIGURATION,
        ) from None


def _enforce_request_size(value: bytes) -> None:
    if len(value) > MAX_REQUEST_BYTES:
        raise _ActionRejectedError(AwsActionFailureCode.REQUEST_TOO_LARGE)


def _request_path(base_path: str, action_path: str) -> str:
    prefix = "" if base_path == "/" else base_path.rstrip("/")
    return f"{prefix}{action_path}"


def _request_target(
    path: str,
    query: list[tuple[str, str]],
) -> _RequestTarget:
    encoded_query = urlencode(
        query,
        doseq=False,
        safe="-_.~",
        quote_via=quote,
    )
    value = f"{path}?{encoded_query}" if encoded_query else path
    return _RequestTarget(value=value, query=encoded_query)


def _correlation_id(run_id: str, scenario_id: str, action_id: str) -> str:
    material = f"{run_id}\0{scenario_id}\0{action_id}".encode()
    return f"aws-{hashlib.sha256(material).hexdigest()[:24]}"


def _correlation_state(
    *,
    expected: str,
    observed: str | None,
) -> _CorrelationState:
    if observed is None:
        return _CorrelationState.NOT_RETURNED
    if observed == expected:
        return _CorrelationState.MATCHED
    return _CorrelationState.MISMATCHED


def _outcome(
    status: int,
    *,
    too_large: bool,
    correlation_state: _CorrelationState,
) -> tuple[ActionOutcome, AwsActionFailureCode | None]:
    if too_large:
        return ActionOutcome.ERROR, AwsActionFailureCode.RESPONSE_TOO_LARGE
    if correlation_state is _CorrelationState.MISMATCHED:
        return ActionOutcome.ERROR, AwsActionFailureCode.INVALID_CORRELATION
    if status in {401, 403}:
        return ActionOutcome.DENIED, None
    if _HTTP_SUCCESS_MIN <= status < _HTTP_SUCCESS_MAX:
        return ActionOutcome.SUCCEEDED, None
    return ActionOutcome.ERROR, AwsActionFailureCode.UNEXPECTED_HTTP_STATUS


def _normalized_time(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        message = "AWS action clock must return a timezone-aware datetime"
        raise ValueError(message)
    return value.astimezone(UTC)
