"""Bounded HTTP action execution for the loopback synthetic target."""

from __future__ import annotations

import hashlib
import http.client
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, final
from urllib.parse import urlencode, urlsplit

from cai_verify.adapters._limits import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
from cai_verify.config import EnvironmentReference, HttpAction, LiteralInput
from cai_verify.config.models import DeploymentEnvironment, InputLocation
from cai_verify.core import RedactedValue
from cai_verify.local.identity import SyntheticScopedIdentity
from cai_verify.local.telemetry import pseudonymize_principal
from cai_verify.plugins import (
    PLUGIN_API_VERSION,
    ActionExecutionResult,
    ActionOutcome,
    ActionRequest,
    PluginMetadata,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from cai_verify.core import JsonValue

_HTTP_SUCCESS_MIN = 200
_HTTP_SUCCESS_MAX = 300
_RESERVED_HEADERS = {
    "connection",
    "content-length",
    "host",
    "transfer-encoding",
    "x-cai-correlation-id",
    "x-synthetic-principal",
}


@dataclass(frozen=True, slots=True)
class _HttpResponse:
    status: int
    correlation_id: str | None
    too_large: bool


@final
@dataclass(frozen=True, slots=True)
class HttpActionAdapter:
    """Execute declared HTTP actions against an exact localhost endpoint."""

    environment: Mapping[str, str] = field(repr=False)
    occurred_at: datetime

    @property
    def metadata(self) -> PluginMetadata:
        """Declare the built-in loopback HTTP capability."""
        return PluginMetadata(
            name="local-http-action",
            api_version=PLUGIN_API_VERSION,
            capabilities=("action.http.local",),
        )

    def execute_action(self, request: ActionRequest, /) -> ActionExecutionResult:
        """Perform one bounded request without retaining request or response bodies."""
        action = request.action
        target = request.context.target
        if not isinstance(action, HttpAction):
            message = "HTTP adapter requires an http action declaration"
            raise TypeError(message)
        if target.environment is not DeploymentEnvironment.LOCAL:
            message = "built-in HTTP adapter is restricted to local targets"
            raise ValueError(message)
        identity = request.identity
        if type(identity) is not SyntheticScopedIdentity:
            message = "local HTTP actions require a synthetic scoped identity"
            raise TypeError(message)

        port = _local_port(str(target.endpoint))

        correlation_id = _correlation_id(
            request.context.run_id,
            request.context.scenario_id,
            action.id,
        )
        headers, query, body = self._resolve_inputs(action)
        headers["Content-Type"] = "application/json"
        headers["X-Cai-Correlation-Id"] = correlation_id
        headers["X-Synthetic-Principal"] = identity.principal
        encoded_body = json.dumps(
            body,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        if len(encoded_body) > MAX_REQUEST_BYTES:
            return self._error_result(
                action.id,
                identity.principal,
                error="request_too_large",
            )
        path = action.path
        if query:
            path = f"{path}?{urlencode(query)}"

        response = _send_request(
            port=port,
            timeout=action.timeout_seconds,
            method=action.method.value,
            path=path,
            body=encoded_body,
            headers=headers,
        )
        if response is None:
            return self._error_result(
                action.id,
                identity.principal,
                error="transport_error",
            )
        correlation_valid = response.correlation_id in {None, correlation_id}
        outcome = _outcome(
            response.status,
            too_large=response.too_large,
            correlation_valid=correlation_valid,
        )
        correlations = (
            (correlation_id,)
            if response.correlation_id == correlation_id and correlation_valid
            else ()
        )
        return ActionExecutionResult(
            action_id=action.id,
            outcome=outcome,
            started_at=self.occurred_at,
            completed_at=self.occurred_at,
            observed=RedactedValue(
                {
                    "http_status": response.status,
                    "correlation_valid": correlation_valid,
                    "principal_pseudonym": pseudonymize_principal(
                        identity.principal,
                    ),
                    "response_too_large": response.too_large,
                },
            ),
            correlation_ids=correlations,
            limitations=(
                "Request and response bodies are excluded from normalized evidence.",
                "This built-in adapter is restricted to an exact loopback target.",
            ),
        )

    def _resolve_inputs(
        self,
        action: HttpAction,
    ) -> tuple[dict[str, str], list[tuple[str, str]], dict[str, JsonValue]]:
        headers: dict[str, str] = {}
        query: list[tuple[str, str]] = []
        body: dict[str, JsonValue] = {}
        for item in action.inputs:
            value = item.value
            if isinstance(value, EnvironmentReference):
                try:
                    resolved: JsonValue = self.environment[value.name]
                except KeyError as error:
                    message = f"missing environment value: {value.name}"
                    raise ValueError(message) from error
                if not resolved:
                    message = f"environment value must not be empty: {value.name}"
                    raise ValueError(message)
            elif isinstance(value, LiteralInput):
                resolved = value.value
            else:
                message = "unsupported HTTP input source"
                raise TypeError(message)

            _place_input(item.location, item.name, resolved, headers, query, body)
        return headers, sorted(query), body

    def _error_result(
        self,
        action_id: str,
        principal: str,
        *,
        error: str,
    ) -> ActionExecutionResult:
        return ActionExecutionResult(
            action_id=action_id,
            outcome=ActionOutcome.ERROR,
            started_at=self.occurred_at,
            completed_at=self.occurred_at,
            observed=RedactedValue(
                {
                    "error": error,
                    "principal_pseudonym": pseudonymize_principal(principal),
                },
            ),
            correlation_ids=(),
            limitations=(
                "Transport failures are normalized without exception details.",
            ),
        )


def _correlation_id(run_id: str, scenario_id: str, action_id: str) -> str:
    material = f"{run_id}\0{scenario_id}\0{action_id}".encode()
    return f"local-{hashlib.sha256(material).hexdigest()[:24]}"


def _local_port(endpoint_value: str) -> int:
    endpoint = urlsplit(endpoint_value)
    if (
        endpoint.scheme != "http"
        or endpoint.hostname != "localhost"
        or endpoint.port is None
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.path not in {"", "/"}
        or endpoint.query
        or endpoint.fragment
    ):
        message = "local HTTP endpoint must be an explicit localhost port"
        raise ValueError(message)
    return endpoint.port


def _send_request(  # noqa: PLR0913 - exact HTTP request fields are explicit.
    *,
    port: int,
    timeout: int,
    method: str,
    path: str,
    body: bytes,
    headers: Mapping[str, str],
) -> _HttpResponse | None:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(method, path, body, headers)
        response = connection.getresponse()
        content = response.read(MAX_RESPONSE_BYTES + 1)
        return _HttpResponse(
            status=response.status,
            correlation_id=response.getheader("X-Cai-Correlation-Id"),
            too_large=len(content) > MAX_RESPONSE_BYTES,
        )
    except OSError, TimeoutError, http.client.HTTPException:
        return None
    finally:
        connection.close()


def _outcome(
    status: int,
    *,
    too_large: bool,
    correlation_valid: bool,
) -> ActionOutcome:
    if too_large or not correlation_valid:
        return ActionOutcome.ERROR
    if status in {401, 403}:
        return ActionOutcome.DENIED
    if _HTTP_SUCCESS_MIN <= status < _HTTP_SUCCESS_MAX:
        return ActionOutcome.SUCCEEDED
    return ActionOutcome.ERROR


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
            message = f"reserved HTTP header: {name}"
            raise ValueError(message)
        if not isinstance(value, str):
            message = f"HTTP header input must resolve to text: {name}"
            raise TypeError(message)
        if "\r" in value or "\n" in value or len(value) > MAX_REQUEST_BYTES:
            message = f"HTTP header input is invalid: {name}"
            raise ValueError(message)
        headers[name] = value
    elif location is InputLocation.QUERY:
        if not isinstance(value, str | int | float | bool):
            message = f"HTTP query input must resolve to a scalar: {name}"
            raise TypeError(message)
        query.append((name, str(value)))
    else:
        body[name] = value
