"""Hardened loopback HTTP surface for the local operator console."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import socket
import threading
import time
import webbrowser
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Never, final

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from cai_verify.aws import MAX_AWS_EXECUTION_POLICY_BYTES
from cai_verify.config import MAX_SUITE_BYTES
from cai_verify.ui.history import (
    EvidenceHistoryError,
    EvidenceHistoryLimitError,
    EvidenceHistoryRunNotFoundError,
    InvalidEvidenceHistoryRequestError,
    UnsafeEvidenceHistoryError,
    get_evidence_history_record,
    list_evidence_history,
)
from cai_verify.ui.state import (
    ConsoleRuntime,
    ConsoleState,
    ConsoleStateError,
    ConsoleStateFailureCode,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
    from datetime import datetime

    from starlette.responses import Response

_SCHEMA_VERSION = "1"
_COOKIE_NAME = "cai_verify_ui"
_SESSION_SECONDS = 8 * 60 * 60
_MAX_SMALL_BODY_BYTES = 16 * 1024
_MAX_BOOTSTRAP_TOKEN_LENGTH = 512
_MAX_HISTORY_CURSOR_LENGTH = 128
_MAX_HISTORY_LIMIT = 50
_MIN_BOOTSTRAP_TOKEN_LENGTH = 32
_MAX_TCP_PORT = 65535
_SOCKET_PORT_INDEX = 1
_CONFIGURATION_DIGEST_COUNT = 2
_SHA256_HEX_LENGTH = 64
_SHA256_HEX_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_SUITE_DIGEST_ENVIRONMENT = "CAI_VERIFY_UI_SUITE_SHA256"
_POLICY_DIGEST_ENVIRONMENT = "CAI_VERIFY_UI_POLICY_SHA256"

_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "base-uri 'none'; "
    "child-src 'none'; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "img-src 'self' data:; "
    "manifest-src 'none'; "
    "media-src 'none'; "
    "object-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "worker-src 'none'"
)


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class ConsoleAppOptions:
    """Explicit launch and injected-runtime settings for one console process."""

    evidence_root: Path = field(repr=False)
    port: int
    bootstrap_token: str = field(repr=False)
    static_directory: Path | None = field(default=None, repr=False)
    environment: Mapping[str, str] | None = field(default=None, repr=False)
    runtime: ConsoleRuntime | None = field(default=None, repr=False)
    clock: Callable[[], datetime] | None = field(default=None, repr=False)
    configuration_digests: tuple[str, str] | None = field(
        default=None,
        repr=False,
    )


@final
class _SessionBoundary:
    """One-use bootstrap capability and one process-local browser session."""

    def __init__(self, bootstrap_token: str) -> None:
        if (
            type(bootstrap_token) is not str
            or not _MIN_BOOTSTRAP_TOKEN_LENGTH
            <= len(bootstrap_token)
            <= _MAX_BOOTSTRAP_TOKEN_LENGTH
        ):
            message = "bootstrap token must be a bounded high-entropy string"
            raise ValueError(message)
        self._bootstrap_token = bootstrap_token
        self._session_token = secrets.token_urlsafe(48)
        self._csrf_token = secrets.token_urlsafe(32)
        self._consumed = False
        self._expires_at: float | None = None
        self._lock = threading.Lock()

    def bootstrap(self, candidate: object) -> str:
        """Consume the launch capability exactly once and return the CSRF value."""
        if type(candidate) is not str:
            _fail("invalid_bootstrap", 401)
        with self._lock:
            if self._consumed or not hmac.compare_digest(
                self._bootstrap_token,
                candidate,
            ):
                _fail("invalid_bootstrap", 401)
            self._consumed = True
            self._bootstrap_token = ""
            self._expires_at = time.monotonic() + _SESSION_SECONDS
            return self._csrf_token

    def session_matches(self, candidate: str | None) -> bool:
        with self._lock:
            expires_at = self._expires_at
            return (
                candidate is not None
                and expires_at is not None
                and time.monotonic() < expires_at
                and hmac.compare_digest(
                    self._session_token,
                    candidate,
                )
            )

    def csrf_matches(self, candidate: str | None) -> bool:
        return candidate is not None and hmac.compare_digest(
            self._csrf_token,
            candidate,
        )

    @property
    def session_token(self) -> str:
        return self._session_token

    @property
    def csrf_token(self) -> str:
        return self._csrf_token

    @property
    def remaining_seconds(self) -> int:
        """Return a conservative bounded session lifetime for UI recovery."""
        with self._lock:
            if self._expires_at is None:
                return 0
            return max(0, math.ceil(self._expires_at - time.monotonic()))


class ConsoleApiError(RuntimeError):
    """A stable API failure that contains no input or implementation detail."""

    def __init__(self, category: str, status_code: int) -> None:
        """Construct a fixed failure without retaining request values."""
        self.category = category
        self.status_code = status_code
        super().__init__(f"console API request failed ({category})")


def create_console_app(  # noqa: C901, PLR0915 - routes share one trust boundary.
    options: ConsoleAppOptions,
) -> FastAPI:
    """Create one exact-origin app without opening a socket."""
    if not 1 <= options.port <= _MAX_TCP_PORT:
        message = "console port must be in range 1..65535"
        raise ValueError(message)
    configuration_digests = _validated_configuration_digests(
        options.configuration_digests
    )
    expected_authority = f"127.0.0.1:{options.port}"
    expected_origin = f"http://{expected_authority}"
    session = _SessionBoundary(options.bootstrap_token)
    state = ConsoleState(
        evidence_root=options.evidence_root,
        environment=options.environment,
        runtime=options.runtime,
        clock=options.clock,
    )
    static_directory = options.static_directory or Path(
        str(files("cai_verify.ui").joinpath("static"))
    )
    index_path = static_directory / "index.html"
    assets_path = static_directory / "assets"

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            state.close()

    app = FastAPI(
        docs_url=None,
        lifespan=lifespan,
        openapi_url=None,
        redoc_url=None,
        title="",
    )
    app.state.console_state = state
    app.state.expected_origin = expected_origin

    @app.middleware("http")
    async def security_boundary(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        try:
            if request.headers.get("host") != expected_authority:
                _fail("invalid_host", 400)
            path = request.url.path
            if path.startswith("/api/"):
                is_bootstrap = path == "/api/v1/session/bootstrap"
                if is_bootstrap:
                    if request.method != "POST":
                        _fail("method_not_allowed", 405)
                    _require_origin(request, expected_origin)
                else:
                    if not session.session_matches(request.cookies.get(_COOKIE_NAME)):
                        _fail("session_required", 401)
                    if request.method not in {"GET", "HEAD", "OPTIONS"}:
                        _require_origin(request, expected_origin)
                        if not session.csrf_matches(
                            request.headers.get("x-csrf-token")
                        ):
                            _fail("csrf_required", 403)
            response = await call_next(request)
        except ConsoleApiError as error:
            response = _error_response(error.category, error.status_code)
        except Exception:  # noqa: BLE001 - never expose framework diagnostics.
            response = _error_response("internal_error", 500)
        _set_security_headers(response, path=request.url.path)
        return response

    @app.exception_handler(ConsoleApiError)
    async def api_error_handler(
        _request: Request,
        error: ConsoleApiError,
    ) -> JSONResponse:
        return _error_response(error.category, error.status_code)

    @app.exception_handler(ConsoleStateError)
    async def state_error_handler(
        _request: Request,
        error: ConsoleStateError,
    ) -> JSONResponse:
        return _error_response(
            error.code.value,
            _state_status_code(error.code),
        )

    @app.exception_handler(EvidenceHistoryError)
    async def history_error_handler(
        _request: Request,
        error: EvidenceHistoryError,
    ) -> JSONResponse:
        category, status_code = _history_error_response(error)
        return _error_response(category, status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        _request: Request,
        _error: RequestValidationError,
    ) -> JSONResponse:
        return _error_response("invalid_request", 422)

    @app.get("/")
    async def index() -> Response:
        if not index_path.is_file():
            _fail("ui_assets_unavailable", 503)
        return FileResponse(index_path, media_type="text/html")

    if assets_path.is_dir():
        app.mount(
            "/assets",
            StaticFiles(directory=assets_path, check_dir=True),
            name="ui-assets",
        )

    @app.post("/api/v1/session/bootstrap")
    async def bootstrap(request: Request) -> JSONResponse:
        body = await _read_json_object(request, _MAX_SMALL_BODY_BYTES)
        if set(body) != {"token"}:
            _fail("invalid_bootstrap", 401)
        csrf_token = session.bootstrap(body["token"])
        response = JSONResponse(
            {
                "csrfToken": csrf_token,
                "expiresInSeconds": _SESSION_SECONDS,
                "schemaVersion": _SCHEMA_VERSION,
            }
        )
        response.set_cookie(
            _COOKIE_NAME,
            session.session_token,
            httponly=True,
            max_age=_SESSION_SECONDS,
            path="/",
            samesite="strict",
        )
        return response

    @app.get("/api/v1/session")
    async def current_session() -> JSONResponse:
        return JSONResponse(
            {
                "csrfToken": session.csrf_token,
                "expiresInSeconds": session.remaining_seconds,
                "schemaVersion": _SCHEMA_VERSION,
            }
        )

    @app.post("/api/v1/configuration/suite")
    async def upload_suite(request: Request) -> JSONResponse:
        content = await _read_bounded_body(request, MAX_SUITE_BYTES)
        if configuration_digests is not None:
            _require_configuration_digest(
                content,
                expected=configuration_digests[0],
                failure_category="invalid_suite",
            )
        try:
            payload = state.load_suite(content)
        except ConsoleStateError:
            raise
        except Exception:  # noqa: BLE001 - parser/model diagnostics stay private.
            _fail("invalid_suite", 422)
        return JSONResponse(payload)

    @app.post("/api/v1/configuration/policy")
    async def upload_policy(request: Request) -> JSONResponse:
        content = await _read_bounded_body(
            request,
            MAX_AWS_EXECUTION_POLICY_BYTES,
        )
        if configuration_digests is not None:
            _require_configuration_digest(
                content,
                expected=configuration_digests[1],
                failure_category="invalid_execution_policy",
            )
        try:
            payload = state.load_policy(content)
        except ConsoleStateError:
            raise
        except Exception:  # noqa: BLE001 - parser/model diagnostics stay private.
            _fail("invalid_execution_policy", 422)
        return JSONResponse(payload)

    @app.get("/api/v1/configuration")
    async def configuration() -> JSONResponse:
        return JSONResponse(state.configuration_view())

    @app.post("/api/v1/configuration/reveal")
    async def reveal(request: Request) -> JSONResponse:
        body = await _read_json_object(request, _MAX_SMALL_BODY_BYTES)
        if set(body) != {"configurationRevision", "fields"}:
            _fail("invalid_request", 422)
        return JSONResponse(state.reveal(body["fields"], body["configurationRevision"]))

    @app.post("/api/v1/readiness")
    async def readiness(request: Request) -> JSONResponse:
        await _require_empty_json_or_body(request)
        return JSONResponse(await run_in_threadpool(state.run_readiness))

    @app.get("/api/v1/readiness")
    async def current_readiness() -> JSONResponse:
        return JSONResponse(
            {
                "readiness": state.readiness_view(),
                "schemaVersion": _SCHEMA_VERSION,
            }
        )

    @app.post("/api/v1/runs")
    async def start_run(request: Request) -> JSONResponse:
        body = await _read_json_object(request, _MAX_SMALL_BODY_BYTES)
        if set(body) != {"configurationRevision", "scenarioId"}:
            _fail("invalid_request", 422)
        return JSONResponse(
            state.start_run(
                body["scenarioId"],
                body["configurationRevision"],
            ),
            status_code=202,
        )

    @app.get("/api/v1/runs/active")
    async def active_run() -> JSONResponse:
        return JSONResponse(state.active_run_view())

    @app.get("/api/v1/history")
    async def evidence_history(
        cursor: str | None = None,
        limit: int = _MAX_HISTORY_LIMIT,
    ) -> JSONResponse:
        if (
            (cursor is not None and len(cursor) > _MAX_HISTORY_CURSOR_LENGTH)
            or type(limit) is not int
            or not 1 <= limit <= _MAX_HISTORY_LIMIT
        ):
            _fail("history_invalid_request", 400)
        return JSONResponse(
            (
                await run_in_threadpool(
                    list_evidence_history,
                    state.evidence_root,
                    cursor=cursor,
                    limit=limit,
                )
            ).to_dict()
        )

    @app.get("/api/v1/history/{run_id}")
    async def evidence_history_record(run_id: str) -> JSONResponse:
        if not run_id or len(run_id) > _MAX_HISTORY_CURSOR_LENGTH:
            _fail("history_invalid_request", 400)
        return JSONResponse(
            (
                await run_in_threadpool(
                    get_evidence_history_record,
                    state.evidence_root,
                    run_id,
                )
            ).to_dict()
        )

    return app


def run_console(
    *,
    evidence_root: Path,
    port: int = 0,
    open_browser: bool = True,
) -> None:
    """Bind only IPv4 loopback, optionally open the browser, and serve."""
    if not 0 <= port <= _MAX_TCP_PORT:
        message = "console port must be in range 0..65535"
        raise ValueError(message)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", port))
        listener.listen(128)
        actual_port = cast_port(listener.getsockname())
        bootstrap_token = secrets.token_urlsafe(48)
        app = create_console_app(
            ConsoleAppOptions(
                evidence_root=evidence_root,
                port=actual_port,
                bootstrap_token=bootstrap_token,
                configuration_digests=_configuration_digests_from_environment(
                    os.environ
                ),
            )
        )
        origin = f"http://127.0.0.1:{actual_port}"
        launch_url = f"{origin}/#bootstrap={bootstrap_token}"
        if open_browser:
            if not webbrowser.open(launch_url):
                message = "could not open the local console browser"
                raise RuntimeError(message)
        else:
            # ``--no-open`` is an explicit operator/automation handoff. The URL
            # is a one-use local capability and is never sent through Uvicorn.
            print(launch_url, flush=True)  # noqa: T201
        config = uvicorn.Config(
            app,
            access_log=False,
            host="127.0.0.1",
            limit_concurrency=32,
            log_level="warning",
            port=actual_port,
            proxy_headers=False,
            server_header=False,
            timeout_keep_alive=5,
            ws="none",
        )
        server = uvicorn.Server(config)
        server.run(sockets=[listener])
    finally:
        listener.close()


def cast_port(address: object) -> int:
    """Extract one validated TCP port without accepting guessed socket shapes."""
    if (
        not isinstance(address, tuple)
        or len(address) <= _SOCKET_PORT_INDEX
        or type(address[1]) is not int
        or not 1 <= address[1] <= _MAX_TCP_PORT
    ):
        message = "loopback listener returned an invalid address"
        raise RuntimeError(message)
    return address[1]


def _configuration_digests_from_environment(
    environment: Mapping[str, str],
) -> tuple[str, str] | None:
    """Read only the paired internal digest lock, never configuration bytes."""
    suite_digest = environment.get(_SUITE_DIGEST_ENVIRONMENT)
    policy_digest = environment.get(_POLICY_DIGEST_ENVIRONMENT)
    if suite_digest is None and policy_digest is None:
        return None
    return _validated_configuration_digests((suite_digest, policy_digest))


def _validated_configuration_digests(
    value: object,
) -> tuple[str, str] | None:
    if value is None:
        return None
    if (
        type(value) is not tuple
        or len(value) != _CONFIGURATION_DIGEST_COUNT
        or any(
            type(item) is not str
            or len(item) != _SHA256_HEX_LENGTH
            or _SHA256_HEX_PATTERN.fullmatch(item) is None
            for item in value
        )
    ):
        message = "configuration digest lock must contain two SHA-256 values"
        raise ValueError(message)
    return value


def _require_configuration_digest(
    content: bytes,
    *,
    expected: str,
    failure_category: str,
) -> None:
    """Fail before parsing when an upload differs from the locked local file."""
    observed = hashlib.sha256(content).hexdigest()
    if not hmac.compare_digest(observed, expected):
        _fail(failure_category, 422)


async def _read_bounded_body(request: Request, maximum_bytes: int) -> bytes:
    _require_json_content_type(request)
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            declared_size = int(declared)
        except ValueError:
            _fail("invalid_request", 400)
        if declared_size < 0 or declared_size > maximum_bytes:
            _fail("request_too_large", 413)
    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > maximum_bytes:
            _fail("request_too_large", 413)
        content.extend(chunk)
    if not content:
        _fail("invalid_request", 400)
    return bytes(content)


async def _read_json_object(
    request: Request,
    maximum_bytes: int,
) -> dict[str, object]:
    content = await _read_bounded_body(request, maximum_bytes)
    try:
        utf8 = content.decode("utf-8")
        value = json.loads(
            utf8,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError, ValueError, RecursionError:
        _fail("invalid_request", 422)
    if not isinstance(value, dict):
        _fail("invalid_request", 422)
    return value


async def _require_empty_json_or_body(request: Request) -> None:
    declared = request.headers.get("content-length")
    if declared in {None, "0"}:
        return
    content = await _read_bounded_body(request, _MAX_SMALL_BODY_BYTES)
    if content not in {b"{}", b"null"}:
        _fail("invalid_request", 422)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def _require_json_content_type(request: Request) -> None:
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip()
    if media_type != "application/json":
        _fail("unsupported_media_type", 415)


def _require_origin(request: Request, expected_origin: str) -> None:
    if request.headers.get("origin") != expected_origin:
        _fail("invalid_origin", 403)


def _fail(category: str, status_code: int) -> Never:
    raise ConsoleApiError(category, status_code)


def _set_security_headers(response: Response, *, path: str) -> None:
    response.headers["Content-Security-Policy"] = _CONTENT_SECURITY_POLICY
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    if path.startswith("/assets/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    else:
        response.headers["Cache-Control"] = "no-store"


def _error_response(category: str, status_code: int) -> JSONResponse:
    messages = {
        "configuration_changed": "Configuration changed; review it again.",
        "configuration_required": "Load a valid suite and execution policy.",
        "csrf_required": "The local session could not authorize this request.",
        "invalid_bootstrap": "The console launch link is invalid or already used.",
        "invalid_execution_policy": "The execution policy is invalid.",
        "invalid_host": "The local console host is invalid.",
        "invalid_origin": "The local console origin is invalid.",
        "invalid_request": "The request is invalid.",
        "invalid_suite": "The verification suite is invalid.",
        "history_invalid_request": "The evidence-history request is invalid.",
        "history_limit_exceeded": (
            "The evidence root exceeds the supported history limit."
        ),
        "history_run_not_found": "The selected evidence run was not found.",
        "history_unsafe": "The evidence root contains an unsafe path.",
        "readiness_required": "Run fresh readiness checks before execution.",
        "readiness_in_progress": "Readiness checks are already in progress.",
        "request_too_large": "The request exceeds the fixed size limit.",
        "run_already_active": "A reciprocal run is already active.",
        "session_required": "Open the console from its one-time launch link.",
        "ui_assets_unavailable": "The packaged console assets are unavailable.",
        "unsupported_media_type": "The request must use application/json.",
    }
    return JSONResponse(
        {
            "error": {
                "category": category,
                "message": messages.get(
                    category,
                    "The local console could not complete this request.",
                ),
            },
            "schemaVersion": _SCHEMA_VERSION,
        },
        status_code=status_code,
    )


def _state_status_code(code: ConsoleStateFailureCode) -> int:
    if code in {
        ConsoleStateFailureCode.READINESS_IN_PROGRESS,
        ConsoleStateFailureCode.RUN_ALREADY_ACTIVE,
    }:
        return 409
    if code in {
        ConsoleStateFailureCode.CONFIGURATION_REQUIRED,
        ConsoleStateFailureCode.READINESS_REQUIRED,
    }:
        return 412
    if code is ConsoleStateFailureCode.CONFIGURATION_CHANGED:
        return 409
    if code is ConsoleStateFailureCode.INVALID_REQUEST:
        return 422
    return 422


def _history_error_response(error: EvidenceHistoryError) -> tuple[str, int]:
    if isinstance(error, InvalidEvidenceHistoryRequestError):
        return ("history_invalid_request", 400)
    if isinstance(error, EvidenceHistoryRunNotFoundError):
        return ("history_run_not_found", 404)
    if isinstance(error, EvidenceHistoryLimitError):
        return ("history_limit_exceeded", 409)
    if isinstance(error, UnsafeEvidenceHistoryError):
        return ("history_unsafe", 409)
    return ("history_unsafe", 409)
