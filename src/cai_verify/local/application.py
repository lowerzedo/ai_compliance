"""A loopback-only synthetic AI application with two telemetry modes."""

from __future__ import annotations

import json
import re
import threading
from enum import StrEnum
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Self, final

from cai_verify.local.telemetry import AuditRecord, LocalTelemetrySink, TelemetryRecord

if TYPE_CHECKING:
    from datetime import datetime
    from types import TracebackType

_MAX_REQUEST_BYTES = 16 * 1024
_MAX_PROMPT_CHARACTERS = 4_096
_REQUEST_READ_TIMEOUT_SECONDS = 5
_CORRELATION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_PRINCIPAL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")


class SyntheticTelemetryMode(StrEnum):
    """Whether the synthetic application omits or records request content."""

    SECURE = "secure"
    VULNERABLE = "vulnerable"


@final
class SyntheticAiApplication:
    """Serve one deterministic synthetic inference endpoint on loopback."""

    def __init__(
        self,
        *,
        mode: SyntheticTelemetryMode,
        sink: LocalTelemetrySink,
        occurred_at: datetime,
    ) -> None:
        """Configure one mode, sink, and deterministic event timestamp."""
        if not isinstance(mode, SyntheticTelemetryMode):
            message = "mode must be a SyntheticTelemetryMode"
            raise TypeError(message)
        self._mode = mode
        self._sink = sink
        self._occurred_at = occurred_at
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def endpoint(self) -> str:
        """Return the active loopback endpoint using the declared hostname."""
        if self._server is None:
            message = "synthetic application has not been started"
            raise RuntimeError(message)
        port = self._server.server_address[1]
        return f"http://localhost:{port}"

    def __enter__(self) -> Self:
        """Start the application on an ephemeral loopback port."""
        if self._server is not None:
            message = "synthetic application is already running"
            raise RuntimeError(message)
        application = self

        class RequestHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                application._handle_post(self)

            def log_message(self, format_string: str, *args: object) -> None:
                """Suppress request data from the default stderr logger."""
                del format_string, args

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), RequestHandler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="cai-verify-synthetic-app",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Stop the application and release the loopback port."""
        del exc_type, exc_value, traceback
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    def _handle_post(self, handler: BaseHTTPRequestHandler) -> None:
        if handler.path != "/v1/inference":
            self._write_response(handler, HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        content_type = handler.headers.get_content_type()
        if content_type != "application/json":
            self._write_response(
                handler,
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {"error": "unsupported_media_type"},
            )
            return
        try:
            length = int(handler.headers.get("Content-Length", ""))
        except ValueError:
            length = -1
        if length < 0 or length > _MAX_REQUEST_BYTES:
            self._write_response(
                handler,
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": "invalid_content_length"},
            )
            return
        handler.connection.settimeout(_REQUEST_READ_TIMEOUT_SECONDS)
        try:
            content = handler.rfile.read(length)
        except OSError:
            return
        try:
            payload = json.loads(content, object_pairs_hook=_unique_payload)
        except UnicodeDecodeError, ValueError, RecursionError:
            payload = None
        if not isinstance(payload, dict) or set(payload) != {"prompt"}:
            self._write_response(
                handler,
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_request"},
            )
            return
        prompt = payload["prompt"]
        principal = handler.headers.get("X-Synthetic-Principal", "")
        correlation_id = handler.headers.get("X-Cai-Correlation-Id", "")
        if (
            not isinstance(prompt, str)
            or not prompt
            or len(prompt) > _MAX_PROMPT_CHARACTERS
            or _PRINCIPAL_PATTERN.fullmatch(principal) is None
            or _CORRELATION_PATTERN.fullmatch(correlation_id) is None
        ):
            self._write_response(
                handler,
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_request"},
            )
            return

        telemetry_message = (
            "synthetic_prompt_received"
            if self._mode is SyntheticTelemetryMode.SECURE
            else prompt
        )
        self._sink.record_telemetry(
            TelemetryRecord(
                correlation_id=correlation_id,
                message=telemetry_message,
                occurred_at=self._occurred_at,
            ),
        )
        self._sink.record_audit(
            AuditRecord(
                correlation_id=correlation_id,
                event_name="SyntheticInference",
                principal=principal,
                occurred_at=self._occurred_at,
            ),
        )
        self._write_response(
            handler,
            HTTPStatus.OK,
            {"summary": "Synthetic response generated locally."},
            correlation_id=correlation_id,
        )

    @staticmethod
    def _write_response(
        handler: BaseHTTPRequestHandler,
        status: HTTPStatus,
        payload: dict[str, str],
        *,
        correlation_id: str | None = None,
    ) -> None:
        content = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        handler.send_response(status.value)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(content)))
        if correlation_id is not None:
            handler.send_header("X-Cai-Correlation-Id", correlation_id)
        handler.end_headers()
        handler.wfile.write(content)


def _unique_payload(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            message = "duplicate request field"
            raise ValueError(message)
        value[key] = item
    return value
