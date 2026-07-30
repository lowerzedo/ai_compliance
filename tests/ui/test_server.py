"""Exact-origin HTTP boundary tests for the local operator console."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, replace
from datetime import timedelta
from http import HTTPStatus
from typing import TYPE_CHECKING, cast

import pytest
import pytest_socket
from fastapi.testclient import TestClient

from cai_verify.aws import (
    MAX_AWS_EXECUTION_POLICY_BYTES,
    AwsReciprocalRetrievalRunError,
    AwsReciprocalRetrievalRunFailureCode,
    AwsReciprocalRetrievalRunOptions,
    AwsReciprocalRetrievalRunResult,
    AwsSessionFactory,
    run_aws_reciprocal_retrieval,
)
from cai_verify.config import MAX_SUITE_BYTES
from cai_verify.ui.server import ConsoleAppOptions, create_console_app, run_console
from cai_verify.ui.state import ConsoleRuntime
from tests.aws import (
    test_reciprocal_retrieval_runner as reciprocal_test_support,
)
from tests.ui._console_fakes import (
    POLICY_BYTES,
    ROOT,
    SCENARIO_ID,
    SENSITIVE_CONFIGURATION_VALUES,
    SUITE_BYTES,
    SYNTHETIC_ENVIRONMENT,
    MutableClock,
    RuntimeHarness,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping
    from pathlib import Path

    from fastapi import FastAPI
    from httpx import Response

    from cai_verify.config import VerificationSuite

_PORT = 43123
_ORIGIN = f"http://127.0.0.1:{_PORT}"
_BOOTSTRAP_TOKEN = "bootstrap-token-" + ("a" * 48)
_MIN_CSRF_TOKEN_LENGTH = 32
_SESSION_SECONDS = 28800
_REVEAL_SECONDS = 30
_LISTEN_BACKLOG = 128
_SECURITY_HEADERS = {
    "cache-control": "no-store",
    "content-security-policy": (
        "default-src 'self'; base-uri 'none'; child-src 'none'; "
        "connect-src 'self'; font-src 'self'; form-action 'self'; "
        "frame-ancestors 'none'; img-src 'self' data:; "
        "manifest-src 'none'; media-src 'none'; object-src 'none'; "
        "script-src 'self'; style-src 'self'; worker-src 'none'"
    ),
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": (
        "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
    ),
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}


@pytest.fixture(autouse=True)
def _allow_only_event_loop_socketpair() -> Iterator[None]:
    """Permit AF_UNIX asyncio internals while continuing to block networking."""
    pytest_socket.enable_socket()
    pytest_socket.disable_socket(allow_unix_socket=True)
    yield
    pytest_socket.enable_socket()
    pytest_socket.disable_socket()


@dataclass(frozen=True, slots=True)
class _ConsoleFixture:
    """One ASGI app plus its injected synthetic seams."""

    app: FastAPI
    harness: RuntimeHarness
    clock: MutableClock
    static_directory: Path


def _build_console(
    tmp_path: Path,
    *,
    harness: RuntimeHarness | None = None,
    clock: MutableClock | None = None,
    runtime: ConsoleRuntime | None = None,
    environment: Mapping[str, str] | None = None,
) -> _ConsoleFixture:
    selected_harness = harness or RuntimeHarness()
    selected_clock = clock or MutableClock()
    static_directory = tmp_path / "static"
    assets_directory = static_directory / "assets"
    assets_directory.mkdir(parents=True)
    (static_directory / "index.html").write_text(
        "<!doctype html><title>CAI Verify</title><main>Forensic console</main>",
        encoding="utf-8",
    )
    (assets_directory / "app.js").write_text(
        "document.documentElement.dataset.ready='true';",
        encoding="utf-8",
    )
    app = create_console_app(
        ConsoleAppOptions(
            evidence_root=tmp_path / "evidence",
            port=_PORT,
            bootstrap_token=_BOOTSTRAP_TOKEN,
            static_directory=static_directory,
            environment=environment or SYNTHETIC_ENVIRONMENT,
            runtime=runtime or selected_harness.as_runtime(),
            clock=selected_clock,
        )
    )
    return _ConsoleFixture(
        app=app,
        harness=selected_harness,
        clock=selected_clock,
        static_directory=static_directory,
    )


@pytest.fixture
def console(
    tmp_path: Path,
) -> Iterator[tuple[_ConsoleFixture, TestClient, str]]:
    """Yield one bootstrapped exact-origin client."""
    fixture = _build_console(tmp_path)
    with TestClient(
        fixture.app,
        base_url=_ORIGIN,
        raise_server_exceptions=False,
    ) as client:
        csrf, _response = _bootstrap(client)
        try:
            yield fixture, client, csrf
        finally:
            fixture.harness.release.set()


def _bootstrap(client: TestClient) -> tuple[str, Response]:
    response = client.post(
        "/api/v1/session/bootstrap",
        headers={"origin": _ORIGIN},
        json={"token": _BOOTSTRAP_TOKEN},
    )
    assert response.status_code == HTTPStatus.OK
    payload = _json(response)
    token = payload["csrfToken"]
    assert isinstance(token, str)
    return token, response


def _mutation_headers(csrf: str) -> dict[str, str]:
    return {
        "content-type": "application/json",
        "origin": _ORIGIN,
        "x-csrf-token": csrf,
    }


def _load_configuration(client: TestClient, csrf: str) -> None:
    headers = _mutation_headers(csrf)
    suite = client.post(
        "/api/v1/configuration/suite",
        headers=headers,
        content=SUITE_BYTES,
    )
    policy = client.post(
        "/api/v1/configuration/policy",
        headers=headers,
        content=POLICY_BYTES,
    )
    assert suite.status_code == HTTPStatus.OK
    assert policy.status_code == HTTPStatus.OK


def _json(response: Response) -> dict[str, object]:
    payload = response.json()
    assert isinstance(payload, dict)
    return cast("dict[str, object]", payload)


def _run_request_body(client: TestClient) -> bytes:
    configuration = _json(client.get("/api/v1/configuration"))
    revision = configuration["configurationRevision"]
    assert type(revision) is int
    return json.dumps(
        {
            "configurationRevision": revision,
            "scenarioId": SCENARIO_ID,
        }
    ).encode()


def _wait_for_api_terminal(
    client: TestClient,
    *,
    timeout_seconds: float = 2,
) -> tuple[Response, dict[str, object]]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        response = client.get("/api/v1/runs/active")
        payload = _json(response)
        if payload["state"] in {"complete", "failed"}:
            return response, payload
        time.sleep(0.005)
    message = "console API run did not reach a terminal state"
    raise AssertionError(message)


def test_bootstrap_is_one_time_and_sets_only_a_host_cookie(
    tmp_path: Path,
) -> None:
    """The URL capability is exchanged once for HttpOnly session state."""
    fixture = _build_console(tmp_path)
    with TestClient(
        fixture.app,
        base_url=_ORIGIN,
        raise_server_exceptions=False,
    ) as client:
        csrf, response = _bootstrap(client)

        assert len(csrf) >= _MIN_CSRF_TOKEN_LENGTH
        assert _json(response)["expiresInSeconds"] == _SESSION_SECONDS
        cookie = response.headers["set-cookie"]
        assert "cai_verify_ui=" in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=strict" in cookie
        assert "Max-Age=28800" in cookie
        assert "Path=/" in cookie
        assert "Domain=" not in cookie
        assert _BOOTSTRAP_TOKEN not in cookie

        recovered = client.get("/api/v1/session")
        repeated = client.post(
            "/api/v1/session/bootstrap",
            headers={"origin": _ORIGIN},
            json={"token": _BOOTSTRAP_TOKEN},
        )

    assert recovered.status_code == HTTPStatus.OK
    recovered_payload = _json(recovered)
    assert recovered_payload["csrfToken"] == csrf
    assert recovered_payload["schemaVersion"] == "1"
    remaining = recovered_payload["expiresInSeconds"]
    assert type(remaining) is int
    assert 0 < remaining <= _SESSION_SECONDS
    assert repeated.status_code == HTTPStatus.UNAUTHORIZED
    assert _json(repeated)["error"] == {
        "category": "invalid_bootstrap",
        "message": "The console launch link is invalid or already used.",
    }
    assert _BOOTSTRAP_TOKEN not in repeated.text


def test_exact_host_origin_session_and_csrf_are_enforced(
    tmp_path: Path,
) -> None:
    """Every request crosses the fixed authority and mutation protections."""
    fixture = _build_console(tmp_path)
    with TestClient(
        fixture.app,
        base_url=_ORIGIN,
        raise_server_exceptions=False,
    ) as client:
        no_session = client.get("/api/v1/configuration")
        bad_host = client.post(
            "/api/v1/session/bootstrap",
            headers={
                "host": "localhost:43123",
                "origin": _ORIGIN,
            },
            json={"token": _BOOTSTRAP_TOKEN},
        )
        bad_bootstrap_origin = client.post(
            "/api/v1/session/bootstrap",
            headers={"origin": "http://127.0.0.1:43124"},
            json={"token": _BOOTSTRAP_TOKEN},
        )
        csrf, _response = _bootstrap(client)
        get_without_origin = client.get("/api/v1/configuration")
        missing_origin = client.post(
            "/api/v1/readiness",
            headers={
                "content-type": "application/json",
                "x-csrf-token": csrf,
            },
            content=b"{}",
        )
        wrong_origin = client.post(
            "/api/v1/readiness",
            headers={
                "content-type": "application/json",
                "origin": "http://localhost:43123",
                "x-csrf-token": csrf,
            },
            content=b"{}",
        )
        missing_csrf = client.post(
            "/api/v1/readiness",
            headers={
                "content-type": "application/json",
                "origin": _ORIGIN,
            },
            content=b"{}",
        )
        wrong_csrf = client.post(
            "/api/v1/readiness",
            headers={
                "content-type": "application/json",
                "origin": _ORIGIN,
                "x-csrf-token": "wrong-csrf",
            },
            content=b"{}",
        )

    assert no_session.status_code == HTTPStatus.UNAUTHORIZED
    assert _json(no_session)["error"] == {
        "category": "session_required",
        "message": "Open the console from its one-time launch link.",
    }
    assert bad_host.status_code == HTTPStatus.BAD_REQUEST
    assert _json(bad_host)["error"] == {
        "category": "invalid_host",
        "message": "The local console host is invalid.",
    }
    assert bad_bootstrap_origin.status_code == HTTPStatus.FORBIDDEN
    assert get_without_origin.status_code == HTTPStatus.OK
    assert missing_origin.status_code == HTTPStatus.FORBIDDEN
    assert _json(missing_origin)["error"] == {
        "category": "invalid_origin",
        "message": "The local console origin is invalid.",
    }
    assert wrong_origin.status_code == HTTPStatus.FORBIDDEN
    assert missing_csrf.status_code == HTTPStatus.FORBIDDEN
    assert wrong_csrf.status_code == HTTPStatus.FORBIDDEN


def test_static_and_api_responses_apply_strict_security_headers(
    console: tuple[_ConsoleFixture, TestClient, str],
) -> None:
    """Assets are local-only, documentation is off, and framing is denied."""
    _fixture, client, _csrf = console

    index = client.get("/")
    asset = client.get("/assets/app.js")
    source_map = client.get("/assets/app.js.map")
    openapi = client.get("/openapi.json")
    swagger = client.get("/docs")
    redoc = client.get("/redoc")

    assert index.status_code == HTTPStatus.OK
    assert index.headers["content-type"].startswith("text/html")
    assert asset.status_code == HTTPStatus.OK
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert source_map.status_code == HTTPStatus.NOT_FOUND
    assert openapi.status_code == HTTPStatus.NOT_FOUND
    assert swagger.status_code == HTTPStatus.NOT_FOUND
    assert redoc.status_code == HTTPStatus.NOT_FOUND
    assert "access-control-allow-origin" not in index.headers
    for name, value in _SECURITY_HEADERS.items():
        assert index.headers[name] == value
        if name != "cache-control":
            assert asset.headers[name] == value
            assert source_map.headers[name] == value


@pytest.mark.parametrize(
    ("route", "maximum"),
    [
        ("/api/v1/configuration/suite", MAX_SUITE_BYTES),
        ("/api/v1/configuration/policy", MAX_AWS_EXECUTION_POLICY_BYTES),
    ],
)
def test_uploads_reject_oversized_bodies_before_parsing(
    console: tuple[_ConsoleFixture, TestClient, str],
    route: str,
    maximum: int,
) -> None:
    """Each upload enforces its existing byte ceiling."""
    _fixture, client, csrf = console

    response = client.post(
        route,
        headers=_mutation_headers(csrf),
        content=b"{" + (b" " * maximum),
    )

    assert response.status_code == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    assert _json(response)["error"] == {
        "category": "request_too_large",
        "message": "The request exceeds the fixed size limit.",
    }


@pytest.mark.parametrize(
    ("route", "content", "category"),
    [
        (
            "/api/v1/configuration/suite",
            b'{"schemaVersion":"1alpha1","schemaVersion":"1alpha1"}',
            "invalid_suite",
        ),
        (
            "/api/v1/configuration/policy",
            b'{"region":"eu-west-2","region":"eu-west-2"}',
            "invalid_execution_policy",
        ),
        (
            "/api/v1/configuration/suite",
            b"\xff",
            "invalid_suite",
        ),
        (
            "/api/v1/configuration/policy",
            b"{not-json}",
            "invalid_execution_policy",
        ),
    ],
)
def test_uploads_return_deterministic_duplicate_and_malformed_errors(
    console: tuple[_ConsoleFixture, TestClient, str],
    route: str,
    content: bytes,
    category: str,
) -> None:
    """Strict JSON failures never echo untrusted source bytes."""
    _fixture, client, csrf = console

    response = client.post(
        route,
        headers=_mutation_headers(csrf),
        content=content,
    )

    assert response.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
    assert _json(response)["error"] == {
        "category": category,
        "message": (
            "The verification suite is invalid."
            if category == "invalid_suite"
            else "The execution policy is invalid."
        ),
    }
    decoded_source = content.decode("utf-8", errors="ignore")
    assert not decoded_source or decoded_source not in response.text


def test_uploads_require_json_and_failed_replacement_clears_state(
    console: tuple[_ConsoleFixture, TestClient, str],
) -> None:
    """Wrong media types fail and invalid replacement cannot retain readiness."""
    _fixture, client, csrf = console
    _load_configuration(client, csrf)
    readiness = client.post(
        "/api/v1/readiness",
        headers=_mutation_headers(csrf),
        content=b"{}",
    )
    assert readiness.status_code == HTTPStatus.OK

    wrong_media = client.post(
        "/api/v1/configuration/suite",
        headers={
            "content-type": "text/plain",
            "origin": _ORIGIN,
            "x-csrf-token": csrf,
        },
        content=SUITE_BYTES,
    )
    malformed = client.post(
        "/api/v1/configuration/suite",
        headers=_mutation_headers(csrf),
        content=b"{}",
    )
    configuration = client.get("/api/v1/configuration")
    current_readiness = client.get("/api/v1/readiness")

    assert wrong_media.status_code == HTTPStatus.UNSUPPORTED_MEDIA_TYPE
    assert malformed.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
    assert _json(configuration)["suiteLoaded"] is False
    assert _json(configuration)["policyLoaded"] is True
    assert _json(current_readiness)["readiness"] is None


def test_redacted_review_and_explicit_reveal_never_return_environment_values(
    console: tuple[_ConsoleFixture, TestClient, str],
) -> None:
    """The API separates a masked plan from its narrowly allowlisted reveal."""
    _fixture, client, csrf = console
    _load_configuration(client, csrf)

    configuration = client.get("/api/v1/configuration")
    payload = _json(configuration)
    review = payload["review"]
    assert isinstance(review, dict)
    sensitive_fields = review["sensitiveFields"]
    assert isinstance(sensitive_fields, list)
    serialized_review = configuration.text
    for sensitive in (
        *SENSITIVE_CONFIGURATION_VALUES,
        *SYNTHETIC_ENVIRONMENT.values(),
    ):
        assert sensitive not in serialized_review
    ids = [field["id"] for field in sensitive_fields if isinstance(field, dict)]
    revision = payload["configurationRevision"]
    assert type(revision) is int

    reveal = client.post(
        "/api/v1/configuration/reveal",
        headers=_mutation_headers(csrf),
        content=json.dumps({"configurationRevision": revision, "fields": ids}).encode(),
    )
    duplicate = client.post(
        "/api/v1/configuration/reveal",
        headers=_mutation_headers(csrf),
        content=(
            b'{"configurationRevision":4,"fields":["field-01"],"fields":["field-02"]}'
        ),
    )
    unknown = client.post(
        "/api/v1/configuration/reveal",
        headers=_mutation_headers(csrf),
        content=(b'{"configurationRevision":4,"fields":["not-allowlisted"]}'),
    )

    assert reveal.status_code == HTTPStatus.OK
    assert _json(reveal)["configurationRevision"] == revision
    assert _json(reveal)["expiresInSeconds"] == _REVEAL_SECONDS
    assert duplicate.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
    assert unknown.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
    for secret in SYNTHETIC_ENVIRONMENT.values():
        assert secret not in reveal.text
        assert secret not in duplicate.text
        assert secret not in unknown.text


def test_reveal_rejects_stale_configuration_revision(
    console: tuple[_ConsoleFixture, TestClient, str],
) -> None:
    """Field aliases cannot cross configuration generations between batches."""
    _fixture, client, csrf = console
    _load_configuration(client, csrf)
    configuration = _json(client.get("/api/v1/configuration"))
    revision = configuration["configurationRevision"]
    review = configuration["review"]
    assert type(revision) is int
    assert isinstance(review, dict)
    fields = review["sensitiveFields"]
    assert isinstance(fields, list)
    field = fields[0]
    assert isinstance(field, dict)
    field_id = field["id"]

    replacement = client.post(
        "/api/v1/configuration/policy",
        headers=_mutation_headers(csrf),
        content=POLICY_BYTES,
    )
    stale = client.post(
        "/api/v1/configuration/reveal",
        headers=_mutation_headers(csrf),
        content=json.dumps(
            {"configurationRevision": revision, "fields": [field_id]}
        ).encode(),
    )

    assert replacement.status_code == HTTPStatus.OK
    assert stale.status_code == HTTPStatus.CONFLICT
    assert _json(stale)["error"] == {
        "category": "configuration_changed",
        "message": "Configuration changed; review it again.",
    }
    for sensitive in SENSITIVE_CONFIGURATION_VALUES:
        assert sensitive not in stale.text


def test_readiness_is_required_expires_and_is_invalidated(
    console: tuple[_ConsoleFixture, TestClient, str],
) -> None:
    """Execution requires a current successful preflight for current inputs."""
    fixture, client, csrf = console

    without_configuration = client.post(
        "/api/v1/readiness",
        headers=_mutation_headers(csrf),
        content=b"{}",
    )
    assert without_configuration.status_code == HTTPStatus.PRECONDITION_FAILED
    _load_configuration(client, csrf)
    readiness = client.post(
        "/api/v1/readiness",
        headers=_mutation_headers(csrf),
        content=b"{}",
    )
    assert readiness.status_code == HTTPStatus.OK
    assert _json(readiness)["ready"] is True
    fixture.clock.advance(timedelta(minutes=5))
    expired = client.post(
        "/api/v1/runs",
        headers=_mutation_headers(csrf),
        content=_run_request_body(client),
    )
    assert expired.status_code == HTTPStatus.PRECONDITION_FAILED

    rerun = client.post(
        "/api/v1/readiness",
        headers=_mutation_headers(csrf),
        content=b"{}",
    )
    assert rerun.status_code == HTTPStatus.OK
    changed = client.post(
        "/api/v1/configuration/policy",
        headers=_mutation_headers(csrf),
        content=POLICY_BYTES,
    )
    assert changed.status_code == HTTPStatus.OK
    current = client.get("/api/v1/readiness")
    assert _json(current)["readiness"] is None


def test_one_active_run_returns_bounded_progress_and_normalized_result(
    tmp_path: Path,
) -> None:
    """A second run is rejected while the worker exposes only fixed stages."""
    harness = RuntimeHarness(block_runner=True)
    fixture = _build_console(tmp_path, harness=harness)
    with TestClient(
        fixture.app,
        base_url=_ORIGIN,
        raise_server_exceptions=False,
    ) as client:
        csrf, _response = _bootstrap(client)
        _load_configuration(client, csrf)
        ready = client.post(
            "/api/v1/readiness",
            headers=_mutation_headers(csrf),
            content=b"{}",
        )
        assert ready.status_code == HTTPStatus.OK
        first = client.post(
            "/api/v1/runs",
            headers=_mutation_headers(csrf),
            content=_run_request_body(client),
        )
        assert first.status_code == HTTPStatus.ACCEPTED
        assert harness.started.wait(timeout=2)
        active = client.get("/api/v1/runs/active")
        second = client.post(
            "/api/v1/runs",
            headers=_mutation_headers(csrf),
            content=_run_request_body(client),
        )
        harness.release.set()
        terminal_response, terminal = _wait_for_api_terminal(client)

    assert _json(active)["stage"] == "direction_one"
    assert second.status_code == HTTPStatus.CONFLICT
    assert _json(second)["error"] == {
        "category": "run_already_active",
        "message": "A reciprocal run is already active.",
    }
    assert terminal["state"] == "complete"
    assert terminal["stage"] == "complete"
    assert terminal["failureCategory"] is None
    result = terminal["result"]
    assert isinstance(result, dict)
    assert result["aggregateStatus"] == "PASS"
    assert result["exitCode"] == 0
    assert terminal_response.headers["cache-control"] == "no-store"
    serialized = json.dumps(terminal, sort_keys=True)
    for secret in (
        *SENSITIVE_CONFIGURATION_VALUES,
        *SYNTHETIC_ENVIRONMENT.values(),
    ):
        assert secret not in serialized


@pytest.mark.parametrize(
    ("harness", "operation", "expected_category"),
    [
        (
            RuntimeHarness(
                doctor_error=RuntimeError(
                    "AWS SDK diagnostic synthetic-credential-must-never-leak"
                )
            ),
            "readiness",
            "readiness_failed",
        ),
        (
            RuntimeHarness(
                run_error=RuntimeError(
                    "AWS SDK diagnostic synthetic-credential-must-never-leak"
                )
            ),
            "run",
            "execution_failed",
        ),
        (
            RuntimeHarness(
                run_error=AwsReciprocalRetrievalRunError(
                    AwsReciprocalRetrievalRunFailureCode.EVIDENCE_RUN_COLLISION
                )
            ),
            "run",
            "evidence_run_collision",
        ),
    ],
)
def test_operational_failures_never_return_exception_or_sdk_text(
    tmp_path: Path,
    harness: RuntimeHarness,
    operation: str,
    expected_category: str,
) -> None:
    """Injected diagnostics collapse to safe readiness or job categories."""
    fixture = _build_console(tmp_path, harness=harness)
    with TestClient(
        fixture.app,
        base_url=_ORIGIN,
        raise_server_exceptions=False,
    ) as client:
        csrf, _response = _bootstrap(client)
        _load_configuration(client, csrf)
        readiness = client.post(
            "/api/v1/readiness",
            headers=_mutation_headers(csrf),
            content=b"{}",
        )
        if operation == "readiness":
            response_text = readiness.text
            payload = _json(readiness)
            assert readiness.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
            error = payload["error"]
            assert isinstance(error, dict)
            assert error["category"] == expected_category
        else:
            assert readiness.status_code == HTTPStatus.OK
            started = client.post(
                "/api/v1/runs",
                headers=_mutation_headers(csrf),
                content=_run_request_body(client),
            )
            assert started.status_code == HTTPStatus.ACCEPTED
            _terminal_response, payload = _wait_for_api_terminal(client)
            assert payload["state"] == "failed"
            assert payload["failureCategory"] == expected_category
            response_text = json.dumps(payload, sort_keys=True)

    assert "AWS SDK diagnostic" not in response_text
    assert "synthetic-credential-must-never-leak" not in response_text
    assert "Traceback" not in response_text


def test_uploaded_contract_executes_real_synthetic_bundle_and_history(
    tmp_path: Path,
) -> None:
    """The full API path writes, verifies, and reads one immutable bundle."""
    harness = RuntimeHarness()
    synthetic_runtime = reciprocal_test_support._runtime(  # noqa: SLF001
        ("pass", "pass")
    )

    def real_runner(
        suite: VerificationSuite,
        options: AwsReciprocalRetrievalRunOptions,
    ) -> AwsReciprocalRetrievalRunResult:
        return run_aws_reciprocal_retrieval(
            suite,
            replace(
                options,
                action_adapter=synthetic_runtime.action_adapter,
                clock=synthetic_runtime.clock,
                monotonic=synthetic_runtime.monotonic,
                probe_adapter=synthetic_runtime.probe_adapter,
                session_factory=cast(
                    "AwsSessionFactory",
                    synthetic_runtime.factory,
                ),
            ),
        )

    runtime = ConsoleRuntime(
        aws_doctor=harness.aws_doctor,
        retrieval_doctor=harness.retrieval_doctor,
        reciprocal_runner=real_runner,
    )
    synthetic_environment = reciprocal_test_support._ENVIRONMENT  # noqa: SLF001
    fixture = _build_console(
        tmp_path,
        harness=harness,
        runtime=runtime,
        environment=synthetic_environment,
    )
    with TestClient(
        fixture.app,
        base_url=_ORIGIN,
        raise_server_exceptions=False,
    ) as client:
        csrf, _response = _bootstrap(client)
        _load_configuration(client, csrf)
        readiness = client.post(
            "/api/v1/readiness",
            headers=_mutation_headers(csrf),
            content=b"{}",
        )
        started = client.post(
            "/api/v1/runs",
            headers=_mutation_headers(csrf),
            content=_run_request_body(client),
        )
        _terminal_response, terminal = _wait_for_api_terminal(
            client,
            timeout_seconds=5,
        )
        run_id = terminal["runId"]
        assert isinstance(run_id, str)
        history = client.get("/api/v1/history")
        detail = client.get(f"/api/v1/history/{run_id}")

    assert readiness.status_code == HTTPStatus.OK
    assert started.status_code == HTTPStatus.ACCEPTED
    assert terminal["state"] == "complete"
    assert terminal["stage"] == "complete"
    assert terminal["result"] is not None
    normalized_result = terminal["result"]
    assert isinstance(normalized_result, dict)
    frontend_contract_result = json.loads(
        (ROOT / "ui/src/test/contract-result.json").read_bytes()
    )
    assert isinstance(frontend_contract_result, dict)
    result_without_path = dict(normalized_result)
    result_without_path.pop("evidencePath")
    assert result_without_path == frontend_contract_result
    assert history.status_code == HTTPStatus.OK
    history_payload = _json(history)
    items = history_payload["items"]
    assert isinstance(items, list)
    assert len(items) == 1
    record = items[0]
    assert isinstance(record, dict)
    assert record["runId"] == run_id
    assert record["state"] == "verified"
    assert record["aggregateStatus"] == "PASS"
    assert detail.status_code == HTTPStatus.OK
    detail_payload = _json(detail)
    assert detail_payload["runId"] == run_id
    assert detail_payload["state"] == "verified"
    assert detail_payload["evidencePath"] == str(tmp_path / "evidence" / run_id)
    response_surface = "\n".join(
        (
            json.dumps(terminal, sort_keys=True),
            history.text,
            detail.text,
        )
    )
    forbidden = (
        reciprocal_test_support._ACCOUNT,  # noqa: SLF001
        reciprocal_test_support._ACCESS_KEY,  # noqa: SLF001
        reciprocal_test_support._SECRET_KEY,  # noqa: SLF001
        reciprocal_test_support._SESSION_TOKEN,  # noqa: SLF001
        *synthetic_runtime.ledger.values,
        *synthetic_environment.values(),
    )
    for sensitive in forbidden:
        assert sensitive not in response_surface


def test_invalid_bootstrap_options_fail_before_app_creation(
    tmp_path: Path,
) -> None:
    """Invalid port and short capabilities cannot weaken the trust boundary."""
    static_directory = tmp_path / "static"

    with pytest.raises(ValueError, match="port must be in range"):
        create_console_app(
            ConsoleAppOptions(
                evidence_root=tmp_path,
                port=0,
                bootstrap_token=_BOOTSTRAP_TOKEN,
                static_directory=static_directory,
            )
        )
    with pytest.raises(ValueError, match="high-entropy"):
        create_console_app(
            ConsoleAppOptions(
                evidence_root=tmp_path,
                port=_PORT,
                bootstrap_token="too-short",  # noqa: S106 - invalid test token.
                static_directory=static_directory,
            )
        )


def test_console_options_repr_redacts_launch_and_environment_capabilities(
    tmp_path: Path,
) -> None:
    """Generated dataclass diagnostics cannot include local or AWS capabilities."""
    bootstrap = "bootstrap-capability-" + ("x" * 48)
    environment_value = "synthetic-environment-secret"
    options = ConsoleAppOptions(
        evidence_root=tmp_path / "private-evidence",
        port=_PORT,
        bootstrap_token=bootstrap,
        environment={"AWS_SECRET_ACCESS_KEY": environment_value},
    )

    rendered = repr(options)

    assert bootstrap not in rendered
    assert environment_value not in rendered
    assert str(tmp_path) not in rendered


def test_unexpected_api_failure_is_redacted_before_framework_logging(
    console: tuple[_ConsoleFixture, TestClient, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A downstream exception becomes one fixed response without its message."""
    fixture, client, _csrf = console
    diagnostic = "framework-diagnostic-synthetic-secret"

    def fail_configuration() -> dict[str, object]:
        raise RuntimeError(diagnostic)

    fixture.app.state.console_state.configuration_view = fail_configuration
    response = client.get("/api/v1/configuration")

    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert _json(response)["error"] == {
        "category": "internal_error",
        "message": "The local console could not complete this request.",
    }
    assert diagnostic not in response.text
    assert diagnostic not in caplog.text


def test_no_open_prints_one_time_loopback_launch_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Automation receives the fragment URL without invoking a browser."""

    class FakeListener:
        closed = False

        def bind(self, address: tuple[str, int]) -> None:
            assert address == ("127.0.0.1", 0)

        def listen(self, backlog: int) -> None:
            assert backlog == _LISTEN_BACKLOG

        def getsockname(self) -> tuple[str, int]:
            return ("127.0.0.1", _PORT)

        def close(self) -> None:
            self.closed = True

    class FakeServer:
        def __init__(self, _config: object) -> None:
            pass

        def run(self, *, sockets: list[FakeListener]) -> None:
            assert sockets == [listener]

    listener = FakeListener()
    bootstrap = "one-time-bootstrap-" + ("b" * 48)
    emitted: list[str] = []

    def capture_print(value: object, *, flush: bool) -> None:
        assert flush is True
        emitted.append(str(value))

    monkeypatch.setattr(
        "cai_verify.ui.server.socket.socket",
        lambda *_args: listener,
    )
    monkeypatch.setattr(
        "cai_verify.ui.server.secrets.token_urlsafe",
        lambda _size: bootstrap,
    )
    monkeypatch.setattr("cai_verify.ui.server.uvicorn.Server", FakeServer)
    monkeypatch.setattr(
        "builtins.print",
        capture_print,
    )
    monkeypatch.setattr(
        "cai_verify.ui.server.webbrowser.open",
        lambda _url: pytest.fail("browser must not open"),
    )

    run_console(evidence_root=tmp_path, port=0, open_browser=False)

    assert emitted == [f"{_ORIGIN}/#bootstrap={bootstrap}"]
    assert listener.closed is True
