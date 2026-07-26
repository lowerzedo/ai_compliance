"""Security-boundary tests for the loopback HTTP action adapter."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import cai_verify.adapters.http as http_adapter
from cai_verify.adapters import HttpActionAdapter
from cai_verify.config import (
    ActionInput,
    HttpAction,
    SyntheticLocalIdentity,
    Target,
    load_suite,
)
from cai_verify.local import SyntheticScopedIdentity
from cai_verify.local.runner import DETERMINISTIC_TIME
from cai_verify.plugins import ActionOutcome, ActionRequest, ExecutionContext

if TYPE_CHECKING:
    from cai_verify.config import VerificationSuite

_SUITE_PATH = Path(__file__).parents[2] / "examples" / "local" / "synthetic-suite.json"
_SECRET = "synthetic-secret-must-not-leak"  # noqa: S105


class _FailingConnection:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def request(self, *_args: object, **_kwargs: object) -> None:
        raise OSError(_SECRET)

    def close(self) -> None:
        pass


def test_transport_exception_and_adapter_repr_exclude_environment_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Transport diagnostics and dataclass reprs never contain source secrets."""
    monkeypatch.setattr(
        "cai_verify.adapters.http.http.client.HTTPConnection",
        _FailingConnection,
    )
    adapter = HttpActionAdapter({"SYNTHETIC_SECRET": _SECRET}, DETERMINISTIC_TIME)

    result = adapter.execute_action(_request(load_suite(_SUITE_PATH)))

    assert result.outcome is ActionOutcome.ERROR
    observed = result.observed.to_json_value()
    assert isinstance(observed, dict)
    assert observed["error"] == "transport_error"
    assert _SECRET not in repr(adapter)
    assert _SECRET not in repr(result)
    assert _SECRET not in str(result.observed.to_json_value())


@pytest.mark.parametrize(
    "header_name",
    ["Host", "Content-Length", "Transfer-Encoding", "X-Cai-Correlation-Id"],
)
def test_reserved_request_headers_are_rejected(header_name: str) -> None:
    """Suite inputs cannot replace adapter-owned routing or framing headers."""
    suite = load_suite(_SUITE_PATH)
    action = _action_with_input(
        suite,
        ActionInput.model_validate(
            {
                "location": "header",
                "name": header_name,
                "value": {
                    "sensitive": False,
                    "source": "literal",
                    "value": "synthetic",
                },
            },
        ),
    )

    with pytest.raises(ValueError, match="reserved HTTP header"):
        HttpActionAdapter({}, DETERMINISTIC_TIME).execute_action(
            _request(suite, action=action),
        )


def test_header_newlines_are_rejected_without_echoing_the_value() -> None:
    """CRLF input fails before transport and the diagnostic names only the field."""
    suite = load_suite(_SUITE_PATH)
    action = _action_with_input(
        suite,
        ActionInput.model_validate(
            {
                "location": "header",
                "name": "X-Synthetic-Input",
                "value": {"name": "SYNTHETIC_HEADER", "source": "environment"},
            },
        ),
    )
    value = f"{_SECRET}\r\nInjected: true"

    with pytest.raises(ValueError, match="HTTP header input is invalid") as caught:
        HttpActionAdapter(
            {"SYNTHETIC_HEADER": value},
            DETERMINISTIC_TIME,
        ).execute_action(_request(suite, action=action))

    assert value not in str(caught.value)
    assert _SECRET not in str(caught.value)


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (
            http_adapter._HttpResponse(  # noqa: SLF001 - adapter boundary fixture.
                status=403,
                correlation_id=None,
                too_large=False,
            ),
            ActionOutcome.DENIED,
        ),
        (
            http_adapter._HttpResponse(  # noqa: SLF001 - adapter boundary fixture.
                status=200,
                correlation_id="wrong",
                too_large=False,
            ),
            ActionOutcome.ERROR,
        ),
        (
            http_adapter._HttpResponse(  # noqa: SLF001 - adapter boundary fixture.
                status=200,
                correlation_id=None,
                too_large=True,
            ),
            ActionOutcome.ERROR,
        ),
    ],
)
def test_response_guards_normalize_denial_and_boundary_failures(
    response: object,
    expected: ActionOutcome,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Denials remain distinct while correlation and size failures are errors."""
    monkeypatch.setattr(http_adapter, "_send_request", lambda **_kwargs: response)

    result = HttpActionAdapter({}, DETERMINISTIC_TIME).execute_action(
        _request(load_suite(_SUITE_PATH)),
    )

    assert result.outcome is expected


def test_endpoint_with_base_path_is_rejected_before_transport() -> None:
    """The adapter does not reinterpret an ambiguous base URL path."""
    suite = load_suite(_SUITE_PATH)
    target_value = suite.target.model_dump(mode="json", by_alias=True)
    target_value["endpoint"] = "http://localhost:12345/base"
    target = Target.model_validate(target_value)

    with pytest.raises(ValueError, match="explicit localhost port"):
        HttpActionAdapter({}, DETERMINISTIC_TIME).execute_action(
            _request(suite, target=target),
        )


def _request(
    suite: VerificationSuite,
    *,
    action: HttpAction | None = None,
    target: Target | None = None,
) -> ActionRequest:
    scenario = suite.scenarios[0]
    identity = suite.identities[0]
    assert isinstance(identity, SyntheticLocalIdentity)
    runtime_target = target or _runtime_target(suite.target)
    return ActionRequest(
        context=ExecutionContext(
            run_id="adapter-test",
            scenario_id=scenario.id,
            target=runtime_target,
        ),
        action=action or scenario.actions[0],
        identity=SyntheticScopedIdentity(identity.id, identity.principal),
    )


def _runtime_target(target: Target) -> Target:
    value = target.model_dump(mode="json", by_alias=True)
    value["endpoint"] = "http://localhost:12345"
    return Target.model_validate(value)


def _action_with_input(
    suite: VerificationSuite,
    additional_input: ActionInput,
) -> HttpAction:
    action = suite.scenarios[0].actions[0]
    assert isinstance(action, HttpAction)
    value = action.model_dump(mode="json", by_alias=True)
    value["inputs"].append(additional_input.model_dump(mode="json", by_alias=True))
    return HttpAction.model_validate(value)
