"""Fixed Lambda handler for the disposable reciprocal-retrieval target."""

# ruff: noqa: BLE001, TRY300, TRY301

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import boto3  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]

_CORRELATION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_CANARY_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
_ACCOUNT_PATTERN = re.compile(r"\d{12}\Z")
_BODY_LIMIT = 2048
_ENVIRONMENT_LIMIT = 1024
_EVENT_LIMIT = 4096
_HTTP_OK = 200
_REQUESTER_A = "requester-a"
_REQUESTER_B = "requester-b"
_QUERIES = {
    _REQUESTER_A: "requester-a-synthetic-topic",
    _REQUESTER_B: "requester-b-synthetic-topic",
}
_SDK_CONFIG = Config(
    connect_timeout=2,
    read_timeout=2,
    retries={"mode": "standard", "total_max_attempts": 1},
)
_DYNAMODB: Any | None = None
_LOGS: Any | None = None


class _RejectedRequest(ValueError):  # noqa: N818 - intentionally private signal.
    """Internal request rejection without untrusted diagnostic text."""


class _ForbiddenRequest(ValueError):  # noqa: N818 - intentionally private signal.
    """Authenticated request outside the two fixed requester identities."""


def lambda_handler(event: object, _context: object) -> dict[str, object]:
    """Retrieve one fixed synthetic context and emit one correlated fact."""
    try:
        requester, correlation = _validated_request(event)
    except _ForbiddenRequest:
        return _response(403, "forbidden")
    except Exception:
        return _response(400, "invalid_request")
    try:
        documents = _load_documents()
        mode = _required_environment("REFERENCE_MODE")
        selected: tuple[dict[str, str], ...]
        if mode == "isolated":
            selected = (documents[requester],)
        elif mode == "vulnerable":
            selected = (documents[_REQUESTER_A], documents[_REQUESTER_B])
        else:
            raise _RejectedRequest
        milliseconds = _clock_milliseconds()
        record = {
            "canaries": [document["content"] for document in selected],
            "correlationId": correlation,
            "eventKind": "retrievalCanary",
            "eventTime": _rfc3339_milliseconds(milliseconds),
            "phase": "PRE_GENERATION",
            "retrievalStatus": "SUCCEEDED",
            "retrievedItemCount": len(selected),
            "scanStatus": "COMPLETE",
            "schemaVersion": "1",
        }
        message = json.dumps(
            record,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        if len(message.encode("utf-8")) > _EVENT_LIMIT:
            raise _RejectedRequest
        _, logs = _clients()
        response = logs.put_log_events(
            logEvents=[{"message": message, "timestamp": milliseconds}],
            logGroupName=_required_environment("LOG_GROUP_NAME"),
            logStreamName=_required_environment("LOG_STREAM_NAME"),
        )
        if not _successful_log_response(response):
            raise _RejectedRequest
        return {
            "body": '{"retrieval":"completed"}',
            "headers": {
                "Content-Type": "application/json",
                "X-Cai-Correlation-Id": correlation,
            },
            "isBase64Encoded": False,
            "statusCode": 200,
        }
    except Exception:
        return _response(503, "temporarily_unavailable")


def _validated_request(event: object) -> tuple[str, str]:
    if type(event) is not dict:
        raise _RejectedRequest
    if (
        event.get("httpMethod") != "POST"
        or event.get("resource") != "/retrieve"
        or event.get("path") != "/retrieve"
        or event.get("isBase64Encoded") not in {None, False}
    ):
        raise _RejectedRequest
    content_type = _one_header(event, "content-type")
    if content_type not in {"application/json", "application/json; charset=utf-8"}:
        raise _RejectedRequest
    correlation = _one_header(event, "x-cai-correlation-id")
    if _CORRELATION_PATTERN.fullmatch(correlation) is None:
        raise _RejectedRequest
    requester = _authenticated_requester(event)
    body = event.get("body")
    if type(body) is not str or len(body.encode("utf-8")) > _BODY_LIMIT:
        raise _RejectedRequest
    decoded = json.loads(
        body,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if (
        type(decoded) is not dict
        or set(decoded) != {"syntheticQuery"}
        or decoded["syntheticQuery"] != _QUERIES[requester]
    ):
        raise _RejectedRequest
    return requester, correlation


def _one_header(event: dict[str, object], requested_name: str) -> str:
    single = _matching_header_values(event.get("headers"), requested_name)
    multiple = _matching_multi_header_values(
        event.get("multiValueHeaders"),
        requested_name,
    )
    if len(single) > 1 or len(multiple) > 1:
        raise _RejectedRequest
    values = [*single, *multiple]
    if not values or len(set(values)) != 1:
        raise _RejectedRequest
    return values[0]


def _matching_header_values(value: object, requested_name: str) -> list[str]:
    if type(value) is not dict:
        return []
    matches: list[str] = []
    for key, item in value.items():
        if type(key) is not str or type(item) is not str:
            raise _RejectedRequest
        if key.lower() == requested_name:
            matches.append(item)
    return matches


def _matching_multi_header_values(value: object, requested_name: str) -> list[str]:
    if value is None:
        return []
    if type(value) is not dict:
        raise _RejectedRequest
    matches: list[str] = []
    for key, item in value.items():
        if type(key) is not str or type(item) is not list:
            raise _RejectedRequest
        if not all(type(part) is str for part in item):
            raise _RejectedRequest
        if key.lower() == requested_name:
            matches.extend(item)
    return matches


def _authenticated_requester(event: dict[str, object]) -> str:
    context = event.get("requestContext")
    if type(context) is not dict:
        raise _RejectedRequest
    identity = context.get("identity")
    if type(identity) is not dict:
        raise _RejectedRequest
    observed = identity.get("userArn")
    if type(observed) is not str:
        raise _RejectedRequest
    account_id = _required_environment("EXPECTED_ACCOUNT_ID")
    if _ACCOUNT_PATTERN.fullmatch(account_id) is None:
        raise _RejectedRequest
    expected = {
        _REQUESTER_A: _assumed_role_arn(
            _required_environment("REQUESTER_A_ROLE_ARN"),
            _required_environment("REQUESTER_A_SESSION_NAME"),
        ),
        _REQUESTER_B: _assumed_role_arn(
            _required_environment("REQUESTER_B_ROLE_ARN"),
            _required_environment("REQUESTER_B_SESSION_NAME"),
        ),
    }
    matches = [requester for requester, arn in expected.items() if observed == arn]
    if len(matches) != 1 or f"::{account_id}:" not in observed:
        raise _ForbiddenRequest
    return matches[0]


def _assumed_role_arn(role_arn: str, session_name: str) -> str:
    match = re.fullmatch(
        r"arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/([^/]+)",
        role_arn,
    )
    if match is None or re.fullmatch(r"[\w+=,.@-]{2,64}", session_name) is None:
        raise _RejectedRequest
    partition, account_id, role_name = match.groups()
    return f"arn:{partition}:sts::{account_id}:assumed-role/{role_name}/{session_name}"


def _load_documents() -> dict[str, dict[str, str]]:
    table_name = _required_environment("DOCUMENTS_TABLE_NAME")
    dynamodb, _ = _clients()
    documents: dict[str, dict[str, str]] = {}
    for document_id in (_REQUESTER_A, _REQUESTER_B):
        response = dynamodb.get_item(
            ConsistentRead=True,
            Key={"documentId": {"S": document_id}},
            TableName=table_name,
        )
        documents[document_id] = _validated_document(response, document_id)
    if documents[_REQUESTER_A]["content"] == documents[_REQUESTER_B]["content"]:
        raise _RejectedRequest
    return documents


def _clients() -> tuple[Any, Any]:
    global _DYNAMODB, _LOGS  # noqa: PLW0603 - Lambda cold-start client cache.
    if _DYNAMODB is None:
        _DYNAMODB = boto3.client("dynamodb", config=_SDK_CONFIG)
    if _LOGS is None:
        _LOGS = boto3.client("logs", config=_SDK_CONFIG)
    return _DYNAMODB, _LOGS


def _validated_document(value: object, document_id: str) -> dict[str, str]:
    if type(value) is not dict or type(value.get("Item")) is not dict:
        raise _RejectedRequest
    metadata = value.get("ResponseMetadata")
    if type(metadata) is not dict or metadata.get("HTTPStatusCode") != _HTTP_OK:
        raise _RejectedRequest
    item = value["Item"]
    if set(item) != {"content", "documentId", "syntheticQuery"}:
        raise _RejectedRequest
    decoded: dict[str, str] = {}
    for key, attribute in item.items():
        if type(attribute) is not dict or set(attribute) != {"S"}:
            raise _RejectedRequest
        scalar = attribute["S"]
        if type(scalar) is not str:
            raise _RejectedRequest
        decoded[key] = scalar
    if (
        decoded["documentId"] != document_id
        or decoded["syntheticQuery"] != _QUERIES[document_id]
        or _CANARY_PATTERN.fullmatch(decoded["content"]) is None
    ):
        raise _RejectedRequest
    return decoded


def _successful_log_response(value: object) -> bool:
    if type(value) is not dict or "rejectedLogEventsInfo" in value:
        return False
    metadata = value.get("ResponseMetadata")
    return type(metadata) is dict and metadata.get("HTTPStatusCode") == _HTTP_OK


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8")) > _ENVIRONMENT_LIMIT
    ):
        raise _RejectedRequest
    return value


def _rfc3339_milliseconds(milliseconds: int) -> str:
    seconds, remainder = divmod(milliseconds, 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds)) + (
        f".{remainder:03d}Z"
    )


def _clock_milliseconds() -> int:
    return time.time_ns() // 1_000_000


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _RejectedRequest
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise _RejectedRequest


def _response(status_code: int, category: str) -> dict[str, object]:
    return {
        "body": json.dumps(
            {"error": category},
            separators=(",", ":"),
            sort_keys=True,
        ),
        "headers": {"Content-Type": "application/json"},
        "isBase64Encoded": False,
        "statusCode": status_code,
    }
