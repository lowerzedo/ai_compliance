"""Synthetic fixed data shared by reference-target tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

ACCOUNT_ID = "111122223333"
REGION = "eu-west-2"
STACK_NAME = "cai-verify-ref-sandbox"
API_ID = "a1b2c3d4e5"
HOST = f"{API_ID}.execute-api.{REGION}.amazonaws.com"
ENDPOINT = f"https://{HOST}/sandbox"
REQUESTER_A_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/{STACK_NAME}-requester-a"
REQUESTER_B_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/{STACK_NAME}-requester-b"
EVIDENCE_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/{STACK_NAME}-evidence-reader"
REQUESTER_A_SESSION = "cai-verify-reference-requester-a"
REQUESTER_B_SESSION = "cai-verify-reference-requester-b"
EVIDENCE_SESSION = "cai-verify-reference-evidence-reader"
LOG_GROUP = f"/aws/cai-verify/reference/{STACK_NAME}"
TABLE_NAME = f"{STACK_NAME}-documents"


def description_bytes(*, mode: str = "isolated") -> bytes:
    """Return one synthetic DescribeStacks response in shuffled output order."""
    values: Mapping[str, str] = {
        "SchemaVersion": "1",
        "StackName": STACK_NAME,
        "AccountId": ACCOUNT_ID,
        "Partition": "aws",
        "Region": REGION,
        "ApplicationEndpoint": ENDPOINT,
        "AllowedHost": HOST,
        "RequesterARoleArn": REQUESTER_A_ROLE_ARN,
        "RequesterASessionName": REQUESTER_A_SESSION,
        "RequesterBRoleArn": REQUESTER_B_ROLE_ARN,
        "RequesterBSessionName": REQUESTER_B_SESSION,
        "EvidenceReaderRoleArn": EVIDENCE_ROLE_ARN,
        "EvidenceReaderSessionName": EVIDENCE_SESSION,
        "LogGroupName": LOG_GROUP,
        "OwnershipMarker": "cai-verify-reference-target/1",
        "DocumentsTableName": TABLE_NAME,
        "ReferenceMode": mode,
    }
    outputs = [
        {"OutputKey": key, "OutputValue": value}
        for key, value in reversed(tuple(values.items()))
    ]
    return json.dumps(
        {
            "Stacks": [
                {
                    "CreationTime": "2026-08-12T12:00:00Z",
                    "Outputs": outputs,
                    "StackName": STACK_NAME,
                    "StackStatus": "CREATE_COMPLETE",
                }
            ]
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def caller_identity_bytes() -> bytes:
    """Return a synthetic non-root IAM-user caller identity."""
    return json.dumps(
        {
            "Account": ACCOUNT_ID,
            "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/cai-verify-sandbox-operator",
            "UserId": "AIDASYNTHETIC000001",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
