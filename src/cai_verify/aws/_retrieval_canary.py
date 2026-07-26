"""Private paired-canary validation shared by AWS retrieval boundaries."""

from __future__ import annotations

import hmac
from enum import StrEnum

MAX_RETRIEVAL_CANARY_BYTES = 1024


class RetrievalCanaryValidationFailure(StrEnum):
    """Internal validation categories kept outside public result contracts."""

    INVALID = "invalid"
    LIMIT_EXCEEDED = "limit_exceeded"


def validated_retrieval_canary(
    value: object,
) -> tuple[bytes | None, RetrievalCanaryValidationFailure | None]:
    """Validate one transient canary using the CloudWatch 1.2.0 contract."""
    if type(value) is not str or not value:
        return None, RetrievalCanaryValidationFailure.INVALID
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return None, RetrievalCanaryValidationFailure.INVALID
    if not encoded:
        return None, RetrievalCanaryValidationFailure.INVALID
    if len(encoded) > MAX_RETRIEVAL_CANARY_BYTES:
        return None, RetrievalCanaryValidationFailure.LIMIT_EXCEEDED
    return encoded, None


def retrieval_canaries_are_distinct(baseline: bytes, boundary: bytes) -> bool:
    """Compare validated canaries without value-dependent early termination."""
    return not hmac.compare_digest(baseline, boundary)
