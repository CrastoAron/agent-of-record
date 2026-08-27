"""JSON Canonicalization Scheme (RFC 8785) helpers."""

from typing import Any

import rfc8785


def canonicalize(data: dict[str, Any]) -> bytes:
    """Return the RFC 8785 (JCS) canonical UTF-8 JSON representation.

    Canonicalization is delegated to the maintained ``rfc8785`` package.  It
    also validates values that RFC 8785 cannot represent, such as NaN.
    """
    if not isinstance(data, dict):
        raise TypeError("data must be a dictionary")
    return rfc8785.dumps(data)
