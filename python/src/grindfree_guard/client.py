from __future__ import annotations

import json
import os
import re
from typing import Any, Callable

from .errors import GuardConfigError, GuardError
from .services import NETWORK

KEY_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
DEFAULT_TIMEOUT = 15.0

# (url, body) -> dict  OR raises GuardError
PostFn = Callable[[str, dict[str, Any]], dict[str, Any]]


def read_private_key(explicit: str | None = None) -> str | None:
    return explicit or os.environ.get("X402_PRIVATE_KEY") or os.environ.get("PRIVATE_KEY") or os.environ.get("EVM_PRIVATE_KEY")


def _build_x402_post(private_key: str, timeout: float) -> PostFn:
    try:
        from eth_account import Account
        from x402 import x402ClientSync
        from x402.http.clients import x402_requests
        from x402.mechanisms.evm import EthAccountSigner
        from x402.mechanisms.evm.exact.register import register_exact_evm_client
    except ImportError as err:
        raise GuardConfigError(
            "Official x402 Python extras are not installed. Run: pip install 'grindfree-guard[x402]'"
        ) from err

    if not KEY_RE.match(private_key):
        raise GuardConfigError("X402_PRIVATE_KEY / PRIVATE_KEY / EVM_PRIVATE_KEY must be 0x + 64 hex characters (caller wallet only).")

    account = Account.from_key(private_key)
    client = x402ClientSync()
    register_exact_evm_client(client, EthAccountSigner(account), networks=NETWORK)

    def post(url: str, body: dict[str, Any]) -> dict[str, Any]:
        with x402_requests(client) as session:
            response = session.post(url, json=body, headers={"content-type": "application/json", "accept": "application/json"}, timeout=timeout)
            try:
                payload = response.json()
            except Exception:
                payload = {"raw": response.text[:2000]}
            if not response.ok:
                raise GuardError(f"HTTP {response.status_code}", service="unknown", status=response.status_code, body=payload)
            if not isinstance(payload, dict):
                return {"value": payload}
            return payload

    return post


def create_post(private_key: str | None = None, post: PostFn | None = None, timeout: float = DEFAULT_TIMEOUT) -> PostFn:
    """Return a POST callable. Tests should pass `post=` (no wallet, no spend)."""
    if post is not None:
        return post
    key = read_private_key(private_key)
    if not key:
        raise GuardConfigError(
            "Missing X402_PRIVATE_KEY (or PRIVATE_KEY / EVM_PRIVATE_KEY). Set the caller's Base USDC wallet key. "
            "GrindFree never supplies keys. For tests, pass post= with a mock."
        )
    return _build_x402_post(key, timeout)
