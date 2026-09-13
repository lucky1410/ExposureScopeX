"""Forward a local evaluation batch to a customer-owned HTTP adapter endpoint."""

from __future__ import annotations

import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def _fail(message: str) -> None:
    print(f"adapter: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    endpoint = os.environ.get("ESX_LOCAL_ADAPTER_URL", "")
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        _fail("ESX_LOCAL_ADAPTER_URL must be an http(s) endpoint without URL credentials")
    try:
        timeout = int(os.environ.get("ESX_LOCAL_ADAPTER_TIMEOUT_SECONDS", "60"))
    except ValueError:
        _fail("ESX_LOCAL_ADAPTER_TIMEOUT_SECONDS must be an integer")
    if not 1 <= timeout <= 300:
        _fail("ESX_LOCAL_ADAPTER_TIMEOUT_SECONDS must be between 1 and 300")
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            _fail("runner request must be a JSON object")
        request = Request(
            endpoint,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        # Customer endpoint details and output stay local even when the adapter fails.
        _fail("customer-owned adapter endpoint did not return a valid response")
    if not isinstance(result, dict):
        _fail("customer-owned adapter endpoint must return a JSON object")
    json.dump(result, sys.stdout, separators=(",", ":"))


if __name__ == "__main__":
    main()
