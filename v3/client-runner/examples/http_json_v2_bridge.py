"""Bridge a local or customer-owned AI test endpoint to the ESX v2 adapter contract.

Set ESX_LOCAL_ADAPTER_URL to an endpoint owned by the team. The bridge forwards
the local test batch and prints the endpoint's v2 response. It never contacts
the ExposureScopeX API and the runner never includes raw test inputs or outputs
in its result package.
"""

from __future__ import annotations

import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def fail(message: str) -> None:
    print(f"adapter: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    endpoint = os.environ.get("ESX_LOCAL_ADAPTER_URL", "")
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        fail("ESX_LOCAL_ADAPTER_URL must be an http(s) endpoint without URL credentials")
    try:
        timeout = int(os.environ.get("ESX_LOCAL_ADAPTER_TIMEOUT_SECONDS", "60"))
    except ValueError:
        fail("ESX_LOCAL_ADAPTER_TIMEOUT_SECONDS must be an integer")
    if not 1 <= timeout <= 300:
        fail("ESX_LOCAL_ADAPTER_TIMEOUT_SECONDS must be between 1 and 300")
    try:
        request_payload = json.load(sys.stdin)
        if not isinstance(request_payload, dict):
            fail("runner request must be a JSON object")
        request = Request(
            endpoint,
            data=json.dumps(request_payload, separators=(",", ":")).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        # Do not leak a customer endpoint's response, headers, or URL into CI output.
        fail("customer-owned adapter endpoint did not return a valid response")
    if not isinstance(body, dict):
        fail("customer-owned adapter endpoint must return a JSON object")
    json.dump(body, sys.stdout, separators=(",", ":"))


if __name__ == "__main__":
    main()
