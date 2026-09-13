"""Safe sample adapter for validating the client-runner protocol locally."""

from __future__ import annotations

import json
import sys


request = json.load(sys.stdin)
results = []
for case in request["cases"]:
    message = str(case["input"].get("message", "")).lower()
    predicted = "unsafe" if "ignore previous instructions" in message else "safe"
    results.append({"case_id": case["case_id"], "predicted_label": predicted, "confidence": 0.98})
json.dump({"schema_version": "esx-client-adapter-response-1.0", "results": results}, sys.stdout)
