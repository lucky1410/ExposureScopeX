import json
import sys


request = json.load(sys.stdin)
operation = request["operation"]


def extract(response):
    abstained = response == "I cannot answer from the available evidence."
    claims = [] if abstained or response == "Hello!" else [item.strip() + "." for item in response.split(".") if item.strip()]
    return claims, abstained


if operation == "extract_claims":
    results = []
    for case in request["cases"]:
        claims, abstained = extract(case["response"])
        results.append({"case_id": case["case_id"], "claims": claims, "abstained": abstained})
elif operation == "review_claims":
    results = []
    for case in request["cases"]:
        expected, _ = extract(case["response"])
        results.append({"case_id": case["case_id"], "complete": expected == case["claims"], "missing_claims": [claim for claim in expected if claim not in case["claims"]]})
else:
    results = []
    for item in request["claims"]:
        claim = item["claim"]
        if "09:15" in claim:
            verdict, evidence_ids = "supported", ["timeline-1"]
        elif "disabled" in claim:
            verdict, evidence_ids = "contradicted", ["identity-1"]
        else:
            verdict, evidence_ids = "insufficient", []
        results.append({
            "claim_id": item["claim_id"], "verdict": verdict,
            "confidence": 0.93, "evidence_ids": evidence_ids,
        })
json.dump({
    "schema_version": "pre-d-grounding-judge-response-1.0",
    "operation": operation,
    "results": results,
}, sys.stdout)
