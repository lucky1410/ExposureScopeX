"""Keep verified arithmetic separate from reviewed probability semantics."""

from __future__ import annotations

import math


NATIVE_CONFIDENCE = {"kind": "native_probability", "meaning": "predicted_label_correctness"}


def confidence_provenance(raw: object = None) -> dict:
    if raw is None:
        return {"kind": "unknown", "meaning": "unspecified"}
    if not isinstance(raw, dict) or set(raw) - {"kind", "meaning", "mapping"}:
        raise ValueError("evaluation.confidence_provenance must contain only kind, meaning and optional mapping")
    kind = raw.get("kind")
    if kind not in ("native_probability", "adapter_mapped", "unknown"):
        raise ValueError("confidence_provenance.kind must be native_probability, adapter_mapped or unknown")
    meaning = {"native_probability": "predicted_label_correctness", "adapter_mapped": "ordinal_category_mapping", "unknown": "unspecified"}[kind]
    if kind == "native_probability" and raw.get("meaning") != meaning:
        raise ValueError("Native confidence requires meaning=predicted_label_correctness; a positive-class probability is not interchangeable")
    if "meaning" in raw and raw["meaning"] != meaning:
        raise ValueError("confidence_provenance.meaning does not match its kind")
    result = {"kind": kind, "meaning": meaning}
    if kind == "adapter_mapped":
        mapping = raw.get("mapping")
        if not isinstance(mapping, dict) or not 1 <= len(mapping) <= 100:
            raise ValueError("Adapter-mapped confidence requires a reviewed category-to-number mapping")
        for category, value in mapping.items():
            if not isinstance(category, str) or not category.strip() or len(category) > 80 or any(ord(c) < 32 for c in category):
                raise ValueError("Confidence mapping categories must be short non-empty labels without control characters")
            if type(value) not in (int, float) or not 0 <= value <= 1 or not math.isfinite(value):
                raise ValueError("Confidence mapping values must be finite numbers from 0 to 1")
        result["mapping"] = dict(mapping)
    elif "mapping" in raw:
        raise ValueError("Only adapter_mapped confidence can declare a mapping")
    return result


def calibration_eligible(metric: dict) -> bool:
    try:
        return confidence_provenance(metric.get("confidence_provenance")) == NATIVE_CONFIDENCE
    except ValueError:
        return False


def annotate_confidence(metric: dict, raw: object = None) -> dict:
    provenance = confidence_provenance(raw)
    native = provenance == NATIVE_CONFIDENCE
    kind = provenance["kind"]
    explanation = (
        "Calculated against labelled correctness using values the evaluator identified as native probabilities of the returned label being correct. PRE-D verifies the arithmetic, not the application's probability-generation process."
        if native else
        "Calculated from adapter-mapped categories. These diagnostics describe the reviewed mapping, not native application probability calibration."
        if kind == "adapter_mapped" else
        "The origin and probability meaning of these numbers are unspecified. Arithmetic is available, but native probability calibration is not established."
    )
    return {
        **metric,
        "confidence_provenance": provenance,
        "provenance_basis": "evaluator_configuration" if kind != "unknown" else "not_supplied",
        "calibration_eligible": native,
        "calculation_status": "verified_locally" if metric.get("measurement_status") == "measured" else "not_measured",
        "interpretation": explanation,
        "definition": explanation,
    }
