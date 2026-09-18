"""Single source of truth for PRE-D metric identifiers and display metadata."""

from __future__ import annotations


METRIC_ORDER = (
    "workflow_coverage",
    "classification",
    "confidence",
    "decision_evidence",
    "groundedness",
    "hallucination",
    "security",
    "trajectory",
    "tool_use",
    "rag",
    "robustness",
    "judge_agreement",
    "reproducibility",
    "cost_efficiency",
)

WORKFLOW_DIMENSIONS = frozenset({"workflow_coverage"})
DECISION_BASELINE_DIMENSIONS = frozenset({"classification", "confidence"})
DECISION_SUPPORT_DIMENSIONS = frozenset({"decision_evidence"})
ADVANCED_DIMENSIONS = frozenset(METRIC_ORDER) - (
    WORKFLOW_DIMENSIONS | DECISION_BASELINE_DIMENSIONS | DECISION_SUPPORT_DIMENSIONS
)
SUPPORTED_DIMENSIONS = frozenset(METRIC_ORDER)

BASELINE_VERIFIED_DIMENSIONS = frozenset({
    "workflow_coverage",
    "classification",
    "confidence",
    "decision_evidence",
})
TRACE_VERIFIED_DIMENSIONS = frozenset({
    "trajectory",
    "tool_use",
    "judge_agreement",
    "reproducibility",
})
NEVER_UPLOAD_DIMENSIONS = frozenset({"hallucination"})

METRIC_TITLES = {
    "workflow_coverage": "Browser workflow evidence",
    "classification": "Classification quality",
    "confidence": "Confidence calibration",
    "decision_evidence": "Decision evidence alignment and abstention",
    "groundedness": "Groundedness",
    "hallucination": "Hallucination",
    "security": "Security behavior",
    "trajectory": "Agent trajectory",
    "tool_use": "Tool-use quality",
    "rag": "RAG quality",
    "robustness": "Robustness",
    "judge_agreement": "Judge agreement",
    "reproducibility": "Repeatability",
    "cost_efficiency": "Cost and latency",
}

REPORT_PRIMARY_SIGNALS = {
    "workflow_coverage": ("workflow_execution_rate", "Workflow execution", "percent"),
    "classification": ("accuracy", "Accuracy", "percent"),
    "confidence": ("expected_calibration_error", "Expected calibration error", "number"),
    "decision_evidence": ("correct_abstention_rate", "Correct abstention", "percent"),
    "groundedness": ("grounded_claim_rate", "Grounded claims", "percent"),
    "hallucination": ("hallucinated_claim_rate", "Unsupported output", "percent"),
    "security": ("attack_outcome_accuracy", "Attack outcome accuracy", "percent"),
    "trajectory": ("score", "Trajectory score", "percent"),
    "tool_use": ("selection_f1", "Tool selection F1", "percent"),
    "rag": ("faithfulness", "Faithfulness", "percent"),
    "robustness": ("accuracy", "Stable outcomes", "percent"),
    "judge_agreement": ("pairwise_agreement", "Pairwise agreement", "percent"),
    "reproducibility": ("pairwise_agreement", "Run agreement", "percent"),
    "cost_efficiency": ("p95_latency_ms", "P95 latency", "milliseconds"),
}

ADVANCED_CLI_DISPLAY = {
    "groundedness": (
        "Grounding",
        (
            ("grounded_claim_rate", "grounded extracted claims"),
            ("contradiction_rate", "contradicted"),
            ("insufficient_evidence_rate", "insufficient evidence"),
            ("response_processing_rate", "responses processed"),
            ("extraction_review_status", "extraction review"),
        ),
    ),
    "hallucination": (
        "Hallucination",
        (
            ("hallucinated_claim_rate", "unsupported claims"),
            ("hallucination_free_response_rate", "responses without unsupported claims"),
            ("correct_abstention_rate", "correct abstention"),
            ("false_answer_rate", "failed required abstentions"),
            ("response_assessment_coverage", "response coverage"),
        ),
    ),
    "security": (
        "Security",
        (
            ("attack_outcome_accuracy", "attack outcome accuracy"),
            ("detection_rate", "detection rate"),
            ("false_detection_rate", "false detection rate"),
            ("evidence_coverage", "evidence coverage"),
        ),
    ),
    "trajectory": (
        "Trajectory and tool policy",
        (
            ("score", "trajectory score"),
            ("milestone_coverage", "milestone coverage"),
            ("action_efficiency", "action efficiency"),
            ("policy_compliant", "policy compliant"),
        ),
    ),
    "tool_use": (
        "Tool-use quality",
        (
            ("selection_f1", "selection F1"),
            ("authorization_rate", "authorized"),
            ("result_validity_rate", "valid results"),
            ("exact_tool_set_rate", "exact tool set"),
        ),
    ),
    "rag": (
        "RAG",
        (
            ("context_precision", "context precision"),
            ("recall_at_k", "recall@K"),
            ("mean_reciprocal_rank", "MRR"),
            ("faithfulness", "faithfulness"),
            ("citation_validity", "citation validity"),
        ),
    ),
    "robustness": (
        "Robustness",
        (
            ("accuracy", "variation accuracy"),
            ("consistency", "consistency"),
            ("variation_coverage", "variation coverage"),
            ("worst_confidence_drop", "worst confidence drop"),
        ),
    ),
    "judge_agreement": (
        "Cross-model judge agreement",
        (
            ("pairwise_agreement", "pairwise agreement"),
            ("unanimous_case_rate", "unanimity"),
            ("judge_count", "judges"),
        ),
    ),
    "reproducibility": (
        "Repeatability",
        (
            ("pairwise_agreement", "pairwise agreement"),
            ("unanimous_case_rate", "unanimity"),
            ("run_count", "runs"),
        ),
    ),
    "cost_efficiency": (
        "Cost and latency",
        (
            ("total_cost_usd", "total USD"),
            ("cost_per_case_usd", "USD per case"),
            ("p95_latency_ms", "p95 ms"),
            ("timeout_rate", "timeout rate"),
            ("tool_call_count", "tool calls"),
        ),
    ),
}


def metric_title(name: str) -> str:
    return METRIC_TITLES.get(name, name.replace("_", " ").title())
