# Architecture Decision Records

ADRs record decisions that constrain future implementation. Status values are
Proposed, Accepted, Superseded or Rejected.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-control-plane-worker-separation.md) | Separate control plane from scanner execution | Accepted |
| [0002](0002-normalized-evidence-model.md) | Use shared normalized evidence and scan observations | Accepted |
| [0003](0003-capability-aware-open-source-adapters.md) | Use pinned adapters and runtime capability truth | Accepted |
| [0004](0004-compose-and-kubernetes-execution.md) | Support efficient Compose and isolated Kubernetes execution | Accepted |

New ADRs must state context, decision, consequences and alternatives. Do not
rewrite accepted history; supersede it with a new record.
