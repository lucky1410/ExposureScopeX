def blocks_downstream(adapter: str, status: str) -> bool:
    return adapter == "scope_preflight" and status != "succeeded"
