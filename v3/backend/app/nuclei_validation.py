from __future__ import annotations


SAFE_REPLAY_TEMPLATES = frozenset({
    "phpinfo-files",
    "readme-md",
    "robots-txt",
    "robots-txt-endpoint",
    "apache-detect",
    "php-detect",
})


def has_safe_replay_oracle(template_id: str | None) -> bool:
    return str(template_id or "").strip().lower() in SAFE_REPLAY_TEMPLATES


def evaluate_nuclei_replay(template_id: str, response: dict) -> tuple[str, str]:
    template = template_id.strip().lower()
    status = response.get("status")
    headers = {str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()}
    body = str(response.get("body_preview") or "").lower()
    final_url = str(response.get("final_url") or "").lower()

    if template == "phpinfo-files":
        matched = status == 200 and ("phpinfo()" in body or "php version" in body)
        return ("passed", "Independent GET replay confirmed an exposed PHPInfo response.") if matched else ("failed", "Independent GET replay did not reproduce the PHPInfo response markers.")
    if template == "readme-md":
        matched = status == 200 and final_url.split("?", 1)[0].endswith("/readme.md") and bool(body.strip())
        return ("passed", "Independent GET replay confirmed that the README resource is directly accessible.") if matched else ("failed", "Independent GET replay did not reproduce an accessible README resource.")
    if template in {"robots-txt", "robots-txt-endpoint"}:
        matched = status == 200 and "user-agent:" in body
        return ("passed", "Independent GET replay confirmed a parseable robots.txt response.") if matched else ("failed", "Independent GET replay did not reproduce a parseable robots.txt response.")
    if template == "apache-detect":
        matched = status is not None and "apache" in headers.get("server", "").lower()
        return ("passed", "Independent response-header replay confirmed Apache attribution.") if matched else ("failed", "Independent replay did not reproduce Apache response attribution.")
    if template == "php-detect":
        matched = status is not None and (
            "php" in headers.get("x-powered-by", "").lower()
            or "phpsessid" in headers.get("set-cookie", "").lower()
        )
        return ("passed", "Independent response-header replay confirmed PHP attribution.") if matched else ("failed", "Independent replay did not reproduce PHP response attribution.")
    return "not_evaluated", "No approved independent replay oracle is registered for this Nuclei template."
