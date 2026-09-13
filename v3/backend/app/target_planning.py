import re
from urllib.parse import urlsplit, urlunsplit


def canonical_http_url(value: str) -> str:
    """Normalize an HTTP URL without changing its origin or decoded path data."""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return value
    path = re.sub(r"/{2,}", "/", parsed.path)
    # Nuclei templates commonly append an absolute path to BaseURL. Keeping a
    # root target slash would turn that into //path in the captured request.
    if path == "/":
        path = ""
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))


def nuclei_targets(target: str, discovered_urls: list[str]) -> list[str]:
    """Return deterministic, credential-free URLs within the authorized origin."""
    targets: list[str] = []
    authorized = urlsplit(target)
    authorized_port = authorized.port or (443 if authorized.scheme == "https" else 80)
    for candidate in [target, *discovered_urls]:
        parsed = urlsplit(candidate)
        candidate_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.scheme != authorized.scheme
            or parsed.hostname != authorized.hostname
            or candidate_port != authorized_port
            or parsed.username
            or parsed.password
        ):
            continue
        # Fragments are browser-local and queries can contain secrets or create
        # unbounded duplicates. Preserve each discovered application path.
        normalized = canonical_http_url(urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")))
        if normalized not in targets:
            targets.append(normalized)
    return targets
