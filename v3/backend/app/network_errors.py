import ssl
from urllib.error import URLError


def classify_target_connection_error(error: BaseException) -> tuple[str, str]:
    """Produce a stable operator message without weakening TLS verification."""
    nested = error.reason if isinstance(error, URLError) else error
    detail = str(nested)
    if isinstance(nested, ssl.SSLError):
        if "UNRECOGNIZED_NAME" in detail.upper() or "UNRECOGNIZED NAME" in detail.upper():
            return (
                "TARGET_TLS_SNI_REJECTED",
                "The HTTPS endpoint rejected this hostname during TLS SNI negotiation. "
                "Use the service's documented canonical HTTPS hostname, or correct the target configuration. "
                "ExposureScopeX did not bypass certificate or hostname verification.",
            )
        return (
            "TARGET_TLS_ERROR",
            "The HTTPS handshake failed before an HTTP response was available. "
            "Check the exact target URL and the service's TLS configuration; TLS verification was not bypassed.",
        )
    return "TARGET_UNREACHABLE", detail
