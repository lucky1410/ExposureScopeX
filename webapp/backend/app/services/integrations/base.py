"""Abstract base class and provider registry for integration services."""

from abc import ABC, abstractmethod


class IntegrationService(ABC):
    """Base class that every integration provider must subclass.

    Subclasses must set PROVIDER (provider slug string) and
    SUPPORTED_EVENTS (list of event names the provider handles).
    The ``config`` dict is the *decrypted* provider configuration.
    """

    PROVIDER: str = ""
    SUPPORTED_EVENTS: list[str] = []

    def __init__(self, config: dict) -> None:
        self.config = config

    @abstractmethod
    async def send(self, event: str, org_id: str, payload: dict) -> None:
        """Deliver ``payload`` to the integration endpoint for ``event``.

        Must not raise — callers use ``return_exceptions=True`` but
        concrete implementations should still suppress transient errors
        internally and re-raise only on genuine misconfiguration so the
        dispatcher can record ``last_error`` accurately.
        """

    @abstractmethod
    async def test_connection(self) -> dict:
        """Validate credentials without sending a real event.

        Returns a dict with at minimum::

            {"ok": bool, "message": str}
        """


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

REGISTRY: dict[str, type[IntegrationService]] = {}


def register(cls: type[IntegrationService]) -> type[IntegrationService]:
    """Class decorator that registers a provider implementation."""
    if not cls.PROVIDER:
        raise ValueError(f"{cls.__name__}.PROVIDER must be set before registering")
    REGISTRY[cls.PROVIDER] = cls
    return cls


def get_service(provider: str, config: dict) -> IntegrationService:
    """Instantiate the integration service for *provider* with *config*.

    Raises ``ValueError`` when *provider* is not in the registry.
    """
    cls = REGISTRY.get(provider)
    if not cls:
        raise ValueError(f"Unknown integration provider: {provider!r}")
    return cls(config)
