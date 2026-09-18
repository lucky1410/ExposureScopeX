"""Shared local HTTP safety helpers."""

from __future__ import annotations

from urllib.request import HTTPRedirectHandler, build_opener


class NoRedirectHandler(HTTPRedirectHandler):
    """Keep a configured local or attested target from silently changing URL."""

    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def build_no_redirect_opener(*handlers: object):
    return build_opener(NoRedirectHandler(), *handlers)
