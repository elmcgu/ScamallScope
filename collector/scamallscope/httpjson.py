"""Small JSON-over-HTTPS client for the integrations (standard library only).

- https only, TLS always verified (an extra CA file can be given, verification cannot be off).
- Credentials go in headers and never appear in error messages.
- Redirects are not followed, so a credential header never leaves the host it was meant for.
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlencode, urlsplit

TIMEOUT_S = 30
MAX_ERROR_BODY = 200

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib re-sends every header, Authorization included, to wherever a redirect points
    (another host, or plain http). Refuse instead: a 3xx becomes an HttpError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def urlopen(req: urllib.request.Request, timeout: float, context: ssl.SSLContext) -> Any:
    """Tests replace this with a fake; real runs use urllib without redirects."""
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirect())
    return opener.open(req, timeout=timeout)


class HttpError(RuntimeError):
    pass


def require_https(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.netloc:
        raise ValueError(f"URL must start with https:// (got {parts.scheme or 'no scheme'}://{parts.netloc})")
    return url.rstrip("/")


def basic_auth(user: str, password: str) -> str:  # pragma: allowlist secret
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def context(ca_file: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
    return ctx


def request(method: str, url: str, headers: dict[str, str] | None = None, params: dict[str, Any] | None = None,
            body: Any = None, ca_file: str | None = None) -> Any:
    """Send a request and return the parsed JSON. Raises HttpError with a safe message."""
    require_https(url)
    full = f"{url}?{urlencode(params)}" if params else url
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Accept": "application/json", "User-Agent": "scamallscope", **(headers or {})}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(full, data=data, headers=hdrs, method=method)
    where = f"{method} {urlsplit(url).netloc}{urlsplit(url).path}"
    try:
        with urlopen(req, timeout=TIMEOUT_S, context=context(ca_file)) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        snippet = exc.read()[:MAX_ERROR_BODY].decode("utf-8", "replace") if exc.fp else ""
        raise HttpError(f"{where}: HTTP {exc.code} {snippet}".strip()) from None
    except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
        raise HttpError(f"{where}: {type(exc).__name__}: {getattr(exc, 'reason', exc)}") from None
    except json.JSONDecodeError:
        raise HttpError(f"{where}: response is not JSON") from None
