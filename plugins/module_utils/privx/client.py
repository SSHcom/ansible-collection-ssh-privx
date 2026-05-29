import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.urls import open_url
from urllib.parse import quote, urlencode, urlparse

_API_BASE = "/vault/api/v1"
_SECRETS_API = _API_BASE + "/secrets"
_TOKEN_EXCHANGE_API = "/auth/api/v1/token/login"  # nosec B105
_OAUTH_TOKEN_API = "/auth/api/v1/oauth/token"  # nosec B105

_RETRY_STATUSES = {408, 429, 500, 502, 503, 504}


class PrivxError(Exception):
    pass


class PrivxAuthError(PrivxError):
    pass


class PrivxNotFoundError(PrivxError):
    pass


class PrivxRequestError(PrivxError):
    pass


class PrivxClientError(Exception):
    """Raised when the client input is invalid."""


@dataclass(frozen=True)
class PrivxClientConfig:
    """
    Configuration for the PrivX API client.

    Parameters
    ----------
    base_url
        Base URL of the PrivX server, for example
        ``https://privx.example.com``.

    jwt_token
        JWT token that will be exchanged for a PrivX API access token.
        Optional when OAuth credentials are provided instead.

    client_id
        API client identifier for OAuth authentication (sent as username
        in the form body).

    client_secret
        API client secret for OAuth authentication (sent as password
        in the form body).

    oauth_client_id
        OAuth client identifier used in the HTTP Basic Auth header.

    oauth_client_secret
        OAuth client secret used in the HTTP Basic Auth header.

    exchange_scope
        Scope requested during PrivX token exchange.

    exchange_client_id
        Client identifier used in the token login request.

    validate_certs
        Whether to verify TLS certificates. Set to ``False`` only for testing
        environments with self-signed certificates.
    """

    base_url: str

    # JWT auth (existing) — now Optional
    jwt_token: Optional[str] = None

    # OAuth credentials (new)
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    oauth_client_id: Optional[str] = None
    oauth_client_secret: Optional[str] = None

    exchange_scope: str = "privx-user connections-manual"
    exchange_client_id: str = "privx-ui"

    timeout: int = 30
    validate_certs: bool = True
    user_agent: str = "ansible-privx-collection"
    max_retries: int = 2
    retry_delay: float = 1.0

    def __post_init__(self):
        # base_url must not be empty
        if not self.base_url:
            raise ValueError("base_url must not be empty")

        parsed = urlparse(self.base_url)

        # Must have scheme and host
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("base_url must be a valid URL")

        # Enforce HTTPS (can relax if needed)
        if parsed.scheme != "https":
            raise ValueError("base_url must use https")

        # Disallow path component (keep base_url clean)
        if parsed.path not in ("", "/"):
            raise ValueError("base_url must not contain a path")

        # Authentication validation: require either jwt_token OR all four OAuth fields
        has_jwt = bool(self.jwt_token)
        has_client_id = bool(self.client_id)
        has_client_secret = bool(self.client_secret)
        has_oauth_client_id = bool(self.oauth_client_id)
        has_oauth_client_secret = bool(self.oauth_client_secret)

        # If jwt_token was explicitly provided as empty string, give a specific error
        if self.jwt_token is not None and not self.jwt_token:
            raise ValueError("jwt_token must not be empty")

        if has_jwt:
            # JWT provided — valid, no further auth checks needed
            pass
        elif has_client_id or has_client_secret or has_oauth_client_id or has_oauth_client_secret:
            # Some OAuth credentials provided — all four must be present
            missing = []
            if not has_client_id:
                missing.append("client_id")
            if not has_client_secret:
                missing.append("client_secret")
            if not has_oauth_client_id:
                missing.append("oauth_client_id")
            if not has_oauth_client_secret:
                missing.append("oauth_client_secret")
            if missing:
                raise ValueError(
                    f"Incomplete OAuth credentials: missing {', '.join(missing)}"
                )
        else:
            # No credentials at all
            raise ValueError(
                "No authentication credentials provided: supply either jwt_token"
                " or all OAuth credentials"
                " (client_id, client_secret, oauth_client_id, oauth_client_secret)"
            )

        # Basic sanity checks for numeric values
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")

        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0")

        if self.retry_delay < 0:
            raise ValueError("retry_delay must be >= 0")

    def __repr__(self) -> str:
        return (
            f"PrivxClientConfig("
            f"base_url={self.base_url!r}, "
            f"jwt_token={_mask_token(self.jwt_token)!r}, "
            f"client_id={self.client_id!r}, "
            f"client_secret={_mask_token(self.client_secret)!r}, "
            f"oauth_client_id={_mask_token(self.oauth_client_id)!r}, "
            f"oauth_client_secret={_mask_token(self.oauth_client_secret)!r}"
            f")"
        )


class PrivxClient:
    def __init__(self, cfg: PrivxClientConfig, logger=None):
        """
        Initialize the client and obtain a PrivX API access token.

        Authentication method is selected based on available credentials:
        1. If jwt_token is present, use the existing JWT token exchange flow.
        2. If client_id and client_secret are present (no jwt_token), use OAuth flow.
        3. Otherwise, raise PrivxAuthError.
        """
        self._cfg = cfg
        self._logger = logger

        if cfg.jwt_token:
            # Existing JWT flow — unchanged
            exchanged = self.exchange_token(
                jwt_token=cfg.jwt_token,
                scope=cfg.exchange_scope,
                client_id=cfg.exchange_client_id,
            )
            access_token = exchanged.get("access_token")
            if not access_token:
                raise PrivxAuthError(
                    "PrivX token exchange response did not contain token"
                )
            self._access_token = access_token
        elif cfg.client_id and cfg.client_secret:
            # New OAuth flow
            token_response = self.oauth_token(
                api_client_id=cfg.client_id,
                api_client_secret=cfg.client_secret,
                oauth_client_id=cfg.oauth_client_id,
                oauth_client_secret=cfg.oauth_client_secret,
            )
            self._access_token = token_response["access_token"]
        else:
            raise PrivxAuthError("No valid credentials provided")

    def __repr__(self) -> str:
        """
        Define a secure way to print the object.
        """
        return (
            f"PrivxClient("
            f"base_url={self._cfg.base_url!r}, "
            f"validate_certs={self._cfg.validate_certs!r}, "
            f"access_token={_mask_token(self._access_token)!r}"
            f")"
        )

    def _debug(self, message):
        """Log a debug message when a logger is available."""
        if self._logger is not None:
            self._logger(message)

    def get_secret(self, path: str) -> Dict[str, Any]:
        """
        Retrieve a secret from PrivX Secret Vault.

        Parameters
        ----------
        path
            Path of the secret in the PrivX vault.

        Returns
        -------
        dict
            JSON response returned by the PrivX API.
        """
        return self._request_json(
            method="GET",
            path=_SECRETS_API + "/" + _sanitize_secret_path(path),
        )

    def exchange_token(
        self,
        jwt_token: str,
        scope: str,
        client_id: str,
    ) -> Dict[str, Any]:
        payload = {
            "token": jwt_token,
            "scope": scope,
            "client_id": client_id,
        }

        return self._request_json(
            method="POST",
            path=_TOKEN_EXCHANGE_API,
            payload=payload,
            use_auth=False,
        )

    def oauth_token(
        self,
        api_client_id: str,
        api_client_secret: str,
        oauth_client_id: str,
        oauth_client_secret: str,
    ) -> Dict[str, Any]:
        """
        Obtain an access token using OAuth client credentials.

        Sends a form-encoded POST to /auth/api/v1/oauth/token with:
        - Basic Auth header from oauth_client_id:oauth_client_secret
        - Form body: grant_type=password&username=<api_client_id>&password=<api_client_secret>

        Parameters
        ----------
        api_client_id
            API client identifier, sent as the ``username`` form field.
        api_client_secret
            API client secret, sent as the ``password`` form field.
        oauth_client_id
            OAuth client identifier for the HTTP Basic Auth header.
        oauth_client_secret
            OAuth client secret for the HTTP Basic Auth header.

        Returns
        -------
        dict
            Parsed JSON response from the OAuth token endpoint.

        Raises
        ------
        PrivxAuthError
            If the response does not contain a non-empty ``access_token``.
        """
        # Build form-encoded body
        form_body = urlencode({
            "grant_type": "password",
            "username": api_client_id,
            "password": api_client_secret,
        })
        data = form_body.encode("utf-8")

        # Construct Basic Auth header
        credentials = f"{oauth_client_id}:{oauth_client_secret}"
        b64_credentials = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        auth_header = f"Basic {b64_credentials}"

        headers = {
            "Authorization": auth_header,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        # Use _request for retry logic
        status, content_type, body = self._request(
            method="POST",
            url=self._build_url(_OAUTH_TOKEN_API),
            headers=headers,
            data=data,
        )

        # Parse JSON response
        if not body:
            raise PrivxAuthError("OAuth token endpoint returned an empty response")

        text = body.decode("utf-8", errors="strict")

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as e:
            raise PrivxAuthError(f"OAuth token endpoint returned invalid JSON: {e}") from e

        if not isinstance(parsed, dict):
            raise PrivxAuthError("OAuth token endpoint response was not a JSON object")

        # Validate access_token is present and non-empty
        access_token = parsed.get("access_token")
        if not access_token:
            raise PrivxAuthError(
                "OAuth token endpoint response did not contain a valid access_token"
            )

        return parsed

    def post_json(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._request_json(
            method="POST",
            path=path,
            payload=payload,
        )

    def _auth_headers(self) -> Dict[str, str]:
        """
        Construct HTTP headers used for authenticated requests.
        """
        return {
            "Authorization": f"Bearer {self._access_token}",
            "Accept": "application/json",
            "User-Agent": self._cfg.user_agent,
        }

    def _build_url(self, path: str) -> str:
        """
        Build a full API URL from the configured base URL and a relative path.
        """
        return f"{self._cfg.base_url.rstrip('/')}/{path.lstrip('/')}"

    def _request_json(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        allow_empty: bool = False,
        use_auth: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute an HTTP request and return the parsed JSON response.

        Builds request headers, optionally includes authentication, and encodes
        the payload as JSON. The request is executed via the internal `_request`
        helper, which handles retries and low-level HTTP interaction.

        The response body is expected to be JSON. It is decoded and parsed into
        a Python dictionary.

        Parameters
        ----------
        method
            HTTP method (for example "GET" or "POST").
        path
            API path relative to the configured base URL.
        payload
            Optional request body that will be JSON-encoded.
        extra_headers
            Additional HTTP headers to include in the request.
        allow_empty
            If True, an empty response body is accepted and returned as an empty
            dictionary. Otherwise, an empty response raises an error.
        use_auth
            If True, include authentication headers in the request.

        Returns
        -------
        dict
            Parsed JSON response.

        Raises
        ------
        PrivxRequestError
            If the response is empty (and not allowed), has an unexpected content
            type, contains invalid JSON, or does not decode into a JSON object.
        """
        headers = {}
        if use_auth:
            headers.update(self._auth_headers())
        if extra_headers:
            headers.update(extra_headers)
        headers.setdefault("Accept", "application/json")

        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")

        status, content_type, body = self._request(
            method=method,
            url=self._build_url(path),
            headers=headers,
            data=data,
        )

        if not body:
            if allow_empty:
                return {}
            raise PrivxRequestError(f"PrivX returned an empty response (HTTP {status})")

        text = body.decode("utf-8", errors="strict")

        if content_type and "json" not in content_type.lower():
            msg = _extract_error_message(text)
            if msg:
                raise PrivxRequestError(
                    f"PrivX returned unexpected content type {content_type}: {msg}"
                )
            raise PrivxRequestError(
                f"PrivX returned unexpected content type: {content_type}"
            )

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as e:
            msg = _extract_error_message(text)
            if msg:
                raise PrivxRequestError(f"PrivX returned invalid JSON: {msg}") from e
            raise PrivxRequestError(f"PrivX returned invalid JSON: {e}") from e

        if not isinstance(parsed, dict):
            raise PrivxRequestError("PrivX response JSON was not an object")

        return parsed

    def _request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        data: Optional[bytes] = None,
    ) -> Tuple[int, str, bytes]:
        attempts = self._cfg.max_retries + 1

        for attempt in range(1, attempts + 1):
            try:
                self._debug(
                    f"PrivX request method={method} url={url} attempt={attempt}"
                )

                resp = open_url(
                    url,
                    method=method,
                    headers=headers,
                    data=data,
                    timeout=self._cfg.timeout,
                    validate_certs=self._cfg.validate_certs,
                    follow_redirects="safe",
                )

                body = resp.read()
                content_type = ""
                if getattr(resp, "headers", None):
                    content_type = resp.headers.get("Content-Type", "")

                status = getattr(resp, "status", 200)

                self._debug(
                    f"PrivX response status={status} content_type={content_type or '-'}"
                )
                if body:
                    self._debug(f"PrivX response body={_safe_body_for_log(body)}")

                return status, content_type, body

            except HTTPError as e:
                status = getattr(e, "code", None)
                body_text = _read_http_error_body(e)
                content_type = ""
                if getattr(e, "headers", None):
                    content_type = e.headers.get("Content-Type", "")

                self._debug(
                    f"PrivX HTTP error status={status} content_type={content_type or '-'}"
                )
                if body_text:
                    self._debug(f"PrivX error body={body_text[:500]}")

                if self._should_retry(
                    status=status, attempt=attempt, max_attempts=attempts
                ):
                    # Exponential backoff
                    delay = min(self._cfg.retry_delay * (2 ** attempt), 5.0)
                    time.sleep(delay)
                    continue

                server_msg = _extract_error_message(body_text)

                self._debug(f"PrivX HTTP error status={status}")
                self._debug(f"PrivX error body={body_text}")

                if status in (401, 403):
                    raise PrivxAuthError(
                        server_msg or f"PrivX auth failed (HTTP {status})"
                    )
                if status == 404:
                    raise PrivxNotFoundError(server_msg or "PrivX resource not found")
                if status == 503:
                    raise PrivxRequestError(
                        server_msg or "PrivX service temporarily unavailable (HTTP 503)"
                    )

                raise PrivxRequestError(
                    server_msg or f"PrivX request failed (HTTP {status})"
                ) from e

            except URLError as e:
                self._debug(f"PrivX connection error={e}")

                if self._should_retry(
                    status=None, attempt=attempt, max_attempts=attempts
                ):
                    time.sleep(self._cfg.retry_delay)
                    continue

                raise PrivxRequestError(f"PrivX connection failed: {e}") from e

            except UnicodeDecodeError as e:
                raise PrivxRequestError(f"PrivX response decoding failed: {e}") from e

        raise PrivxRequestError("PrivX request failed after retries")

    def _should_retry(
        self,
        status: Optional[int],
        attempt: int,
        max_attempts: int,
    ) -> bool:
        """
        Determine whether a request should be retried based on status code.
        """
        if attempt >= max_attempts:
            return False

        if status is None:
            return True

        return status in _RETRY_STATUSES


def _read_http_error_body(err: Exception, limit: int = 4096) -> Optional[str]:
    try:
        raw = err.read(limit)
        if not raw:
            return None
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return str(raw)
    except Exception:
        return None


def _extract_error_message(body: Optional[str]) -> Optional[str]:
    """
    Extract a human-readable error message from an HTTP response body.

    Attempts to parse JSON and look for common error fields. Falls back to
    returning a trimmed version of the raw body if it appears to be plain text.

    :param body: HTTP response body as string
    :return: Extracted error message or None if not found
    """
    if not body:
        return None

    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, TypeError, ValueError):
        obj = None

    if isinstance(obj, dict):
        # Common top-level fields
        for key in ("message", "error", "detail", "title"):
            val = obj.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()

        # Nested error structures
        for key in ("error", "detail"):
            nested = obj.get(key)
            if isinstance(nested, dict):
                msg = nested.get("message")
                if isinstance(msg, str) and msg.strip():
                    return msg.strip()

    stripped = body.strip()
    if not stripped:
        return None

    # Avoid dumping raw HTML error pages to the user
    if stripped.startswith("<"):
        return None

    return stripped[:300]


def _truncate_for_log(data: bytes, limit: int = 500) -> str:
    text = data.decode("utf-8", errors="replace")
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "...(truncated)"


def _decode_jwt(token: str) -> Dict[str, Any]:
    """
    Decode JWT header and payload without verifying the signature.
    Intended only for debugging/logging.
    """

    try:
        header_b64, payload_b64, _ignored = token.split(".")
    except ValueError:
        return {"error": "token is not a valid JWT"}

    def _b64decode(data: str) -> Dict[str, Any]:
        padding = "=" * (-len(data) % 4)
        raw = base64.urlsafe_b64decode(data + padding)
        return json.loads(raw.decode("utf-8"))

    try:
        return {
            "header": _b64decode(header_b64),
            "payload": _b64decode(payload_b64),
        }
    except Exception as e:
        return {"error": f"JWT decode failed: {e}"}


def _safe_body_for_log(data: bytes, limit: int = 500) -> str:
    """Return a sanitized body string for logging.

    If the payload is valid JSON, mask every "data" field recursively.
    If the payload is not valid JSON, do not log the raw payload at all.
    """
    text = data.decode("utf-8", errors="replace").strip()
    if not text:
        return ""

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return "(non-JSON body omitted)"

    masked = _mask_json_field(payload, "data", "(masked)")
    rendered = json.dumps(masked, ensure_ascii=False, separators=(",", ":"))

    if len(rendered) <= limit:
        return rendered
    return rendered[:limit] + "...(truncated)"


def _mask_json_field(value: Any, field_name: str, replacement: str) -> Any:
    """Recursively mask matching JSON fields."""
    if isinstance(value, dict):
        return {
            key: (
                replacement
                if key == field_name
                else _mask_json_field(val, field_name, replacement)
            )
            for key, val in value.items()
        }

    if isinstance(value, list):
        return [_mask_json_field(item, field_name, replacement) for item in value]

    return value


def _sanitize_secret_path(secret_path: str) -> str:
    """
    Build a safe PrivX API path for a secret lookup.
    """
    raw_parts = secret_path.split("/")
    parts = []

    for part in raw_parts:
        if not part:
            continue
        if part in {".", ".."}:
            raise PrivxClientError("no relative path allowed in secret path")
        parts.append(quote(part, safe=""))

    if not parts:
        raise PrivxClientError("secret path must not be empty")

    return "/".join(parts)


def _resolve_oauth_credentials(
    client_id=None,
    client_secret=None,
    oauth_client_id=None,
    oauth_client_secret=None,
):
    """
    Resolve OAuth credentials from explicit parameters with environment variable fallback.

    Returns a tuple of (client_id, client_secret, oauth_client_id, oauth_client_secret).
    Each value is resolved from the explicit parameter first, falling back to the
    corresponding environment variable if the parameter is None or empty.
    """
    import os

    resolved_client_id = client_id or os.environ.get("PRIVX_CLIENT_ID")
    resolved_client_secret = client_secret or os.environ.get("PRIVX_CLIENT_SECRET")
    resolved_oauth_client_id = oauth_client_id or os.environ.get("PRIVX_OAUTH_CLIENT_ID")
    resolved_oauth_client_secret = oauth_client_secret or os.environ.get("PRIVX_OAUTH_CLIENT_SECRET")
    return (resolved_client_id, resolved_client_secret, resolved_oauth_client_id, resolved_oauth_client_secret)


def _mask_token(token: "str | None") -> "str | None":
    """
    Mask token values in case they are printed.
    """
    if not token:
        return None
    if len(token) <= 8:
        return "***"
    return token[:4] + "..." + token[-4:]
