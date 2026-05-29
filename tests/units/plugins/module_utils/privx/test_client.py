"""Unit tests for the PrivX client."""

# GNU General Public License v3.0+

import io
import json
import pytest

from ansible_collections.sshcom.privx.plugins.module_utils.privx.client import (
    PrivxAuthError,
    PrivxClient,
    PrivxClientConfig,
    PrivxRequestError,
    PrivxNotFoundError,
    PrivxClientError,
    _sanitize_secret_path
)
from urllib.error import URLError, HTTPError
from io import BytesIO


class FakeResponse:
    """Simple fake HTTP response for open_url mocking."""

    def __init__(
        self,
        body,
        status=200,
        content_type="application/json",
    ):
        """Store fake response payload and headers."""
        if body is None:
            body = b""
        elif isinstance(body, (dict, list, int, float, bool)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")

        self._body = io.BytesIO(body)
        self.status = status
        self.headers = {
            "Content-Type": content_type,
        }

    def read(self):
        """Return response body bytes."""
        return self._body.read()


def test_init_exchanges_token_and_stores_access_token(monkeypatch):
    """Client initialization should exchange JWT and store access token."""
    exchange_response = {
        "access_token": "privx-access-token",
    }

    def fake_open_url(url, method, headers, data=None, **kwargs):
        """Return a successful token exchange response."""
        assert method == "POST"
        assert url == "https://privx.example.com/auth/api/v1/token/login"
        assert "Authorization" not in headers

        payload = json.loads(data.decode("utf-8"))
        assert payload["token"] == "jwt-token"
        assert payload["scope"] == "privx-user connections-manual"
        assert payload["client_id"] == "privx-ui"

        return FakeResponse(exchange_response)

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
        fake_open_url,
    )

    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        jwt_token="jwt-token",
    )

    client = PrivxClient(cfg)

    assert client._access_token == "privx-access-token"


def test_init_raises_when_exchange_response_has_no_access_token(monkeypatch):
    """Client initialization should fail if token exchange returns no access token."""

    def fake_open_url(url, method, headers, data=None, **kwargs):
        """Return token exchange response without access token."""
        return FakeResponse({"token_type": "Bearer"})

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
        fake_open_url,
    )

    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        jwt_token="jwt-token",
    )

    try:
        PrivxClient(cfg)
        assert False, "expected PrivxAuthError"
    except PrivxAuthError as err:
        assert "did not contain token" in str(err)


def test_get_secret_returns_json(monkeypatch):
    """Client should return parsed JSON from secret endpoint."""
    responses = [
        FakeResponse({"access_token": "privx-access-token"}),
        FakeResponse({"value": "secret-value"}),
    ]

    def fake_open_url(url, method, headers, data=None, **kwargs):
        """Return token exchange first and secret response second."""
        response = responses.pop(0)

        if url.endswith("/auth/api/v1/token/login"):
            assert method == "POST"
            assert "Authorization" not in headers

        elif url.endswith("/vault/api/v1/secrets/example"):
            assert method == "GET"
            assert headers["Authorization"] == "Bearer privx-access-token"

        return response

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
        fake_open_url,
    )

    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        jwt_token="jwt-token",
    )

    client = PrivxClient(cfg)
    result = client.get_secret("example")

    assert result == {"value": "secret-value"}


def test_request_json_raises_on_invalid_json(monkeypatch):
    """Client should raise an error if response body is not valid JSON."""
    responses = [
        FakeResponse({"access_token": "privx-access-token"}),
        FakeResponse("{not-json}", content_type="application/json"),
    ]

    def fake_open_url(url, method, headers, data=None, **kwargs):
        """Return token exchange first and invalid JSON second."""
        return responses.pop(0)

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
        fake_open_url,
    )

    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        jwt_token="jwt-token",
    )

    client = PrivxClient(cfg)

    try:
        client.get_secret("example")
        assert False, "expected PrivxRequestError"
    except PrivxRequestError as err:
        assert "invalid JSON" in str(err)


def test_request_json_raises_on_empty_body(monkeypatch):
    """Client should raise an error on empty response body by default."""
    responses = [
        FakeResponse({"access_token": "privx-access-token"}),
        FakeResponse(b""),
    ]

    def fake_open_url(url, method, headers, data=None, **kwargs):
        """Return token exchange first and empty response second."""
        return responses.pop(0)

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
        fake_open_url,
    )

    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        jwt_token="jwt-token",
    )

    client = PrivxClient(cfg)

    try:
        client.get_secret("example")
        assert False, "expected PrivxRequestError"
    except PrivxRequestError as err:
        assert "empty response" in str(err)


def test_request_json_raises_on_non_json_content_type(monkeypatch):
    """Client should fail if response content type is not JSON."""
    responses = [
        FakeResponse({"access_token": "privx-access-token"}),
        FakeResponse("not-json", content_type="text/plain"),
    ]

    def fake_open_url(*args, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
        fake_open_url,
    )

    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        jwt_token="jwt-token",
    )

    client = PrivxClient(cfg)

    try:
        client.get_secret("example")
        assert False, "expected PrivxRequestError"
    except PrivxRequestError as err:
        assert "content type" in str(err)


def test_request_json_returns_empty_dict_when_allow_empty(monkeypatch):
    """Empty body should be allowed when allow_empty=True."""
    responses = [
        FakeResponse({"access_token": "privx-access-token"}),
        FakeResponse(b""),
    ]

    def fake_open_url(*args, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
        fake_open_url,
    )

    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        jwt_token="jwt-token",
    )

    client = PrivxClient(cfg)

    result = client._request_json(
        method="GET",
        path="/vault/api/v1/secrets/example",
        allow_empty=True,
    )

    assert result == {}


def test_request_json_raises_if_json_is_not_object(monkeypatch):
    """Client should fail if JSON is not a dict."""
    responses = [
        FakeResponse({"access_token": "privx-access-token"}),
        FakeResponse(["not", "a", "dict"]),
    ]

    def fake_open_url(*args, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
        fake_open_url,
    )

    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        jwt_token="jwt-token",
    )

    client = PrivxClient(cfg)

    try:
        client.get_secret("example")
        assert False, "expected PrivxRequestError"
    except PrivxRequestError as err:
        assert "not an object" in str(err)


def test_get_secret_sends_bearer_token(monkeypatch):
    """Client should send Authorization header with bearer token."""
    responses = [
        FakeResponse({"access_token": "privx-access-token"}),
        FakeResponse({"value": "secret"}),
    ]

    def fake_open_url(url, method, headers, data=None, **kwargs):
        if url.endswith("/vault/api/v1/secrets/example"):
            assert headers["Authorization"] == "Bearer privx-access-token"
        return responses.pop(0)

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
        fake_open_url,
    )

    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        jwt_token="jwt-token",
    )

    client = PrivxClient(cfg)
    client.get_secret("example")


def test_should_retry_transient_statuses():
    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        jwt_token="jwt",
    )
    client = PrivxClient.__new__(PrivxClient)
    client._cfg = cfg

    assert client._should_retry(500, attempt=0, max_attempts=3)
    assert client._should_retry(429, attempt=0, max_attempts=3)
    assert not client._should_retry(404, attempt=0, max_attempts=3)


def test_request_retries_once_and_succeeds(monkeypatch):
    """Client should retry once on transient error and then succeed."""
    responses = [
        FakeResponse({"access_token": "privx-access-token"}),
        URLError("temporary failure"),
        FakeResponse({"value": "secret"}),
    ]

    def fake_open_url(*args, **kwargs):
        result = responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
        fake_open_url,
    )

    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        jwt_token="jwt-token",
        max_retries=2,
        retry_delay=0,
    )

    client = PrivxClient(cfg)
    result = client.get_secret("example")

    assert result == {"value": "secret"}


@pytest.mark.parametrize(
    ("status_code", "expected_exception"),
    [
        (401, PrivxAuthError),
        (403, PrivxAuthError),
        (404, PrivxNotFoundError),
    ],
)
def test_get_secret_maps_http_errors(monkeypatch, status_code, expected_exception):
    """Client should map HTTP errors to the expected exception types."""
    responses = [
        FakeResponse({"access_token": "privx-access-token"}),
        HTTPError(
            url="https://privx.example.com/vault/api/v1/secrets/example",
            code=status_code,
            msg="HTTP error",
            hdrs={"Content-Type": "application/json"},
            fp=BytesIO(b'{"message":"server error"}'),
        ),
    ]

    def fake_open_url(*args, **kwargs):
        """Return token exchange first and HTTP error second."""
        result = responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
        fake_open_url,
    )

    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        jwt_token="jwt-token",
    )

    client = PrivxClient(cfg)

    with pytest.raises(expected_exception):
        client.get_secret("example")


def test_get_secret_retries_once_on_503_and_succeeds(monkeypatch):
    """Client should retry once on HTTP 503 and then succeed."""
    responses = [
        FakeResponse({"access_token": "privx-access-token"}),
        HTTPError(
            url="https://privx.example.com/vault/api/v1/secrets/example",
            code=503,
            msg="Service Unavailable",
            hdrs={"Content-Type": "application/json"},
            fp=BytesIO(b'{"message":"temporary problem"}'),
        ),
        FakeResponse({"value": "secret-value"}),
    ]

    def fake_open_url(*args, **kwargs):
        """Return token exchange, one transient HTTP error, then success."""
        result = responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
        fake_open_url,
    )

    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        jwt_token="jwt-token",
        max_retries=2,
        retry_delay=0,
    )

    client = PrivxClient(cfg)
    result = client.get_secret("example")

    assert result == {"value": "secret-value"}


@pytest.mark.parametrize(
    ("kwargs", "expected_message"),
    [
        (
            {
                "base_url": "",
                "jwt_token": "jwt-token",
            },
            "base_url must not be empty",
        ),
        (
            {
                "base_url": "not-a-url",
                "jwt_token": "jwt-token",
            },
            "base_url must be a valid URL",
        ),
        (
            {
                "base_url": "http://privx.example.com",
                "jwt_token": "jwt-token",
            },
            "base_url must use https",
        ),
        (
            {
                "base_url": "https://privx.example.com/api",
                "jwt_token": "jwt-token",
            },
            "base_url must not contain a path",
        ),
        (
            {
                "base_url": "https://privx.example.com",
                "jwt_token": "",
            },
            "jwt_token must not be empty",
        ),
        (
            {
                "base_url": "https://privx.example.com",
                "jwt_token": "jwt-token",
                "timeout": 0,
            },
            "timeout must be positive",
        ),
        (
            {
                "base_url": "https://privx.example.com",
                "jwt_token": "jwt-token",
                "timeout": -1,
            },
            "timeout must be positive",
        ),
        (
            {
                "base_url": "https://privx.example.com",
                "jwt_token": "jwt-token",
                "max_retries": -1,
            },
            "max_retries must be >= 0",
        ),
        (
            {
                "base_url": "https://privx.example.com",
                "jwt_token": "jwt-token",
                "retry_delay": -0.1,
            },
            "retry_delay must be >= 0",
        ),
    ],
)
def test_privx_client_config_rejects_invalid_values(kwargs, expected_message):
    """PrivxClientConfig should reject invalid configuration values."""
    with pytest.raises(ValueError, match=expected_message):
        PrivxClientConfig(**kwargs)


def test_privx_client_config_accepts_valid_values():
    """PrivxClientConfig should accept a valid configuration."""
    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        jwt_token="jwt-token",
        timeout=30,
        validate_certs=True,
        max_retries=2,
        retry_delay=1.0,
    )

    assert cfg.base_url == "https://privx.example.com"
    assert cfg.jwt_token == "jwt-token"
    assert cfg.timeout == 30
    assert cfg.validate_certs is True
    assert cfg.max_retries == 2
    assert cfg.retry_delay == 1.0


def test_privx_client_config_accepts_base_url_with_trailing_slash():
    """PrivxClientConfig should accept base_url with a trailing slash."""
    cfg = PrivxClientConfig(
        base_url="https://privx.example.com/",
        jwt_token="jwt-token",
    )

    assert cfg.base_url == "https://privx.example.com/"


@pytest.mark.parametrize(
    ("secret_path", "expected"),
    [
        ("example", "example"),
        ("/example", "example"),
        ("//example", "example"),
        ("folder/secret", "folder/secret"),
        ("/folder/secret", "folder/secret"),
        ("folder//secret", "folder/secret"),
        ("a b", "a%20b"),
        ("folder/a b", "folder/a%20b"),
        ("a?b", "a%3Fb"),
        ("a#b", "a%23b"),
    ],
)
def test_sanitize_secret_path_accepts_and_encodes_valid_paths(secret_path, expected):
    """_sanitize_secret_path should normalize and encode valid secret paths."""
    assert _sanitize_secret_path(secret_path) == expected


@pytest.mark.parametrize(
    "secret_path",
    [
        "",
        "/",
        "//",
    ],
)
def test_sanitize_secret_path_rejects_empty_paths(secret_path):
    """_sanitize_secret_path should reject empty secret paths."""
    with pytest.raises(PrivxClientError, match="secret path must not be empty"):
        _sanitize_secret_path(secret_path)


@pytest.mark.parametrize(
    "secret_path",
    [
        ".",
        "..",
        "./secret",
        "../secret",
        "folder/./secret",
        "folder/../secret",
        "../../admin/api/v1/something",
        "secret/..",
        "secret/.",
    ],
)
def test_sanitize_secret_path_rejects_relative_segments(secret_path):
    """_sanitize_secret_path should reject relative path segments."""
    with pytest.raises(
        PrivxClientError,
        match="no relative path allowed in secret path",
    ):
        _sanitize_secret_path(secret_path)


def test_get_secret_uses_sanitized_secret_path(monkeypatch):
    """Client should use sanitized secret path in the request URL."""
    responses = [
        FakeResponse({"access_token": "privx-access-token"}),
        FakeResponse({"value": "secret-value"}),
    ]

    def fake_open_url(url, method, headers, data=None, **kwargs):
        response = responses.pop(0)

        if url.endswith("/auth/api/v1/token/login"):
            return response

        assert url == "https://privx.example.com/vault/api/v1/secrets/folder/a%20b"
        return response

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
        fake_open_url,
    )

    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        jwt_token="jwt-token",
    )

    client = PrivxClient(cfg)
    result = client.get_secret("folder/a b")

    assert result == {"value": "secret-value"}
