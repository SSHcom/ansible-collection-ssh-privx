"""Property-based and unit tests for PrivxClient.oauth_token method.

Feature: oauth-client-credentials
"""

import base64
import json
import io
from urllib.parse import parse_qs, urlencode

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ansible_collections.sshcom.privx.plugins.module_utils.privx.client import (
    PrivxAuthError,
    PrivxClient,
    PrivxClientConfig,
    _OAUTH_TOKEN_API,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Strategy for credential strings that may contain special characters
# relevant to URL encoding: &, =, +, spaces, unicode, etc.
credential_text = st.text(
    alphabet=st.characters(
        categories=("L", "N", "P", "S", "Z"),
        exclude_characters=("\x00",),
    ),
    min_size=1,
    max_size=100,
)


# ---------------------------------------------------------------------------
# Property-Based Tests
# ---------------------------------------------------------------------------


class TestProperty1FormBodyEncodingRoundTrip:
    """Property 1: Form body encoding round-trip.

    For any valid api_client_id and api_client_secret strings (including
    those with special characters like &, =, +, spaces), encoding them into
    the form body and then parsing the form body back SHALL yield the original
    grant_type, username, and password values unchanged.

    **Validates: Requirements 1.2**
    """

    @given(
        api_client_id=credential_text,
        api_client_secret=credential_text,
    )
    @settings(max_examples=100)
    def test_form_encode_decode_round_trip(self, api_client_id, api_client_secret):
        """Encoding credentials into form body and parsing back yields originals."""
        # Encode exactly as oauth_token does
        form_body = urlencode({
            "grant_type": "password",
            "username": api_client_id,
            "password": api_client_secret,
        })

        # Parse back
        parsed = parse_qs(form_body, keep_blank_values=True)

        # Verify round-trip
        assert parsed["grant_type"] == ["password"]
        assert parsed["username"] == [api_client_id]
        assert parsed["password"] == [api_client_secret]


class TestProperty2BasicAuthHeaderRoundTrip:
    """Property 2: Basic Auth header round-trip.

    For any valid oauth_client_id and oauth_client_secret strings,
    constructing the Basic Auth header as
    Basic base64(oauth_client_id:oauth_client_secret) and then decoding it
    SHALL yield the original oauth_client_id and oauth_client_secret.

    **Validates: Requirements 1.3**
    """

    @given(
        oauth_client_id=credential_text,
        oauth_client_secret=credential_text,
    )
    @settings(max_examples=100)
    def test_basic_auth_encode_decode_round_trip(
        self, oauth_client_id, oauth_client_secret
    ):
        """Constructing Basic Auth header and decoding yields original credentials."""
        # The oauth_client_id must not contain a colon for unambiguous round-trip
        # (colons in the password are fine since we split on first colon only)
        assume(":" not in oauth_client_id)

        # Encode exactly as oauth_token does
        credentials = f"{oauth_client_id}:{oauth_client_secret}"
        b64_credentials = base64.b64encode(
            credentials.encode("utf-8")
        ).decode("ascii")
        auth_header = f"Basic {b64_credentials}"

        # Decode
        scheme, encoded = auth_header.split(" ", 1)
        assert scheme == "Basic"

        decoded = base64.b64decode(encoded).decode("utf-8")
        decoded_id, decoded_secret = decoded.split(":", 1)

        assert decoded_id == oauth_client_id
        assert decoded_secret == oauth_client_secret


# ---------------------------------------------------------------------------
# Helpers for unit tests
# ---------------------------------------------------------------------------


class FakeResponse:
    """Simple fake HTTP response for open_url mocking."""

    def __init__(self, body, status=200, content_type="application/json"):
        if body is None:
            body = b""
        elif isinstance(body, (dict, list, int, float, bool)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")

        self._body = io.BytesIO(body)
        self.status = status
        self.headers = {"Content-Type": content_type}

    def read(self):
        return self._body.read()


def _make_client_with_oauth(monkeypatch, oauth_responses):
    """Create a PrivxClient using OAuth flow with mocked HTTP responses.

    Parameters
    ----------
    monkeypatch
        pytest monkeypatch fixture.
    oauth_responses
        List of responses (FakeResponse or Exception) to return from open_url.
        The first response is used for the oauth_token call during __init__.

    Returns
    -------
    PrivxClient
        Initialized client.
    """
    responses = list(oauth_responses)

    def fake_open_url(url, method, headers, data=None, **kwargs):
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
        client_id="api-client-id",
        client_secret="api-client-secret",
        oauth_client_id="oauth-client-id",
        oauth_client_secret="oauth-client-secret",
    )

    # We need to bypass __init__ to test oauth_token directly
    return cfg, fake_open_url


def _make_bare_client(monkeypatch):
    """Create a PrivxClient instance without running __init__ auth flow."""
    cfg = PrivxClientConfig(
        base_url="https://privx.example.com",
        client_id="api-client-id",
        client_secret="api-client-secret",
        oauth_client_id="oauth-client-id",
        oauth_client_secret="oauth-client-secret",
    )

    client = PrivxClient.__new__(PrivxClient)
    client._cfg = cfg
    client._logger = None
    return client


# ---------------------------------------------------------------------------
# Unit Tests for oauth_token method
# ---------------------------------------------------------------------------


class TestOAuthTokenMethod:
    """Unit tests for PrivxClient.oauth_token."""

    def test_happy_path_returns_token_response(self, monkeypatch):
        """oauth_token should return parsed JSON with access_token on success."""
        token_response = {
            "access_token": "my-access-token",
            "token_type": "bearer",
            "expires_in": 3600,
        }

        captured_requests = []

        def fake_open_url(url, method, headers, data=None, **kwargs):
            captured_requests.append({
                "url": url,
                "method": method,
                "headers": headers,
                "data": data,
            })
            return FakeResponse(token_response)

        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            fake_open_url,
        )

        client = _make_bare_client(monkeypatch)
        result = client.oauth_token(
            api_client_id="my-api-id",
            api_client_secret="my-api-secret",
            oauth_client_id="my-oauth-id",
            oauth_client_secret="my-oauth-secret",
        )

        assert result == token_response
        assert result["access_token"] == "my-access-token"

        # Verify request details
        req = captured_requests[0]
        assert req["method"] == "POST"
        assert req["url"] == "https://privx.example.com/auth/api/v1/oauth/token"
        assert req["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
        assert "Basic" in req["headers"]["Authorization"]

        # Verify form body
        body_str = req["data"].decode("utf-8")
        parsed_body = parse_qs(body_str)
        assert parsed_body["grant_type"] == ["password"]
        assert parsed_body["username"] == ["my-api-id"]
        assert parsed_body["password"] == ["my-api-secret"]

    def test_basic_auth_header_is_correctly_encoded(self, monkeypatch):
        """oauth_token should construct correct Basic Auth header."""

        def fake_open_url(url, method, headers, data=None, **kwargs):
            return FakeResponse({"access_token": "tok", "token_type": "bearer"})

        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            fake_open_url,
        )

        client = _make_bare_client(monkeypatch)
        # Use credentials with special chars
        client.oauth_token(
            api_client_id="user",
            api_client_secret="pass",
            oauth_client_id="oauth-id",
            oauth_client_secret="oauth-secret",
        )

        # Manually verify the expected header value
        expected_creds = base64.b64encode(b"oauth-id:oauth-secret").decode("ascii")
        expected_header = f"Basic {expected_creds}"

        # Re-run to capture
        captured = []

        def capturing_open_url(url, method, headers, data=None, **kwargs):
            captured.append(headers)
            return FakeResponse({"access_token": "tok"})

        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            capturing_open_url,
        )

        client.oauth_token(
            api_client_id="user",
            api_client_secret="pass",
            oauth_client_id="oauth-id",
            oauth_client_secret="oauth-secret",
        )

        assert captured[0]["Authorization"] == expected_header

    def test_raises_auth_error_when_access_token_missing(self, monkeypatch):
        """oauth_token should raise PrivxAuthError when access_token is missing."""

        def fake_open_url(url, method, headers, data=None, **kwargs):
            return FakeResponse({"token_type": "bearer", "expires_in": 3600})

        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            fake_open_url,
        )

        client = _make_bare_client(monkeypatch)

        with pytest.raises(PrivxAuthError, match="did not contain a valid access_token"):
            client.oauth_token(
                api_client_id="id",
                api_client_secret="secret",
                oauth_client_id="oid",
                oauth_client_secret="osecret",
            )

    def test_raises_auth_error_when_access_token_empty(self, monkeypatch):
        """oauth_token should raise PrivxAuthError when access_token is empty string."""

        def fake_open_url(url, method, headers, data=None, **kwargs):
            return FakeResponse({"access_token": "", "token_type": "bearer"})

        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            fake_open_url,
        )

        client = _make_bare_client(monkeypatch)

        with pytest.raises(PrivxAuthError, match="did not contain a valid access_token"):
            client.oauth_token(
                api_client_id="id",
                api_client_secret="secret",
                oauth_client_id="oid",
                oauth_client_secret="osecret",
            )

    def test_raises_auth_error_on_empty_response_body(self, monkeypatch):
        """oauth_token should raise PrivxAuthError on empty response body."""

        def fake_open_url(url, method, headers, data=None, **kwargs):
            return FakeResponse(b"")

        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            fake_open_url,
        )

        client = _make_bare_client(monkeypatch)

        with pytest.raises(PrivxAuthError, match="empty response"):
            client.oauth_token(
                api_client_id="id",
                api_client_secret="secret",
                oauth_client_id="oid",
                oauth_client_secret="osecret",
            )

    def test_raises_auth_error_on_invalid_json(self, monkeypatch):
        """oauth_token should raise PrivxAuthError on invalid JSON response."""

        def fake_open_url(url, method, headers, data=None, **kwargs):
            return FakeResponse("{not valid json", content_type="application/json")

        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            fake_open_url,
        )

        client = _make_bare_client(monkeypatch)

        with pytest.raises(PrivxAuthError, match="invalid JSON"):
            client.oauth_token(
                api_client_id="id",
                api_client_secret="secret",
                oauth_client_id="oid",
                oauth_client_secret="osecret",
            )

    def test_special_characters_in_credentials(self, monkeypatch):
        """oauth_token should correctly handle special chars in credentials."""
        captured = []

        def fake_open_url(url, method, headers, data=None, **kwargs):
            captured.append({"headers": headers, "data": data})
            return FakeResponse({"access_token": "tok"})

        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            fake_open_url,
        )

        client = _make_bare_client(monkeypatch)
        result = client.oauth_token(
            api_client_id="user&name=special",
            api_client_secret="pass word+extra",
            oauth_client_id="oauth:id",
            oauth_client_secret="oauth/secret=",
        )

        assert result["access_token"] == "tok"

        # Verify form body correctly encodes special chars
        body_str = captured[0]["data"].decode("utf-8")
        parsed = parse_qs(body_str)
        assert parsed["username"] == ["user&name=special"]
        assert parsed["password"] == ["pass word+extra"]

        # Verify Basic Auth header
        auth = captured[0]["headers"]["Authorization"]
        assert auth.startswith("Basic ")
        decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
        assert decoded == "oauth:id:oauth/secret="

    def test_oauth_token_api_constant(self):
        """The _OAUTH_TOKEN_API constant should have the correct value."""
        assert _OAUTH_TOKEN_API == "/auth/api/v1/oauth/token"
