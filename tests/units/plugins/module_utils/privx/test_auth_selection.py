"""Property-based tests for PrivxClient auth method selection.

Feature: oauth-client-credentials
"""

import io
import json
from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ansible_collections.sshcom.privx.plugins.module_utils.privx.client import (
    PrivxAuthError,
    PrivxClient,
    PrivxClientConfig,
    PrivxNotFoundError,
    PrivxRequestError,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Non-empty text for tokens/credentials
non_empty_text = st.text(
    alphabet=st.characters(
        categories=("L", "N", "P", "S"),
        exclude_characters=("\x00",),
    ),
    min_size=1,
    max_size=50,
)

# Strategy for access token strings (non-empty, printable)
access_token_text = st.text(
    alphabet=st.characters(
        categories=("L", "N", "P", "S"),
        exclude_characters=("\x00",),
    ),
    min_size=1,
    max_size=200,
)

# Strategy for HTTP error status codes (4xx and 5xx)
http_error_status = st.one_of(
    st.integers(min_value=400, max_value=499),
    st.integers(min_value=500, max_value=599),
)


# ---------------------------------------------------------------------------
# Helpers
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


# ---------------------------------------------------------------------------
# Property 5: Auth method selection — JWT priority
# ---------------------------------------------------------------------------


class TestProperty5JWTPriority:
    """Property 5: Auth method selection — JWT priority.

    For any PrivxClientConfig where jwt_token is non-empty, the client SHALL
    use the JWT token exchange flow regardless of whether OAuth credential
    fields are also populated.

    **Validates: Requirements 2.1, 2.2**
    """

    @given(
        jwt_token=non_empty_text,
        client_id=st.one_of(st.none(), non_empty_text),
        client_secret=st.one_of(st.none(), non_empty_text),
        oauth_client_id=st.one_of(st.none(), non_empty_text),
        oauth_client_secret=st.one_of(st.none(), non_empty_text),
    )
    @settings(max_examples=100)
    def test_jwt_token_always_uses_exchange_flow(
        self,
        jwt_token,
        client_id,
        client_secret,
        oauth_client_id,
        oauth_client_secret,
    ):
        """When jwt_token is set, exchange_token is called and oauth_token is NOT called."""
        # Build kwargs for config — only include OAuth fields if all four are present
        # (otherwise config validation will reject partial OAuth creds)
        config_kwargs = {
            "base_url": "https://privx.example.com",
            "jwt_token": jwt_token,
        }

        # If we provide any OAuth field, we must provide all four to pass validation
        if client_id and client_secret and oauth_client_id and oauth_client_secret:
            config_kwargs["client_id"] = client_id
            config_kwargs["client_secret"] = client_secret
            config_kwargs["oauth_client_id"] = oauth_client_id
            config_kwargs["oauth_client_secret"] = oauth_client_secret

        cfg = PrivxClientConfig(**config_kwargs)

        exchange_called = []
        oauth_called = []

        def fake_exchange_token(self_inner, jwt_token, scope, client_id):
            exchange_called.append(True)
            return {"access_token": "jwt-access-token"}

        def fake_oauth_token(self_inner, **kwargs):
            oauth_called.append(True)
            return {"access_token": "oauth-access-token"}

        with patch.object(PrivxClient, "exchange_token", fake_exchange_token):
            with patch.object(PrivxClient, "oauth_token", fake_oauth_token):
                client = PrivxClient(cfg)

        # exchange_token MUST have been called
        assert len(exchange_called) == 1, "exchange_token should be called exactly once"
        # oauth_token MUST NOT have been called
        assert len(oauth_called) == 0, "oauth_token should not be called when jwt_token is set"
        # The access token should come from the JWT exchange
        assert client._access_token == "jwt-access-token"


# ---------------------------------------------------------------------------
# Property 3: Access token preservation
# ---------------------------------------------------------------------------


class TestProperty3AccessTokenPreservation:
    """Property 3: Access token preservation.

    For any non-empty access token string returned by the OAuth endpoint,
    the client SHALL store that exact string as its bearer token.

    **Validates: Requirements 1.4**
    """

    @given(token_value=access_token_text)
    @settings(max_examples=100)
    def test_oauth_access_token_stored_exactly(self, token_value):
        """The access token from OAuth response is stored exactly as-is."""
        cfg = PrivxClientConfig(
            base_url="https://privx.example.com",
            client_id="api-client-id",
            client_secret="api-client-secret",
            oauth_client_id="oauth-client-id",
            oauth_client_secret="oauth-client-secret",
        )

        def fake_oauth_token(self_inner, api_client_id, api_client_secret,
                             oauth_client_id, oauth_client_secret):
            return {"access_token": token_value}

        with patch.object(PrivxClient, "oauth_token", fake_oauth_token):
            client = PrivxClient(cfg)

        assert client._access_token == token_value


# ---------------------------------------------------------------------------
# Property 4: Error status propagation
# ---------------------------------------------------------------------------


class TestProperty4ErrorStatusPropagation:
    """Property 4: Error status propagation.

    For any HTTP error status code (4xx or 5xx) returned by the OAuth endpoint,
    the raised exception message SHALL contain the numeric status code.

    **Validates: Requirements 1.5**
    """

    @given(status_code=http_error_status)
    @settings(max_examples=100, deadline=None)
    def test_http_error_status_in_exception_message(self, status_code):
        """HTTP error status codes are included in the raised exception message."""
        from ansible.module_utils.six.moves.urllib.error import HTTPError
        from io import BytesIO

        cfg = PrivxClientConfig(
            base_url="https://privx.example.com",
            client_id="api-client-id",
            client_secret="api-client-secret",
            oauth_client_id="oauth-client-id",
            oauth_client_secret="oauth-client-secret",
            max_retries=0,
        )

        def fake_open_url(url, method, headers, data=None, **kwargs):
            raise HTTPError(
                url=url,
                code=status_code,
                msg=f"HTTP {status_code}",
                hdrs={"Content-Type": "application/json"},
                fp=BytesIO(json.dumps({"message": f"error {status_code}"}).encode()),
            )

        with patch(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            fake_open_url,
        ):
            with pytest.raises(
                (PrivxAuthError, PrivxRequestError, PrivxNotFoundError)
            ) as exc_info:
                PrivxClient(cfg)

        assert str(status_code) in str(exc_info.value)
