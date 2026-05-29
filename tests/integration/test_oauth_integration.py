"""Integration tests for the full OAuth client credentials flow.

These tests exercise the complete path through PrivxClient initialization
using OAuth credentials, verifying the full flow:
  token request → token response → API call with bearer token

Unlike unit tests that mock intermediate methods, these tests monkeypatch
only the lowest-level HTTP function (open_url) to simulate the integration
flow end-to-end.

Feature: oauth-client-credentials
"""

import io
import json

import pytest

from ansible_collections.sshcom.privx.plugins.module_utils.privx.client import (
    PrivxClient,
    PrivxClientConfig,
    PrivxRequestError,
)
from ansible.module_utils.six.moves.urllib.error import HTTPError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeHTTPResponse:
    """Minimal HTTP response object compatible with open_url return value."""

    def __init__(self, body, status=200, content_type="application/json"):
        if isinstance(body, dict):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        elif body is None:
            body = b""

        self._body = body
        self.status = status
        self.headers = {"Content-Type": content_type}

    def read(self, *args):
        return self._body


def make_http_error(status, body=None):
    """Create an HTTPError that mimics urllib behavior."""
    if body is None:
        body = json.dumps({"error": f"HTTP {status}"}).encode("utf-8")
    elif isinstance(body, dict):
        body = json.dumps(body).encode("utf-8")
    elif isinstance(body, str):
        body = body.encode("utf-8")

    fp = io.BytesIO(body)
    err = HTTPError(
        url="https://privx.example.com/auth/api/v1/oauth/token",
        code=status,
        msg=f"HTTP Error {status}",
        hdrs={"Content-Type": "application/json"},
        fp=fp,
    )
    return err


# ---------------------------------------------------------------------------
# Test 7.1: Full OAuth flow integration
# ---------------------------------------------------------------------------


class TestFullOAuthFlowIntegration:
    """Integration test exercising the full OAuth flow:
    PrivxClient.__init__ → oauth_token → get_secret.
    """

    def test_full_flow_token_request_then_api_call(self, monkeypatch):
        """Full OAuth flow: init obtains token, then get_secret uses bearer token.

        This test verifies:
        1. Client initialization triggers a POST to the OAuth token endpoint
        2. The token response access_token is stored
        3. A subsequent get_secret call uses the obtained bearer token
        4. The API call returns the expected secret data
        """
        call_log = []

        token_response = {
            "access_token": "integration-test-token-abc123",
            "token_type": "bearer",
            "expires_in": 3600,
        }

        secret_response = {
            "name": "test/secret",
            "data": "super-secret-value",
        }

        def fake_open_url(url, method="GET", headers=None, data=None, **kwargs):
            call_log.append({
                "url": url,
                "method": method,
                "headers": headers or {},
                "data": data,
                "kwargs": kwargs,
            })

            if "/auth/api/v1/oauth/token" in url:
                return FakeHTTPResponse(token_response)
            elif "/vault/api/v1/secrets/" in url:
                return FakeHTTPResponse(secret_response)
            else:
                raise AssertionError(f"Unexpected URL: {url}")

        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            fake_open_url,
        )

        # Create config with OAuth credentials
        cfg = PrivxClientConfig(
            base_url="https://privx.example.com",
            client_id="my-api-client-id",
            client_secret="my-api-client-secret",
            oauth_client_id="my-oauth-client-id",
            oauth_client_secret="my-oauth-client-secret",
        )

        # Initialize client — this should call the OAuth token endpoint
        client = PrivxClient(cfg)

        # Verify the token request was made
        assert len(call_log) == 1
        token_req = call_log[0]
        assert token_req["url"] == "https://privx.example.com/auth/api/v1/oauth/token"
        assert token_req["method"] == "POST"
        assert "Basic" in token_req["headers"]["Authorization"]
        assert token_req["headers"]["Content-Type"] == "application/x-www-form-urlencoded"

        # Now call get_secret — this should use the obtained bearer token
        result = client.get_secret("test/secret")

        # Verify the API call was made with the bearer token
        assert len(call_log) == 2
        api_req = call_log[1]
        assert "/vault/api/v1/secrets/test/secret" in api_req["url"]
        assert api_req["method"] == "GET"
        assert api_req["headers"]["Authorization"] == "Bearer integration-test-token-abc123"

        # Verify the secret data is returned correctly
        assert result == secret_response
        assert result["data"] == "super-secret-value"

    def test_full_flow_with_special_characters_in_credentials(self, monkeypatch):
        """OAuth flow handles special characters in credentials correctly."""
        call_log = []

        def fake_open_url(url, method="GET", headers=None, data=None, **kwargs):
            call_log.append({
                "url": url,
                "method": method,
                "headers": headers or {},
                "data": data,
            })

            if "/auth/api/v1/oauth/token" in url:
                return FakeHTTPResponse({"access_token": "token-with-specials"})
            elif "/vault/api/v1/secrets/" in url:
                return FakeHTTPResponse({"data": "secret-data"})
            else:
                raise AssertionError(f"Unexpected URL: {url}")

        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            fake_open_url,
        )

        cfg = PrivxClientConfig(
            base_url="https://privx.example.com",
            client_id="user&name=special",
            client_secret="pass word+extra",
            oauth_client_id="oauth-id-with-chars",
            oauth_client_secret="oauth/secret=value",
        )

        client = PrivxClient(cfg)
        result = client.get_secret("my/secret/path")

        # Verify both calls were made successfully
        assert len(call_log) == 2
        assert result["data"] == "secret-data"

        # Verify the form body contains properly encoded credentials
        from urllib.parse import parse_qs
        token_data = call_log[0]["data"].decode("utf-8")
        parsed = parse_qs(token_data)
        assert parsed["username"] == ["user&name=special"]
        assert parsed["password"] == ["pass word+extra"]

    def test_full_flow_validate_certs_passed_through(self, monkeypatch):
        """validate_certs setting is passed to both token and API requests."""
        captured_kwargs = []

        def fake_open_url(url, method="GET", headers=None, data=None, **kwargs):
            captured_kwargs.append(kwargs)

            if "/auth/api/v1/oauth/token" in url:
                return FakeHTTPResponse({"access_token": "test-token"})
            elif "/vault/api/v1/secrets/" in url:
                return FakeHTTPResponse({"data": "secret"})
            else:
                raise AssertionError(f"Unexpected URL: {url}")

        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            fake_open_url,
        )

        cfg = PrivxClientConfig(
            base_url="https://privx.example.com",
            client_id="cid",
            client_secret="csec",
            oauth_client_id="oid",
            oauth_client_secret="osec",
            validate_certs=False,
        )

        client = PrivxClient(cfg)
        client.get_secret("test/path")

        # Both calls should have validate_certs=False
        assert len(captured_kwargs) == 2
        assert captured_kwargs[0]["validate_certs"] is False
        assert captured_kwargs[1]["validate_certs"] is False


# ---------------------------------------------------------------------------
# Test 7.2: Retry behavior on 503 from OAuth endpoint
# ---------------------------------------------------------------------------


class TestOAuthRetryBehavior:
    """Integration tests verifying retry behavior on transient errors."""

    def test_retry_on_503_then_success(self, monkeypatch):
        """Client retries on 503 from OAuth endpoint and eventually succeeds."""
        call_count = [0]

        def fake_open_url(url, method="GET", headers=None, data=None, **kwargs):
            if "/auth/api/v1/oauth/token" in url:
                call_count[0] += 1
                if call_count[0] == 1:
                    # First call: return 503
                    raise make_http_error(503, {"error": "Service Unavailable"})
                else:
                    # Second call: succeed
                    return FakeHTTPResponse({"access_token": "retry-success-token"})
            elif "/vault/api/v1/secrets/" in url:
                return FakeHTTPResponse({"data": "secret-after-retry"})
            else:
                raise AssertionError(f"Unexpected URL: {url}")

        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            fake_open_url,
        )
        # Use minimal retry delay to speed up the test
        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.time.sleep",
            lambda _: None,
        )

        cfg = PrivxClientConfig(
            base_url="https://privx.example.com",
            client_id="cid",
            client_secret="csec",
            oauth_client_id="oid",
            oauth_client_secret="osec",
            max_retries=2,
            retry_delay=0.01,
        )

        client = PrivxClient(cfg)
        result = client.get_secret("test/secret")

        # Verify retry happened: 2 calls to token endpoint (1 fail + 1 success)
        assert call_count[0] == 2
        assert result["data"] == "secret-after-retry"

    def test_max_retries_exhausted_raises_error(self, monkeypatch):
        """After max retries are exhausted on 503, the error is raised."""
        call_count = [0]

        def fake_open_url(url, method="GET", headers=None, data=None, **kwargs):
            if "/auth/api/v1/oauth/token" in url:
                call_count[0] += 1
                # Always return 503
                raise make_http_error(503, {"error": "Service Unavailable"})
            else:
                raise AssertionError(f"Unexpected URL: {url}")

        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            fake_open_url,
        )
        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.time.sleep",
            lambda _: None,
        )

        cfg = PrivxClientConfig(
            base_url="https://privx.example.com",
            client_id="cid",
            client_secret="csec",
            oauth_client_id="oid",
            oauth_client_secret="osec",
            max_retries=2,
            retry_delay=0.01,
        )

        with pytest.raises(PrivxRequestError, match="Service Unavailable|503"):
            PrivxClient(cfg)

        # Should have attempted max_retries + 1 = 3 total calls
        assert call_count[0] == 3

    def test_retry_on_multiple_503_then_success(self, monkeypatch):
        """Client retries multiple times on 503 before succeeding."""
        call_count = [0]

        def fake_open_url(url, method="GET", headers=None, data=None, **kwargs):
            if "/auth/api/v1/oauth/token" in url:
                call_count[0] += 1
                if call_count[0] <= 2:
                    # First two calls: return 503
                    raise make_http_error(503, {"error": "Service Unavailable"})
                else:
                    # Third call: succeed
                    return FakeHTTPResponse({"access_token": "eventual-token"})
            elif "/vault/api/v1/secrets/" in url:
                return FakeHTTPResponse({"data": "eventual-secret"})
            else:
                raise AssertionError(f"Unexpected URL: {url}")

        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            fake_open_url,
        )
        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.time.sleep",
            lambda _: None,
        )

        cfg = PrivxClientConfig(
            base_url="https://privx.example.com",
            client_id="cid",
            client_secret="csec",
            oauth_client_id="oid",
            oauth_client_secret="osec",
            max_retries=3,
            retry_delay=0.01,
        )

        client = PrivxClient(cfg)
        result = client.get_secret("test/secret")

        assert call_count[0] == 3
        assert result["data"] == "eventual-secret"

    def test_no_retry_on_401(self, monkeypatch):
        """Client does NOT retry on 401 (authentication failure)."""
        call_count = [0]

        def fake_open_url(url, method="GET", headers=None, data=None, **kwargs):
            if "/auth/api/v1/oauth/token" in url:
                call_count[0] += 1
                raise make_http_error(401, {"error": "invalid_client"})
            else:
                raise AssertionError(f"Unexpected URL: {url}")

        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.open_url",
            fake_open_url,
        )
        monkeypatch.setattr(
            "ansible_collections.sshcom.privx.plugins.module_utils.privx.client.time.sleep",
            lambda _: None,
        )

        cfg = PrivxClientConfig(
            base_url="https://privx.example.com",
            client_id="cid",
            client_secret="csec",
            oauth_client_id="oid",
            oauth_client_secret="osec",
            max_retries=2,
            retry_delay=0.01,
        )

        from ansible_collections.sshcom.privx.plugins.module_utils.privx.client import PrivxAuthError
        with pytest.raises(PrivxAuthError):
            PrivxClient(cfg)

        # 401 is not retried — only 1 attempt
        assert call_count[0] == 1
