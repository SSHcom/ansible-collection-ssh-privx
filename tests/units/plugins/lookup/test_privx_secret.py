"""Unit tests for the PrivX lookup plugin."""

# GNU General Public License v3.0+

import pytest
from ansible.errors import AnsibleError

from ansible_collections.sshcom.privx.plugins.lookup.privx_secret import (
    LookupModule,
    _handle_privx_error,
)


class DummyClient:
    """Test double for PrivxClient."""

    def __init__(self, cfg, logger=None):
        """Store constructor arguments for assertions."""
        self.cfg = cfg
        self.logger = logger

    def get_secret(self, path):
        """Return a fixed secret payload."""
        return {"data": "secret-value"}


def test_lookup_returns_secret_value(monkeypatch):
    """Lookup should return the secret data in a single-item list."""
    captured = {}

    class FakeClient:
        """Capture config and return a known secret."""

        def __init__(self, cfg, logger=None):
            """Store constructor arguments for assertions."""
            captured["cfg"] = cfg
            captured["logger"] = logger

        def get_secret(self, path):
            """Return a fixed secret payload."""
            captured["path"] = path
            return {"data": "secret-value"}

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.lookup.privx_secret.PrivxClient",
        FakeClient,
    )

    lookup = LookupModule()
    result = lookup.run(
        ["example/path"],
        url="https://privx.example.com",
        token="jwt-token",
    )

    assert result == ["secret-value"]
    assert captured["path"] == "example/path"
    assert captured["cfg"].base_url == "https://privx.example.com"
    assert captured["cfg"].jwt_token == "jwt-token"
    assert captured["cfg"].validate_certs is True
    assert captured["logger"] is not None


def test_lookup_rejects_multiple_terms():
    """Lookup should require exactly one secret path."""
    lookup = LookupModule()

    with pytest.raises(AnsibleError, match="expects one secret path"):
        lookup.run(
            ["one", "two"],
            url="https://privx.example.com",
            token="jwt-token",
        )


@pytest.mark.parametrize(
    ("kwargs", "expected_match"),
    [
        ({}, "url parameter is required"),
        ({"token": "jwt-token"}, "url parameter is required"),
        ({"url": "", "token": "jwt-token"}, "url parameter is required"),
        ({"url": "https://privx.example.com"}, "Either 'token' or all OAuth credentials"),
        ({"url": "https://privx.example.com", "token": ""}, "Either 'token' or all OAuth credentials"),
    ],
)
def test_lookup_requires_credentials(kwargs, expected_match):
    """Lookup should require url and either token or OAuth credentials."""
    lookup = LookupModule()

    with pytest.raises(AnsibleError, match=expected_match):
        lookup.run(["example/path"], **kwargs)


def test_lookup_passes_validate_certs_to_config(monkeypatch):
    """Lookup should pass validate_certs to PrivxClientConfig."""
    captured = {}

    class FakeClient:
        """Capture config and return a known secret."""

        def __init__(self, cfg, logger=None):
            """Store constructor arguments for assertions."""
            captured["cfg"] = cfg

        def get_secret(self, path):
            """Return a fixed secret payload."""
            return {"data": "secret-value"}

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.lookup.privx_secret.PrivxClient",
        FakeClient,
    )

    lookup = LookupModule()
    result = lookup.run(
        ["example/path"],
        url="https://privx.example.com",
        token="jwt-token",
        validate_certs=False,
    )

    assert result == ["secret-value"]
    assert captured["cfg"].validate_certs is False


def test_handle_privx_error_maps_not_found():
    """Not found errors should be translated to a user-friendly AnsibleError."""
    with pytest.raises(AnsibleError, match="PrivX secret not found: missing/path"):
        _handle_privx_error("missing/path", Exception("resource not found"))


def test_handle_privx_error_maps_generic_error():
    """Generic client errors should be translated to a generic lookup failure."""
    with pytest.raises(AnsibleError, match="PrivX lookup failed: boom"):
        _handle_privx_error("example/path", Exception("boom"))


def test_lookup_raises_malformed_error_when_data_missing(monkeypatch):
    """Lookup should fail if the secret payload does not contain data."""

    class FakeClient:
        """Return a malformed secret payload."""

        def __init__(self, cfg, logger=None):
            """Accept constructor arguments."""
            self.cfg = cfg
            self.logger = logger

        def get_secret(self, path):
            """Return malformed payload without data."""
            return {"value": "secret-value"}

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.lookup.privx_secret.PrivxClient",
        FakeClient,
    )

    lookup = LookupModule()

    with pytest.raises(AnsibleError, match="PrivX secret malformed: example/path"):
        lookup.run(
            ["example/path"],
            url="https://privx.example.com",
            token="jwt-token",
        )


def test_lookup_maps_client_not_found_error(monkeypatch):
    """Lookup should translate client not found errors via _handle_privx_error."""

    class FakeClient:
        """Raise a not found style error from get_secret."""

        def __init__(self, cfg, logger=None):
            """Accept constructor arguments."""
            self.cfg = cfg
            self.logger = logger

        def get_secret(self, path):
            """Raise a not found style exception."""
            raise Exception("secret not found")

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.lookup.privx_secret.PrivxClient",
        FakeClient,
    )

    lookup = LookupModule()

    with pytest.raises(AnsibleError, match="PrivX secret not found: missing/path"):
        lookup.run(
            ["missing/path"],
            url="https://privx.example.com",
            token="jwt-token",
        )


# --- OAuth path tests ---


def test_lookup_oauth_kwargs_constructs_config_with_oauth_fields(monkeypatch):
    """When token is not provided but OAuth kwargs are given, PrivxClientConfig should use OAuth fields."""
    captured = {}

    class FakeClient:
        """Capture config and return a known secret."""

        def __init__(self, cfg, logger=None):
            captured["cfg"] = cfg

        def get_secret(self, path):
            return {"data": "oauth-secret"}

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.lookup.privx_secret.PrivxClient",
        FakeClient,
    )

    lookup = LookupModule()
    result = lookup.run(
        ["example/path"],
        url="https://privx.example.com",
        client_id="my-client-id",
        client_secret="my-client-secret",
        oauth_client_id="my-oauth-id",
        oauth_client_secret="my-oauth-secret",
    )

    assert result == ["oauth-secret"]
    cfg = captured["cfg"]
    assert cfg.base_url == "https://privx.example.com"
    assert cfg.jwt_token is None
    assert cfg.client_id == "my-client-id"
    assert cfg.client_secret == "my-client-secret"
    assert cfg.oauth_client_id == "my-oauth-id"
    assert cfg.oauth_client_secret == "my-oauth-secret"
    assert cfg.validate_certs is True


def test_lookup_oauth_env_var_fallback(monkeypatch):
    """When neither token nor OAuth kwargs are provided, env vars should be used."""
    captured = {}

    class FakeClient:
        """Capture config and return a known secret."""

        def __init__(self, cfg, logger=None):
            captured["cfg"] = cfg

        def get_secret(self, path):
            return {"data": "env-secret"}

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.lookup.privx_secret.PrivxClient",
        FakeClient,
    )
    monkeypatch.setenv("PRIVX_CLIENT_ID", "env-client-id")
    monkeypatch.setenv("PRIVX_CLIENT_SECRET", "env-client-secret")
    monkeypatch.setenv("PRIVX_OAUTH_CLIENT_ID", "env-oauth-id")
    monkeypatch.setenv("PRIVX_OAUTH_CLIENT_SECRET", "env-oauth-secret")

    lookup = LookupModule()
    result = lookup.run(
        ["example/path"],
        url="https://privx.example.com",
    )

    assert result == ["env-secret"]
    cfg = captured["cfg"]
    assert cfg.jwt_token is None
    assert cfg.client_id == "env-client-id"
    assert cfg.client_secret == "env-client-secret"
    assert cfg.oauth_client_id == "env-oauth-id"
    assert cfg.oauth_client_secret == "env-oauth-secret"


def test_lookup_oauth_kwargs_override_env_vars(monkeypatch):
    """Explicit kwargs should take priority over environment variables."""
    captured = {}

    class FakeClient:
        """Capture config and return a known secret."""

        def __init__(self, cfg, logger=None):
            captured["cfg"] = cfg

        def get_secret(self, path):
            return {"data": "override-secret"}

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.lookup.privx_secret.PrivxClient",
        FakeClient,
    )
    monkeypatch.setenv("PRIVX_CLIENT_ID", "env-client-id")
    monkeypatch.setenv("PRIVX_CLIENT_SECRET", "env-client-secret")
    monkeypatch.setenv("PRIVX_OAUTH_CLIENT_ID", "env-oauth-id")
    monkeypatch.setenv("PRIVX_OAUTH_CLIENT_SECRET", "env-oauth-secret")

    lookup = LookupModule()
    result = lookup.run(
        ["example/path"],
        url="https://privx.example.com",
        client_id="kwarg-client-id",
        client_secret="kwarg-client-secret",
        oauth_client_id="kwarg-oauth-id",
        oauth_client_secret="kwarg-oauth-secret",
    )

    assert result == ["override-secret"]
    cfg = captured["cfg"]
    assert cfg.client_id == "kwarg-client-id"
    assert cfg.client_secret == "kwarg-client-secret"
    assert cfg.oauth_client_id == "kwarg-oauth-id"
    assert cfg.oauth_client_secret == "kwarg-oauth-secret"


def test_lookup_error_no_credentials_at_all(monkeypatch):
    """When no token, no OAuth kwargs, and no env vars are set, an error should be raised."""
    # Ensure env vars are not set
    monkeypatch.delenv("PRIVX_CLIENT_ID", raising=False)
    monkeypatch.delenv("PRIVX_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("PRIVX_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("PRIVX_OAUTH_CLIENT_SECRET", raising=False)

    lookup = LookupModule()

    with pytest.raises(AnsibleError, match="Either 'token' or all OAuth credentials"):
        lookup.run(
            ["example/path"],
            url="https://privx.example.com",
        )


def test_lookup_backward_compat_jwt_token(monkeypatch):
    """Existing url + token invocations should work unchanged (backward compatibility)."""
    captured = {}

    class FakeClient:
        """Capture config and return a known secret."""

        def __init__(self, cfg, logger=None):
            captured["cfg"] = cfg

        def get_secret(self, path):
            return {"data": "jwt-secret"}

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.lookup.privx_secret.PrivxClient",
        FakeClient,
    )

    lookup = LookupModule()
    result = lookup.run(
        ["example/path"],
        url="https://privx.example.com",
        token="my-jwt-token",
    )

    assert result == ["jwt-secret"]
    cfg = captured["cfg"]
    assert cfg.base_url == "https://privx.example.com"
    assert cfg.jwt_token == "my-jwt-token"
    assert cfg.client_id is None
    assert cfg.client_secret is None
    assert cfg.oauth_client_id is None
    assert cfg.oauth_client_secret is None


def test_lookup_oauth_passes_validate_certs_false(monkeypatch):
    """OAuth path should pass validate_certs=False to PrivxClientConfig."""
    captured = {}

    class FakeClient:
        """Capture config and return a known secret."""

        def __init__(self, cfg, logger=None):
            captured["cfg"] = cfg

        def get_secret(self, path):
            return {"data": "secret"}

    monkeypatch.setattr(
        "ansible_collections.sshcom.privx.plugins.lookup.privx_secret.PrivxClient",
        FakeClient,
    )

    lookup = LookupModule()
    result = lookup.run(
        ["example/path"],
        url="https://privx.example.com",
        client_id="cid",
        client_secret="csec",
        oauth_client_id="oid",
        oauth_client_secret="osec",
        validate_certs=False,
    )

    assert result == ["secret"]
    assert captured["cfg"].validate_certs is False


def test_lookup_partial_oauth_credentials_error(monkeypatch):
    """When only some OAuth credentials are provided, an error should be raised."""
    monkeypatch.delenv("PRIVX_CLIENT_ID", raising=False)
    monkeypatch.delenv("PRIVX_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("PRIVX_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("PRIVX_OAUTH_CLIENT_SECRET", raising=False)

    lookup = LookupModule()

    with pytest.raises(AnsibleError, match="Either 'token' or all OAuth credentials"):
        lookup.run(
            ["example/path"],
            url="https://privx.example.com",
            client_id="my-client-id",
            # Missing client_secret, oauth_client_id, oauth_client_secret
        )
