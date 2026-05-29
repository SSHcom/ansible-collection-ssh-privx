"""Unit tests for the PrivX module."""

# GNU General Public License v3.0+

import pytest

from ansible_collections.sshcom.privx.plugins.modules import privx_secret_info


class AnsibleExitJson(BaseException):
    """Raised when the fake module exits successfully."""

    def __init__(self, result):
        """Store module result."""
        self.result = result


class AnsibleFailJson(BaseException):
    """Raised when the fake module fails."""

    def __init__(self, result):
        """Store module result."""
        self.result = result


class FakeModule:
    """Minimal fake AnsibleModule."""

    def __init__(self, params):
        """Store module params."""
        self.params = params

    def exit_json(self, **kwargs):
        """Simulate successful module exit."""
        raise AnsibleExitJson(kwargs)

    def fail_json(self, **kwargs):
        """Simulate failed module exit."""
        raise AnsibleFailJson(kwargs)


def test_run_module_returns_secret(monkeypatch):
    """Module should return secret data on success."""
    captured = {}

    def fake_ansible_module(**kwargs):
        """Return fake module with predefined params."""
        return FakeModule(
            {
                "url": "https://privx.example.com",
                "token": "jwt-token",
                "path": "example/path",
                "validate_certs": True,
                "client_id": None,
                "client_secret": None,
                "oauth_client_id": None,
                "oauth_client_secret": None,
            }
        )

    class FakeClient:
        """Capture config and return a fixed secret."""

        def __init__(self, cfg, logger=None):
            """Store constructor arguments for assertions."""
            captured["cfg"] = cfg
            captured["logger"] = logger

        def get_secret(self, path):
            """Return a fixed secret payload."""
            captured["path"] = path
            return {"data": "secret-value"}

    monkeypatch.setattr(
        privx_secret_info,
        "AnsibleModule",
        fake_ansible_module,
    )
    monkeypatch.setattr(
        privx_secret_info,
        "PrivxClient",
        FakeClient,
    )

    with pytest.raises(AnsibleExitJson) as exc:
        privx_secret_info.run_module()

    result = exc.value.result

    assert result["changed"] is False
    assert result["secret"] == {"data": "secret-value"}
    assert captured["path"] == "example/path"
    assert captured["cfg"].base_url == "https://privx.example.com"
    assert captured["cfg"].jwt_token == "jwt-token"
    assert captured["cfg"].validate_certs is True
    assert captured["logger"] is None


def test_run_module_passes_validate_certs(monkeypatch):
    """Module should pass validate_certs into client config."""
    captured = {}

    def fake_ansible_module(**kwargs):
        """Return fake module with predefined params."""
        return FakeModule(
            {
                "url": "https://privx.example.com",
                "token": "jwt-token",
                "path": "example/path",
                "validate_certs": False,
                "client_id": None,
                "client_secret": None,
                "oauth_client_id": None,
                "oauth_client_secret": None,
            }
        )

    class FakeClient:
        """Capture config and return a fixed secret."""

        def __init__(self, cfg, logger=None):
            """Store constructor arguments for assertions."""
            captured["cfg"] = cfg

        def get_secret(self, path):
            """Return a fixed secret payload."""
            return {"data": "secret-value"}

    monkeypatch.setattr(
        privx_secret_info,
        "AnsibleModule",
        fake_ansible_module,
    )
    monkeypatch.setattr(
        privx_secret_info,
        "PrivxClient",
        FakeClient,
    )

    with pytest.raises(AnsibleExitJson):
        privx_secret_info.run_module()

    assert captured["cfg"].validate_certs is False


def test_run_module_fails_when_client_raises(monkeypatch):
    """Module should fail_json when client raises an exception."""

    def fake_ansible_module(**kwargs):
        """Return fake module with predefined params."""
        return FakeModule(
            {
                "url": "https://privx.example.com",
                "token": "jwt-token",
                "path": "example/path",
                "validate_certs": True,
                "client_id": None,
                "client_secret": None,
                "oauth_client_id": None,
                "oauth_client_secret": None,
            }
        )

    class FakeClient:
        """Raise an error from get_secret."""

        def __init__(self, cfg, logger=None):
            """Accept constructor arguments."""
            self.cfg = cfg
            self.logger = logger

        def get_secret(self, path):
            """Raise a client error."""
            raise Exception("boom")

    monkeypatch.setattr(
        privx_secret_info,
        "AnsibleModule",
        fake_ansible_module,
    )
    monkeypatch.setattr(
        privx_secret_info,
        "PrivxClient",
        FakeClient,
    )

    with pytest.raises(AnsibleFailJson) as exc:
        privx_secret_info.run_module()

    result = exc.value.result
    assert result["msg"] == "boom"


def test_run_module_constructs_client_with_config_object(monkeypatch):
    """Module should construct PrivxClient with PrivxClientConfig."""

    def fake_ansible_module(**kwargs):
        """Return fake module with predefined params."""
        return FakeModule(
            {
                "url": "https://privx.example.com",
                "token": "jwt-token",
                "path": "example/path",
                "validate_certs": True,
                "client_id": None,
                "client_secret": None,
                "oauth_client_id": None,
                "oauth_client_secret": None,
            }
        )

    class FakeClient:
        """Assert constructor argument types."""

        def __init__(self, cfg, logger=None):
            """Validate that cfg is a PrivxClientConfig instance."""
            assert isinstance(cfg, privx_secret_info.PrivxClientConfig)
            self.cfg = cfg
            self.logger = logger

        def get_secret(self, path):
            """Return a fixed secret payload."""
            return {"data": "secret-value"}

    monkeypatch.setattr(
        privx_secret_info,
        "AnsibleModule",
        fake_ansible_module,
    )
    monkeypatch.setattr(
        privx_secret_info,
        "PrivxClient",
        FakeClient,
    )

    with pytest.raises(AnsibleExitJson):
        privx_secret_info.run_module()


def test_run_module_oauth_path(monkeypatch):
    """Module should use OAuth credentials when token is not provided."""
    captured = {}

    def fake_ansible_module(**kwargs):
        """Return fake module with OAuth params."""
        return FakeModule(
            {
                "url": "https://privx.example.com",
                "token": None,
                "path": "example/path",
                "validate_certs": True,
                "client_id": "my-client-id",
                "client_secret": "my-client-secret",
                "oauth_client_id": "my-oauth-id",
                "oauth_client_secret": "my-oauth-secret",
            }
        )

    class FakeClient:
        """Capture config and return a fixed secret."""

        def __init__(self, cfg, logger=None):
            """Store constructor arguments for assertions."""
            captured["cfg"] = cfg

        def get_secret(self, path):
            """Return a fixed secret payload."""
            return {"data": "oauth-secret-value"}

    monkeypatch.setattr(
        privx_secret_info,
        "AnsibleModule",
        fake_ansible_module,
    )
    monkeypatch.setattr(
        privx_secret_info,
        "PrivxClient",
        FakeClient,
    )

    with pytest.raises(AnsibleExitJson) as exc:
        privx_secret_info.run_module()

    result = exc.value.result

    assert result["changed"] is False
    assert result["secret"] == {"data": "oauth-secret-value"}
    assert captured["cfg"].jwt_token is None
    assert captured["cfg"].client_id == "my-client-id"
    assert captured["cfg"].client_secret == "my-client-secret"
    assert captured["cfg"].oauth_client_id == "my-oauth-id"
    assert captured["cfg"].oauth_client_secret == "my-oauth-secret"
    assert captured["cfg"].base_url == "https://privx.example.com"
    assert captured["cfg"].validate_certs is True


def test_run_module_oauth_env_var_fallback(monkeypatch):
    """Module should fall back to environment variables for OAuth credentials."""
    captured = {}

    def fake_ansible_module(**kwargs):
        """Return fake module with no token and no OAuth params."""
        return FakeModule(
            {
                "url": "https://privx.example.com",
                "token": None,
                "path": "example/path",
                "validate_certs": True,
                "client_id": None,
                "client_secret": None,
                "oauth_client_id": None,
                "oauth_client_secret": None,
            }
        )

    class FakeClient:
        """Capture config and return a fixed secret."""

        def __init__(self, cfg, logger=None):
            """Store constructor arguments for assertions."""
            captured["cfg"] = cfg

        def get_secret(self, path):
            """Return a fixed secret payload."""
            return {"data": "env-secret-value"}

    monkeypatch.setattr(
        privx_secret_info,
        "AnsibleModule",
        fake_ansible_module,
    )
    monkeypatch.setattr(
        privx_secret_info,
        "PrivxClient",
        FakeClient,
    )

    # Set environment variables
    monkeypatch.setenv("PRIVX_CLIENT_ID", "env-client-id")
    monkeypatch.setenv("PRIVX_CLIENT_SECRET", "env-client-secret")
    monkeypatch.setenv("PRIVX_OAUTH_CLIENT_ID", "env-oauth-id")
    monkeypatch.setenv("PRIVX_OAUTH_CLIENT_SECRET", "env-oauth-secret")

    with pytest.raises(AnsibleExitJson) as exc:
        privx_secret_info.run_module()

    result = exc.value.result

    assert result["changed"] is False
    assert result["secret"] == {"data": "env-secret-value"}
    assert captured["cfg"].jwt_token is None
    assert captured["cfg"].client_id == "env-client-id"
    assert captured["cfg"].client_secret == "env-client-secret"
    assert captured["cfg"].oauth_client_id == "env-oauth-id"
    assert captured["cfg"].oauth_client_secret == "env-oauth-secret"


def test_run_module_fails_no_credentials(monkeypatch):
    """Module should fail_json when no token and no OAuth credentials are provided."""

    def fake_ansible_module(**kwargs):
        """Return fake module with no credentials."""
        return FakeModule(
            {
                "url": "https://privx.example.com",
                "token": None,
                "path": "example/path",
                "validate_certs": True,
                "client_id": None,
                "client_secret": None,
                "oauth_client_id": None,
                "oauth_client_secret": None,
            }
        )

    monkeypatch.setattr(
        privx_secret_info,
        "AnsibleModule",
        fake_ansible_module,
    )

    # Ensure no env vars are set
    monkeypatch.delenv("PRIVX_CLIENT_ID", raising=False)
    monkeypatch.delenv("PRIVX_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("PRIVX_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("PRIVX_OAUTH_CLIENT_SECRET", raising=False)

    with pytest.raises(AnsibleFailJson) as exc:
        privx_secret_info.run_module()

    result = exc.value.result
    assert "token" in result["msg"].lower() or "oauth" in result["msg"].lower()


def test_run_module_fails_partial_oauth_credentials(monkeypatch):
    """Module should fail_json when only partial OAuth credentials are provided."""

    def fake_ansible_module(**kwargs):
        """Return fake module with partial OAuth params."""
        return FakeModule(
            {
                "url": "https://privx.example.com",
                "token": None,
                "path": "example/path",
                "validate_certs": True,
                "client_id": "my-client-id",
                "client_secret": None,
                "oauth_client_id": None,
                "oauth_client_secret": None,
            }
        )

    monkeypatch.setattr(
        privx_secret_info,
        "AnsibleModule",
        fake_ansible_module,
    )

    # Ensure no env vars are set
    monkeypatch.delenv("PRIVX_CLIENT_ID", raising=False)
    monkeypatch.delenv("PRIVX_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("PRIVX_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("PRIVX_OAUTH_CLIENT_SECRET", raising=False)

    with pytest.raises(AnsibleFailJson) as exc:
        privx_secret_info.run_module()

    result = exc.value.result
    assert "oauth" in result["msg"].lower() or "token" in result["msg"].lower()


def test_run_module_jwt_takes_priority_over_oauth(monkeypatch):
    """Module should use JWT when both token and OAuth credentials are provided."""
    captured = {}

    def fake_ansible_module(**kwargs):
        """Return fake module with both JWT and OAuth params."""
        return FakeModule(
            {
                "url": "https://privx.example.com",
                "token": "jwt-token",
                "path": "example/path",
                "validate_certs": True,
                "client_id": "my-client-id",
                "client_secret": "my-client-secret",
                "oauth_client_id": "my-oauth-id",
                "oauth_client_secret": "my-oauth-secret",
            }
        )

    class FakeClient:
        """Capture config and return a fixed secret."""

        def __init__(self, cfg, logger=None):
            """Store constructor arguments for assertions."""
            captured["cfg"] = cfg

        def get_secret(self, path):
            """Return a fixed secret payload."""
            return {"data": "jwt-secret-value"}

    monkeypatch.setattr(
        privx_secret_info,
        "AnsibleModule",
        fake_ansible_module,
    )
    monkeypatch.setattr(
        privx_secret_info,
        "PrivxClient",
        FakeClient,
    )

    with pytest.raises(AnsibleExitJson) as exc:
        privx_secret_info.run_module()

    result = exc.value.result

    assert result["secret"] == {"data": "jwt-secret-value"}
    # JWT should be used, OAuth fields should not be set
    assert captured["cfg"].jwt_token == "jwt-token"
    assert captured["cfg"].client_id is None
    assert captured["cfg"].client_secret is None
    assert captured["cfg"].oauth_client_id is None
    assert captured["cfg"].oauth_client_secret is None


def test_run_module_oauth_params_override_env_vars(monkeypatch):
    """Module should prefer explicit params over environment variables."""
    captured = {}

    def fake_ansible_module(**kwargs):
        """Return fake module with explicit OAuth params."""
        return FakeModule(
            {
                "url": "https://privx.example.com",
                "token": None,
                "path": "example/path",
                "validate_certs": True,
                "client_id": "param-client-id",
                "client_secret": "param-client-secret",
                "oauth_client_id": "param-oauth-id",
                "oauth_client_secret": "param-oauth-secret",
            }
        )

    class FakeClient:
        """Capture config and return a fixed secret."""

        def __init__(self, cfg, logger=None):
            """Store constructor arguments for assertions."""
            captured["cfg"] = cfg

        def get_secret(self, path):
            """Return a fixed secret payload."""
            return {"data": "param-secret-value"}

    monkeypatch.setattr(
        privx_secret_info,
        "AnsibleModule",
        fake_ansible_module,
    )
    monkeypatch.setattr(
        privx_secret_info,
        "PrivxClient",
        FakeClient,
    )

    # Set environment variables that should be overridden
    monkeypatch.setenv("PRIVX_CLIENT_ID", "env-client-id")
    monkeypatch.setenv("PRIVX_CLIENT_SECRET", "env-client-secret")
    monkeypatch.setenv("PRIVX_OAUTH_CLIENT_ID", "env-oauth-id")
    monkeypatch.setenv("PRIVX_OAUTH_CLIENT_SECRET", "env-oauth-secret")

    with pytest.raises(AnsibleExitJson) as exc:
        privx_secret_info.run_module()

    result = exc.value.result

    assert result["secret"] == {"data": "param-secret-value"}
    # Explicit params should take priority over env vars
    assert captured["cfg"].client_id == "param-client-id"
    assert captured["cfg"].client_secret == "param-client-secret"
    assert captured["cfg"].oauth_client_id == "param-oauth-id"
    assert captured["cfg"].oauth_client_secret == "param-oauth-secret"
