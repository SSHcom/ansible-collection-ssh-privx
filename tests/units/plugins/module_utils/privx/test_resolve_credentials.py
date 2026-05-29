"""Property-based tests for _resolve_oauth_credentials helper.

**Validates: Requirements 3.5**

Property 7: Environment variable fallback — For any set of credential values
stored in environment variables PRIVX_CLIENT_ID, PRIVX_CLIENT_SECRET,
PRIVX_OAUTH_CLIENT_ID, PRIVX_OAUTH_CLIENT_SECRET, when no explicit parameters
are provided, the resolved credentials SHALL equal the environment variable values.
"""

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from ansible_collections.sshcom.privx.plugins.module_utils.privx.client import (
    _resolve_oauth_credentials,
)

# Strategy for non-empty credential strings (env vars are always strings)
credential_text = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
    min_size=1,
    max_size=50,
)

# Strategy for optional credential values (None or non-empty string)
optional_credential = st.one_of(st.none(), credential_text)


@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    env_client_id=credential_text,
    env_client_secret=credential_text,
    env_oauth_client_id=credential_text,
    env_oauth_client_secret=credential_text,
)
def test_env_var_fallback_when_no_explicit_params(
    monkeypatch,
    env_client_id,
    env_client_secret,
    env_oauth_client_id,
    env_oauth_client_secret,
):
    """Property 7: When no explicit parameters are provided, resolved credentials
    SHALL equal the environment variable values.

    **Validates: Requirements 3.5**
    """
    monkeypatch.setenv("PRIVX_CLIENT_ID", env_client_id)
    monkeypatch.setenv("PRIVX_CLIENT_SECRET", env_client_secret)
    monkeypatch.setenv("PRIVX_OAUTH_CLIENT_ID", env_oauth_client_id)
    monkeypatch.setenv("PRIVX_OAUTH_CLIENT_SECRET", env_oauth_client_secret)

    result = _resolve_oauth_credentials()

    assert result == (
        env_client_id,
        env_client_secret,
        env_oauth_client_id,
        env_oauth_client_secret,
    )


@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    param_client_id=credential_text,
    param_client_secret=credential_text,
    param_oauth_client_id=credential_text,
    param_oauth_client_secret=credential_text,
    env_client_id=credential_text,
    env_client_secret=credential_text,
    env_oauth_client_id=credential_text,
    env_oauth_client_secret=credential_text,
)
def test_explicit_params_take_priority_over_env_vars(
    monkeypatch,
    param_client_id,
    param_client_secret,
    param_oauth_client_id,
    param_oauth_client_secret,
    env_client_id,
    env_client_secret,
    env_oauth_client_id,
    env_oauth_client_secret,
):
    """Explicit params take priority over env vars.

    **Validates: Requirements 3.5**
    """
    monkeypatch.setenv("PRIVX_CLIENT_ID", env_client_id)
    monkeypatch.setenv("PRIVX_CLIENT_SECRET", env_client_secret)
    monkeypatch.setenv("PRIVX_OAUTH_CLIENT_ID", env_oauth_client_id)
    monkeypatch.setenv("PRIVX_OAUTH_CLIENT_SECRET", env_oauth_client_secret)

    result = _resolve_oauth_credentials(
        client_id=param_client_id,
        client_secret=param_client_secret,
        oauth_client_id=param_oauth_client_id,
        oauth_client_secret=param_oauth_client_secret,
    )

    assert result == (
        param_client_id,
        param_client_secret,
        param_oauth_client_id,
        param_oauth_client_secret,
    )


@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    param_client_id=optional_credential,
    param_client_secret=optional_credential,
    param_oauth_client_id=optional_credential,
    param_oauth_client_secret=optional_credential,
    env_client_id=optional_credential,
    env_client_secret=optional_credential,
    env_oauth_client_id=optional_credential,
    env_oauth_client_secret=optional_credential,
)
def test_mixed_resolution_params_and_env_vars(
    monkeypatch,
    param_client_id,
    param_client_secret,
    param_oauth_client_id,
    param_oauth_client_secret,
    env_client_id,
    env_client_secret,
    env_oauth_client_id,
    env_oauth_client_secret,
):
    """Mixed: some from params, some from env vars. Each credential resolves
    independently — explicit param wins, then env var, then None.

    **Validates: Requirements 3.5**
    """
    # Set or unset env vars based on generated values
    env_mapping = {
        "PRIVX_CLIENT_ID": env_client_id,
        "PRIVX_CLIENT_SECRET": env_client_secret,
        "PRIVX_OAUTH_CLIENT_ID": env_oauth_client_id,
        "PRIVX_OAUTH_CLIENT_SECRET": env_oauth_client_secret,
    }
    for var_name, var_value in env_mapping.items():
        if var_value is not None:
            monkeypatch.setenv(var_name, var_value)
        else:
            monkeypatch.delenv(var_name, raising=False)

    result = _resolve_oauth_credentials(
        client_id=param_client_id,
        client_secret=param_client_secret,
        oauth_client_id=param_oauth_client_id,
        oauth_client_secret=param_oauth_client_secret,
    )

    # Each field should resolve: param if truthy, else env var, else None
    expected_client_id = param_client_id or env_client_id
    expected_client_secret = param_client_secret or env_client_secret
    expected_oauth_client_id = param_oauth_client_id or env_oauth_client_id
    expected_oauth_client_secret = param_oauth_client_secret or env_oauth_client_secret

    assert result == (
        expected_client_id,
        expected_client_secret,
        expected_oauth_client_id,
        expected_oauth_client_secret,
    )


def test_all_none_when_no_params_and_no_env_vars(monkeypatch):
    """When both params and env vars are None/empty, result is None for each field."""
    monkeypatch.delenv("PRIVX_CLIENT_ID", raising=False)
    monkeypatch.delenv("PRIVX_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("PRIVX_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("PRIVX_OAUTH_CLIENT_SECRET", raising=False)

    result = _resolve_oauth_credentials()

    assert result == (None, None, None, None)
