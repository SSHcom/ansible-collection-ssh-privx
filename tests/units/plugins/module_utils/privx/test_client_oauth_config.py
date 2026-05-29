"""Property-based tests for PrivxClientConfig OAuth credential validation.

Feature: oauth-client-credentials
"""

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ansible_collections.sshcom.privx.plugins.module_utils.privx.client import (
    PrivxClientConfig,
    _mask_token,
)


# Strategy for non-empty strings (valid credential values)
non_empty_text = st.text(
    alphabet=st.characters(categories=("L", "N", "P", "S")),
    min_size=1,
    max_size=100,
)

# Strategy for empty-or-None values (missing credentials)
missing_value = st.sampled_from([None, ""])


class TestProperty6CredentialCompleteness:
    """Property 6: Auth method selection — credential completeness.

    For any PrivxClientConfig where jwt_token is None and client_id and
    client_secret are non-empty, if oauth_client_id or oauth_client_secret
    is missing then config validation SHALL raise an error listing the
    missing credentials.

    **Validates: Requirements 2.4, 5.4**
    """

    @given(
        client_id=non_empty_text,
        client_secret=non_empty_text,
        oauth_client_id=missing_value,
        oauth_client_secret=non_empty_text,
    )
    @settings(max_examples=100)
    def test_missing_oauth_client_id_raises_error(
        self, client_id, client_secret, oauth_client_id, oauth_client_secret
    ):
        """When client_id and client_secret are set but oauth_client_id is missing,
        validation raises ValueError listing oauth_client_id."""
        with pytest.raises(ValueError, match="oauth_client_id"):
            PrivxClientConfig(
                base_url="https://privx.example.com",
                jwt_token=None,
                client_id=client_id,
                client_secret=client_secret,
                oauth_client_id=oauth_client_id,
                oauth_client_secret=oauth_client_secret,
            )

    @given(
        client_id=non_empty_text,
        client_secret=non_empty_text,
        oauth_client_id=non_empty_text,
        oauth_client_secret=missing_value,
    )
    @settings(max_examples=100)
    def test_missing_oauth_client_secret_raises_error(
        self, client_id, client_secret, oauth_client_id, oauth_client_secret
    ):
        """When client_id and client_secret are set but oauth_client_secret is missing,
        validation raises ValueError listing oauth_client_secret."""
        with pytest.raises(ValueError, match="oauth_client_secret"):
            PrivxClientConfig(
                base_url="https://privx.example.com",
                jwt_token=None,
                client_id=client_id,
                client_secret=client_secret,
                oauth_client_id=oauth_client_id,
                oauth_client_secret=oauth_client_secret,
            )

    @given(
        client_id=non_empty_text,
        client_secret=missing_value,
        oauth_client_id=missing_value,
        oauth_client_secret=missing_value,
    )
    @settings(max_examples=100)
    def test_only_client_id_raises_error_listing_all_missing(
        self, client_id, client_secret, oauth_client_id, oauth_client_secret
    ):
        """When only client_id is provided, validation raises ValueError listing
        all other missing OAuth fields."""
        with pytest.raises(ValueError, match="Incomplete OAuth credentials"):
            PrivxClientConfig(
                base_url="https://privx.example.com",
                jwt_token=None,
                client_id=client_id,
                client_secret=client_secret,
                oauth_client_id=oauth_client_id,
                oauth_client_secret=oauth_client_secret,
            )

    @given(
        client_id=non_empty_text,
        client_secret=non_empty_text,
        oauth_client_id=missing_value,
        oauth_client_secret=missing_value,
    )
    @settings(max_examples=100)
    def test_missing_both_oauth_fields_raises_error(
        self, client_id, client_secret, oauth_client_id, oauth_client_secret
    ):
        """When client_id and client_secret are set but both oauth fields are missing,
        validation raises ValueError listing both missing fields."""
        with pytest.raises(ValueError) as exc_info:
            PrivxClientConfig(
                base_url="https://privx.example.com",
                jwt_token=None,
                client_id=client_id,
                client_secret=client_secret,
                oauth_client_id=oauth_client_id,
                oauth_client_secret=oauth_client_secret,
            )
        error_msg = str(exc_info.value)
        assert "oauth_client_id" in error_msg
        assert "oauth_client_secret" in error_msg

    @given(
        client_id=non_empty_text,
        client_secret=non_empty_text,
        oauth_client_id=non_empty_text,
        oauth_client_secret=non_empty_text,
    )
    @settings(max_examples=100)
    def test_all_oauth_fields_present_does_not_raise(
        self, client_id, client_secret, oauth_client_id, oauth_client_secret
    ):
        """When all four OAuth fields are provided, config creation succeeds."""
        cfg = PrivxClientConfig(
            base_url="https://privx.example.com",
            jwt_token=None,
            client_id=client_id,
            client_secret=client_secret,
            oauth_client_id=oauth_client_id,
            oauth_client_secret=oauth_client_secret,
        )
        assert cfg.client_id == client_id
        assert cfg.client_secret == client_secret
        assert cfg.oauth_client_id == oauth_client_id
        assert cfg.oauth_client_secret == oauth_client_secret


class TestProperty8SensitiveValueMasking:
    """Property 8: Sensitive value masking.

    For any PrivxClientConfig containing OAuth credentials, the string
    representation (__repr__) SHALL NOT contain the raw client_secret,
    oauth_client_id, or oauth_client_secret values.

    **Validates: Requirements 3.6**
    """

    @given(
        client_id=non_empty_text,
        client_secret=st.text(
            alphabet=st.characters(categories=("L", "N", "P", "S")),
            min_size=9,
            max_size=100,
        ),
        oauth_client_id=st.text(
            alphabet=st.characters(categories=("L", "N", "P", "S")),
            min_size=9,
            max_size=100,
        ),
        oauth_client_secret=st.text(
            alphabet=st.characters(categories=("L", "N", "P", "S")),
            min_size=9,
            max_size=100,
        ),
    )
    @settings(max_examples=100)
    def test_repr_does_not_contain_raw_secrets(
        self, client_id, client_secret, oauth_client_id, oauth_client_secret
    ):
        """The repr of a config with OAuth credentials must not expose raw
        secret values (client_secret, oauth_client_id, oauth_client_secret)."""
        # Ensure secrets are distinct from non-masked fields and structural
        # text in the repr to avoid false positives where a secret substring
        # appears in field names, the unmasked client_id, or the base_url.
        repr_structural_text = (
            "PrivxClientConfig base_url https privx example com "
            "jwt_token client_id client_secret oauth_client_id "
            "oauth_client_secret validate_certs None True False"
        )
        assume(client_secret != client_id)
        assume(oauth_client_id != client_id)
        assume(oauth_client_secret != client_id)
        assume(client_secret not in repr_structural_text)
        assume(oauth_client_id not in repr_structural_text)
        assume(oauth_client_secret not in repr_structural_text)
        assume(client_secret not in "https://privx.example.com")
        assume(oauth_client_id not in "https://privx.example.com")
        assume(oauth_client_secret not in "https://privx.example.com")
        # Also ensure secrets don't appear as substrings of the client_id field value
        assume(client_secret not in client_id)
        assume(oauth_client_id not in client_id)
        assume(oauth_client_secret not in client_id)

        cfg = PrivxClientConfig(
            base_url="https://privx.example.com",
            jwt_token=None,
            client_id=client_id,
            client_secret=client_secret,
            oauth_client_id=oauth_client_id,
            oauth_client_secret=oauth_client_secret,
        )
        repr_str = repr(cfg)

        # The raw secret values must not appear in the repr
        assert client_secret not in repr_str, (
            f"client_secret '{client_secret}' found in repr"
        )
        assert oauth_client_id not in repr_str, (
            f"oauth_client_id '{oauth_client_id}' found in repr"
        )
        assert oauth_client_secret not in repr_str, (
            f"oauth_client_secret '{oauth_client_secret}' found in repr"
        )

    @given(
        jwt_token=st.text(
            alphabet=st.characters(categories=("L", "N", "P", "S")),
            min_size=9,
            max_size=100,
        ),
    )
    @settings(max_examples=100)
    def test_repr_does_not_contain_raw_jwt_token(self, jwt_token):
        """The repr of a config with jwt_token must not expose the raw token."""
        # Avoid false positives where the token is a substring of field names
        # or the base_url in the repr
        repr_structural_text = (
            "PrivxClientConfig base_url https privx example com "
            "jwt_token client_id client_secret oauth_client_id "
            "oauth_client_secret None"
        )
        assume(jwt_token not in repr_structural_text)

        cfg = PrivxClientConfig(
            base_url="https://privx.example.com",
            jwt_token=jwt_token,
        )
        repr_str = repr(cfg)

        # The raw jwt_token must not appear in the repr
        assert jwt_token not in repr_str, (
            f"jwt_token '{jwt_token}' found in repr"
        )

    @given(
        client_secret=st.text(
            alphabet=st.characters(categories=("L", "N")),
            min_size=9,
            max_size=100,
        ),
        oauth_client_id=st.text(
            alphabet=st.characters(categories=("L", "N")),
            min_size=9,
            max_size=100,
        ),
        oauth_client_secret=st.text(
            alphabet=st.characters(categories=("L", "N")),
            min_size=9,
            max_size=100,
        ),
    )
    @settings(max_examples=100)
    def test_repr_contains_masked_form_of_secrets(
        self, client_secret, oauth_client_id, oauth_client_secret
    ):
        """The repr should contain the masked form of sensitive values."""
        cfg = PrivxClientConfig(
            base_url="https://privx.example.com",
            jwt_token=None,
            client_id="my-client",
            client_secret=client_secret,
            oauth_client_id=oauth_client_id,
            oauth_client_secret=oauth_client_secret,
        )
        repr_str = repr(cfg)

        # Masked values should use the _mask_token format (first4...last4)
        assert _mask_token(client_secret) in repr_str
        assert _mask_token(oauth_client_id) in repr_str
        assert _mask_token(oauth_client_secret) in repr_str
