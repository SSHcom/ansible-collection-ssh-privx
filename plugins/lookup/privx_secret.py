# GNU General Public License v3.0+

DOCUMENTATION = r"""
name: privx_secret
author:
  - Mauri Tikka (@mauri-valays-fi)
  - SSH Communications Security Oyj (@SSHcom)
version_added: "0.1.0"
short_description: Retrieve a secret from PrivX Secret Vault
description:
  - Fetches a secret value from PrivX Secret Vault.
  - Intended for use in playbooks to retrieve runtime secrets.
  - Supports authentication via JWT token or OAuth client credentials.

options:
  _terms:
    description:
      - Path of the secret to retrieve.
    required: true

  url:
    description:
      - Base URL of the PrivX server.
    required: true
    type: str

  token:
    description:
      - JWT token used to authenticate with PrivX.
      - If provided, OAuth credentials are ignored.
    required: false
    type: str

  client_id:
    description:
      - API client identifier for OAuth authentication.
      - Falls back to the C(PRIVX_CLIENT_ID) environment variable if not provided.
    required: false
    type: str

  client_secret:
    description:
      - API client secret for OAuth authentication.
      - Falls back to the C(PRIVX_CLIENT_SECRET) environment variable if not provided.
    required: false
    type: str

  oauth_client_id:
    description:
      - OAuth client identifier used in the HTTP Basic Auth header.
      - Falls back to the C(PRIVX_OAUTH_CLIENT_ID) environment variable if not provided.
    required: false
    type: str

  oauth_client_secret:
    description:
      - OAuth client secret used in the HTTP Basic Auth header.
      - Falls back to the C(PRIVX_OAUTH_CLIENT_SECRET) environment variable if not provided.
    required: false
    type: str

  validate_certs:
    description:
      - Whether to verify TLS certificates.
      - Set to C(false) only for testing environments with self-signed certificates.
    required: false
    type: bool
    default: true
"""

EXAMPLES = r"""
- name: Retrieve secret using JWT token
  debug:
    msg: "{{ lookup('sshcom.privx.privx_secret',
                    'database/password',
                    url=privx_url,
                    token=privx_token) }}"

- name: Retrieve secret using OAuth credentials
  debug:
    msg: "{{ lookup('sshcom.privx.privx_secret',
                    'database/password',
                    url=privx_url,
                    client_id=my_client_id,
                    client_secret=my_client_secret,
                    oauth_client_id=my_oauth_id,
                    oauth_client_secret=my_oauth_secret) }}"

- name: Retrieve secret using OAuth credentials from environment variables
  debug:
    msg: "{{ lookup('sshcom.privx.privx_secret',
                    'database/password',
                    url=privx_url) }}"
"""

RETURN = r"""
_raw:
  description:
    - Secret value retrieved from PrivX.
  type: str
"""

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
from ansible.utils.display import Display

from ansible_collections.sshcom.privx.plugins.module_utils.privx.client import (
    PrivxClient,
    PrivxClientConfig,
    _resolve_oauth_credentials,
)

display = Display()


def _handle_privx_error(secret_name, err):
    """
    Translate PrivX client errors into user-friendly AnsibleError.

    :param secret_name: Name/path of the requested secret
    :param err: Original exception from client
    :raises AnsibleError: Always raised with normalized message
    """
    message = str(err)

    if "not found" in message.lower():
        raise AnsibleError("PrivX secret not found: %s" % secret_name)

    raise AnsibleError("PrivX lookup failed: %s" % message)


class LookupModule(LookupBase):
    """Ansible lookup plugin for retrieving secrets from PrivX."""

    def run(self, terms, variables=None, **kwargs):
        """
        Execute the lookup and return the secret value.

        :param terms: List containing a single secret path
        :param variables: Ansible variables (unused)
        :param kwargs: url, token, and OAuth credential parameters
        :return: List containing the secret data
        :raises AnsibleError: On invalid input or lookup failure
        """
        if len(terms) != 1:
            raise AnsibleError("privx_secret lookup expects one secret path")

        path = terms[0]

        base_url = kwargs.get("url")
        jwt_token = kwargs.get("token")

        if not base_url:
            raise AnsibleError("url parameter is required")

        if jwt_token:
            # JWT flow (backward compatible)
            cfg = PrivxClientConfig(
                base_url=base_url,
                jwt_token=jwt_token,
                validate_certs=kwargs.get("validate_certs", True),
            )
        else:
            # OAuth flow: read from kwargs first, then fall back to env vars
            creds = _resolve_oauth_credentials(
                client_id=kwargs.get("client_id"),
                client_secret=kwargs.get("client_secret"),
                oauth_client_id=kwargs.get("oauth_client_id"),
                oauth_client_secret=kwargs.get("oauth_client_secret"),
            )
            client_id, client_secret, oauth_client_id, oauth_client_secret = creds

            if not all([client_id, client_secret, oauth_client_id, oauth_client_secret]):
                raise AnsibleError(
                    "Either 'token' or all OAuth credentials (client_id, client_secret, "
                    "oauth_client_id, oauth_client_secret) must be provided. "
                    "OAuth credentials can be set via parameters or environment variables "
                    "(PRIVX_CLIENT_ID, PRIVX_CLIENT_SECRET, PRIVX_OAUTH_CLIENT_ID, "
                    "PRIVX_OAUTH_CLIENT_SECRET)."
                )

            cfg = PrivxClientConfig(
                base_url=base_url,
                client_id=client_id,
                client_secret=client_secret,
                oauth_client_id=oauth_client_id,
                oauth_client_secret=oauth_client_secret,
                validate_certs=kwargs.get("validate_certs", True),
            )

        client = PrivxClient(cfg, logger=display.vvv)

        try:
            secret = client.get_secret(path)
        except Exception as e:
            _handle_privx_error(path, e)

        if "data" not in secret:
            raise AnsibleError("PrivX secret malformed: %s" % path)

        return [secret["data"]]
