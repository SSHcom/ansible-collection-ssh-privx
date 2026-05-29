# GNU General Public License v3.0+

DOCUMENTATION = r"""
---
module: privx_secret_info
short_description: Read a secret from PrivX
version_added: "1.0.0"
author:
  - Mauri Tikka (@mauri-valays-fi)
  - SSH Communications Security Oyj (@SSHcom)
description:
  - Read a secret from PrivX.
  - Supports authentication via JWT token or OAuth client credentials.
options:
  path:
    description:
      - Secret path in PrivX.
    required: true
    type: str
  url:
    description:
      - PrivX base URL.
    required: true
    type: str
  token:
    description:
      - JWT authentication token.
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
- name: Read secret info using JWT token
  sshcom.privx.privx_secret_info:
    path: example
    url: https://privx.example.com
    token: "{{ privx_token }}"

- name: Read secret info using OAuth credentials
  sshcom.privx.privx_secret_info:
    path: example
    url: https://privx.example.com
    client_id: "{{ my_client_id }}"
    client_secret: "{{ my_client_secret }}"
    oauth_client_id: "{{ my_oauth_id }}"
    oauth_client_secret: "{{ my_oauth_secret }}"

- name: Read secret info using OAuth credentials from environment variables
  sshcom.privx.privx_secret_info:
    path: example
    url: https://privx.example.com
"""

RETURN = r"""
secret:
  description: Secret data returned by PrivX.
  returned: success
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sshcom.privx.plugins.module_utils.privx.client import (
    PrivxClient,
    PrivxClientConfig,
    _resolve_oauth_credentials,
)


def run_module():

    module_args = dict(
        url=dict(type="str", required=True),
        token=dict(type="str", required=False, no_log=True),
        path=dict(type="str", required=True),
        client_id=dict(type="str", required=False, no_log=True),
        client_secret=dict(type="str", required=False, no_log=True),
        oauth_client_id=dict(type="str", required=False, no_log=True),
        oauth_client_secret=dict(type="str", required=False, no_log=True),
        validate_certs=dict(type="bool", default=True),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    token = module.params.get("token")

    if token:
        # JWT flow (backward compatible)
        cfg = PrivxClientConfig(
            base_url=module.params["url"],
            jwt_token=token,
            validate_certs=module.params["validate_certs"],
        )
    else:
        # OAuth flow: read from params first, then fall back to env vars
        creds = _resolve_oauth_credentials(
            client_id=module.params.get("client_id"),
            client_secret=module.params.get("client_secret"),
            oauth_client_id=module.params.get("oauth_client_id"),
            oauth_client_secret=module.params.get("oauth_client_secret"),
        )
        client_id, client_secret, oauth_client_id, oauth_client_secret = creds

        if not all([client_id, client_secret, oauth_client_id, oauth_client_secret]):
            module.fail_json(
                msg="Either 'token' or all OAuth credentials (client_id, "
                    "client_secret, oauth_client_id, oauth_client_secret) must "
                    "be provided. OAuth credentials can be set via parameters "
                    "or environment variables (PRIVX_CLIENT_ID, "
                    "PRIVX_CLIENT_SECRET, PRIVX_OAUTH_CLIENT_ID, "
                    "PRIVX_OAUTH_CLIENT_SECRET)."
            )

        cfg = PrivxClientConfig(
            base_url=module.params["url"],
            client_id=client_id,
            client_secret=client_secret,
            oauth_client_id=oauth_client_id,
            oauth_client_secret=oauth_client_secret,
            validate_certs=module.params["validate_certs"],
        )

    client = PrivxClient(cfg)

    try:
        secret = client.get_secret(module.params["path"])

        module.exit_json(
            changed=False,
            secret=secret
        )

    except Exception as e:
        module.fail_json(msg=str(e))


def main():
    run_module()


if __name__ == "__main__":
    main()
