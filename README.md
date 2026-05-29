# SSH PrivX Ansible Collection

[![CI](https://github.com/SSHcom/ansible-collection-ssh-privx/actions/workflows/ci.yml/badge.svg)](https://github.com/SSHcom/ansible-collection-ssh-privx/actions/workflows/ci.yml)
[![QA](https://github.com/SSHcom/ansible-collection-ssh-privx/actions/workflows/qa.yml/badge.svg)](https://github.com/SSHcom/ansible-collection-ssh-privx/actions/workflows/qa.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Provides lookup plugins and modules for retrieving secrets from PrivX Secret Vault.

## Installation

```bash
ansible-galaxy collection install sshcom.privx
```

## Authentication

The module uses JWT authentication towards PrivX. Note that for PrivX 43 the token **must have**

```JSON
  "header": {
    "alg": "Ed25519",
    "typ": "JWT"
  },

```

whereas the following is standards compliant. The typ field is optional. This will be fixed in PrivX 44

```JSON
  "header": {
    "alg": "EdDSA"
  },

```

A script is included to produce a short lived token. You need to create a key pair and configure the public key to PrivX. The `sub` field should correspond exactly to a user name in PrivX.

```bash
export PRIVX_TOKEN=$(./scripts/make_test_jwt.py --key path/to/private/key.pem --iss ansible --sub ansible-secrets --aud https://address.of.your.privx/)
```

## OAuth Authentication

The collection also supports OAuth client credentials authentication as an alternative to JWT tokens. This flow posts form-encoded credentials to the PrivX OAuth token endpoint with HTTP Basic Auth, matching the pattern used by the PrivX Go-based tools.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `PRIVX_CLIENT_ID` | API client identifier (sent as `username` in the token request body) |
| `PRIVX_CLIENT_SECRET` | API client secret (sent as `password` in the token request body) |
| `PRIVX_OAUTH_CLIENT_ID` | OAuth client identifier (used in the HTTP Basic Auth header) |
| `PRIVX_OAUTH_CLIENT_SECRET` | OAuth client secret (used in the HTTP Basic Auth header) |

### Example: OAuth with explicit credentials

```yaml
- hosts: localhost
  gather_facts: false

  tasks:
    - name: Read secret using OAuth credentials
      debug:
        msg: "{{ lookup('sshcom.privx.privx_secret',
                        'name_of_your_secret',
                        url='https://address.of.your.privx',
                        client_id='my-api-client-id',
                        client_secret='my-api-client-secret',
                        oauth_client_id='my-oauth-client-id',
                        oauth_client_secret='my-oauth-client-secret') }}"
```

### Example: OAuth with environment variables

```yaml
- hosts: localhost
  gather_facts: false

  tasks:
    - name: Read secret using OAuth credentials from environment
      debug:
        msg: "{{ lookup('sshcom.privx.privx_secret',
                        'name_of_your_secret',
                        url='https://address.of.your.privx') }}"
```

When no `token` parameter is provided, the plugin automatically reads OAuth credentials from the environment variables listed above. If a JWT token is provided, it takes precedence over OAuth credentials.

## Example

This is an example Ansible playbook.
```yaml
- hosts: localhost
  gather_facts: false

  vars:
    privx_url: https://address.of.your.privx
    privx_token: "{{ lookup('env','PRIVX_TOKEN') }}"

  tasks:

    - name: Read secret from PrivX
      debug:
        msg: "{{ lookup('sshcom.privx.privx_secret',
                        'name_of_your_secret',
                        url=privx_url,
                        token=privx_token) }}"
```

## Implementation notes

Ansible modules do not generally have access to `requests` library, so the PrivX Python SDK can not be used.

# Development

To test the lookup, define the Ansible path to point to your test directory (the top level).
```bash
export ANSIBLE_COLLECTIONS_PATHS="/path/to/your/top/level/test/directory"
```
Then clone the repository to path `ansible_collections/sshcom/privx` under that directory so Ansible will find it.

Note how the directory path `ssh/privx` is duplicated in the example above as the module path.

Run this simple playbook with
```bash
ansible-playbook -vvv ansible_collections/sshcom/privx/scripts/test-privx.yaml
```

## Deploy

Build the collection deliverable
```bash
ansible-galaxy collection build
```
The resulting archive can be installed standalone
```bash
ansible-galaxy collection install ./ssh-privx-1.43.0.tar.gz
```
and it can be published to ansible-galaxy after getting a token from `https://galaxy.ansible.com/me/preference`
```bash
ansible-galaxy collection publish ssh-privx-1.43.0.tar.gz --api-key <TOKEN>
```

## Support & Commercial Services
This is a public open-source project licensed under Apache 2.0 and not covered by standard support SLA. Community feedback and contributions are welcome. Support is provided on a best-effort basis only. For dedicated support, customisations, or enterprise assistance, please raise a ticket via our support portal ( https://care.ssh.com) or via your local support partner. Any requests would be assigned to your account manager.