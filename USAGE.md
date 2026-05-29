# Usage Guide

This guide explains how to use the `sshcom.privx` Ansible collection to retrieve secrets from PrivX and use them in playbooks.

## Prerequisites

- Python 3.8+
- Ansible 2.12+
- `pywinrm` (if connecting to Windows hosts)

```bash
pip install ansible pywinrm
```

## Setup

### 1. Clone into the Ansible collection path

```bash
mkdir -p ansible_collections/ssh
git clone <your-repo-url> ansible_collections/sshcom/privx
cd ansible_collections/sshcom/privx
```

The included `ansible.cfg` automatically sets the collections path — no manual export needed.

### 2. Configure OAuth credentials

You have three options:

**Option A: Environment variables**

```bash
export PRIVX_CLIENT_ID="your-api-client-id"
export PRIVX_CLIENT_SECRET="your-api-client-secret"
export PRIVX_OAUTH_CLIENT_ID="your-oauth-client-id"
export PRIVX_OAUTH_CLIENT_SECRET="your-oauth-client-secret"
```

**Option B: Ansible Vault (recommended for production)**

```bash
mkdir -p group_vars/all
ansible-vault create group_vars/all/vault.yml
```

Add the following content:

```yaml
vault_privx_client_id: "your-api-client-id"
vault_privx_client_secret: "your-api-client-secret"
vault_privx_oauth_client_id: "your-oauth-client-id"
vault_privx_oauth_client_secret: "your-oauth-client-secret"
```

Then reference them in your playbook:

```yaml
- name: Read secret using vault credentials
  set_fact:
    secret: "{{ lookup('sshcom.privx.privx_secret',
                       'my/secret',
                       url='https://privx.example.com',
                       client_id=vault_privx_client_id,
                       client_secret=vault_privx_client_secret,
                       oauth_client_id=vault_privx_oauth_client_id,
                       oauth_client_secret=vault_privx_oauth_client_secret) }}"
```

**Option C: Explicit parameters in the playbook**

Pass credentials directly as lookup parameters (see example below).

## Retrieving a Secret

The secret returned from PrivX is a JSON object. For credential-type secrets, it typically contains `user` and `pass` fields.

### Using the lookup plugin

```yaml
- name: Retrieve secret
  set_fact:
    my_secret: "{{ lookup('sshcom.privx.privx_secret',
                          'path/to/secret',
                          url='https://privx.example.com') }}"

- name: Use the credentials
  debug:
    msg: "Username: {{ my_secret.user }}, Password: {{ my_secret.pass }}"
```

### Using the module

```yaml
- name: Retrieve secret via module
  sshcom.privx.privx_secret_info:
    path: path/to/secret
    url: https://privx.example.com
  register: result

- name: Use the credentials
  debug:
    msg: "Username: {{ result.secret.data.user }}"
```

## Full Example

See [`docs/examples/oauth_read_secret.yaml`](docs/examples/oauth_read_secret.yaml) for a complete OAuth example and [`docs/examples/jwt_read_secret.yaml`](docs/examples/jwt_read_secret.yaml) for JWT authentication.

Run with:

```bash
ansible-playbook docs/examples/oauth_read_secret.yaml
```

Or with vault:

```bash
ansible-playbook docs/examples/oauth_read_secret.yaml --ask-vault-pass
```

## Using Retrieved Credentials with Windows Hosts

Once you have the credentials, you can use them to connect to Windows hosts via WinRM:

```yaml
- hosts: localhost
  gather_facts: false
  vars:
    privx_url: https://privx.example.com
    secret_name: my/windows/creds
    target_host: 10.0.0.16

  tasks:
    - name: Retrieve credentials from PrivX
      set_fact:
        creds: "{{ lookup('sshcom.privx.privx_secret',
                          secret_name,
                          url=privx_url) }}"

    - name: Query service on Windows host
      ansible.windows.win_shell: |
        Get-Service -Name Spooler | Select-Object Name, Status, DisplayName | ConvertTo-Json
      delegate_to: "{{ target_host }}"
      vars:
        ansible_user: "{{ hostvars['localhost']['creds']['user'] }}"
        ansible_password: "{{ hostvars['localhost']['creds']['pass'] }}"
        ansible_connection: winrm
        ansible_winrm_transport: ntlm
        ansible_winrm_server_cert_validation: ignore
        ansible_port: 5985
      register: svc_info

    - name: Show result
      debug:
        msg: "{{ svc_info.stdout | from_json }}"
```

## Environment Variables Reference

| Variable | Description |
|----------|-------------|
| `PRIVX_CLIENT_ID` | API client identifier (form body `username`) |
| `PRIVX_CLIENT_SECRET` | API client secret (form body `password`) |
| `PRIVX_OAUTH_CLIENT_ID` | OAuth client ID (Basic Auth header) |
| `PRIVX_OAUTH_CLIENT_SECRET` | OAuth client secret (Basic Auth header) |

## Authentication Priority

When both JWT token and OAuth credentials are available, JWT takes precedence. The selection logic is:

1. If `token` parameter is provided → use JWT flow
2. If no token but OAuth credentials are available → use OAuth flow
3. If neither → error

## Troubleshooting

- **"url parameter is required"** — Ensure `url` is passed to the lookup or module
- **"Either 'token' or all OAuth credentials..."** — Set all four OAuth env vars or pass them explicitly
- **"Cannot open Service Control Manager"** — The Windows user needs "Server Operators" group membership to query services
- **Python 3.6 "No module named dataclasses"** — Upgrade to Python 3.8+
