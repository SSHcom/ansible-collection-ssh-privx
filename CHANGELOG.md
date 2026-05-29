# Changelog

## v1.43.0 (2026-05-29)

Initial release of the `sshcom.privx` Ansible collection, aligned with PrivX v43.

### Features

- **Lookup plugin** (`sshcom.privx.privx_secret`) — Retrieve secrets from PrivX Secret Vault in playbooks and templates
- **Module** (`sshcom.privx.privx_secret_info`) — Retrieve secrets as a standard Ansible module with `register` support
- **OAuth client credentials authentication** — Authenticate using API client credentials posted to the PrivX OAuth token endpoint with HTTP Basic Auth
- **JWT token authentication** — Authenticate using an externally-issued JWT token exchanged for a PrivX access token
- **Automatic auth method selection** — JWT takes priority when provided; falls back to OAuth credentials automatically
- **Environment variable support** — OAuth credentials can be sourced from `PRIVX_CLIENT_ID`, `PRIVX_CLIENT_SECRET`, `PRIVX_OAUTH_CLIENT_ID`, `PRIVX_OAUTH_CLIENT_SECRET`
- **TLS certificate validation control** — `validate_certs` parameter for testing with self-signed certificates
- **Retry logic** — Automatic retries with exponential backoff on transient HTTP errors (408, 429, 500, 502, 503, 504)
- **Sensitive value masking** — Credentials are never logged in plaintext

### Supported Authentication Methods

| Method | Parameters | Description |
|--------|-----------|-------------|
| JWT | `token` | Exchange a JWT for a PrivX access token |
| OAuth | `client_id`, `client_secret`, `oauth_client_id`, `oauth_client_secret` | Post form-encoded credentials with Basic Auth |

### Requirements

- Python 3.8+
- Ansible 2.12+

### Installation

```bash
ansible-galaxy collection install sshcom.privx
```
