# GNU General Public License v3.0+

"""
Generate a signed JWT token for testing the PrivX Ansible lookup plugin.

This helper script creates a short-lived JWT using a private key and prints
the token to stdout. Supported algorithms:

- RS256  (RSA)
- EdDSA  (Ed25519)

The selected algorithm must match the key type.

Typical usage:

    export PRIVX_TOKEN="$(
        python3 scripts/make_test_jwt.py \
            --key jwt_rsa_private.pem \
            --alg RS256 \
            --iss my-client \
            --sub my-client \
            --aud privx
    )"

or:

    export PRIVX_TOKEN="$(
        python3 scripts/make_test_jwt.py \
            --key jwt_ed25519_private.pem \
            --alg EdDSA \
            --iss my-client \
            --sub my-client \
            --aud privx
    )"

The generated token can then be consumed by the Ansible lookup plugin via:

    token: "{{ lookup('env', 'PRIVX_TOKEN') }}"
"""

import argparse
import time
from pathlib import Path

import jwt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=True, help="Path to private key PEM file")
    parser.add_argument(
        "--alg",
        choices=["RS256", "EdDSA"],
        default="RS256",
        help="Signing algorithm (must match key type)",
    )
    parser.add_argument("--iss", required=True)
    parser.add_argument("--sub", required=True)
    parser.add_argument("--aud", required=True)
    parser.add_argument("--ttl", type=int, default=900, help="Token lifetime in seconds")
    args = parser.parse_args()

    now = int(time.time())

    payload = {
        "iss": args.iss,
        "sub": args.sub,
        "aud": args.aud,
        "iat": now,
        "nbf": now,
        "exp": now + args.ttl,
    }

    private_key = Path(args.key).read_text()

    token = jwt.encode(
        payload,
        private_key,
        algorithm=args.alg,
    )

    print(token)


if __name__ == "__main__":
    main()
