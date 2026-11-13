#!/usr/bin/env python3
"""Sign exact manifest bytes with a protected Ed25519 key. No publication.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import base64
import os
from pathlib import Path
import subprocess
import sys

PHP = r'''
$key = base64_decode(getenv($argv[1]), true);
if ($key === false || strlen($key) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) { exit(2); }
$expected = base64_decode($argv[2], true);
$public = sodium_crypto_sign_publickey_from_secretkey($key);
if ($expected === false || !hash_equals($expected, $public)) { exit(3); }
echo sodium_crypto_sign_detached(stream_get_contents(STDIN), $key);
sodium_memzero($key);
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--signature', type=Path, required=True)
    parser.add_argument('--key-env', default='COMPACT_SIGNING_KEY_B64')
    parser.add_argument('--public-key-b64', required=True)
    args = parser.parse_args()
    if not os.environ.get(args.key_env):
        print('Release signing key unavailable; candidate remains pending.', file=sys.stderr)
        return 78
    if args.signature.exists():
        parser.error('Refusing to replace an existing release signature')
    signature = subprocess.check_output(['php', '-r', PHP, args.key_env, args.public_key_b64],
                                        input=args.manifest.read_bytes())
    if len(signature) != 64:
        raise ValueError('Invalid signer output')
    args.signature.write_bytes(signature)
    return 0


if __name__ == '__main__':
    sys.exit(main())
