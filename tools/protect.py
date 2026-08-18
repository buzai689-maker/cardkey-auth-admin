"""Encrypt/decrypt a protected payload with the server's K_payload.

Build-time you encrypt the software's valuable core (a DLL, script, or resource)
and ship the .enc alongside the app. The plaintext key never leaves the server;
the client obtains it only via a valid /api/v1/session handshake.

    python -m tools.protect encrypt examples/core_plain.py examples/core.enc
    python -m tools.protect decrypt examples/core.enc /tmp/core.py      # sanity check
    python -m tools.protect keyinfo
"""
import hashlib
import sys

from app import crypto


def _usage() -> int:
    print(__doc__)
    return 2


def cmd_encrypt(src: str, dst: str) -> int:
    data = open(src, "rb").read()
    blob = crypto.encrypt_payload(data, crypto.payload_key())
    open(dst, "wb").write(blob)
    print(f"encrypted {len(data)} -> {len(blob)} bytes  {src} -> {dst}")
    return 0


def cmd_decrypt(src: str, dst: str) -> int:
    blob = open(src, "rb").read()
    data = crypto.decrypt_payload(blob, crypto.payload_key())
    open(dst, "wb").write(data)
    print(f"decrypted {len(blob)} -> {len(data)} bytes  {src} -> {dst}")
    return 0


def cmd_keyinfo() -> int:
    k = crypto.payload_key()
    print("K_payload sha256 :", hashlib.sha256(k).hexdigest())
    print("server pubkey    :", crypto.server_public_key_b64())
    print("(embed the pubkey in the client for signature pinning)")
    return 0


def main(argv) -> int:
    if not argv:
        return _usage()
    cmd = argv[0]
    if cmd == "encrypt" and len(argv) == 3:
        return cmd_encrypt(argv[1], argv[2])
    if cmd == "decrypt" and len(argv) == 3:
        return cmd_decrypt(argv[1], argv[2])
    if cmd == "keyinfo":
        return cmd_keyinfo()
    return _usage()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
