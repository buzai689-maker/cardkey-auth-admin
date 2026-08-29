"""Test helper: call the encrypted /secure transport and return the inner result.

Mirrors what the reference client does, so tests exercise the real (only) path.
"""
import json

from app import crypto


def call(client, op: str, fields: dict) -> dict:
    inner = dict(fields)
    inner["op"] = op
    env, k_s2c = crypto.seal_request(
        json.dumps(inner).encode(), crypto.server_enc_public_key_b64()
    )
    reply = client.post("/api/v1/secure", json=env).json()
    return json.loads(crypto.open_reply(reply, k_s2c))
