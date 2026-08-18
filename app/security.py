import base64
import hashlib
import hmac
import os
import secrets
import string

_ALG = "pbkdf2_sha256"
# Ambiguous glyphs stripped from generated card codes so buyers don't mistype.
_AMBIGUOUS = "0O1Il"


def hash_password(password: str, iterations: int = 200_000) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{_ALG}${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        alg, iters, b64salt, b64dk = stored.split("$")
        if alg != _ALG:
            return False
        salt = base64.b64decode(b64salt)
        expected = base64.b64decode(b64dk)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iters))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def default_charset() -> str:
    return "".join(
        c for c in (string.ascii_uppercase + string.digits) if c not in _AMBIGUOUS
    )


def random_code(
    length: int = 16,
    prefix: str = "",
    charset: str | None = None,
    group_size: int = 0,
    group_sep: str = "-",
) -> str:
    charset = charset or default_charset()
    body = "".join(secrets.choice(charset) for _ in range(length))
    if group_size and group_size > 0:
        body = group_sep.join(
            body[i : i + group_size] for i in range(0, len(body), group_size)
        )
    return f"{prefix}{body}"


def gen_token(nbytes: int = 24) -> str:
    return secrets.token_hex(nbytes)
