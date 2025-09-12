# Remote-viewing-commitment-scheme

#!/usr/bin/env python3
import secrets, hmac, hashlib, base64, json, time

# Canonicalize input (lowercase, strip, alnum + spaces only)
def canon(s: str) -> str:
    return "".join(ch for ch in s.strip().lower() if ch.isalnum() or ch.isspace())

# Base64 helpers
def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

# Seal a message: returns (commitment, secret key)
def seal(msg: str, key: bytes = None, ctx: bytes = b"psi-commit:v4"):
    if key is None:
        key = secrets.token_bytes(32)      # fresh secret key
    salt = secrets.token_bytes(16)         # per-trial randomness
    mac = hmac.new(key, ctx + salt + msg.encode("utf-8"), hashlib.sha256).digest()
    c = json.dumps({
        "v": "4",
        "algo": "hmac-sha256",
        "ctx": _b64e(ctx),
        "salt": _b64e(salt),
        "mac": _b64e(mac)
    }, separators=(",", ":"))
    return c, key

# Verify a message/key against a commitment
def verify(msg: str, key: bytes, c: str) -> bool:
    o = json.loads(c)
    ctx = _b64d(o["ctx"])
    salt = _b64d(o["salt"])
    mac_expected = _b64d(o["mac"])
    mac_actual = hmac.new(key, ctx + salt + msg.encode("utf-8"), hashlib.sha256).digest()
    return hmac.compare_digest(mac_actual, mac_expected)

# Log JSON with timestamp
def log(entry: dict):
    entry["ts"] = round(time.time(), 6)
    print(json.dumps(entry, ensure_ascii=False))

# Demo
if __name__ == "__main__":
    target = "Apple"

    # Commit phase
    commitment, key = seal(canon(target))
    log({"type": "trial_start", "trial_id": 1, "commitment": commitment})

    # Reveal + verify
    ok = verify(canon(target), key, commitment)
    log({
        "type": "reveal",
        "trial_id": 1,
        "target": target,
        "key_b64": _b64e(key),
        "verify_ok": ok,
        "outcome": "success" if ok else "failure"
    })
