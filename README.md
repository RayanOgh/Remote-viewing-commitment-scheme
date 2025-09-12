# Remote-viewing-commitment-scheme

A cryptographic commitment scheme for remote viewing experiments.  
Implements message sealing + verification using HMAC-SHA256.

## Code

```python
#!/usr/bin/env python3
import secrets, hmac, hashlib, base64, json, time

# --- Helpers ---
def canon(s: str) -> str:
    """Canonicalize input (lowercase, strip, alnum + spaces only)."""
    return "".join(ch for ch in s.strip().lower() if ch.isalnum() or ch.isspace())

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

# --- Core ---
def seal(msg: str, key: bytes = None, ctx: bytes = b"psi-commit:v4"):
    """Seal a message: returns (commitment, secret key)."""
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

def verify(msg: str, key: bytes, c: str) -> bool:
    """Verify that a commitment matches a message and key."""
    o = json.loads(c)
    ctx = _b64d(o["ctx"])
    salt = _b64d(o["salt"])
    mac_expected = _b64d(o["mac"])
    mac_actual = hmac.new(key, ctx + salt + msg.encode("utf-8"), hashlib.sha256).digest()
    return hmac.compare_digest(mac_actual, mac_expected)

# --- Logging ---
def log(entry: dict):
    entry["ts"] = round(time.time(), 6)   # microsecond precision
    print(json.dumps(entry, ensure_ascii=False))

# --- Demo ---
if __name__ == "__main__":
    target = "Apple"

    # Commit phase
    commitment, key = seal(canon(target))
    log({"type": "trial_start", "trial_id": 1, "commitment": commitment})

    # Guess phase (skipped here — normally participant guesses)

    # Reveal + verify
    ok = verify(canon(target), key, commitment)
    outcome = "success" if ok else "failure"
    log({
        "type": "reveal",
        "trial_id": 1,
        "target": target,
        "key_b64": _b64e(key),
        "verify_ok": ok,
        "outcome": outcome
    })