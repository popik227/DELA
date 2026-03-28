from flask import Flask, request, jsonify
import hashlib
import time
import os
import pg8000.native

app = Flask(__name__)

SECRET_SALT = "Mattellai"
DATABASE_URL = os.environ.get("DATABASE_URL")


def get_db():
    # Railway даёт URL вида postgres://user:pass@host:port/db
    url = DATABASE_URL
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    import urllib.parse
    p = urllib.parse.urlparse(url)
    return pg8000.native.Connection(
        host=p.hostname,
        port=p.port or 5432,
        database=p.path.lstrip("/"),
        user=p.username,
        password=p.password,
        ssl_context=True
    )


def init_db():
    db = get_db()
    db.run("""
        CREATE TABLE IF NOT EXISTS activated_keys (
            key TEXT PRIMARY KEY,
            activated_at TEXT NOT NULL
        )
    """)
    db.close()


def verify_key_signature(key: str) -> bool:
    if len(key) != 32:
        return False
    try:
        expire_hex = key[:8]
        signature  = key[8:]
        int(expire_hex, 16)
    except ValueError:
        return False
    expected = hashlib.sha256((expire_hex + SECRET_SALT).encode()).hexdigest()[:24]
    return signature == expected


def is_key_expired(key: str) -> bool:
    expire_minute = int(key[:8], 16)
    now_minute = int(time.time() // 60)
    return now_minute > expire_minute


@app.route("/activate", methods=["POST"])
def activate():
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip().lower()

    if not verify_key_signature(key):
        return jsonify({"ok": False, "reason": "invalid"}), 200

    if is_key_expired(key):
        return jsonify({"ok": False, "reason": "expired"}), 200

    db = get_db()
    rows = db.run("SELECT key FROM activated_keys WHERE key = :key", key=key)
    if rows:
        db.close()
        return jsonify({"ok": False, "reason": "used"}), 200

    db.run(
        "INSERT INTO activated_keys (key, activated_at) VALUES (:key, :ts)",
        key=key, ts=time.strftime("%Y-%m-%d %H:%M:%S")
    )
    db.close()
    return jsonify({"ok": True}), 200


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip().lower()

    if not verify_key_signature(key):
        return jsonify({"ok": False, "reason": "invalid"}), 200

    if is_key_expired(key):
        return jsonify({"ok": False, "reason": "expired"}), 200

    db = get_db()
    rows = db.run("SELECT key FROM activated_keys WHERE key = :key", key=key)
    db.close()

    if not rows:
        return jsonify({"ok": False, "reason": "not_activated"}), 200

    return jsonify({"ok": True}), 200


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
