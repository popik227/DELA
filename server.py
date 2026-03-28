"""
server.py — запускаешь на Railway. Покупатель не видит этот файл.
Хранит ключи в PostgreSQL — данные не теряются при редеплое.
"""
from flask import Flask, request, jsonify
import hashlib
import time
import os
import psycopg2

app = Flask(__name__)

SECRET_SALT = "Mattellai"

DATABASE_URL = os.environ.get("DATABASE_URL")


def get_db():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS activated_keys (
                    key TEXT PRIMARY KEY,
                    activated_at TEXT NOT NULL
                )
            """)
        conn.commit()


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

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT key FROM activated_keys WHERE key = %s", (key,))
            if cur.fetchone():
                return jsonify({"ok": False, "reason": "used"}), 200
            cur.execute(
                "INSERT INTO activated_keys (key, activated_at) VALUES (%s, %s)",
                (key, time.strftime("%Y-%m-%d %H:%M:%S"))
            )
        conn.commit()

    return jsonify({"ok": True}), 200


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip().lower()

    if not verify_key_signature(key):
        return jsonify({"ok": False, "reason": "invalid"}), 200

    if is_key_expired(key):
        return jsonify({"ok": False, "reason": "expired"}), 200

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT key FROM activated_keys WHERE key = %s", (key,))
            if not cur.fetchone():
                return jsonify({"ok": False, "reason": "not_activated"}), 200

    return jsonify({"ok": True}), 200


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
