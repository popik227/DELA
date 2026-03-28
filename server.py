"""
server.py — запускаешь на Railway. Покупатель не видит этот файл.
"""
from flask import Flask, request, jsonify
import hashlib
import time
import json
import os

app = Flask(__name__)

# ⚠️ Та же соль что и в generate_key.py и bike_booker.py
SECRET_SALT = "BikeBo0ker_SecretKey_XJ9z#qlm"

# Файл где хранятся активированные ключи (Railway сохраняет его между запусками)
KEYS_FILE = "activated_keys.json"


def load_keys():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_keys(keys):
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=2)


def verify_key_signature(key: str) -> bool:
    """Проверяет что ключ настоящий (подпись верная)."""
    if len(key) != 32:
        return False
    try:
        expire_hex = key[:8]
        signature  = key[8:]
        int(expire_hex, 16)  # проверяем что это hex
    except ValueError:
        return False
    expected = hashlib.sha256((expire_hex + SECRET_SALT).encode()).hexdigest()[:24]
    return signature == expected


def is_key_expired(key: str) -> bool:
    """Проверяет не истёк ли срок ключа."""
    expire_minute = int(key[:8], 16)
    now_minute = int(time.time() // 60)
    return now_minute > expire_minute


@app.route("/activate", methods=["POST"])
def activate():
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip().lower()

    # 1. Проверяем подпись
    if not verify_key_signature(key):
        return jsonify({"ok": False, "reason": "invalid"}), 200

    # 2. Проверяем срок
    if is_key_expired(key):
        return jsonify({"ok": False, "reason": "expired"}), 200

    # 3. Проверяем не был ли уже активирован
    keys = load_keys()
    if key in keys:
        return jsonify({"ok": False, "reason": "used"}), 200

    # 4. Всё ок — активируем (сохраняем навсегда)
    keys[key] = {
        "activated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    save_keys(keys)
    return jsonify({"ok": True}), 200


@app.route("/check", methods=["POST"])
def check():
    """Проверка при каждом запуске — активирован ли ключ на сервере."""
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip().lower()

    if not verify_key_signature(key):
        return jsonify({"ok": False, "reason": "invalid"}), 200

    if is_key_expired(key):
        return jsonify({"ok": False, "reason": "expired"}), 200

    keys = load_keys()
    if key not in keys:
        return jsonify({"ok": False, "reason": "not_activated"}), 200

    return jsonify({"ok": True}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
