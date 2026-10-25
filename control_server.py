#!/usr/bin/env python3
"""Private control API for starting/stopping the existing Telegram hosting-manager bot."""
from __future__ import annotations

import hmac
import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, jsonify, request, make_response

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("PANEL_DATA_DIR", BASE_DIR / "panel_data")).resolve()
CONFIG_FILE = DATA_DIR / "bot_config.enc"
LOG_FILE = DATA_DIR / "bot.log"
PID_FILE = DATA_DIR / "bot.pid"
APP_FILE = BASE_DIR / "app.py"
DATA_DIR.mkdir(parents=True, exist_ok=True)
try:
    os.chmod(DATA_DIR, 0o700)
except OSError:
    pass

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("panel")
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

process: subprocess.Popen | None = None
process_lock = threading.Lock()


def configured_origins() -> set[str]:
    raw = os.environ.get("FRONTEND_ORIGIN", "")
    return {x.strip().rstrip("/") for x in raw.split(",") if x.strip()}


def cors_allowed(origin: str | None) -> bool:
    if not origin:
        return True  # command-line clients still require the panel password
    origins = configured_origins()
    return origin.rstrip("/") in origins


@app.before_request
def protect_origin_and_preflight():
    origin = request.headers.get("Origin")
    if request.path.startswith("/api/") and not cors_allowed(origin):
        return jsonify({"ok": False, "error": "Origin not allowed. Set FRONTEND_ORIGIN on the backend."}), 403
    if request.method == "OPTIONS":
        return make_response("", 204)


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin and cors_allowed(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


def authorized() -> bool:
    expected = os.environ.get("PANEL_PASSWORD", "")
    supplied = request.headers.get("Authorization", "")
    if not expected or not supplied.startswith("Bearer "):
        return False
    return hmac.compare_digest(supplied[7:], expected)


def require_auth():
    if not authorized():
        return jsonify({"ok": False, "error": "Panel password is missing or incorrect."}), 401
    return None


def cipher() -> Fernet:
    key = os.environ.get("PANEL_ENCRYPTION_KEY", "").strip()
    if not key:
        raise RuntimeError("Set PANEL_ENCRYPTION_KEY in the backend host environment.")
    try:
        return Fernet(key.encode("ascii"))
    except Exception as exc:
        raise RuntimeError("PANEL_ENCRYPTION_KEY is invalid. Generate a Fernet key.") from exc


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    try:
        raw = cipher().decrypt(CONFIG_FILE.read_bytes())
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except (InvalidToken, ValueError, OSError, RuntimeError) as exc:
        log.error("Could not decrypt saved bot configuration: %s", type(exc).__name__)
        return {}


def save_config(token: str, admin_ids: str) -> None:
    payload = json.dumps({"bot_token": token, "admin_ids": admin_ids}).encode("utf-8")
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_bytes(cipher().encrypt(payload))
    os.chmod(tmp, 0o600)
    tmp.replace(CONFIG_FILE)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass


def bot_running() -> bool:
    global process
    if process is not None and process.poll() is None:
        return True
    if process is not None and process.poll() is not None:
        process = None
    # Check a saved PID only if it still points to this project's app.py.
    if PID_FILE.exists():
        try:
            import psutil
            pid = int(PID_FILE.read_text().strip())
            p = psutil.Process(pid)
            cmd = " ".join(p.cmdline())
            if p.is_running() and str(APP_FILE) in cmd:
                return True
        except Exception:
            pass
        try:
            PID_FILE.unlink(missing_ok=True)
        except OSError:
            pass
    return False


def tail_logs(limit: int = 180) -> str:
    if not LOG_FILE.exists():
        return "No logs yet."
    try:
        with LOG_FILE.open("r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-limit:]
        config = load_config()
        token = config.get("bot_token", "")
        out = "".join(lines)
        if token:
            out = out.replace(token, "[REDACTED]")
        return out[-24000:]
    except OSError:
        return "Unable to read logs."


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "telegram-bot-control-api"})


@app.route("/api/status", methods=["GET", "OPTIONS"])
def status():
    auth = require_auth()
    if auth:
        return auth
    return jsonify({"ok": True, "running": bot_running(), "pid": process.pid if process and process.poll() is None else None})


@app.route("/api/logs", methods=["GET", "OPTIONS"])
def logs():
    auth = require_auth()
    if auth:
        return auth
    return jsonify({"ok": True, "logs": tail_logs()})


@app.route("/api/start", methods=["POST", "OPTIONS"])
def start():
    global process
    auth = require_auth()
    if auth:
        return auth
    body = request.get_json(silent=True) or {}
    token = str(body.get("bot_token", "")).strip()
    admin_ids = str(body.get("admin_ids", "")).strip()
    if not re.fullmatch(r"\d{5,15}:[A-Za-z0-9_-]{20,}", token):
        return jsonify({"ok": False, "error": "Bot token format looks invalid. Paste the token from BotFather."}), 400
    ids = re.findall(r"\d+", admin_ids)
    if not ids or re.sub(r"[\s,;]+", "", admin_ids) != re.sub(r"[\s,;]+", "", ",".join(ids)):
        return jsonify({"ok": False, "error": "Admin ID must contain numeric Telegram user IDs, separated by commas."}), 400
    admin_ids = ",".join(dict.fromkeys(ids))

    with process_lock:
        if bot_running():
            return jsonify({"ok": False, "error": "Bot is already running. Stop it before changing its configuration."}), 409
        try:
            save_config(token, admin_ids)
        except Exception as exc:
            log.exception("Unable to save encrypted config")
            return jsonify({"ok": False, "error": f"Could not save encrypted settings: {type(exc).__name__}"}), 500

        env = os.environ.copy()
        env.update({
            "BOT_TOKEN": token,
            "ADMIN_IDS": admin_ids,
            "SANDBOX_MODE": "process",
            "ALLOW_UNSANDBOXED_USERS": "false",
        })
        # Do not inherit a local .env: this panel intentionally uses encrypted config + process env.
        env.pop("PYTHONPATH", None)
        try:
            log_handle = LOG_FILE.open("a", encoding="utf-8")
            log_handle.write(f"\n--- Bot start requested at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
            log_handle.flush()
            process = subprocess.Popen(
                [sys.executable, "-u", str(APP_FILE)],
                cwd=str(BASE_DIR),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
            )
            PID_FILE.write_text(str(process.pid), encoding="utf-8")
            os.chmod(PID_FILE, 0o600)
            time.sleep(1.2)
            if process.poll() is not None:
                code = process.returncode
                process = None
                return jsonify({"ok": False, "error": f"Bot exited immediately (code {code}). Check logs below.", "logs": tail_logs()}), 500
            return jsonify({"ok": True, "message": "Bot process started.", "pid": process.pid})
        except Exception as exc:
            log.exception("Could not start bot")
            return jsonify({"ok": False, "error": f"Could not start bot: {type(exc).__name__}"}), 500


@app.route("/api/stop", methods=["POST", "OPTIONS"])
def stop():
    global process
    auth = require_auth()
    if auth:
        return auth
    with process_lock:
        if not bot_running():
            return jsonify({"ok": True, "message": "Bot is not running."})
        pid = process.pid if process and process.poll() is None else None
        if pid is None and PID_FILE.exists():
            try:
                pid = int(PID_FILE.read_text().strip())
            except Exception:
                pid = None
        if pid is None:
            return jsonify({"ok": False, "error": "Could not identify the running bot process."}), 500
        try:
            # The bot is started in its own process group.
            os.killpg(pid, signal.SIGTERM)
            deadline = time.time() + 8
            while time.time() < deadline:
                if process is not None and process.poll() is not None:
                    break
                time.sleep(0.2)
            if process is not None and process.poll() is None:
                os.killpg(pid, signal.SIGKILL)
            process = None
            PID_FILE.unlink(missing_ok=True)
            return jsonify({"ok": True, "message": "Stop signal sent."})
        except ProcessLookupError:
            process = None
            PID_FILE.unlink(missing_ok=True)
            return jsonify({"ok": True, "message": "Bot process was already stopped."})
        except Exception as exc:
            log.exception("Could not stop bot")
            return jsonify({"ok": False, "error": f"Could not stop bot: {type(exc).__name__}"}), 500


if __name__ == "__main__":
    if not os.environ.get("PANEL_PASSWORD"):
        raise SystemExit("Set PANEL_PASSWORD in the backend host environment.")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
