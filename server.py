from __future__ import annotations

import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DATA_FILE = ROOT / "data" / "user.json"
DEFAULT_PORT = int(os.environ.get("PORT", "1337"))
DEFAULT_HOST = os.environ.get("HOST", "0.0.0.0")
ITERATIONS = 210_000
SESSION_TTL_SECONDS = 60 * 60 * 24 * 7
USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{2,32}$")
STATE_LOCK = threading.Lock()


def _now() -> float:
    return __import__("time").time()


def _pbkdf2_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS,
    )
    return "pbkdf2_sha256${iterations}${salt}${digest}".format(
        iterations=ITERATIONS,
        salt=base64.urlsafe_b64encode(salt).decode("ascii"),
        digest=base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def _verify_password(stored: str, password: str) -> bool:
    try:
        algorithm, iterations, salt_b64, digest_b64 = stored.split("$", 3)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    try:
        salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_b64.encode("ascii"))
        count = int(iterations)
    except (ValueError, base64.binascii.Error):
        return False

    actual = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        count,
    )
    return hmac.compare_digest(actual, expected)


def _legacy_users_to_state(raw_users: dict[str, Any]) -> dict[str, Any]:
    users: dict[str, Any] = {}
    for username, workbook in raw_users.items():
        users[username] = {
            "passwordHash": _pbkdf2_hash(username),
            "db": workbook if isinstance(workbook, dict) else {},
        }
    return {"version": 1, "users": users}


def _normalize_state(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {"version": 1, "users": {}, "sessions": {}}

    users = raw.get("users")
    sessions = raw.get("sessions")
    if isinstance(users, dict):
        normalized: dict[str, Any] = {}
        changed = raw.get("version") != 1
        for username, user_data in users.items():
            if not isinstance(user_data, dict):
                continue
            password_hash = user_data.get("passwordHash")
            db = user_data.get("db")
            if not isinstance(password_hash, str):
                password_hash = _pbkdf2_hash(str(username))
                changed = True
            if not isinstance(db, dict):
                db = {}
                changed = True
            normalized[str(username)] = {
                "passwordHash": password_hash,
                "db": db,
            }
        normalized_sessions: dict[str, Any] = {}
        cutoff = _now() - SESSION_TTL_SECONDS
        if isinstance(sessions, dict):
            for token, session_data in sessions.items():
                if not isinstance(session_data, dict):
                    changed = True
                    continue
                username = session_data.get("username")
                created_at = session_data.get("createdAt")
                if not isinstance(username, str) or not isinstance(
                    created_at, (int, float)
                ):
                    changed = True
                    continue
                if float(created_at) < cutoff:
                    changed = True
                    continue
                normalized_sessions[str(token)] = {
                    "username": username,
                    "createdAt": float(created_at),
                }
        elif sessions is not None:
            changed = True

        state = {"version": 1, "users": normalized, "sessions": normalized_sessions}
        if changed:
            _write_state(state)
        return state

    legacy_users = raw.get("db")
    if isinstance(legacy_users, dict):
        state = _legacy_users_to_state(legacy_users)
        _write_state(state)
        return state

    return {"version": 1, "users": {}, "sessions": {}}


def _load_state() -> dict[str, Any]:
    if not DATA_FILE.exists():
        DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        state = {"version": 1, "users": {}, "sessions": {}}
        _write_state(state)
        return state

    with DATA_FILE.open("r", encoding="utf-8") as handle:
        try:
            raw = json.load(handle)
        except json.JSONDecodeError:
            raw = {}
    return _normalize_state(raw)


def _write_state(state: dict[str, Any]) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp_path = DATA_FILE.with_suffix(".json.tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, DATA_FILE)


def _state() -> dict[str, Any]:
    with STATE_LOCK:
        return _load_state()


def _list_workbooks(state: dict[str, Any]) -> list[dict[str, Any]]:
    users = state.get("users", {})
    if not isinstance(users, dict):
        return []
    workbooks = []
    for username, user_data in users.items():
        if not isinstance(user_data, dict):
            continue
        workbooks.append(
            {
                "id": username,
                "userId": username,
                "label": username,
                "db": user_data.get("db", {}),
            }
        )
    return workbooks


def _create_session(state: dict[str, Any], username: str) -> str:
    token = secrets.token_urlsafe(32)
    state.setdefault("sessions", {})[token] = {
        "username": username,
        "createdAt": _now(),
    }
    return token


def _auth_username(handler: BaseHTTPRequestHandler) -> str | None:
    header = handler.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header.removeprefix("Bearer ").strip()
    state = _state()
    session = state.get("sessions", {}).get(token)
    if not session:
        return None
    created_at = session.get("createdAt")
    if not isinstance(created_at, (int, float)):
        return None
    if float(created_at) < _now() - SESSION_TTL_SECONDS:
        return None
    return str(session.get("username", "")) or None


def _read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or 0)
    if length <= 0:
        return {}
    payload = handler.rfile.read(length)
    if not payload:
        return {}
    return json.loads(payload.decode("utf-8"))


def _send_json(handler: BaseHTTPRequestHandler, status: int, payload: Any) -> None:
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
    handler.send_header(
        "Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, OPTIONS"
    )
    handler.end_headers()
    handler.wfile.write(body)


def _send_text(
    handler: BaseHTTPRequestHandler, status: int, body: bytes, content_type: str
) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _error(handler: BaseHTTPRequestHandler, status: int, message: str) -> None:
    _send_json(handler, status, {"message": message})


def _login_or_register(handler: BaseHTTPRequestHandler, *, register: bool) -> None:
    payload = _read_json(handler)
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()
    if not username or not password:
        _error(handler, HTTPStatus.BAD_REQUEST, "Enter username and password.")
        return
    if not USERNAME_RE.fullmatch(username):
        _error(
            handler,
            HTTPStatus.BAD_REQUEST,
            "Username must be 2-32 chars: letters, numbers, dot, dash, underscore.",
        )
        return

    with STATE_LOCK:
        state = _load_state()
        users = state.setdefault("users", {})
        user = users.get(username)

        if register:
            if user is not None:
                _error(handler, HTTPStatus.CONFLICT, "Username already taken.")
                return
            users[username] = {
                "passwordHash": _pbkdf2_hash(password),
                "db": {},
            }
        else:
            if not isinstance(user, dict):
                _error(handler, HTTPStatus.UNAUTHORIZED, "Login failed")
                return
            stored_hash = str(user.get("passwordHash", ""))
            if not _verify_password(stored_hash, password):
                _error(handler, HTTPStatus.UNAUTHORIZED, "Login failed")
                return

        token = _create_session(state, username)
        _write_state(state)
        _send_json(
            handler,
            HTTPStatus.OK,
            {
                "token": token,
                "record": {
                    "id": username,
                    "username": username,
                },
            },
        )


def _handle_workbooks(handler: BaseHTTPRequestHandler, method: str) -> None:
    username = _auth_username(handler)
    if not username:
        _error(handler, HTTPStatus.UNAUTHORIZED, "Log in to load local data.")
        return

    if method == "GET":
        state = _state()
        _send_json(
            handler,
            HTTPStatus.OK,
            {
                "items": _list_workbooks(state),
                "record": {"id": username, "username": username},
            },
        )
        return

    if method in {"PUT", "PATCH", "POST"}:
        payload = _read_json(handler)
        workbooks = payload.get("workbooks")
        if not isinstance(workbooks, list):
            _error(handler, HTTPStatus.BAD_REQUEST, "Missing workbooks array.")
            return

        with STATE_LOCK:
            state = _load_state()
            users = state.setdefault("users", {})
            # Only allow the authenticated user to modify their own workbook.
            # Ignore any workbooks in the payload that target other users.
            if username not in users:
                _error(handler, HTTPStatus.UNAUTHORIZED, "Unauthorized")
                return
            for workbook in workbooks:
                if not isinstance(workbook, dict):
                    continue
                db = workbook.get("db")
                if isinstance(db, dict):
                    users[username]["db"] = db
            _write_state(state)

        _send_json(handler, HTTPStatus.OK, {"ok": True})
        return

    _error(handler, HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed")


def _serve_file(handler: BaseHTTPRequestHandler, relative_path: str) -> None:
    file_path = (ROOT / relative_path).resolve()
    if not file_path.exists() or not file_path.is_file():
        _error(handler, HTTPStatus.NOT_FOUND, "Not found")
        return
    if ROOT not in file_path.parents and file_path != ROOT:
        _error(handler, HTTPStatus.FORBIDDEN, "Forbidden")
        return
    mime_type, _ = mimetypes.guess_type(file_path.name)
    body = file_path.read_bytes()
    _send_text(handler, HTTPStatus.OK, body, mime_type or "application/octet-stream")


class DragonflyHandler(BaseHTTPRequestHandler):
    server_version = "DragonflyTables/1.0"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header(
            "Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, OPTIONS"
        )
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            return _serve_file(self, "simple_frontend.html")
        if path == "/input_table.html":
            return _serve_file(self, "input_table.html")
        if path == "/api/workbooks":
            return _handle_workbooks(self, "GET")
        if path == "/api/me":
            username = _auth_username(self)
            if not username:
                return _error(self, HTTPStatus.UNAUTHORIZED, "Unauthorized")
            return _send_json(
                self, HTTPStatus.OK, {"id": username, "username": username}
            )
        if path.startswith("/data/") or path.startswith("/assets/"):
            return _serve_file(self, path.lstrip("/"))
        return _error(self, HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/login":
            return _login_or_register(self, register=False)
        if path == "/api/register":
            return _login_or_register(self, register=True)
        if path == "/api/workbooks":
            return _handle_workbooks(self, "POST")
        return _error(self, HTTPStatus.NOT_FOUND, "Not found")

    def do_PUT(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/workbooks":
            return _handle_workbooks(self, "PUT")
        return _error(self, HTTPStatus.NOT_FOUND, "Not found")

    def do_PATCH(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/workbooks":
            return _handle_workbooks(self, "PATCH")
        return _error(self, HTTPStatus.NOT_FOUND, "Not found")


def main() -> None:
    _state()
    server = ThreadingHTTPServer((DEFAULT_HOST, DEFAULT_PORT), DragonflyHandler)
    print(f"Serving Dragonfly Tables on http://{DEFAULT_HOST}:{DEFAULT_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
