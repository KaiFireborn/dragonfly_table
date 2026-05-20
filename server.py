from __future__ import annotations

import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DB_FILE = ROOT / "data" / "dragonfly.sqlite3"
DEFAULT_PORT = int(os.environ.get("PORT", "1337"))
DEFAULT_HOST = os.environ.get("HOST", "0.0.0.0")
ITERATIONS = 210_000
SESSION_TTL_SECONDS = 60 * 60 * 24 * 7
USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{2,32}$")


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workbooks (
    username TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
    db_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);
"""


def _now() -> float:
    return __import__("time").time()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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


def _ensure_db() -> None:
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(SCHEMA)


def _db_connection() -> sqlite3.Connection:
    _ensure_db()
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def _serialize_db(db: Any) -> str:
    if not isinstance(db, dict):
        db = {}
    return json.dumps(db, indent=2, sort_keys=True)


def _deserialize_db(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    created_at = _now()
    with _db_connection() as conn:
        conn.execute(
            "DELETE FROM sessions WHERE created_at < ?",
            (created_at - SESSION_TTL_SECONDS,),
        )
        conn.execute(
            "INSERT INTO sessions (token, username, created_at) VALUES (?, ?, ?)",
            (token, username, created_at),
        )
    return token


def _create_user(username: str, password: str) -> None:
    password_hash = _pbkdf2_hash(password)
    with _db_connection() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("Username already taken.") from exc
        conn.execute(
            "INSERT INTO workbooks (username, db_json) VALUES (?, ?)"
            " ON CONFLICT(username) DO NOTHING",
            (username, "{}"),
        )


def _update_workbook(username: str, db: dict[str, Any]) -> None:
    with _db_connection() as conn:
        conn.execute(
            "INSERT INTO workbooks (username, db_json) VALUES (?, ?)"
            " ON CONFLICT(username) DO UPDATE SET db_json = excluded.db_json",
            (username, _serialize_db(db)),
        )


def _list_workbooks() -> list[dict[str, Any]]:
    with _db_connection() as conn:
        rows = conn.execute("""
            SELECT u.username, u.username AS label, COALESCE(w.db_json, '{}') AS db_json
            FROM users AS u
            LEFT JOIN workbooks AS w ON w.username = u.username
            ORDER BY u.username
            """).fetchall()

    return [
        {
            "id": row["username"],
            "userId": row["username"],
            "label": row["label"],
            "db": _deserialize_db(row["db_json"]),
        }
        for row in rows
    ]


def _export_snapshot() -> dict[str, Any]:
    return {
        "exportedAt": _utc_now_iso(),
        "app": "Dragonfly Tables",
        "workbooks": _list_workbooks(),
    }


def _auth_username(handler: BaseHTTPRequestHandler) -> str | None:
    header = handler.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header.removeprefix("Bearer ").strip()
    cutoff = _now() - SESSION_TTL_SECONDS

    with _db_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE created_at < ?", (cutoff,))
        row = conn.execute(
            "SELECT username, created_at FROM sessions WHERE token = ?",
            (token,),
        ).fetchone()

    if not row:
        return None
    if float(row["created_at"]) < cutoff:
        return None
    return str(row["username"])


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

    if register:
        try:
            _create_user(username, password)
        except ValueError as exc:
            _error(handler, HTTPStatus.CONFLICT, str(exc))
            return
    else:
        with _db_connection() as conn:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        if not row or not _verify_password(str(row["password_hash"]), password):
            _error(handler, HTTPStatus.UNAUTHORIZED, "Login failed")
            return

    token = _create_session(username)
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
        _send_json(
            handler,
            HTTPStatus.OK,
            {
                "items": _list_workbooks(),
                "record": {"id": username, "username": username},
            },
        )
        return

    if method in {"PUT", "PATCH", "POST"}:
        payload = _read_json(handler)
        workbook = payload.get("workbook")
        if not isinstance(workbook, dict):
            workbooks = payload.get("workbooks")
            if isinstance(workbooks, list):
                workbook = next(
                    (
                        item
                        for item in workbooks
                        if isinstance(item, dict)
                        and str(item.get("userId") or item.get("id") or "").strip()
                        == username
                    ),
                    None,
                )

        if not isinstance(workbook, dict):
            _error(handler, HTTPStatus.BAD_REQUEST, "Missing workbook.")
            return

        db = workbook.get("db")
        if not isinstance(db, dict):
            _error(handler, HTTPStatus.BAD_REQUEST, "Missing workbook data.")
            return

        _update_workbook(username, db)
        _send_json(handler, HTTPStatus.OK, {"ok": True})
        return

    _error(handler, HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed")


def _handle_export(handler: BaseHTTPRequestHandler) -> None:
    username = _auth_username(handler)
    if not username:
        _error(handler, HTTPStatus.UNAUTHORIZED, "Log in to export data.")
        return

    _send_json(handler, HTTPStatus.OK, _export_snapshot())


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
    server_version = "DragonflyTables/2.0"

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
        if path in {"/export.json", "/api/export.json"}:
            return _handle_export(self)
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
    _ensure_db()
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
