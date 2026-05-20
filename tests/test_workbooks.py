import io
import json
import os
import sqlite3
import sys
import threading
from pathlib import Path

import pytest

# Ensure project root is on sys.path so `import server` works when running pytest.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import server


class DummyHeaders(dict):
    def get(self, key, default=None):
        return super().get(key, default)


class DummyHandler:
    def __init__(self, headers: dict, body: bytes = b""):
        self.headers = DummyHeaders(headers)
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self._sent = []

    def send_response(self, code: int) -> None:
        self._sent.append(("status", code))

    def send_header(self, name: str, value: str) -> None:
        self._sent.append(("header", name, value))

    def end_headers(self) -> None:
        self._sent.append(("end",))


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DB_FILE", tmp_path / "dragonfly.sqlite3")
    server._ensure_db()
    return tmp_path


def seed_user(username: str, password: str, db: dict[str, object]) -> None:
    server._create_user(username, password)
    server._update_workbook(username, db)


def workbook_map(snapshot: dict[str, object]) -> dict[str, dict[str, object]]:
    return {
        workbook["userId"]: workbook["db"] for workbook in snapshot.get("workbooks", [])
    }


def test_concurrent_saves_by_different_users_are_preserved(temp_db):
    seed_user("alice", "alicepw", {"week1": {"pushup": {"monday": 1}}})
    seed_user("bob", "bobpw", {"week1": {"pullup": {"tuesday": 2}}})

    alice_token = server._create_session("alice")
    bob_token = server._create_session("bob")

    alice_payload = json.dumps(
        {"workbook": {"db": {"week1": {"pushup": {"monday": 11}}}}}
    ).encode("utf-8")
    bob_payload = json.dumps(
        {"workbook": {"db": {"week1": {"pullup": {"tuesday": 22}}}}}
    ).encode("utf-8")

    barrier = threading.Barrier(3)
    errors: list[BaseException] = []

    def worker(token: str, payload: bytes) -> None:
        handler = DummyHandler(
            {
                "Authorization": f"Bearer {token}",
                "Content-Length": str(len(payload)),
            },
            body=payload,
        )
        barrier.wait()
        try:
            server._handle_workbooks(handler, "PUT")
        except BaseException as exc:  # pragma: no cover - surfaced by assertion
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(alice_token, alice_payload)),
        threading.Thread(target=worker, args=(bob_token, bob_payload)),
    ]

    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()

    assert not errors

    snapshot = server._export_snapshot()
    workbooks = workbook_map(snapshot)
    assert workbooks["alice"] == {"week1": {"pushup": {"monday": 11}}}
    assert workbooks["bob"] == {"week1": {"pullup": {"tuesday": 22}}}

    with sqlite3.connect(server.DB_FILE) as conn:
        alice_row = conn.execute(
            "SELECT db_json FROM workbooks WHERE username = ?", ("alice",)
        ).fetchone()
        bob_row = conn.execute(
            "SELECT db_json FROM workbooks WHERE username = ?", ("bob",)
        ).fetchone()

    assert json.loads(alice_row[0]) == {"week1": {"pushup": {"monday": 11}}}
    assert json.loads(bob_row[0]) == {"week1": {"pullup": {"tuesday": 22}}}


def test_export_snapshot_reflects_latest_data(temp_db):
    seed_user("alice", "alicepw", {"week1": {"pushup": {"monday": 1}}})
    token = server._create_session("alice")
    payload = json.dumps(
        {"workbook": {"db": {"week1": {"pushup": {"monday": 99}}}}}
    ).encode("utf-8")
    handler = DummyHandler(
        {
            "Authorization": f"Bearer {token}",
            "Content-Length": str(len(payload)),
        },
        body=payload,
    )

    server._handle_workbooks(handler, "PUT")

    snapshot = server._export_snapshot()
    workbooks = workbook_map(snapshot)
    assert workbooks["alice"] == {"week1": {"pushup": {"monday": 99}}}
