import json
import os
import sqlite3
import sys

# Ensure project root is on sys.path so local imports work in pytest.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import backup_users
import server


def test_backup_users_creates_sqlite_snapshot(tmp_path, monkeypatch):
    db_file = tmp_path / "dragonfly.sqlite3"
    backup_dir = tmp_path / "backups"
    monkeypatch.setattr(server, "DB_FILE", db_file)
    monkeypatch.setattr(backup_users, "DB_FILE", db_file)
    monkeypatch.setattr(backup_users, "BACKUP_DIR", backup_dir)

    server._ensure_db()
    server._create_user("alice", "alicepw")
    server._update_workbook("alice", {"week1": {"pushup": {"monday": 5}}})

    assert backup_users.main() == 0

    backups = sorted(backup_dir.glob("dragonfly-*.sqlite3"))
    assert len(backups) == 1

    with sqlite3.connect(backups[0]) as conn:
        row = conn.execute(
            "SELECT db_json FROM workbooks WHERE username = ?", ("alice",)
        ).fetchone()

    assert json.loads(row[0]) == {"week1": {"pushup": {"monday": 5}}}
