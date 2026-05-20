#!/usr/bin/env python3
"""Create a daily backup of the SQLite database and keep the last 14 days."""

from __future__ import annotations

import datetime
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data"
DB_FILE = DATA_DIR / "dragonfly.sqlite3"
BACKUP_DIR = DATA_DIR / "backups"
KEEP_DAYS = 14


def main() -> int:
    if not DB_FILE.exists():
        print(f"Database file not found: {DB_FILE}", file=sys.stderr)
        return 2

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    now = datetime.datetime.now(datetime.timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    dest = BACKUP_DIR / f"dragonfly-{stamp}.sqlite3"

    with sqlite3.connect(DB_FILE) as source, sqlite3.connect(dest) as target:
        source.backup(target)

    print(f"Wrote backup: {dest}")

    cutoff = now - datetime.timedelta(days=KEEP_DAYS)
    for path in sorted(BACKUP_DIR.glob("dragonfly-*.sqlite3")):
        try:
            mtime = datetime.datetime.fromtimestamp(
                path.stat().st_mtime, datetime.timezone.utc
            )
            if mtime < cutoff:
                path.unlink()
                print(f"Removed old backup: {path}")
        except Exception as exc:
            print(f"Failed to consider {path}: {exc}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
