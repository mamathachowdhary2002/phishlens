import sqlite3
import os
import uuid

DB = os.getenv("CASE_DB", "/tmp/phishlens.db")


def init():
    directory = os.path.dirname(DB)

    if directory:
        os.makedirs(directory, exist_ok=True)

    with sqlite3.connect(DB) as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                title TEXT,
                notes TEXT,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


def save_case(title, notes):
    cid = str(uuid.uuid4())[:8].upper()

    with sqlite3.connect(DB) as c:
        c.execute(
            "INSERT INTO cases(id, title, notes) VALUES (?, ?, ?)",
            (cid, title, notes)
        )

    return cid


def list_cases():
    with sqlite3.connect(DB) as c:
        return [
            {
                "id": r[0],
                "title": r[1],
                "notes": r[2],
                "created": r[3]
            }
            for r in c.execute(
                "SELECT id, title, notes, created FROM cases ORDER BY created DESC"
            )
        ]
