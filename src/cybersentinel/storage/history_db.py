"""Local SQLite persistence for CyberSentinel analysis and replay run history."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import time
from typing import Any

DB_PATH = Path("data/cybersentinel_history.db")


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path = DB_PATH) -> None:
    """Initialize local schema."""
    with get_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                dataset_name TEXT,
                dataset_hash TEXT,
                total_records INTEGER,
                blocked_records INTEGER,
                allowed_records INTEGER,
                policies_created INTEGER,
                containment_rate REAL,
                throughput_fps REAL,
                elapsed_seconds REAL,
                status TEXT,
                metadata_json TEXT
            );
        """)
        conn.commit()


def record_run(
    run_id: str,
    dataset_name: str,
    total_records: int,
    blocked_records: int,
    allowed_records: int,
    policies_created: int,
    containment_rate: float,
    throughput_fps: float,
    elapsed_seconds: float,
    status: str = "COMPLETED",
    dataset_hash: str = "",
    metadata: dict[str, Any] | None = None,
    db_path: Path = DB_PATH,
) -> dict[str, Any]:
    init_db(db_path)
    meta_str = json.dumps(metadata or {})
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO runs (
                id, dataset_name, dataset_hash, total_records, blocked_records,
                allowed_records, policies_created, containment_rate, throughput_fps,
                elapsed_seconds, status, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                dataset_name,
                dataset_hash,
                total_records,
                blocked_records,
                allowed_records,
                policies_created,
                containment_rate,
                throughput_fps,
                elapsed_seconds,
                status,
                meta_str,
            ),
        )
        conn.commit()
    return {
        "id": run_id,
        "dataset_name": dataset_name,
        "total_records": total_records,
        "status": status,
    }


def list_runs(limit: int = 15, db_path: Path = DB_PATH) -> list[dict[str, Any]]:
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)
        )
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

