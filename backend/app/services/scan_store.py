"""SQLite persistence for scan results with basic input redaction."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

DEFAULT_DATABASE_PATH = Path(__file__).resolve().parents[2] / "data" / "phishguard.sqlite3"
EMAIL_PATTERN = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_PATTERN = re.compile(r"(?<!\w)(?:\+?\d[\d(). -]{7,}\d)(?!\w)")
SECRET_PATTERN = re.compile(r"(?i)\b(password|passcode|token|api[_ -]?key|secret)\s*[:=]\s*([^\s,;]+)")
URL_PATTERN = re.compile(r"(?i)https?://[^\s<>\"']+")


def redact_url(url: str) -> str:
    """Remove URL credentials and redact query values before persistence."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        try:
            port = parsed.port
        except ValueError:
            port = None
        netloc = host + (f":{port}" if port else "")
        query = urlencode([(key, "[redacted]") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
        return urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))
    except (ValueError, UnicodeError):
        return "[URL omitted: invalid format]"


def redact_message(text: str) -> str:
    """Reduce common direct identifiers/secrets before writing a message to disk."""
    redacted = EMAIL_PATTERN.sub("[email redacted]", text)
    redacted = PHONE_PATTERN.sub("[phone redacted]", redacted)
    redacted = SECRET_PATTERN.sub(lambda match: f"{match.group(1)}=[redacted]", redacted)
    return URL_PATTERN.sub(lambda match: redact_url(match.group(0)), redacted)


class ScanStore:
    def __init__(self, database_path: Path | None = None) -> None:
        configured_path = os.environ.get("PHISHGUARD_DATABASE_PATH")
        self.database_path = Path(configured_path) if configured_path else (database_path or DEFAULT_DATABASE_PATH)

    def _connect(self) -> sqlite3.Connection:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    scan_type TEXT NOT NULL CHECK (scan_type IN ('url', 'message')),
                    input_redacted TEXT NOT NULL,
                    prediction TEXT NOT NULL CHECK (prediction IN ('potential_phishing', 'no_phishing_detected')),
                    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
                    risk_category TEXT NOT NULL CHECK (risk_category IN ('low', 'medium', 'high', 'critical')),
                    indicators_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )"""
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_scans_prediction ON scans(prediction)")

    @staticmethod
    def _public_record(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "scan_type": row["scan_type"],
            "input_excerpt": row["input_redacted"][:180],
            "prediction": row["prediction"],
            "risk_score": row["risk_score"],
            "risk_category": row["risk_category"],
            "created_at": row["created_at"],
        }

    def save(self, result: dict[str, Any], submitted_input: str) -> dict[str, Any]:
        scan_type = result["scan_type"]
        redacted = redact_url(submitted_input) if scan_type == "url" else redact_message(submitted_input)
        result = {**result, "input_excerpt": redacted[:180]}
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO scans
                    (id, scan_type, input_redacted, prediction, risk_score, risk_category, indicators_json, result_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    result["id"], scan_type, redacted, result["prediction"], result["risk_score"],
                    result["risk_category"], json.dumps(result["indicators"], ensure_ascii=False),
                    json.dumps(result, ensure_ascii=False), result["created_at"],
                ),
            )
        return result

    def list_scans(self, limit: int = 100, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        with self._connection() as connection:
            total = int(connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0])
            rows = connection.execute(
                "SELECT * FROM scans ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [self._public_record(row) for row in rows], total

    def get(self, scan_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        result = json.loads(row["result_json"])
        result["input_excerpt"] = row["input_redacted"][:180]
        return result

    def delete(self, scan_id: str) -> bool:
        with self._connection() as connection:
            cursor = connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cursor.rowcount > 0

    def statistics(self) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute(
                """SELECT COUNT(*) AS total_scans,
                    SUM(CASE WHEN prediction = 'potential_phishing' THEN 1 ELSE 0 END) AS phishing_detections,
                    SUM(CASE WHEN risk_category IN ('high', 'critical') THEN 1 ELSE 0 END) AS suspicious_results,
                    SUM(CASE WHEN scan_type = 'url' THEN 1 ELSE 0 END) AS url_scans,
                    SUM(CASE WHEN scan_type = 'message' THEN 1 ELSE 0 END) AS message_scans,
                    MAX(created_at) AS last_scan_at
                    FROM scans"""
            ).fetchone()
        return {
            "total_scans": int(row["total_scans"] or 0),
            "phishing_detections": int(row["phishing_detections"] or 0),
            "suspicious_results": int(row["suspicious_results"] or 0),
            "url_scans": int(row["url_scans"] or 0),
            "message_scans": int(row["message_scans"] or 0),
            "last_scan_at": row["last_scan_at"],
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
