"""Persistência local de eventos usando apenas SQLite da biblioteca padrão."""

import json
import sqlite3
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from minisiem.domain import Event


class SQLiteEventRepository:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    host TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    raw_message TEXT NOT NULL,
                    fields_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(event_type, timestamp)"
            )

    def add(self, event: Event) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO events
                (id, timestamp, source, host, event_type, raw_message, fields_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                self._event_row(event),
            )

    def add_many(self, events: Iterable[Event]) -> None:
        with self._connect() as connection:
            connection.executemany(
                """INSERT OR IGNORE INTO events
                (id, timestamp, source, host, event_type, raw_message, fields_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (self._event_row(event) for event in events),
            )

    def list_all(self) -> list[Event]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, timestamp, source, host, event_type, raw_message, fields_json "
                "FROM events ORDER BY timestamp"
            ).fetchall()
        return [
            Event(
                id=row["id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                source=row["source"],
                host=row["host"],
                event_type=row["event_type"],
                raw_message=row["raw_message"],
                fields=json.loads(row["fields_json"]),
            )
            for row in rows
        ]

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _event_row(event: Event) -> tuple[str, str, str, str, str, str, str]:
        return (
            event.id,
            event.timestamp.isoformat(),
            event.source,
            event.host,
            event.event_type,
            event.raw_message,
            json.dumps(event.fields, sort_keys=True),
        )
