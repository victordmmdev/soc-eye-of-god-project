from datetime import datetime, timezone

from minisiem.domain import Event
from minisiem.storage import SQLiteEventRepository


def make_event() -> Event:
    return Event(
        timestamp=datetime(2026, 8, 10, tzinfo=timezone.utc),
        source="linux.auth",
        host="lab-host",
        event_type="auth.failure",
        raw_message="synthetic event",
        fields={"source_ip": "192.0.2.10"},
    )


def test_event_identity_is_deterministic() -> None:
    assert make_event().id == make_event().id


def test_repository_deduplicates_reprocessed_events(tmp_path) -> None:
    repository = SQLiteEventRepository(tmp_path / "events.db")
    repository.initialize()
    event = make_event()

    assert repository.add_many([event]) == 1
    assert repository.add_many([event]) == 0
    assert repository.list_all() == [event]
