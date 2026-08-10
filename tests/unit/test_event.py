from datetime import datetime, timezone

import pytest

from minisiem.domain import Event


def test_event_accepts_required_normalized_data() -> None:
    event = Event(
        timestamp=datetime(2026, 8, 10, tzinfo=timezone.utc),
        source="linux.auth",
        host="web-01",
        event_type="auth.failure",
        raw_message="Failed password",
        fields={"source_ip": "203.0.113.10"},
    )

    assert event.fields["source_ip"] == "203.0.113.10"
    assert event.id


def test_event_requires_timezone_aware_timestamp() -> None:
    with pytest.raises(ValueError, match="fuso horário"):
        Event(
            timestamp=datetime(2026, 8, 10),
            source="linux.auth",
            host="web-01",
            event_type="auth.failure",
            raw_message="Failed password",
        )
