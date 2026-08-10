from datetime import datetime, timedelta, timezone

from minisiem.detection import MultipleFailedAuthenticationRule
from minisiem.domain import Event


def failed_event(offset_seconds: int, source_ip: str = "203.0.113.10") -> Event:
    return Event(
        timestamp=datetime(2026, 8, 10, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds),
        source="linux.auth",
        host="web-01",
        event_type="auth.failure",
        raw_message="Failed password",
        fields={"source_ip": source_ip},
    )


def test_rule_alerts_after_three_failures_in_window() -> None:
    alerts = MultipleFailedAuthenticationRule(threshold=3).evaluate(
        [failed_event(0), failed_event(60), failed_event(120)]
    )

    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-001"
    assert alerts[0].context["source_ip"] == "203.0.113.10"
    assert len(alerts[0].event_ids) == 3


def test_rule_does_not_alert_when_failures_are_outside_window() -> None:
    alerts = MultipleFailedAuthenticationRule(window=timedelta(minutes=5)).evaluate(
        [failed_event(0), failed_event(60), failed_event(360)]
    )

    assert alerts == []
