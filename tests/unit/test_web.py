from minisiem.web import DashboardData, render_dashboard


def test_dashboard_includes_technical_navigation_and_release_history() -> None:
    page = render_dashboard(
        DashboardData(normalized_count=0, events=[], alerts=[]),
        selected_sample="auth.log",
        year=2026,
        threshold=3,
        window_minutes=5,
    )

    assert 'data-page="overview"' in page
    assert 'data-page="pipeline"' in page
    assert 'data-page="components"' in page
    assert 'data-page="releases"' in page
    assert "domain/event.py" in page
    assert "Regra AUTH-001" in page
    assert "v1.0.1" in page


def test_dashboard_escapes_event_data_in_the_table() -> None:
    from datetime import datetime, timezone

    from minisiem.domain import Event

    event = Event(
        timestamp=datetime(2026, 8, 10, tzinfo=timezone.utc),
        source="linux.auth",
        host="<host>",
        event_type="auth.failure",
        raw_message="Failed password",
        fields={"username": "<admin>", "source_ip": "203.0.113.10"},
    )

    page = render_dashboard(DashboardData(1, [event], []), "auth.log", 2026, 3, 5)

    assert "&lt;host&gt;" in page
    assert "&lt;admin&gt;" in page
