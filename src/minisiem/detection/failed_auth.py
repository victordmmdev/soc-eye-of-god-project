"""Regra de correlação para múltiplas falhas de autenticação."""

from collections import defaultdict, deque
from collections.abc import Iterable
from datetime import timedelta, timezone

from minisiem.domain import Alert, Event


class MultipleFailedAuthenticationRule:
    rule_id = "AUTH-001"

    def __init__(self, threshold: int = 3, window: timedelta = timedelta(minutes=5)) -> None:
        if threshold < 2:
            raise ValueError("threshold deve ser pelo menos 2")
        self.threshold = threshold
        self.window = window

    def evaluate(self, events: Iterable[Event]) -> list[Alert]:
        failures_by_ip: dict[str, deque[Event]] = defaultdict(deque)
        alerts: list[Alert] = []
        alerted_ips: set[str] = set()

        failures = sorted(
            (event for event in events if event.event_type == "auth.failure"),
            key=lambda event: event.timestamp,
        )
        for event in failures:
            source_ip = event.fields.get("source_ip")
            if not isinstance(source_ip, str):
                continue
            recent = failures_by_ip[source_ip]
            while recent and event.timestamp - recent[0].timestamp > self.window:
                recent.popleft()
            recent.append(event)
            if len(recent) >= self.threshold and source_ip not in alerted_ips:
                alerts.append(
                    Alert(
                        rule_id=self.rule_id,
                        title="Múltiplas falhas de autenticação SSH",
                        severity="medium",
                        created_at=event.timestamp.astimezone(timezone.utc),
                        event_ids=tuple(item.id for item in recent),
                        context={
                            "source_ip": source_ip,
                            "failure_count": len(recent),
                            "window_seconds": int(self.window.total_seconds()),
                        },
                    )
                )
                alerted_ips.add(source_ip)
        return alerts
