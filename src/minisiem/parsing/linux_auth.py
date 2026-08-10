"""Parser inicial para eventos SSH no formato de syslog Linux."""

import re
from datetime import datetime, timezone

from minisiem.domain import Event


_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
)
_FAILED_AUTH = re.compile(
    r"^Failed password for (?:invalid user )?(?P<username>\S+) from (?P<source_ip>\S+) port (?P<port>\d+)"
)
_SUCCESSFUL_AUTH = re.compile(
    r"^Accepted \S+ for (?P<username>\S+) from (?P<source_ip>\S+) port (?P<port>\d+)"
)


class LinuxAuthParser:
    """Converte mensagens sshd suportadas em eventos normalizados."""

    def __init__(self, year: int | None = None) -> None:
        self.year = year or datetime.now(timezone.utc).year

    def parse(self, raw_message: str) -> Event | None:
        prefix = _SYSLOG_PREFIX.match(raw_message)
        if prefix is None:
            return None

        details = _FAILED_AUTH.match(prefix["message"])
        event_type = "auth.failure"
        if details is None:
            details = _SUCCESSFUL_AUTH.match(prefix["message"])
            event_type = "auth.success"
        if details is None:
            return None

        timestamp = datetime.strptime(
            f"{self.year} {prefix['month']} {prefix['day']} {prefix['time']}",
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
        fields = {
            "username": details["username"],
            "source_ip": details["source_ip"],
            "source_port": int(details["port"]),
            "service": "sshd",
        }
        if prefix["pid"] is not None:
            fields["process_id"] = int(prefix["pid"])

        return Event(
            timestamp=timestamp,
            source="linux.auth",
            host=prefix["host"],
            event_type=event_type,
            raw_message=raw_message,
            fields=fields,
        )
