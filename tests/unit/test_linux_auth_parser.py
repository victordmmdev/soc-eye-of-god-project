from minisiem.parsing import LinuxAuthParser


def test_parser_normalizes_failed_ssh_authentication() -> None:
    raw = "Aug 10 09:00:01 web-01 sshd[2418]: Failed password for invalid user admin from 203.0.113.10 port 50122 ssh2"

    event = LinuxAuthParser(year=2026).parse(raw)

    assert event is not None
    assert event.event_type == "auth.failure"
    assert event.host == "web-01"
    assert event.fields["username"] == "admin"
    assert event.fields["source_ip"] == "203.0.113.10"
    assert event.fields["source_port"] == 50122


def test_parser_ignores_unsupported_messages() -> None:
    assert LinuxAuthParser(year=2026).parse("Aug 10 09:00:01 web-01 cron: job started") is None
