"""Interface de linha de comando do primeiro pipeline vertical."""

import argparse
from datetime import timedelta
from pathlib import Path

from minisiem.detection import MultipleFailedAuthenticationRule
from minisiem.ingestion import LinuxLogFileReader
from minisiem.parsing import LinuxAuthParser
from minisiem.storage import SQLiteEventRepository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Executa o pipeline inicial do Mini-SIEM.")
    parser.add_argument("log_file", type=Path, help="arquivo Linux auth/syslog a processar")
    parser.add_argument("--database", type=Path, default=Path("data/runtime/minisiem.db"))
    parser.add_argument("--threshold", type=int, default=3, help="falhas para gerar alerta")
    parser.add_argument("--window-minutes", type=int, default=5, help="janela de correlação")
    parser.add_argument("--year", type=int, default=None, help="ano dos registros syslog")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.database.parent.mkdir(parents=True, exist_ok=True)

    parser = LinuxAuthParser(year=args.year)
    events = [event for line in LinuxLogFileReader(args.log_file).read() if (event := parser.parse(line))]

    repository = SQLiteEventRepository(args.database)
    repository.initialize()
    repository.add_many(events)

    rule = MultipleFailedAuthenticationRule(
        threshold=args.threshold,
        window=timedelta(minutes=args.window_minutes),
    )
    alerts = rule.evaluate(events)
    print(f"Eventos normalizados e armazenados: {len(events)}")
    print(f"Alertas gerados: {len(alerts)}")
    for alert in alerts:
        print(f"[{alert.severity.upper()}] {alert.rule_id}: {alert.title} ({alert.context['source_ip']})")


if __name__ == "__main__":
    main()
