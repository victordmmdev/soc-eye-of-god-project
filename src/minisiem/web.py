"""Painel web local para visualizar o primeiro vertical slice do Mini-SIEM."""

import argparse
import html
from dataclasses import dataclass
from datetime import timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from minisiem.detection import MultipleFailedAuthenticationRule
from minisiem.domain import Alert, Event
from minisiem.ingestion import LinuxLogFileReader
from minisiem.parsing import LinuxAuthParser
from minisiem.storage import SQLiteEventRepository


@dataclass(frozen=True, slots=True)
class DashboardData:
    """Dados apresentados pelo painel após uma análise."""

    normalized_count: int
    events: list[Event]
    alerts: list[Alert]
    message: str | None = None


def analyze_sample(
    sample_path: Path,
    database_path: Path,
    year: int,
    threshold: int,
    window_minutes: int,
) -> DashboardData:
    """Executa o pipeline existente e prepara os dados para a interface."""
    parser = LinuxAuthParser(year=year)
    normalized_events = [
        event
        for line in LinuxLogFileReader(sample_path).read()
        if (event := parser.parse(line)) is not None
    ]
    repository = SQLiteEventRepository(database_path)
    repository.initialize()
    repository.add_many(normalized_events)
    events = repository.list_all()
    rule = MultipleFailedAuthenticationRule(
        threshold=threshold,
        window=timedelta(minutes=window_minutes),
    )
    return DashboardData(
        normalized_count=len(normalized_events),
        events=events,
        alerts=rule.evaluate(events),
        message=f"Análise concluída para {sample_path.name}.",
    )


def load_dashboard(database_path: Path, threshold: int, window_minutes: int) -> DashboardData:
    """Carrega os eventos já persistidos, sem processar novamente o log."""
    repository = SQLiteEventRepository(database_path)
    repository.initialize()
    events = repository.list_all()
    rule = MultipleFailedAuthenticationRule(
        threshold=threshold,
        window=timedelta(minutes=window_minutes),
    )
    return DashboardData(normalized_count=0, events=events, alerts=rule.evaluate(events))


def _escape(value: object) -> str:
    return html.escape(str(value))


def _event_table(events: list[Event]) -> str:
    if not events:
        return '<p class="empty">Nenhum evento persistido ainda.</p>'
    rows = []
    for event in reversed(events[-20:]):
        source_ip = event.fields.get("source_ip", "—")
        username = event.fields.get("username", "—")
        event_class = event.event_type.replace(".", "-")
        rows.append(
            "<tr>"
            f"<td>{_escape(event.timestamp.strftime('%Y-%m-%d %H:%M:%S %Z'))}</td>"
            f"<td><span class=\"tag {_escape(event_class)}\">{_escape(event.event_type)}</span></td>"
            f"<td>{_escape(event.host)}</td><td>{_escape(username)}</td><td>{_escape(source_ip)}</td>"
            "</tr>"
        )
    return """<div class="table-wrap"><table><thead><tr>
    <th>Horário</th><th>Tipo</th><th>Host</th><th>Usuário</th><th>IP de origem</th>
    </tr></thead><tbody>""" + "".join(rows) + "</tbody></table></div>"


def _alert_cards(alerts: list[Alert]) -> str:
    if not alerts:
        return '<p class="empty">Nenhum alerta para os parâmetros atuais.</p>'
    cards = []
    for alert in alerts:
        cards.append(
            "<article class=\"alert\">"
            f"<span class=\"severity\">{_escape(alert.severity)}</span>"
            f"<h3>{_escape(alert.rule_id)} · {_escape(alert.title)}</h3>"
            f"<p><strong>Origem:</strong> {_escape(alert.context.get('source_ip', '—'))} "
            f"<strong>Falhas:</strong> {_escape(alert.context.get('failure_count', '—'))} "
            f"em {_escape(alert.context.get('window_seconds', '—'))} segundos.</p>"
            "</article>"
        )
    return "".join(cards)


def render_dashboard(data: DashboardData, selected_sample: str, year: int, threshold: int, window_minutes: int) -> str:
    """Renderiza o dashboard sem depender de bibliotecas de frontend."""
    failures = sum(event.event_type == "auth.failure" for event in data.events)
    successes = sum(event.event_type == "auth.success" for event in data.events)
    total_events = len(data.events)
    failure_percent = round((failures / total_events) * 100) if total_events else 0
    success_percent = round((successes / total_events) * 100) if total_events else 0
    message = f'<p class="notice">{_escape(data.message)}</p>' if data.message else ""
    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Eye of GOD · Console de segurança</title><style>
:root {{ color-scheme:dark; --page:#1b1d20; --surface:#24272b; --surface-raised:#2a2d31; --line:#3a3e43; --text:#f1f2f3; --muted:#a9afb7; --dim:#777e87; --accent:#d8dde3; --red:#db6c68; --green:#72b998; --amber:#d6a85c; }}
* {{ box-sizing:border-box }} body {{ margin:0; background:var(--page); color:var(--text); font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif }}
.topbar {{ border-bottom:1px solid var(--line); background:#202225 }} .topbar-inner,main {{ max-width:1240px; margin:auto; padding-left:28px; padding-right:28px }} .topbar-inner {{ height:62px; display:flex; align-items:center; justify-content:space-between }} .brand {{ font-size:.92rem; font-weight:700; letter-spacing:.06em; text-transform:uppercase }} .brand span {{ color:var(--muted); font-weight:500 }} .environment {{ display:flex; align-items:center; gap:9px; color:var(--muted); font-size:.8rem }} .status-dot {{ width:8px; height:8px; border-radius:50%; background:var(--green); box-shadow:0 0 0 3px rgb(114 185 152 / .13) }}
main {{ padding-top:36px; padding-bottom:64px }} .page-head {{ display:flex; justify-content:space-between; align-items:end; margin-bottom:26px; gap:20px }} h1 {{ margin:0; font-size:1.75rem; letter-spacing:-.035em; font-weight:650 }} .subtitle {{ margin:5px 0 0; color:var(--muted) }} .updated {{ color:var(--dim); font-size:.8rem; white-space:nowrap }} h2 {{ margin:0; font-size:.92rem; letter-spacing:.01em }} h3 {{ margin:0 }}
.panel,.metric {{ background:var(--surface); border:1px solid var(--line); border-radius:8px }} .panel {{ padding:20px; margin-top:16px }} .panel-head {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:16px }} .panel-caption {{ color:var(--dim); font-size:.78rem }}
.run {{ display:flex; align-items:end; flex-wrap:wrap; gap:12px }} label {{ display:grid; gap:5px; color:var(--muted); font-size:.75rem; font-weight:600; text-transform:uppercase; letter-spacing:.045em }} input,select,button {{ border-radius:5px; border:1px solid var(--line); padding:9px 10px; font:inherit }} input,select {{ min-width:108px; background:#1d1f22; color:var(--text); outline:none }} input:focus,select:focus {{ border-color:#7d858e }} button {{ margin-left:auto; background:#d9dde1; color:#202225; border:0; font-size:.82rem; font-weight:700; cursor:pointer }} button:hover {{ background:#fff }}
.metrics {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin:16px 0 }} .metric {{ padding:17px 18px }} .metric b {{ display:block; font-size:1.7rem; font-weight:650; line-height:1.2; letter-spacing:-.04em }} .metric small {{ display:block; color:var(--muted); margin-top:3px }} .metric.alert-count b {{ color:var(--amber) }} .notice {{ margin:16px 0 0; border:1px solid #48505a; background:#252a30; border-radius:6px; padding:9px 12px; color:var(--muted); font-size:.86rem }}
.dashboard-grid {{ display:grid; grid-template-columns:1.35fr .65fr; gap:16px }} .distribution {{ display:grid; gap:16px }} .bar-label {{ display:flex; justify-content:space-between; color:var(--muted); font-size:.82rem; margin-bottom:6px }} .bar {{ height:7px; border-radius:99px; background:#17191c; overflow:hidden }} .bar > i {{ display:block; height:100%; border-radius:inherit }} .bar-fail {{ background:var(--red) }} .bar-success {{ background:var(--green) }} .risk {{ border-left:3px solid var(--amber); padding-left:13px }} .risk strong {{ display:block; margin-bottom:4px; font-size:1.1rem }} .risk p {{ margin:0; color:var(--muted); font-size:.86rem }}
.alert {{ border:1px solid #51483a; border-left:3px solid var(--amber); padding:14px 15px; background:#292720; border-radius:5px; margin:9px 0 }} .alert h3 {{ margin:4px 0; font-size:.93rem }} .alert p {{ margin:0; color:var(--muted); font-size:.86rem }} .severity {{ color:var(--amber); text-transform:uppercase; font-size:.7rem; font-weight:750; letter-spacing:.08em }}
.table-wrap {{ overflow:auto }} table {{ width:100%; border-collapse:collapse; min-width:680px }} th,td {{ padding:12px 10px; border-bottom:1px solid var(--line); text-align:left }} td:first-child,th:first-child {{ padding-left:0 }} td:last-child,th:last-child {{ padding-right:0 }} th {{ color:var(--dim); font-size:.7rem; text-transform:uppercase; letter-spacing:.07em; font-weight:650 }} .tag {{ padding:3px 7px; border-radius:4px; font-size:.72rem; white-space:nowrap; font-weight:600 }} .auth-failure {{ background:#482d2e; color:#f0aaa6 }} .auth-success {{ background:#263c34; color:#a5d8be }} .empty {{ color:var(--muted) }} footer {{ color:var(--dim); font-size:.78rem; margin-top:20px }} @media(max-width:780px) {{ .topbar-inner,main {{ padding-left:18px; padding-right:18px }} .page-head {{ display:block }} .updated {{ margin-top:9px }} .metrics {{ grid-template-columns:repeat(2,1fr) }} .dashboard-grid {{ grid-template-columns:1fr }} button {{ margin-left:0 }} }}
</style></head><body>
<div class="topbar"><div class="topbar-inner"><div class="brand">SOC Eye of GOD <span>/ Security Operations</span></div><div class="environment"><i class="status-dot"></i> Sensor local ativo</div></div></div><main>
<header class="page-head"><div><h1>Visão geral de segurança</h1><p class="subtitle">Monitoramento de eventos de autenticação SSH</p></div><div class="updated">Fonte: SQLite local · Regra AUTH-001</div></header>
<section class="panel"><div class="panel-head"><h2>Configuração de análise</h2><span class="panel-caption">Log de exemplo</span></div><form class="run" method="post" action="/run"><label>Fonte<select name="sample"><option value="{_escape(selected_sample)}">{_escape(selected_sample)}</option></select></label><label>Ano<input name="year" type="number" value="{year}" min="2000" max="2100"></label><label>Limiar<input name="threshold" type="number" value="{threshold}" min="2" max="100"></label><label>Janela<input name="window_minutes" type="number" value="{window_minutes}" min="1" max="1440"></label><button type="submit">Executar análise</button></form></section>
{message}<section class="metrics"><article class="metric"><b>{total_events}</b><small>Eventos armazenados</small></article><article class="metric"><b>{failures}</b><small>Falhas de autenticação</small></article><article class="metric"><b>{successes}</b><small>Acessos aceitos</small></article><article class="metric alert-count"><b>{len(data.alerts)}</b><small>Alertas de segurança</small></article></section>
<section class="dashboard-grid"><article class="panel"><div class="panel-head"><h2>Distribuição de eventos</h2><span class="panel-caption">Base persistida</span></div><div class="distribution"><div><div class="bar-label"><span>Falhas de autenticação</span><span>{failure_percent}%</span></div><div class="bar"><i class="bar-fail" style="width:{failure_percent}%"></i></div></div><div><div class="bar-label"><span>Acessos aceitos</span><span>{success_percent}%</span></div><div class="bar"><i class="bar-success" style="width:{success_percent}%"></i></div></div></div></article><article class="panel risk"><h2>Postura atual</h2><strong>{'Atenção necessária' if data.alerts else 'Sem alertas ativos'}</strong><p>{'A regra AUTH-001 identificou tentativas repetidas de autenticação.' if data.alerts else 'Não há correlações que excedam o limiar configurado.'}</p></article></section>
<section class="panel"><div class="panel-head"><h2>Alertas ativos</h2><span class="panel-caption">Correlação por IP de origem</span></div>{_alert_cards(data.alerts)}</section><section class="panel"><div class="panel-head"><h2>Eventos recentes</h2><span class="panel-caption">Últimos 20 registros</span></div>{_event_table(data.events)}</section>
<footer>O painel é local (127.0.0.1). A reexecução do mesmo log ainda pode duplicar eventos — limitação registrada no diário de desenvolvimento.</footer>
</main></body></html>"""


class DashboardServer(ThreadingHTTPServer):
    """Servidor com a configuração de execução do painel."""

    def __init__(self, address: tuple[str, int], samples_dir: Path, database_path: Path) -> None:
        super().__init__(address, DashboardRequestHandler)
        self.samples_dir = samples_dir
        self.database_path = database_path


class DashboardRequestHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def do_GET(self) -> None:
        if self.path != "/":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self._send_dashboard(load_dashboard(self.server.database_path, 3, 5), "auth.log", 2026, 3, 5)

    def do_POST(self) -> None:
        if self.path != "/run":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            form = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
            sample = Path(form.get("sample", ["auth.log"])[0]).name
            year = int(form.get("year", ["2026"])[0])
            threshold = int(form.get("threshold", ["3"])[0])
            window_minutes = int(form.get("window_minutes", ["5"])[0])
            if not 2000 <= year <= 2100 or threshold < 2 or window_minutes < 1:
                raise ValueError("Parâmetros fora do intervalo permitido.")
            sample_path = self.server.samples_dir / sample
            if not sample_path.is_file():
                raise ValueError("Log de exemplo não encontrado.")
            data = analyze_sample(sample_path, self.server.database_path, year, threshold, window_minutes)
        except (UnicodeDecodeError, ValueError) as error:
            data = load_dashboard(self.server.database_path, 3, 5)
            data = DashboardData(data.normalized_count, data.events, data.alerts, f"Erro: {error}")
            sample, year, threshold, window_minutes = "auth.log", 2026, 3, 5
        self._send_dashboard(data, sample, year, threshold, window_minutes)

    def _send_dashboard(self, data: DashboardData, sample: str, year: int, threshold: int, window_minutes: int) -> None:
        content = render_dashboard(data, sample, year, threshold, window_minutes).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def main() -> None:
    parser = argparse.ArgumentParser(description="Inicia o painel web local do Mini-SIEM.")
    parser.add_argument("--host", default="127.0.0.1", help="host local a escutar")
    parser.add_argument("--port", type=int, default=8000, help="porta local")
    parser.add_argument("--database", type=Path, default=Path("data/runtime/minisiem.db"))
    parser.add_argument("--samples-dir", type=Path, default=Path("data/samples"))
    args = parser.parse_args()
    args.database.parent.mkdir(parents=True, exist_ok=True)
    server = DashboardServer((args.host, args.port), args.samples_dir, args.database)
    print(f"Painel disponível em http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nPainel encerrado.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
