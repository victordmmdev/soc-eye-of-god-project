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


TECHNICAL_MODULES = (
    (
        "domain/event.py",
        "Evento normalizado",
        "Define o contrato imutável de um evento de segurança: horário, origem, host, tipo, mensagem bruta e campos enriquecidos.",
        "É o formato comum entre parser, banco, regra de detecção e interfaces.",
        "Trocar UUID aleatório por identidade determinística; tornar fields realmente imutável e validar serialização JSON.",
    ),
    (
        "domain/alert.py",
        "Alerta de detecção",
        "Representa o resultado de uma regra, com severidade, eventos relacionados e contexto investigável.",
        "AUTH-001 cria Alert quando identifica repetição de falhas SSH para o mesmo IP.",
        "Validar severidade e timezone; persistir alertas e permitir estado, responsável e anotações.",
    ),
    (
        "ingestion/linux_file.py",
        "Leitura de logs",
        "Lê um arquivo de texto linha a linha, sem carregar todo o conteúdo de uma vez.",
        "Ignora linhas vazias e substitui bytes inválidos para manter o pipeline executável.",
        "Adicionar rotação de arquivos, acompanhamento contínuo e métricas de ingestão.",
    ),
    (
        "parsing/linux_auth.py",
        "Parser SSH Linux",
        "Reconhece mensagens syslog sshd de falha de senha e de autenticação aceita.",
        "Extrai host, usuário, IP, porta, PID e horário para gerar Event normalizado.",
        "Configurar timezone; validar IP; preservar invalid user e ampliar formatos suportados.",
    ),
    (
        "storage/sqlite.py",
        "Repositório SQLite",
        "Cria o schema local e transforma Event em linhas SQLite com campos adicionais em JSON.",
        "Oferece inicialização, inserção individual/em lote e leitura ordenada de eventos.",
        "Fechar conexões explicitamente, informar inserções efetivas e deduplicar eventos.",
    ),
    (
        "detection/failed_auth.py",
        "Regra AUTH-001",
        "Correlaciona falhas de autenticação por IP dentro de uma janela de tempo configurável.",
        "Ao atingir o limiar, cria um alerta MEDIUM com IDs dos eventos e contexto da ocorrência.",
        "Permitir novas campanhas do mesmo IP em janelas distintas e unificar a correlação CLI/painel.",
    ),
    (
        "cli.py",
        "Execução por terminal",
        "Expõe o pipeline com parâmetros de arquivo, banco, ano, limiar e janela.",
        "Normaliza, persiste e mostra o resumo de eventos e alertas no terminal.",
        "Extrair um serviço de aplicação compartilhado com o painel e melhorar mensagens de erro.",
    ),
    (
        "web.py",
        "Console técnico local",
        "Servidor HTTP local que apresenta operação, fluxo, componentes e histórico de versões.",
        "Usa HTML, CSS e JavaScript locais; nenhuma dependência externa ou telemetria é carregada.",
        "Adicionar testes HTTP, filtros persistentes, páginas de detalhe e autenticação antes de expor à rede.",
    ),
)

RELEASE_HISTORY = (
    (
        "1.0.1",
        "Hotfix · operação e documentação",
        "Painel local, console técnico, comando minisiem-web e documento de status do projeto.",
        "Atual",
    ),
    (
        "0.1.0",
        "Vertical slice inicial",
        "Ingestão Linux, parser SSH, SQLite, AUTH-001, CLI, amostra e testes iniciais.",
        "Base",
    ),
)


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


def _technical_cards() -> str:
    """Monta a documentação navegável dos componentes implementados."""
    cards = []
    for path, title, purpose, behavior, improvement in TECHNICAL_MODULES:
        cards.append(
            "<article class=\"module-card\" data-module>"
            f"<p class=\"file-path\">src/minisiem/{_escape(path)}</p>"
            f"<h3>{_escape(title)}</h3><p>{_escape(purpose)}</p>"
            f"<dl><div><dt>Como funciona</dt><dd>{_escape(behavior)}</dd></div>"
            f"<div><dt>Próxima melhoria</dt><dd>{_escape(improvement)}</dd></div></dl>"
            "</article>"
        )
    return "".join(cards)


def _release_timeline() -> str:
    """Monta o histórico de entregas exibido no painel."""
    return "".join(
        "<article class=\"release\">"
        f"<span class=\"release-version\">v{_escape(version)}</span>"
        f"<div><h3>{_escape(title)}</h3><p>{_escape(description)}</p></div>"
        f"<span class=\"release-state\">{_escape(state)}</span></article>"
        for version, title, description, state in RELEASE_HISTORY
    )


def render_legacy_dashboard(data: DashboardData, selected_sample: str, year: int, threshold: int, window_minutes: int) -> str:
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


def render_dashboard(data: DashboardData, selected_sample: str, year: int, threshold: int, window_minutes: int) -> str:
    """Renderiza o console técnico responsivo do SOC Eye of GOD."""
    failures = sum(event.event_type == "auth.failure" for event in data.events)
    successes = sum(event.event_type == "auth.success" for event in data.events)
    total_events = len(data.events)
    failure_percent = round((failures / total_events) * 100) if total_events else 0
    success_percent = round((successes / total_events) * 100) if total_events else 0
    message = f'<p class="notice">{_escape(data.message)}</p>' if data.message else ""
    style = """
:root { color-scheme:dark; --canvas:#17191c; --sidebar:#1e2024; --surface:#25282d; --surface-2:#2b2e34; --line:#3d4148; --text:#eef0f3; --muted:#a2a8b1; --dim:#757c86; --blue:#8ab4d7; --green:#75b797; --amber:#d8ab62; --red:#d77872; }
* { box-sizing:border-box } body { margin:0; background:var(--canvas); color:var(--text); font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif } button,input,select { font:inherit } button { cursor:pointer }
.app-shell { min-height:100vh; display:grid; grid-template-columns:248px minmax(0,1fr) } .sidebar { position:sticky; top:0; height:100vh; background:var(--sidebar); border-right:1px solid var(--line); padding:23px 16px; display:flex; flex-direction:column; z-index:5 } .logo { font-weight:750; letter-spacing:.055em; font-size:.88rem; text-transform:uppercase } .logo span { display:block; color:var(--dim); font-weight:500; font-size:.69rem; margin-top:2px; letter-spacing:.09em } .nav { display:grid; gap:5px; margin-top:42px } .nav-button { width:100%; border:0; border-radius:6px; padding:10px 11px; background:transparent; color:var(--muted); text-align:left; display:flex; gap:10px; align-items:center } .nav-button:hover { background:#292c31; color:var(--text) } .nav-button.active { background:#30343a; color:var(--text); font-weight:650 } .nav-icon { color:var(--blue); font-size:.76rem; width:16px; text-align:center } .sidebar-foot { margin-top:auto; color:var(--dim); font-size:.76rem; border-top:1px solid var(--line); padding-top:16px } .local-state { display:flex; align-items:center; gap:7px; color:var(--muted); margin-top:7px } .status-dot { width:7px; height:7px; background:var(--green); border-radius:50% }
.content { min-width:0; padding:28px clamp(20px,4vw,54px) 64px } .mobile-bar { display:none } .page { display:none; max-width:1240px; margin:auto } .page.active { display:block; animation:fade .18s ease-out } @keyframes fade { from { opacity:.2; transform:translateY(4px) } to { opacity:1; transform:none } } .page-head { display:flex; align-items:end; justify-content:space-between; gap:18px; margin-bottom:26px } .eyebrow { color:var(--blue); text-transform:uppercase; letter-spacing:.12em; font-size:.68rem; font-weight:700; margin:0 0 7px } h1 { font-size:clamp(1.5rem,2.7vw,2.15rem); letter-spacing:-.04em; margin:0; font-weight:680 } h2 { font-size:.96rem; margin:0 } h3 { margin:0 } .subtitle,.updated { color:var(--muted); margin:5px 0 0 } .updated { color:var(--dim); font-size:.78rem; white-space:nowrap }
.panel,.metric,.module-card { background:var(--surface); border:1px solid var(--line); border-radius:8px } .panel { padding:20px; margin-top:16px } .panel-head { display:flex; justify-content:space-between; gap:16px; align-items:center; margin-bottom:16px } .caption { color:var(--dim); font-size:.77rem } .run { display:flex; align-items:end; flex-wrap:wrap; gap:12px } label { display:grid; gap:5px; color:var(--muted); font-size:.69rem; font-weight:700; text-transform:uppercase; letter-spacing:.06em } input,select { min-width:100px; color:var(--text); background:#1c1e22; border:1px solid var(--line); border-radius:5px; padding:9px 10px; outline:none } input:focus,select:focus { border-color:var(--blue) } .primary { margin-left:auto; border:0; border-radius:5px; padding:10px 14px; background:#d9dde2; color:#1e2024; font-size:.8rem; font-weight:750 } .primary:hover { background:#fff }
.notice { margin:16px 0 0; padding:10px 12px; border:1px solid #44515e; background:#242b32; border-radius:6px; color:var(--muted) } .metrics { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin:16px 0 } .metric { padding:17px } .metric strong { display:block; font-size:1.75rem; letter-spacing:-.05em; line-height:1.1 } .metric span { display:block; color:var(--muted); margin-top:5px; font-size:.8rem } .metric.warning strong { color:var(--amber) } .overview-grid { display:grid; grid-template-columns:1.25fr .75fr; gap:16px } .bar-row + .bar-row { margin-top:15px } .bar-label { display:flex; justify-content:space-between; font-size:.8rem; color:var(--muted); margin-bottom:6px } .bar { height:7px; border-radius:100px; overflow:hidden; background:#17191c } .bar i { display:block; height:100% } .bar .fail { background:var(--red) } .bar .success { background:var(--green) } .posture { border-left:3px solid var(--amber) } .posture strong { font-size:1.1rem; display:block; margin:8px 0 4px } .posture p { margin:0; color:var(--muted) }
.alert { border:1px solid #51483b; border-left:3px solid var(--amber); background:#2b2923; padding:13px 14px; border-radius:5px; margin-top:9px } .severity { color:var(--amber); font-size:.68rem; font-weight:800; letter-spacing:.09em; text-transform:uppercase } .alert h3 { font-size:.91rem; margin:4px 0 } .alert p { color:var(--muted); margin:0; font-size:.84rem } .empty { color:var(--muted) } .table-wrap { overflow:auto } table { width:100%; min-width:680px; border-collapse:collapse } th,td { padding:12px 10px; text-align:left; border-bottom:1px solid var(--line) } th { color:var(--dim); text-transform:uppercase; font-size:.67rem; letter-spacing:.07em } th:first-child,td:first-child { padding-left:0 } th:last-child,td:last-child { padding-right:0 } .tag { display:inline-block; padding:3px 7px; border-radius:4px; font-size:.7rem; font-weight:650 } .auth-failure { background:#4b2e30; color:#f0adaa } .auth-success { background:#263e35; color:#acd9c1 }
.flow { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; counter-reset:flow } .flow-step { position:relative; padding:16px; background:var(--surface); border:1px solid var(--line); border-radius:8px; min-height:145px } .flow-step:before { counter-increment:flow; content:"0" counter(flow); color:var(--blue); font-size:.7rem; font-weight:800 } .flow-step h3 { font-size:.9rem; margin:9px 0 5px } .flow-step p { color:var(--muted); font-size:.82rem; margin:0 } .pipeline-note { margin-top:16px; color:var(--muted); background:#202328; border:1px dashed var(--line); border-radius:7px; padding:14px } code { color:#b9d8ec; font-family:"SFMono-Regular",Consolas,monospace; font-size:.84em }
.component-tools { display:flex; justify-content:space-between; gap:15px; align-items:center; margin-bottom:18px } .search { width:min(330px,100%); padding:10px 12px; background:var(--surface); border:1px solid var(--line); border-radius:6px; color:var(--text) } .modules { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px } .module-card { padding:18px } .module-card h3 { font-size:1rem; margin:4px 0 8px } .module-card > p:not(.file-path) { color:var(--muted); margin:0 0 15px } .file-path { margin:0; color:var(--blue); font-family:"SFMono-Regular",Consolas,monospace; font-size:.73rem } dl { margin:0; display:grid; gap:11px } dt { color:var(--dim); text-transform:uppercase; letter-spacing:.07em; font-size:.65rem; font-weight:750 } dd { margin:2px 0 0; font-size:.81rem; color:#d5d8dd }
.release-list { display:grid; gap:12px } .release { display:grid; grid-template-columns:98px minmax(0,1fr) auto; gap:16px; align-items:start; background:var(--surface); border:1px solid var(--line); border-radius:8px; padding:17px } .release-version { color:var(--blue); font-weight:750; font-family:"SFMono-Regular",Consolas,monospace; font-size:1rem } .release h3 { font-size:.93rem; margin-bottom:4px } .release p { color:var(--muted); margin:0; font-size:.84rem } .release-state { border:1px solid var(--line); color:var(--muted); padding:3px 7px; border-radius:4px; font-size:.7rem } .governance { display:grid; grid-template-columns:repeat(3,1fr); gap:12px } .governance .panel { margin:0 } .governance p { color:var(--muted); font-size:.83rem; margin:8px 0 0 }
footer { color:var(--dim); font-size:.76rem; margin-top:22px } @media(max-width:1020px) { .flow { grid-template-columns:repeat(2,1fr) } .overview-grid { grid-template-columns:1fr } } @media(max-width:760px) { .app-shell { display:block } .sidebar { position:fixed; transform:translateX(-100%); transition:transform .2s ease; width:260px; box-shadow:12px 0 30px #0007 } body.menu-open .sidebar { transform:translateX(0) } .content { padding:0 16px 48px } .mobile-bar { height:58px; display:flex; align-items:center; justify-content:space-between; margin:0 -16px 23px; padding:0 16px; border-bottom:1px solid var(--line); background:var(--sidebar) } .menu-toggle { border:1px solid var(--line); color:var(--text); background:var(--surface); border-radius:5px; padding:7px 10px } .page-head { display:block } .updated { margin-top:9px; white-space:normal } .metrics { grid-template-columns:repeat(2,1fr) } .modules { grid-template-columns:1fr } .release { grid-template-columns:1fr; gap:7px } .release-state { width:max-content } .governance { grid-template-columns:1fr } .primary { margin-left:0; width:100% } .component-tools { display:block } .search { margin-top:11px; width:100% } } @media(max-width:430px) { .metrics,.flow { grid-template-columns:1fr } .panel { padding:16px } }
"""
    script = """
const navigation = document.querySelectorAll('[data-target]');
const pages = document.querySelectorAll('[data-page]');
const title = document.querySelector('[data-page-title]');
const labels = {overview:'Visão geral', pipeline:'Fluxo do pipeline', components:'Componentes técnicos', releases:'Versões e mudanças'};
function showPage(target) {
  pages.forEach((page) => page.classList.toggle('active', page.dataset.page === target));
  navigation.forEach((item) => item.classList.toggle('active', item.dataset.target === target));
  title.textContent = labels[target];
  document.body.classList.remove('menu-open');
  window.scrollTo({top: 0, behavior: 'smooth'});
}
navigation.forEach((item) => item.addEventListener('click', () => showPage(item.dataset.target)));
document.querySelector('[data-menu-toggle]').addEventListener('click', () => document.body.classList.toggle('menu-open'));
const search = document.querySelector('[data-module-search]');
search.addEventListener('input', () => {
  const term = search.value.toLowerCase().trim();
  document.querySelectorAll('[data-module]').forEach((card) => {
    card.hidden = !card.textContent.toLowerCase().includes(term);
  });
});
"""
    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>SOC Eye of GOD · Console técnico</title><style>{style}</style></head>
<body><div class="app-shell"><aside class="sidebar"><div class="logo">SOC Eye of GOD<span>Security operations console</span></div><nav class="nav" aria-label="Navegação do painel"><button class="nav-button active" data-target="overview"><span class="nav-icon">01</span>Operação</button><button class="nav-button" data-target="pipeline"><span class="nav-icon">02</span>Pipeline</button><button class="nav-button" data-target="components"><span class="nav-icon">03</span>Componentes</button><button class="nav-button" data-target="releases"><span class="nav-icon">04</span>Versões</button></nav><div class="sidebar-foot">Ambiente de laboratório<div class="local-state"><i class="status-dot"></i>Servidor local</div></div></aside>
<main class="content"><div class="mobile-bar"><strong data-page-title>Visão geral</strong><button class="menu-toggle" data-menu-toggle>Menu</button></div>
<section class="page active" data-page="overview"><header class="page-head"><div><p class="eyebrow">Operação</p><h1>Visão geral de segurança</h1><p class="subtitle">Monitoramento de autenticação SSH e estado do pipeline.</p></div><p class="updated">SQLite local · Regra AUTH-001</p></header><section class="panel"><div class="panel-head"><h2>Executar análise</h2><span class="caption">Log de demonstração</span></div><form class="run" method="post" action="/run"><label>Fonte<select name="sample"><option value="{_escape(selected_sample)}">{_escape(selected_sample)}</option></select></label><label>Ano<input name="year" type="number" value="{year}" min="2000" max="2100"></label><label>Limiar<input name="threshold" type="number" value="{threshold}" min="2" max="100"></label><label>Janela (min)<input name="window_minutes" type="number" value="{window_minutes}" min="1" max="1440"></label><button class="primary" type="submit">Executar análise</button></form></section>{message}<section class="metrics"><article class="metric"><strong>{total_events}</strong><span>Eventos armazenados</span></article><article class="metric"><strong>{failures}</strong><span>Falhas de autenticação</span></article><article class="metric"><strong>{successes}</strong><span>Acessos aceitos</span></article><article class="metric warning"><strong>{len(data.alerts)}</strong><span>Alertas ativos</span></article></section><section class="overview-grid"><article class="panel"><div class="panel-head"><h2>Distribuição de eventos</h2><span class="caption">Base persistida</span></div><div class="bar-row"><div class="bar-label"><span>Falhas de autenticação</span><span>{failure_percent}%</span></div><div class="bar"><i class="fail" style="width:{failure_percent}%"></i></div></div><div class="bar-row"><div class="bar-label"><span>Acessos aceitos</span><span>{success_percent}%</span></div><div class="bar"><i class="success" style="width:{success_percent}%"></i></div></div></article><article class="panel posture"><h2>Postura atual</h2><strong>{'Atenção necessária' if data.alerts else 'Sem alertas ativos'}</strong><p>{'A regra AUTH-001 encontrou tentativas repetidas para o mesmo IP.' if data.alerts else 'Não há correlações acima do limiar configurado.'}</p></article></section><section class="panel"><div class="panel-head"><h2>Alertas ativos</h2><span class="caption">Correlação por IP</span></div>{_alert_cards(data.alerts)}</section><section class="panel"><div class="panel-head"><h2>Eventos recentes</h2><span class="caption">Últimos 20 registros</span></div>{_event_table(data.events)}</section></section>
<section class="page" data-page="pipeline"><header class="page-head"><div><p class="eyebrow">Arquitetura</p><h1>Fluxo do pipeline</h1><p class="subtitle">Cada etapa transforma um log bruto em informação utilizável para investigação.</p></div></header><section class="flow"><article class="flow-step"><h3>Ingestão</h3><p><code>linux_file.py</code> lê cada linha não vazia do arquivo de log.</p></article><article class="flow-step"><h3>Normalização</h3><p><code>linux_auth.py</code> interpreta mensagens SSH e cria um evento padronizado.</p></article><article class="flow-step"><h3>Persistência</h3><p><code>sqlite.py</code> armazena os eventos e permite recuperá-los por ordem temporal.</p></article><article class="flow-step"><h3>Detecção</h3><p><code>failed_auth.py</code> correlaciona falhas por IP e cria alertas AUTH-001.</p></article></section><section class="panel"><h2>Como investigar o fluxo</h2><p class="pipeline-note">Use a página <strong>Componentes</strong> para entender contratos, decisões e melhorias pendentes de cada arquivo. O próximo marco técnico é tornar o ID do evento determinístico para impedir duplicação ao reprocessar um log.</p></section></section>
<section class="page" data-page="components"><header class="page-head"><div><p class="eyebrow">Referência de código</p><h1>Componentes técnicos</h1><p class="subtitle">Resumo navegável do código implementado e dos pontos que devem evoluir.</p></div></header><div class="component-tools"><span class="caption">8 componentes documentados</span><input class="search" data-module-search type="search" placeholder="Buscar arquivo, função ou melhoria"></div><section class="modules">{_technical_cards()}</section></section>
<section class="page" data-page="releases"><header class="page-head"><div><p class="eyebrow">Governança</p><h1>Versões e mudanças</h1><p class="subtitle">Controle das entregas e registro do que mudou em cada edição.</p></div></header><section class="release-list">{_release_timeline()}</section><section class="governance" style="margin-top:16px"><article class="panel"><h2>Fonte de verdade</h2><p><code>docs/DEVELOPMENT_LOG.md</code> registra decisões, ferramentas e validações de cada entrega.</p></article><article class="panel"><h2>Estado técnico</h2><p><code>docs/PROJECT_STATUS.md</code> concentra inventário, riscos e roadmap priorizado.</p></article><article class="panel"><h2>Próxima edição</h2><p>Deduplicação de eventos, correlação consistente e testes de SQLite devem formar o próximo incremento.</p></article></section></section>
<footer>Painel local em 127.0.0.1 · Sem dependências externas · Dados de execução permanecem em <code>data/runtime/</code>.</footer></main></div><script>{script}</script></body></html>"""


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
