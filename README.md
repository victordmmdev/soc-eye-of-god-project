# SOC Eye of GOD - Project

Mini-SIEM educacional: o primeiro vertical slice de um SIEM próprio, construído para aprendizado. Ele lê logs de autenticação Linux, normaliza eventos SSH, persiste-os em SQLite e identifica múltiplas falhas de autenticação pelo mesmo IP.

**Versão atual:** `1.0.1` (hotfix: painel local e documentação de estado).

O histórico de decisões, ferramentas, validações e próximos incrementos está em [docs/DEVELOPMENT_LOG.md](docs/DEVELOPMENT_LOG.md). Para arquitetura, inventário, riscos e roadmap, consulte [docs/PROJECT_STATUS.md](docs/PROJECT_STATUS.md).

## Pré-requisitos

- Python 3.11 ou superior

O pacote de aplicação não possui dependências externas. Para executar os testes, use `pytest` como dependência de desenvolvimento em um ambiente virtual local.

## Executar o pipeline

Sem instalar o pacote:

```bash
PYTHONPATH=src python -m minisiem.cli data/samples/auth.log --year 2026
```

Isso cria, se necessário, `data/runtime/minisiem.db`, armazena os eventos processados e imprime os alertas encontrados.

Após instalar o projeto em um ambiente virtual, o mesmo fluxo pode ser executado com:

```bash
minisiem data/samples/auth.log --year 2026
```

## Painel visual local

O painel usa os componentes já existentes (leitor, parser, SQLite e regra `AUTH-001`) e não adiciona dependências de runtime:

```bash
PYTHONPATH=src python -m minisiem.web
```

Abra [http://127.0.0.1:8000](http://127.0.0.1:8000). Se o pacote estiver instalado, use `minisiem-web`.

O painel fica restrito ao computador local, permite processar o log de exemplo e mostra métricas, alertas e os 20 eventos mais recentes armazenados.

## Executar testes

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest
```

## Limites deliberados desta etapa

- Apenas mensagens SSH `Failed password` e `Accepted` no formato syslog são interpretadas.
- O ano não existe no prefixo syslog; informe `--year` para reprodução determinística.
- Alertas ainda são exibidos na CLI; a persistência de alertas será uma etapa posterior.
