

Mini-SIEM educacional: o primeiro vertical slice de um SIEM próprio, construído para aprendizado. Ele lê logs de autenticação Linux, normaliza eventos SSH, persiste-os em SQLite e identifica múltiplas falhas de autenticação pelo mesmo IP.

O histórico de decisões, ferramentas, validações e próximos incrementos está em [docs/DEVELOPMENT_LOG.md](docs/DEVELOPMENT_LOG.md).
<img width="1911" height="1073" alt="Captura de tela de 2026-08-10 07-03-01" src="https://github.com/user-attachments/assets/a75ca3fc-9622-42d9-8126-ce96f023ae14" />

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
