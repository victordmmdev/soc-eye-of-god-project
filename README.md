# SOC Eye of GOD

<p align="center">
  <strong>Mini-SIEM educacional para investigação de eventos de autenticação SSH.</strong><br>
  Ingestão de logs Linux · Normalização · SQLite · Detecção de falhas repetidas · Console técnico local
</p>
<img width="1911" height="1073" alt="Captura de tela de 2026-08-10 07-03-01" src="https://github.com/user-attachments/assets/d2a0b45f-8858-4d1d-81d2-d8792ab455dc" />

<p align="center">
  <a href="#visão-geral">Visão geral</a> ·
  <a href="#recursos">Recursos</a> ·
  <a href="#arquitetura">Arquitetura</a> ·
  <a href="#começar">Começar</a> ·
  <a href="#qualidade-e-validação">Validação</a> ·
  <a href="#roadmap">Roadmap</a>
</p>


> **Versão atual:** `1.0.1` · **Status:** laboratório educacional / portfólio · **Licença:** ainda não definida

## Visão geral

SOC Eye of GOD é um projeto de estudo que reproduz, em escala reduzida, um fluxo de um SIEM: recebe logs de autenticação Linux, converte mensagens SSH em eventos estruturados, guarda esses eventos localmente e identifica múltiplas falhas de autenticação originadas pelo mesmo IP.

Além da linha de comando, o projeto oferece um console web local para explorar a operação, a arquitetura, os componentes implementados e o histórico de versões. O objetivo é tornar as decisões técnicas visíveis e evoluir o projeto de forma incremental e documentada.

## Recursos

- Leitura lazy de arquivos de log Linux, linha por linha.
- Parser para mensagens `sshd` de falha de senha e autenticação aceita.
- Modelo tipado de evento e alerta com horário obrigatório e fuso horário.
- Persistência local em SQLite, usando somente a biblioteca padrão do Python.
- Regra `AUTH-001` para múltiplas falhas SSH por IP dentro de uma janela configurável.
- CLI para executar o pipeline por arquivo.
- Console web responsivo em `127.0.0.1`, sem dependências de frontend.
- Páginas técnicas de Operação, Pipeline, Componentes e Versões.
- Documentação de decisões, riscos conhecidos e roadmap técnico.

## Arquitetura

```text
Arquivo auth.log
      │
      ▼
LinuxLogFileReader
      │ linhas de syslog
      ▼
LinuxAuthParser ─────► Event normalizado
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
  SQLiteEventRepository      MultipleFailedAuthenticationRule
               │                             │
               ▼                             ▼
     eventos persistidos                alerta AUTH-001
               └──────────────┬──────────────┘
                              ▼
                     CLI e console web
```

### Estrutura do repositório

```text
src/minisiem/
├── domain/       # Contratos Event e Alert
├── ingestion/    # Leitura de logs Linux
├── parsing/      # Normalização de autenticação SSH
├── storage/      # Repositório SQLite
├── detection/    # Regras de correlação
├── cli.py        # Interface de terminal
└── web.py        # Console técnico local

data/samples/     # Log de demonstração
docs/             # Diário, estado do projeto e roadmap
tests/unit/       # Testes automatizados
```

## Console técnico

O painel está disponível somente na máquina local por padrão e organiza a análise em quatro áreas:

| Área | O que apresenta |
| --- | --- |
| Operação | Parâmetros de análise, métricas, alertas e eventos recentes. |
| Pipeline | As etapas que levam um log bruto a um alerta. |
| Componentes | Responsabilidade, funcionamento e melhoria pendente de cada módulo. |
| Versões | Entregas `0.1.0` e `1.0.1`, com contexto de cada edição. |

<img width="1911" height="1073" alt="Captura de tela de 2026-08-10 07-03-01" src="https://github.com/user-attachments/assets/0cb0ec24-4a21-42ff-b6a6-38455938f9a9" />
## Começar

### Pré-requisitos

- Python 3.11 ou superior.
- `pytest` apenas para executar os testes.

O runtime da aplicação não requer pacotes externos.

### Instalação para desenvolvimento

```bash
git clone git@github.com:victordmmdev/soc-eye-of-god-project.git
cd soc-eye-of-god-project

python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

### Executar o pipeline pela CLI

```bash
PYTHONPATH=src python -m minisiem.cli data/samples/auth.log --year 2026
```

Saída esperada para o log de demonstração:

```text
Eventos normalizados e armazenados: 4
Alertas gerados: 1
[MEDIUM] AUTH-001: Múltiplas falhas de autenticação SSH (203.0.113.10)
```

Por padrão, a execução cria `data/runtime/minisiem.db`. Esse banco é local e está excluído do Git.

### Iniciar o console web

```bash
PYTHONPATH=src python -m minisiem.web
```

Abra [http://127.0.0.1:8000](http://127.0.0.1:8000). Após a instalação do pacote, também é possível usar:

```bash
minisiem-web
```

## Qualidade e validação

```bash
.venv/bin/python -m pytest
```

O estado atual possui **8 testes automatizados** cobrindo contratos de evento, parser, regra de detecção e renderização/escape do painel. A validação funcional do exemplo confirma **4 eventos normalizados** e **1 alerta AUTH-001**.

## Segurança e escopo

Este é um projeto educacional e **não deve ser usado como SIEM de produção**. O painel escuta em `127.0.0.1` por padrão e aceita somente o log de exemplo configurado. Antes de qualquer exposição em rede seriam necessários, no mínimo, autenticação, autorização, auditoria, proteção de requisições e revisão de segurança.

Limitações técnicas importantes já identificadas:

- Reprocessar o mesmo log pode duplicar eventos, pois o ID atual é aleatório.
- A regra `AUTH-001` ainda bloqueia um segundo alerta para o mesmo IP durante a mesma avaliação.
- A CLI e o painel ainda usam fontes de correlação diferentes entre execuções.
- O parser suporta somente duas mensagens SSH em inglês e assume UTC para o horário syslog.

Consulte [PROJECT_STATUS.md](docs/PROJECT_STATUS.md) para a análise completa de riscos e limitações.

## Roadmap

### Próximo marco — confiabilidade do pipeline

1. Implementar ID determinístico e deduplicação de eventos.
2. Correlacionar janelas independentes para o mesmo IP.
3. Unificar o serviço usado pela CLI e pelo painel.
4. Evoluir o repositório SQLite e seus testes.

### Próximos incrementos

- Validar IPs, severidades, fusos horários e serialização de campos.
- Adicionar testes de CLI, HTTP, SQLite e cenários de correlação.
- Persistir alertas e permitir investigação por filtros e histórico.
- Ampliar parsing e regras de detecção para novas fontes e comportamentos suspeitos.

## Documentação do projeto

- [Diário de desenvolvimento](docs/DEVELOPMENT_LOG.md): decisões, ferramentas, entregas e validações.
- [Estado do projeto](docs/PROJECT_STATUS.md): inventário, arquitetura, riscos e roadmap detalhado.

## Autor

Desenvolvido por **Victor Magaldi** como projeto de estudo e portfólio em segurança, monitoramento e engenharia de software.
