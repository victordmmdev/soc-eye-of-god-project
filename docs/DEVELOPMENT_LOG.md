# Diário de desenvolvimento

Este arquivo é o registro versionado das etapas do projeto. A cada mudança relevante, registre a decisão tomada, as ferramentas/comandos utilizados, como a mudança foi validada e o trabalho que ficou pendente.

## Convenções

- Datas seguem o formato `AAAA-MM-DD`.
- Nunca registrar senhas, tokens, códigos de dispositivo ou outros segredos.
- Comandos abaixo servem como referência. Ajuste-os ao seu ambiente e execute apenas aqueles que entender.
- Dados de execução, ambientes virtuais e caches não são versionados; veja [`.gitignore`](../.gitignore).

## 2026-08-10 — Vertical slice inicial

### Entrega

Foi criado o primeiro fluxo funcional do Mini-SIEM educacional:

1. Leitura lazy de logs Linux.
2. Normalização de eventos de autenticação SSH.
3. Persistência de eventos em SQLite.
4. Detecção da regra `AUTH-001` para falhas repetidas de autenticação pelo mesmo IP.
5. Exibição de alertas na linha de comando.

### Arquivos principais

| Área | Arquivos |
| --- | --- |
| Modelos | `src/minisiem/domain/event.py`, `src/minisiem/domain/alert.py` |
| Ingestão e parsing | `src/minisiem/ingestion/linux_file.py`, `src/minisiem/parsing/linux_auth.py` |
| Persistência | `src/minisiem/storage/sqlite.py` |
| Detecção | `src/minisiem/detection/failed_auth.py` |
| Interface | `src/minisiem/cli.py` |
| Testes | `tests/unit/` |
| Exemplo | `data/samples/auth.log` |

### Validação executada

```bash
python -m pytest
PYTHONPATH=src python -m minisiem.cli data/samples/auth.log --year 2026
```

Resultado registrado nesta etapa:

- 6 testes passaram.
- 4 eventos foram normalizados e armazenados.
- 1 alerta `MEDIUM` foi produzido para o IP `203.0.113.10` pela regra `AUTH-001`.

### Ferramentas

- Python 3.11+ e `pytest` para a aplicação e seus testes.
- SQLite, via biblioteca padrão do Python, para persistência local.
- Git para versionamento.
- GitHub CLI (`gh`) para criar e administrar o repositório remoto.
- SSH (`ed25519`) para autenticar operações Git com o GitHub.

### Pontos técnicos para a próxima etapa

1. Tornar a identidade de eventos determinística para impedir duplicação ao reprocessar o mesmo log.
2. Permitir novos alertas para o mesmo IP quando ocorrer uma nova janela de falhas.
3. Correlacionar também eventos persistidos entre execuções da CLI.
4. Fechar conexões SQLite explicitamente e informar quantos eventos foram inseridos.
5. Tornar o fuso horário do syslog configurável, em vez de assumir UTC.
6. Ampliar testes: autenticação aceita, IPs múltiplos, janelas separadas, entradas inválidas e persistência.

## 2026-08-10 — Publicação inicial no GitHub

### Objetivo

Publicar a base atual em um repositório novo, usando SSH, mantendo arquivos transitórios fora do histórico e estabelecendo este diário como fonte de acompanhamento do projeto.

### Processo e comandos esperados

```bash
git init -b main
git add .
git commit -m "Initial Mini-SIEM vertical slice"
gh repo create soc-eye-of-god-project --public --source=. --remote=origin --push
```

O repositório será público em `victordmmdev/soc-eye-of-god-project`. O comando `gh repo create` configura a URL SSH do remoto `origin` e envia a branch `main`.

### Verificações após a publicação

```bash
git status -sb
git remote -v
gh repo view --web
```

### Próximo passo documentado

Abrir uma issue no GitHub para cada melhoria priorizada acima. Cada issue deve conter: contexto, comportamento atual, resultado esperado, critérios de aceite e testes previstos.
