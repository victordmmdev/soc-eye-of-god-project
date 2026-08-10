# Diário de desenvolvimento

Este arquivo é o registro versionado das etapas do projeto. A cada mudança relevante, registre a decisão tomada, as ferramentas/comandos utilizados, como a mudança foi validada e o trabalho que ficou pendente.

## Convenções

- Datas seguem o formato `AAAA-MM-DD`.
- Nunca registrar senhas, tokens, códigos de dispositivo ou outros segredos.
- Comandos abaixo servem como referência. Ajuste-os ao seu ambiente e execute apenas aqueles que entender.
- Dados de execução, ambientes virtuais e caches não são versionados; veja [`.gitignore`](../.gitignore).

## Versão 1.0.1 — Hotfix de operação e documentação

Esta hotfix adiciona o painel web local para inspeção do pipeline, refina sua interface para um console SOC e consolida a documentação técnica em `PROJECT_STATUS.md`. Também adiciona o comando `minisiem-web` ao pacote. Não modifica a lógica de parsing, persistência ou detecção; as limitações registradas permanecem conhecidas e priorizadas para o próximo ciclo.

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

## 2026-08-10 — Painel visual local

### Entrega

Foi adicionado `src/minisiem/web.py`, um painel web local sem dependências externas. Ele reutiliza o pipeline existente para processar `data/samples/auth.log` e apresenta:

- totais de eventos, falhas, autenticações aceitas e alertas;
- alertas da regra `AUTH-001`;
- os 20 eventos persistidos mais recentes;
- parâmetros de ano, limiar e janela de correlação.

### Segurança e operação

O servidor escuta em `127.0.0.1` por padrão, portanto não fica acessível pela rede. A tela só aceita logs do diretório de exemplos configurado, sem upload nem caminhos arbitrários de arquivo.

### Como validar manualmente

```bash
PYTHONPATH=src python -m minisiem.web
```

Abra `http://127.0.0.1:8000`, clique em **Processar log** e confirme que as métricas, a tabela e o alerta são exibidos.

### Refinamento visual

O painel foi redesenhado com linguagem visual de console SOC: superfícies grafite, hierarquia discreta, uma única ação de análise, indicadores de eventos, distribuição de falhas e acessos, postura de risco, alertas e tabela operacional. A validação confirmou que a página continua renderizando os dados e o alerta esperado.

### Console técnico navegável

O painel passou a ter páginas internas responsivas de operação, fluxo do pipeline, componentes técnicos e versões. A página de componentes explica a responsabilidade, comportamento e melhoria pendente de cada módulo; a de versões exibe as entregas `0.1.0` e `1.0.1`. A navegação e busca de componentes usam JavaScript local, sem bibliotecas ou chamadas externas.

## 2026-08-10 — README de portfólio

O README foi reorganizado para apresentação no GitHub: visão geral, recursos, arquitetura, execução, validação, segurança, roadmap e autoria. A referência a screenshots foi preparada para o diretório `docs/assets/`; nenhuma imagem versionada estava disponível no workspace durante esta revisão, portanto não foram adicionados links quebrados.

## 2026-08-10 — Auditoria de estado

Foi criado [PROJECT_STATUS.md](PROJECT_STATUS.md), com o inventário dos arquivos, arquitetura, resultados de validação, riscos conhecidos e roadmap priorizado. A auditoria validou compilação, configuração do pacote, testes unitários, CLI, persistência temporária e renderização do painel.
