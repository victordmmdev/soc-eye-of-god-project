# Estado do projeto — SOC Eye of GOD

**Data da revisão:** 2026-08-10<br>
**Versão:** 1.0.1 (hotfix)<br>
**Estado:** vertical slice funcional para aprendizado; não pronto para operação em produção.

## Visão executiva

O projeto implementa um fluxo mínimo de SIEM para logs SSH de Linux: lê um arquivo de log, extrai eventos de autenticação, persiste-os em SQLite, correlaciona falhas repetidas por IP e os apresenta na CLI e no painel web local.

O fluxo é pequeno, coerente e executável sem dependências de runtime. A principal prioridade técnica agora é corrigir a identidade/deduplicação de eventos e tornar a correlação consistente entre execuções, antes de ampliar fontes de log ou regras de detecção.

## Arquitetura atual

```text
auth.log
  │
  ▼
LinuxLogFileReader ──► LinuxAuthParser ──► Event
                                             │
                  ┌──────────────────────────┴──────────────────────────┐
                  ▼                                                     ▼
       SQLiteEventRepository                         MultipleFailedAuthenticationRule
                  │                                                     │
                  ▼                                                     ▼
          eventos persistidos                                      Alert AUTH-001
                  │                                                     │
                  └──────────────────────► CLI / painel web ◄─────────┘
```

## Inventário de arquivos

| Área | Arquivo | Responsabilidade | Estado |
| --- | --- | --- | --- |
| Projeto | `pyproject.toml` | Metadados, pacote e comandos `minisiem` / `minisiem-web` | Válido |
| Domínio | `src/minisiem/domain/event.py` | Contrato imutável de evento normalizado | Funcional |
| Domínio | `src/minisiem/domain/alert.py` | Contrato de alerta de detecção | Funcional, validação mínima |
| Ingestão | `src/minisiem/ingestion/linux_file.py` | Leitura lazy de linhas de log | Funcional |
| Parsing | `src/minisiem/parsing/linux_auth.py` | Parser de mensagens SSH `Failed password` e `Accepted` | Funcional, escopo limitado |
| Armazenamento | `src/minisiem/storage/sqlite.py` | Schema e repositório SQLite de eventos | Funcional, precisa evoluir |
| Detecção | `src/minisiem/detection/failed_auth.py` | Regra `AUTH-001` | Funcional, sem recorrência por janela |
| CLI | `src/minisiem/cli.py` | Execução de ponta a ponta no terminal | Funcional |
| Web | `src/minisiem/web.py` | Console técnico local em `127.0.0.1` | Funcional, com navegação e busca local |
| Testes | `tests/unit/` | Contratos de evento, parser, regra e painel | 8 testes |
| Dados | `data/samples/auth.log` | Log SSH de demonstração | 4 eventos reconhecidos |
| Documentação | `README.md` | Início rápido e execução | Atualizado |
| Documentação | `docs/DEVELOPMENT_LOG.md` | Diário de decisões e entregas | Atualizado |

Os arquivos `__init__.py` exportam as APIs públicas de cada área. O arquivo `.gitignore` exclui ambientes virtuais, caches e `data/runtime/`, onde fica o banco local.

## Interfaces disponíveis

### Linha de comando

```bash
PYTHONPATH=src python -m minisiem.cli data/samples/auth.log --year 2026
```

Aceita arquivo de log, caminho do banco, limiar, janela de correlação e ano. A saída informa quantos eventos foram processados e os alertas criados naquela execução.

### Painel web local

```bash
PYTHONPATH=src python -m minisiem.web
```

Disponível em `http://127.0.0.1:8000`. O painel utiliza somente a biblioteca padrão do Python e JavaScript local. Ele apresenta quatro páginas internas: operação (configuração, métricas, alertas e eventos), pipeline (etapas do processamento), componentes (detalhes e melhorias de cada módulo) e versões (histórico das entregas). A interface escuta somente no loopback por padrão; não deve ser exposta à rede sem autenticação e revisão de segurança.

## Validação desta revisão

| Verificação | Resultado |
| --- | --- |
| Compilação de `src/` e `tests/` | Aprovada (`compileall`) |
| Leitura de `pyproject.toml` | Válida (`tomllib`) |
| Testes unitários | **8 passed** |
| Pipeline CLI com banco temporário | 4 eventos, 1 alerta `AUTH-001` |
| Renderização do painel | Aprovada; página contém resumo e alerta esperado |
| Espaços em branco/diff | Aprovado (`git diff --check`) |

O banco usado durante a validação foi temporário, portanto a revisão não altera o banco de trabalho em `data/runtime/`.

## Riscos e limitações conhecidos

Estas são limitações reais do estado atual, em ordem aproximada de impacto.

1. **Eventos duplicados ao reprocessar um mesmo log.** `Event` gera UUID aleatório. Portanto, o mesmo registro recebe um ID novo a cada leitura, e `INSERT OR IGNORE` não consegue deduplicá-lo.
2. **Alerta único por IP durante toda a avaliação.** `AUTH-001` guarda IPs já alertados. Uma segunda campanha do mesmo IP, após uma janela independente, não gera novo alerta.
3. **Correlação inconsistente entre interfaces.** A CLI avalia somente os eventos em memória da execução atual; o painel avalia todos os eventos persistidos. O comportamento precisa ser unificado.
4. **Fuso horário presumido como UTC.** O formato syslog não traz timezone, mas o parser o fixa em UTC. Isso pode deslocar horários reais.
5. **Conexões SQLite não são fechadas explicitamente.** O contexto confirma/reverte transações, porém o repositório deve gerenciar o fechamento da conexão de modo explícito.
6. **Validação de domínio incompleta.** `fields` continua mutável apesar do `frozen=True`; `Any` pode conter valores não serializáveis em JSON; `Alert` não valida severidade nem `created_at` com timezone.
7. **Cobertura de testes ainda limitada.** O painel já possui testes de renderização e escape de HTML, mas ainda faltam testes para SQLite, CLI, requisições HTTP, autenticação aceita, parâmetros inválidos, múltiplos IPs, duas janelas de um IP ou reprocessamento.
8. **Escopo de parsing pequeno.** Só reconhece duas mensagens em inglês de `sshd`; IPs não são validados e a informação `invalid user` não é preservada.
9. **Painel é demonstrativo.** Não há autenticação, usuários, CSRF, uploads, gráficos históricos, filtros, paginação ou persistência de alertas. Ele deve continuar local até haver um modelo de segurança apropriado.

## Próximo ciclo recomendado

### Marco 1 — Confiabilidade do pipeline

1. Definir um ID determinístico para `Event` a partir de fonte, host, timestamp, mensagem bruta e campos normalizados.
2. Alterar o repositório para retornar a quantidade efetivamente inserida e fechar conexões explicitamente.
3. Criar consulta por intervalo temporal e fazer CLI e painel usar o mesmo serviço de correlação.
4. Corrigir `AUTH-001` para alertar uma vez quando o limiar é cruzado em cada janela independente.
5. Criar testes para deduplicação, duas janelas, múltiplos IPs e persistência SQLite.

**Critério de aceite:** reprocessar o mesmo arquivo não aumenta a base; duas campanhas separadas do mesmo IP geram dois alertas; CLI e painel exibem o mesmo resultado para os mesmos parâmetros.

### Marco 2 — Qualidade e observabilidade

1. Extrair um serviço de aplicação para evitar duplicação do pipeline entre CLI e painel.
2. Validar IP, severidade, timezone e serialização dos campos de domínio.
3. Adicionar testes de CLI e painel e medir cobertura.
4. Configurar qualidade contínua no GitHub Actions (testes e lint).
5. Persistir alertas e registrar estado/analista/notas.

### Marco 3 — Ampliação do SOC

1. Suportar mais mensagens SSH e outras fontes Linux, preservando campos relevantes.
2. Permitir seleção segura de arquivos de log e filtros por período, IP, host e tipo.
3. Criar regras adicionais, por exemplo login de sucesso após falhas repetidas e acesso fora de horário.
4. Evoluir o painel para histórico temporal, filtros, detalhes de evento e investigação de alerta.



# iniciar o painel
PYTHONPATH=src python -m minisiem.web
```
