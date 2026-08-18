# Estado do projeto — SOC Eye of GOD

**Versão:** 0.1.0

**Estado:** pipeline educacional executável; não indicado para produção.

## Escopo publicado

O projeto lê logs sintéticos de autenticação SSH, normaliza as mensagens suportadas, persiste eventos em SQLite e avalia a regra `AUTH-001` para falhas repetidas originadas pelo mesmo IP.

Interfaces disponíveis:

- CLI local (`minisiem`).
- Módulos Python de parsing, domínio, persistência e detecção.
- Oito testes automatizados.

Não há painel web na versão publicada.

## Verificação

| Verificação | Resultado esperado |
|---|---|
| `python -m pytest` | 8 testes aprovados |
| CLI com fixture sintética | 4 eventos e 1 alerta |
| Reprocessamento | 0 novos eventos na segunda execução |

## Limitações conhecidas

- O parser reconhece apenas mensagens `Failed password` e `Accepted` do `sshd` em inglês.
- O formato syslog usado não informa ano ou fuso; ambos são fornecidos pelo contexto da execução.
- A correlação avalia os eventos da execução atual, não todo o histórico persistido.
- A regra emite somente um alerta por IP durante uma avaliação.
- Alertas ainda não são persistidos.

## Próximos incrementos

1. Consultas SQLite por intervalo e correlação sobre histórico selecionado.
2. Janelas independentes de alerta para o mesmo IP.
3. Testes de CLI, parâmetros inválidos e novos formatos SSH.
4. Persistência de alertas com referências aos eventos de origem.
