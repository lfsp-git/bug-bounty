# Hunt3r Caveman Mode — Instruções do Workspace

## Propósito
Guiar agentes no Hunt3r com princípios "Caveman Mode": resolução direta, mínimo overhead de contexto, máxima velocidade de código.

## Princípios globais

### 1. Análise de causa raiz
- Encontrar a linha/função exata causando o problema
- Rastrear 1-2 passos para trás para entender contexto
- Declarar o problema em 1 frase clara
- Parar de investigar assim que a causa raiz for identificada

### 2. Correções cirúrgicas
- Modificar apenas arquivos diretamente relacionados
- Sem refatoração além do necessário
- Sem otimização prematura
- Responsabilidade única por commit

### 3. Validação antes do commit
- `python3 -m py_compile <arquivo>` para checagem de sintaxe (obrigatório)
- Rodar testes unitários se existirem para o código modificado
- Nunca commitar com testes falhando

### 4. Conservação de contexto
- Agrupar chamadas de ferramentas relacionadas
- Agrupar edições no mesmo arquivo em uma única chamada `edit`
- Suprimir output verboso (`--quiet`, pipe para `head`)

### 5. Documentação
- Atualizar comentários apenas se o comportamento do código mudar
- Manter docstrings sincronizadas com implementação
- Sem comentários "TODO" em commits

## Organização de arquivos

### Código fonte
- `main.py` — Ponto de entrada CLI
- `core/` — Orquestração, IA, watchdog, filtros, UI, config
- `recon/` — Engines, JS Hunter, APIs de plataforma, descoberta de ferramentas
- `tests/` — Suite de testes unitários e integração

### Facades unificadas
- `core/runner.py` — Orquestração (re-exporta de scanner.py)
- `core/intel.py` — IA + scoring (re-exporta de ai.py + bounty_scorer.py)
- `core/state.py` — Baseline + checkpoints (re-exporta de storage.py)
- `core/output.py` — Notificação + relatório + export
- `recon/tools.py` — Ferramentas + descoberta de binários

### Documentação
- `docs/HUNT3R_SPEC.md` — Especificação técnica completa
- `docs/STATUS.md` — Status operacional atual
- `docs/CHANGELOG.md` — Histórico de mudanças
- `docs/IMPROVEMENTS.md` — Resumo de melhorias FASE 1-8
- `docs/temp/architecture_diagram.md` — Diagramas de arquitetura

## Padrões de comando

```bash
# Checagem de sintaxe
python3 -m py_compile core/scanner.py core/watchdog.py

# Encontrar padrões
grep -rn "pattern" core/ recon/ --include="*.py"

# Commit atômico
git add -A && git commit -m "Fix: descrição" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"

# Verificar mudanças
git --no-pager diff HEAD~1 --stat
```

## Workflow Git

Todo commit deve:
1. Abordar um único problema
2. Incluir trailer: `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`
3. Ter mensagem clara: `Fix: <problema>` ou `Refactor: <arquivo> para <objetivo>`
4. Passar todos os testes existentes (73 testes)

## Metas de performance

- **Tempo de fix**: 15-45 minutos por issue
- **Validação**: 5-10 minutos por fix
- **Throughput**: 8-12 issues por FASE
