# Hunt3r — Guia de Estilo de Código

## Formatação

- **Comprimento de linha**: máximo 100 caracteres
- **Indentação**: 4 espaços (PEP 8)
- **Imports**: 3 grupos (stdlib → terceiros → locais), ordenados alfabeticamente
- **f-strings**: sempre (não `.format()` ou `%`)

## Nomenclatura

| Tipo | Convenção | Exemplo |
|------|-----------|---------|
| Classes | PascalCase | `MissionRunner` |
| Funções | snake_case | `run_subfinder()` |
| Constantes | UPPER_SNAKE_CASE | `MAX_SUBS_PER_TARGET` |
| Privados | _underscore | `_load_env()` |

## Type hints

Obrigatórios em assinaturas de funções públicas:

```python
def count_lines(filepath: str) -> int:
    """Conta linhas em um arquivo."""
    ...
```

## Tratamento de erros

- Capturar exceções específicas (nunca bare `except:`)
- Logar com nível apropriado (error, warning, debug)
- Re-raise ou tratar graciosamente conforme contexto

```python
try:
    data = json.loads(response.text)
except json.JSONDecodeError as e:
    logging.error(f"JSON malformado: {e}")
    return {}
```

## Docstrings

- Triple double quotes `"""`
- Primeira linha: resumo imperativo
- Args/Returns/Raises quando aplicável

## Limites de complexidade

- **Função**: máximo ~50 linhas (100 para funções complexas)
- **Nesting**: máximo 3 níveis
- **Argumentos**: máximo 5 (usar kwargs ou dataclass para mais)

## Testes

- Arquivo: `test_<módulo>.py`
- Função: `test_<função>_<cenário>`
- Rodar: `python3 -m pytest tests/ -q`

## Checklist pré-commit

- [ ] Sem erros de sintaxe: `python3 -m py_compile <arquivo>`
- [ ] Imports organizados
- [ ] Sem bare `except:`
- [ ] Type hints em funções públicas
- [ ] f-strings para formatação
- [ ] Linhas < 100 caracteres
- [ ] Mensagem de commit no formato convencional
