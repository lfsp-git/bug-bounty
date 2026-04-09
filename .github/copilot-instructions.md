# Hunt3r Caveman Mode - Workspace Instructions

## Purpose
These instructions guide all agents working on Hunt3r to adopt "Caveman Mode" principles: direct problem-solving, minimal context overhead, maximum code velocity.

## Global Principles

### 1. **Root Cause Analysis (RCA)**
- Find the exact line/function causing the issue
- Trace backwards 1-2 steps to understand context
- State the problem in 1 clear sentence
- Stop investigating once root cause is identified

### 2. **Surgical Fixes**
- Modify only files directly related to the issue
- No refactoring beyond what's necessary to fix the problem
- No premature optimization
- Single responsibility per commit

### 3. **Validation Before Commit**
- `python -m py_compile <file>` for syntax check (mandatory)
- Run unit tests if they exist for the modified code
- Manual spot-check of affected code paths
- Never commit with failing tests

### 4. **Context Conservation**
- Batch related tool calls (grep all patterns at once, not sequential searches)
- Batch file edits to same file in single `edit` call
- Suppress verbose output (use `--quiet`, pipe to `head`)
- Reference session artifacts (action_plan.md, architecture_diagram.md) for context

### 5. **Documentation**
- Update comments only if code behavior changed
- Keep docstrings synchronized with actual implementation
- No "TODO" comments left in commits
- Session artifacts live in `/docs/temp/` for reference

## FASE 2 Workflow

### Initialization
1. Query SQL `todos` table for pending issues
2. Set todo `status = 'in_progress'`
3. Read issue description from SQL for full context

### Execution
1. Locate all occurrences of the problem using grep
2. Understand the context with view/edit
3. Apply minimal fix(es)
4. Validate with syntax/tests
5. Commit atomically

### Completion
1. Set todo `status = 'done'`
2. Log any blockers or follow-up work in SQL

### FASE 2 Issues Checklist

```sql
-- Query: Find next ready todo
SELECT * FROM todos WHERE status = 'pending' ORDER BY id ASC LIMIT 1;

-- Update when starting: UPDATE todos SET status = 'in_progress' WHERE id = 'X';
-- Update when done: UPDATE todos SET status = 'done' WHERE id = 'X';
```

## File Organization

**Hunt3r Source**:
- `core/`: Orchestrator, AI client, watchdog, mission runner
- `recon/`: Engines, JS Hunter, platform APIs
- `config/`: Settings, secrets, tool paths
- `main.py`: CLI entry point
- `tests/`: Unit test suite

**Session Artifacts** (in `/docs/temp/`):
- `architecture_diagram.md`: 10 Mermaid diagrams
- `improvements_analysis.md`: 25 issues with solutions
- `action_plan.md`: Executed FASE 1 steps
- `execution_summary.md`: FASE 1 metrics and results

## Command Patterns

**Syntax check (fast, always safe)**:
```bash
python -m py_compile core/orchestrator.py core/watchdog.py
```

**Find all instances of a pattern**:
```bash
grep -rn "pattern" core/ recon/ --include="*.py"
```

**Commit atomic changes**:
```bash
git add -A && git commit -m "Fix: brief description" -m "Detailed explanation if needed" --no-edit
```

**Verify changes before commit**:
```bash
git diff HEAD~1 --stat  # See what changed
git diff HEAD~1         # See exact changes
```

## Git Workflow

Every commit must:
1. Address a single issue (one todo = one commit)
2. Include co-author trailer: `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`
3. Have clear message: `Fix: <issue> in <file>` or `Refactor: <file> for <goal>`
4. Pass all existing tests

Example:
```
Fix: Bare except clause in core/orchestrator.py _run_tactical_phase()

Replaced generic except with specific ValueError, TimeoutError. Added
proper logging for debugging. Prevents silent failures in production.

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>
```

## Performance Targets

- **Issue fix time**: 15-45 minutes per issue (excluding testing)
- **Validation time**: 5-10 minutes per fix
- **Commit time**: <1 minute
- **Total throughput**: 8-12 issues per FASE (16-20 hours work)

## When to Use Sub-agents

- **explore agent**: For deep codebase questions before starting a fix
- **task agent**: For running slow tests/builds (move to background)
- **code-review agent**: After all FASE 2 fixes complete (final quality check)

Minimize sub-agent calls. Caveman Mode prefers direct action over analysis paralysis.

## Session Continuity

If session restarts:
1. Read plan.md in session folder (updated at phase transitions)
2. Query SQL `todos` table for current progress
3. Continue where you left off (no re-analysis needed)
