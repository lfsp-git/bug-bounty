╔══════════════════════════════════════════════════════════════════════╗
║                    🦖 WATCHDOG MODE (O PREDADOR)                     ║
║              "Um robô que caça bugs enquanto você dorme"              ║
╚══════════════════════════════════════════════════════════════════════╝

  🌐 INTERNET (HackerOne + Intigriti + alvos.txt)
          │
          │  "Ei, quais sites posso testar?"
          ▼
┌─────────────────────┐
│  📋 BUSCA DE ALVOS  │  ← bbscope (H1/IT) busca wildcards e
│  _fetch_global_     │    tags cada alvo com a plataforma origem
│  wildcards()        │    (h1 / it / custom). Cache 12h.
└─────────┬───────────┘
          │
          │  "Limpa a lista, tira lixo"
          ▼
┌─────────────────────┐
│  🧹 NORMALIZA       │  ← transforma "*.acme.com" em "acme.com"
│  _normalize_target  │    detecta IPs/CIDRs e expande em handles
│  _domain()          │    e detecta sites NOVOS! 🆕
└─────────┬───────────┘
          │
          │  "Qual site vale mais a pena?"
          ▼
┌─────────────────────────────────────────────────────┐
│  🧠 SCORING COM IA (0-100)                          │
│  _prioritize_by_bounty_potential()                  │
│                                                     │
│  wildcard scope  35% — *.domínio = superfície total │
│  breadth         25% — mais domínios = mais alvos   │
│  target quality  25% — TLD / bounty / fintech       │
│  platform signal 15% — H1 > IT > BC (histórico)     │
│                                                     │
│  Score gravado no target dict → AI validation       │
│  dispara apenas para score ≥ 60                     │
└─────────┬───────────────────────────────────────────┘
          │
          │  "Vamos atacar em paralelo!"
          ▼
┌────────────────────────────────────────────────────────┐
│               ⚡ WORKERS PARALELOS (até 3)              │
│                                                         │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐           │
│  │   W1 🤖  │   │   W2 🤖  │   │   W3 🤖  │           │
│  │ site A   │   │ site B   │   │ site C   │           │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘           │
│       │              │              │                  │
│       ▼ (cada worker faz isso):     │                  │
│  ┌────────────────────────────────────────────┐        │
│  │           🔍 PIPELINE DE SCAN (9 TOOLS)    │        │
│  │                                            │        │
│  │  [Domínio] subfinder → "acha subdomínios" │        │
│  │            dnsx      → "quais vivos?"      │        │
│  │            uncover   → "Shodan/Censys"     │        │
│  │  [IP/CIDR] naabu 🔌  → "30 portas web!"   │        │
│  │     ↓ (ambos convergem aqui)               │        │
│  │  httpx → "URLs HTTP vivas"                 │        │
│  │     ↓                                      │        │
│  │  katana → "explora páginas + JS 🕷️"        │        │
│  │     (-js-crawl depth 3 → APIs em SPAs)     │        │
│  │     ↓                                      │        │
│  │  urlfinder 📜 → "URLs do passado"          │        │
│  │     (Wayback/AlienVault archives)          │        │
│  │     ↓                                      │        │
│  │  MERGE → dedup de todas as URLs            │        │
│  │     ↓                                      │        │
│  │  js-hunter → "acha senhas em JS 🗝️"        │        │
│  │     (severity: CRITICAL/HIGH/MEDIUM/LOW)   │        │
│  │     ↓                                      │        │
│  │  nuclei → "dispara flechas de vuln! 🎯"    │        │
│  │     (apenas Medium/High/Critical)          │        │
│  └────────────────────────────────────────────┘        │
└──────────────────────┬─────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          │                         │
    😴 NADA NOVO            🚨 ACHOU ALGO!
          │                         │
          ▼                         ▼
  ┌───────────────┐        ┌──────────────────────────────────┐
  │  Salva no     │        │  📣 ALERTAS                       │
  │  histórico    │        │  Telegram 📱 — vulns M/H/C        │
  │  e continua   │        │  Discord  💬 — stats do scan      │
  └───────────────┘        │  (subs, hosts, portas, endpoints, │
                           │   hist URLs, segredos, vulns)      │
                           └──────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────┐
│              😴 DORME UM POUCO...            │
│                                             │
│  Achou muito  → dorme 1h  (fica ligado!)    │
│  Achou nada   → dorme 2-3h (economiza)      │
│  Muitos erros → dorme 3-4h (descansa)       │
│  Sem alvos    → dorme 15min (tenta logo)    │
└─────────────────┬───────────────────────────┘
                  │
                  │  "Acorda e começa tudo de novo!"
                  └──────────────────┐
                                     ▼
                              🔄 VOLTA AO INÍCIO
                              (pra sempre, até Ctrl+C)

## Relatórios

Cada missão gera um `.md` em `reports/` com:
- Plataforma de origem (HackerOne / Intigriti / Custom (alvos.txt))
- Estatísticas: subdomínios, hosts vivos, **portas abertas**, endpoints, **URLs históricas**, segredos JS, vulns
- Tabela de vulnerabilidades (apenas Medium/High/Critical)
- Checklist de submissão

## Modo --clean

```
Purge cache → Update tools → Update deps Python →
Health check ferramentas → Status API keys →
Sync uncover providers → Verificar modelo ML → Rodar testes
```

## Tipos de alvo suportados

```
example.com       → domínio (subfinder + dnsx + uncover)
*.example.com     → wildcard (normalizado para example.com)
192.168.1.1       → IP único (naabu port-scan → httpx)
10.0.0.0/24       → CIDR (expandido, colapsado em handle único)
```

║                    🦖 WATCHDOG MODE (O PREDADOR)                     ║
║              "Um robô que caça bugs enquanto você dorme"              ║
╚══════════════════════════════════════════════════════════════════════╝

  🌐 INTERNET (HackerOne + Intigriti + alvos.txt)
          │
          │  "Ei, quais sites posso testar?"
          ▼
┌─────────────────────┐
│  📋 BUSCA DE ALVOS  │  ← bbscope (H1/IT) busca wildcards e
│  _fetch_global_     │    tags cada alvo com a plataforma origem
│  wildcards()        │    (h1 / it / custom). Cache 12h.
└─────────┬───────────┘
          │
          │  "Limpa a lista, tira lixo"
          ▼
┌─────────────────────┐
│  🧹 NORMALIZA       │  ← transforma "*.acme.com"
│  _normalize_target  │    em "acme.com"
│  _domain()          │    e detecta sites NOVOS! 🆕
└─────────┬───────────┘
          │
          │  "Qual site vale mais a pena?"
          ▼
┌─────────────────────────────────────────────────────┐
│  🧠 SCORING COM IA (0-100)                          │
│  _prioritize_by_bounty_potential()                  │
│                                                     │
│  wildcard scope  35% — *.domínio = superfície total │
│  breadth         25% — mais domínios = mais alvos   │
│  target quality  25% — TLD / bounty / fintech       │
│  platform signal 15% — H1 > IT > BC (histórico)     │
│                                                     │
│  Score gravado no target dict → AI validation       │
│  dispara apenas para score ≥ 60                     │
└─────────┬───────────────────────────────────────────┘
          │
          │  "Vamos atacar em paralelo!"
          ▼
┌────────────────────────────────────────────────────────┐
│               ⚡ WORKERS PARALELOS (até 3)              │
│                                                         │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐           │
│  │   W1 🤖  │   │   W2 🤖  │   │   W3 🤖  │           │
│  │ site A   │   │ site B   │   │ site C   │           │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘           │
│       │              │              │                  │
│       ▼ (cada worker faz isso):     │                  │
│  ┌────────────────────────────────────────────┐        │
│  │           🔍 PIPELINE DE SCAN              │        │
│  │                                            │        │
│  │  subfinder → "acha subdomínios"            │        │
│  │     ↓                                      │        │
│  │  dnsx → "quais estão vivos?"               │        │
│  │     ↓                                      │        │
│  │  uncover → "hosts via Shodan/Censys"       │        │
│  │     ↓                                      │        │
│  │  httpx → "abre as portas HTTP"             │        │
│  │     ↓                                      │        │
│  │  katana → "explora cada página"            │        │
│  │     ↓                                      │        │
│  │  js-hunter → "acha senhas em JS 🗝️"        │        │
│  │     (severity: CRITICAL/HIGH/MEDIUM/LOW)   │        │
│  │     ↓                                      │        │
│  │  nuclei → "dispara flechas de vuln! 🎯"    │        │
│  │     (apenas Medium/High/Critical)          │        │
│  └────────────────────────────────────────────┘        │
└──────────────────────┬─────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          │                         │
    😴 NADA NOVO            🚨 ACHOU ALGO!
          │                         │
          ▼                         ▼
  ┌───────────────┐        ┌─────────────────────────────┐
  │  Salva no     │        │  📣 ALERTAS                  │
  │  histórico    │        │  Telegram 📱 — vulns M/H/C   │
  │  e continua   │        │  Discord  💬 — stats do scan │
  └───────────────┘        │  (plataforma, subs, hosts,   │
                           │   endpoints, segredos)        │
                           └─────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────┐
│              😴 DORME UM POUCO...            │
│                                             │
│  Achou muito  → dorme 1h  (fica ligado!)    │
│  Achou nada   → dorme 2-3h (economiza)      │
│  Muitos erros → dorme 3-4h (descansa)       │
│  Sem alvos    → dorme 15min (tenta logo)    │
└─────────────────┬───────────────────────────┘
                  │
                  │  "Acorda e começa tudo de novo!"
                  └──────────────────┐
                                     ▼
                              🔄 VOLTA AO INÍCIO
                              (pra sempre, até Ctrl+C)

## Relatórios

Cada missão gera um `.md` em `reports/` com:
- Plataforma de origem (HackerOne / Intigriti / Custom (alvos.txt))
- Estatísticas: subdomínios, hosts vivos, endpoints, segredos JS, vulns
- Tabela de vulnerabilidades (apenas Medium/High/Critical)
- Checklist de submissão

## Modo --clean

```
Purge cache → Update tools → Update deps Python →
Health check ferramentas → Status API keys →
Sync uncover providers → Verificar modelo ML → Rodar testes
```
