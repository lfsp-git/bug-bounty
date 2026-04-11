╔══════════════════════════════════════════════════════════════════════╗
║                    🦖 WATCHDOG MODE (O PREDADOR)                     ║
║              "Um robô que caça bugs enquanto você dorme"              ║
╚══════════════════════════════════════════════════════════════════════╝

  🌐 INTERNET (HackerOne + Intigriti)
          │
          │  "Ei, quais sites posso testar?"
          ▼
┌─────────────────────┐
│  📋 BUSCA DE ALVOS  │  ← bbscope busca a lista de sites
│  _fetch_global_     │    e salva no cache por 12h
│  wildcards()        │    (como uma lista de compras!)
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
┌─────────────────────┐
│  🧠 SCORING COM IA  │  ← dá nota 0-100 pra cada site
│  _prioritize_by_    │    (quanto maior a nota,
│  bounty_potential() │     mais dinheiro de recompensa!)
└─────────┬───────────┘
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
│  │  httpx → "abre as portas HTTP"             │        │
│  │     ↓                                      │        │
│  │  katana → "explora cada página"            │        │
│  │     ↓                                      │        │
│  │  js-hunter → "acha senhas em JS"           │        │
│  │     ↓                                      │        │
│  │  nuclei → "dispara flechas de vuln! 🎯"    │        │
│  └────────────────────────────────────────────┘        │
└──────────────────────┬─────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          │                         │
    😴 NADA NOVO            🚨 ACHOU ALGO!
          │                         │
          ▼                         ▼
  ┌───────────────┐        ┌─────────────────────┐
  │  Salva no     │        │  📣 ALERTA!          │
  │  histórico    │        │  Telegram 📱         │
  │  e continua   │        │  Discord  💬         │
  └───────────────┘        └─────────────────────┘

          │
          ▼
┌─────────────────────────────────────────────┐
│              😴 DORME UM POUCO...            │
│                                             │
│  Achou muito → dorme 4h  (fica ligado!)     │
│  Achou nada  → dorme 6-7h (economiza)       │
│  Muitos erros → dorme 7-8h (descansa)       │
│  Sem alvos   → dorme 15min (tenta logo)     │
└─────────────────┬───────────────────────────┘
                  │
                  │  "Acorda e começa tudo de novo!"
                  └──────────────────┐
                                     ▼
                              🔄 VOLTA AO INÍCIO
                              (pra sempre, até Ctrl+C)