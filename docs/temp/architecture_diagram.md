# HUNT3R v2.2 - Diagramas de Arquitetura

## 1. Fluxo Principal da Aplicação

```mermaid
graph TD
    A["🚀 main.py<br/>Inicialização"] --> B["📦 _load_env()<br/>Carregar APIs"]
    B --> C["🔧 init_seq()<br/>Atualizar binários"]
    C --> D["🤖 init_ai()<br/>Inicializar LLM"]
    D --> E["🎯 State Machine"]
    
    E --> E1["📱 state_platforms()<br/>HackerOne API"]
    E --> E2["✍️ state_manual()<br/>Input Manual"]
    E --> E3["📋 state_list()<br/>alvos.txt"]
    
    E1 --> F["IntelMiner<br/>Scoring + Ranking"]
    E2 --> F
    E3 --> F
    
    F --> G["ProOrchestrator<br/>Coordenador"]
    G --> H["MissionRunner<br/>Executor de Missão"]
    
    H --> I1["🔍 Fase Recon"]
    H --> I2["🕷️ Fase Tática"]
    H --> I3["🧠 Fase IA"]
    H --> I4["💾 Fase Storage"]
    
    E1 -.->|--watchdog| J["⏰ Watchdog Mode<br/>24/7 Loop"]
    J --> I1
    
    style A fill:#FF6347
    style E fill:#FFD700
    style F fill:#87CEEB
    style G fill:#DDA0DD
    style H fill:#90EE90
```

## 2. Arquitetura em Camadas

```mermaid
graph LR
    subgraph UI["🖥️ CAMADA UI"]
        UIB["UI Manager<br/>Terminal Display"]
    end
    
    subgraph LOGIC["⚙️ CAMADA LÓGICA"]
        Orch["ProOrchestrator"]
        Intel["IntelMiner"]
        MR["MissionRunner"]
    end
    
    subgraph TOOLS["🔨 CAMADA RECONHECIMENTO"]
        SF["Subfinder"]
        DNS["DNSX"]
        HP["HTTPX"]
        KT["Katana"]
        JS["JS Hunter"]
        NUC["Nuclei"]
    end
    
    subgraph EXTERNAL["🌐 CAMADA EXTERNA"]
        H1["HackerOne API"]
        OR["OpenRouter LLM"]
        TG["Telegram Bot"]
        DC["Discord Webhook"]
    end
    
    subgraph STORAGE["💾 CAMADA PERSISTÊNCIA"]
        BL["Baselines"]
        DB["Recon DB"]
        LOG["Logs"]
    end
    
    UI --> LOGIC
    LOGIC --> TOOLS
    LOGIC --> EXTERNAL
    TOOLS --> STORAGE
    EXTERNAL --> STORAGE
```

## 3. Ciclo de Recon - Fase por Fase

```mermaid
graph TB
    Start["📌 Início: Domínios Alvo"] --> S1["1️⃣ SUBFINDER"]
    S1 -->|Subdomínios| S2["2️⃣ DNSX"]
    S2 -->|Hosts Vivos| S3["3️⃣ UNCOVER"]
    S3 -->|Takeovers| S4["4️⃣ HTTPX"]
    S4 -->|Serviços HTTP| S5["5️⃣ SNIPER FILTER"]
    S5 -->|Limpo| S6["6️⃣ KATANA"]
    S6 -->|URLs Crawled| S7["7️⃣ JS HUNTER"]
    S7 -->|Secrets| S8["8️⃣ NUCLEI"]
    S8 -->|Vulnerabilidades| S9["9️⃣ FALSEPOSITIVE KILLER"]
    S9 -->|Limpo| S10["🔟 AIClient"]
    S10 -->|Validado| S11["✅ DIFF ENGINE"]
    S11 -->|Deltas| End["📊 Resultado Final"]
    
    style Start fill:#90EE90
    style S1 fill:#FFB6C1
    style S2 fill:#FFB6C1
    style S3 fill:#FFB6C1
    style S4 fill:#FFB6C1
    style S5 fill:#FFD700
    style S6 fill:#FFB6C1
    style S7 fill:#87CEEB
    style S8 fill:#87CEEB
    style S9 fill:#FFD700
    style S10 fill:#87CEEB
    style S11 fill:#DDA0DD
    style End fill:#90EE90
```

## 4. Estrutura de Classes - Orquestração

```mermaid
graph TB
    Pro["ProOrchestrator<br/>━━━━━━━━━━━━━━━━<br/>+ start_mission<br/>+ get_status"]
    
    MR["MissionRunner<br/>━━━━━━━━━━━━━━━━<br/>+ _run_recon_phase<br/>+ _run_vulnerability_phase<br/>+ _validate_findings_with_ai"]
    
    AI["AIClient<br/>━━━━━━━━━━━━━━━━<br/>+ complete<br/>+ validate_finding"]
    
    IM["IntelMiner<br/>━━━━━━━━━━━━━━━━<br/>+ score<br/>+ select_surgical_arsenal<br/>+ rank_programs_for_list"]
    
    RD["ReconDiff<br/>━━━━━━━━━━━━━━━━<br/>+ compute_diff<br/>+ load_baseline"]
    
    FP["FalsePositiveKiller<br/>━━━━━━━━━━━━━━━━<br/>+ sanitize_findings<br/>+ filter_oob"]
    
    Pro -->|coordena| MR
    MR -->|usa| AI
    MR -->|usa| IM
    MR -->|usa| RD
    MR -->|usa| FP
    
    style Pro fill:#DDA0DD
    style MR fill:#90EE90
    style AI fill:#87CEEB
    style IM fill:#FFD700
    style RD fill:#FFD700
    style FP fill:#FFB6C1
```

## 5. Pipeline de Dados

```mermaid
graph LR
    Input["📥 INPUT<br/>Domínios Alvo"] 
    
    Input --> R["RECON PHASE<br/>Subfinder + DNSX<br/>+ Uncover + HTTPX<br/>↓<br/>🎯 Hosts Vivos"]
    
    R --> T["TACTICAL PHASE<br/>Katana + JS Hunter<br/>+ Nuclei<br/>↓<br/>🎯 Vulnerabilidades"]
    
    T --> F["FILTERING<br/>FalsePositiveKiller<br/>AIClient<br/>↓<br/>🎯 Limpo + Validado"]
    
    F --> D["DIFF ENGINE<br/>Baseline Comparison<br/>↓<br/>🎯 Deltas"]
    
    D --> O["📤 OUTPUT<br/>Telegram/Discord<br/>Baselines JSON"]
    
    style Input fill:#90EE90
    style R fill:#FFB6C1
    style T fill:#87CEEB
    style F fill:#FFD700
    style D fill:#DDA0DD
    style O fill:#FF6347
```

## 6. Integrações Externas

```mermaid
graph TB
    HR["HUNT3R<br/>Core"]
    
    HR -->|Requisição| H1["HackerOne API<br/>GET /programs<br/>GET /scopes"]
    HR -->|Requisição| OR["OpenRouter API<br/>POST /chat/completions"]
    HR -->|Requisição| TG["Telegram Bot<br/>sendMessage"]
    HR -->|Requisição| DC["Discord Webhook<br/>POST webhook"]
    
    HR -->|Executa| SF["🔨 Subfinder<br/>Go Binary"]
    HR -->|Executa| DNS["🔨 DNSX<br/>Go Binary"]
    HR -->|Executa| HP["🔨 HTTPX<br/>Go Binary"]
    HR -->|Executa| UC["🔨 Uncover<br/>Go Binary"]
    HR -->|Executa| KT["🔨 Katana<br/>Go Binary"]
    HR -->|Executa| NUC["🔨 Nuclei<br/>Go Binary"]
    
    HR -->|Git Clone| PT["PayloadsAllTheThings<br/>Custom Payloads"]
    HR -->|Git Update| NUT["Nuclei Templates<br/>Community Templates"]
    
    style HR fill:#FFD700
    style H1 fill:#87CEEB
    style OR fill:#87CEEB
    style TG fill:#87CEEB
    style DC fill:#87CEEB
    style SF fill:#90EE90
    style DNS fill:#90EE90
    style HP fill:#90EE90
    style UC fill:#90EE90
    style KT fill:#90EE90
    style NUC fill:#90EE90
    style PT fill:#FFB6C1
    style NUT fill:#FFB6C1
```

## 7. Detalhamento: IntelMiner - Scoring & Arsenal

```mermaid
graph TB
    PM["HackerOne API<br/>Programas"]
    
    PM --> SCORE["IntelMiner.score()<br/>━━━━━━━━━━━━━━━━"]
    
    SCORE --> T1["Tier 1: 80+ pontos<br/>Fintech, Crypto, Banks"]
    SCORE --> T2["Tier 2: 60+ pontos<br/>Tech Giants, Cloud"]
    SCORE --> T3["Tier 3: 45+ pontos<br/>Healthcare, E-commerce"]
    SCORE --> T4["Tier 4: 30+ pontos<br/>CMS, DevOps"]
    
    T1 --> ARSENAL1["Arsenal Completo<br/>- exposure<br/>- takeover<br/>- misconfig<br/>- sql-injection<br/>- xss"]
    T2 --> ARSENAL2["Arsenal Médio<br/>- exposure<br/>- takeover<br/>- misconfig"]
    T3 --> ARSENAL3["Arsenal Leve<br/>- exposure<br/>- takeover"]
    T4 --> ARSENAL4["Arsenal Mínimo<br/>- exposure"]
    
    ARSENAL1 --> NUC["Nuclei Tags<br/>Selecionados"]
    ARSENAL2 --> NUC
    ARSENAL3 --> NUC
    ARSENAL4 --> NUC
    
    style PM fill:#87CEEB
    style SCORE fill:#FFD700
    style T1 fill:#90EE90
    style T2 fill:#FFB6C1
    style T3 fill:#FFD700
    style T4 fill:#DDA0DD
    style NUC fill:#90EE90
```

## 8. Estrutura de Diretórios

```mermaid
graph TD
    ROOT["📁 bug-bounty/"]
    
    ROOT --> MAIN["main.py<br/>Entrada Principal"]
    ROOT --> CORE["📁 core/<br/>Módulos Principais"]
    ROOT --> RECON["📁 recon/<br/>Motores & Plataformas"]
    ROOT --> CONFIG["📁 config/<br/>Configurações YAML"]
    ROOT --> DOCS["📁 docs/<br/>Documentação"]
    ROOT --> TESTS["📁 tests/<br/>Testes"]
    
    CORE --> C1["orchestrator.py"]
    CORE --> C2["intelligence.py"]
    CORE --> C3["ai_client.py"]
    CORE --> C4["ui_manager.py"]
    CORE --> C5["fp_filter.py"]
    CORE --> C6["diff_engine.py"]
    CORE --> C7["e outros 8 módulos..."]
    
    RECON --> R1["engines.py"]
    RECON --> R2["platforms.py"]
    RECON --> R3["js_hunter.py"]
    RECON --> R4["baselines/"]
    
    CONFIG --> CF1["platforms_config.yaml"]
    CONFIG --> CF2["tools_config.yaml"]
    
    style ROOT fill:#FFD700
    style MAIN fill:#FF6347
    style CORE fill:#90EE90
    style RECON fill:#87CEEB
    style CONFIG fill:#FFB6C1
    style DOCS fill:#DDA0DD
    style TESTS fill:#90EE90
```

## 9. Fluxo de Usuário - Exemplo HackerOne

```mermaid
sequenceDiagram
    participant User as 👤 Usuário
    participant UI as 🖥️ UI Manager
    participant PM as 📱 PlatformManager
    participant H1 as 🌐 HackerOne API
    participant IM as 🧠 IntelMiner
    participant Orch as 🎯 ProOrchestrator
    participant MR as ⚙️ MissionRunner
    
    User->>UI: Seleciona "HackerOne"
    UI->>PM: Solicita programas
    PM->>H1: GET /programs
    H1-->>PM: Retorna lista
    PM->>IM: Rank programs
    IM-->>PM: Programas ordenados
    PM-->>UI: Exibe menu
    
    User->>UI: Seleciona programa
    UI->>Orch: start_mission(handle, domains, score)
    Orch->>MR: Cria MissionRunner
    
    MR->>MR: Fase Recon
    MR->>MR: Fase Tactical
    MR->>MR: Fase IA
    MR->>MR: Fase Storage
    
    MR-->>Orch: Resultado
    Orch-->>UI: Status completo
    UI-->>User: Exibe resultados
```

## 10. Watchdog Mode - Loop Contínuo

```mermaid
graph TD
    START["⏰ Watchdog.run()"]
    
    START --> LOAD["1. Carregar top 15 wildcards<br/>from global_targets.txt"]
    
    LOAD --> LOOP["🔄 LOOP INFINITO (24/7)"]
    
    LOOP --> DELAY["Aguarda intervalo<br/>12 horas"]
    
    DELAY --> SELECT["Seleciona wildcard<br/>aleatoriamente"]
    
    SELECT --> EXPAND["Expande wildcard<br/>com Subfinder"]
    
    EXPAND --> SCAN["Executa recon completo<br/>(Fases: Recon/Tactical/IA)"]
    
    SCAN --> COMPARE["Diff vs baseline<br/>detecta novos assets"]
    
    COMPARE --> NOTIFY["Notifica deltas<br/>Telegram/Discord"]
    
    NOTIFY --> STORE["Armazena baseline<br/>recon/baselines/"]
    
    STORE --> LOOP
    
    style START fill:#FF6347
    style LOOP fill:#FFD700
    style DELAY fill:#FFB6C1
    style SELECT fill:#87CEEB
    style EXPAND fill:#90EE90
    style SCAN fill:#90EE90
    style COMPARE fill:#FFD700
    style NOTIFY fill:#FF6347
    style STORE fill:#DDA0DD
```

## Legenda de Cores

| Cor | Significado |
|-----|-------------|
| 🟩 Verde (#90EE90) | Recon + Execução |
| 🟪 Roxo (#DDA0DD) | Orquestração/Storage |
| 🟦 Azul (#87CEEB) | APIs/Validação |
| 🟨 Amarelo (#FFD700) | Filtragem/Config |
| 🟥 Vermelho (#FF6347) | Alerts/Notificações |
| 🟧 Rosa (#FFB6C1) | Processamento Intermediário |
