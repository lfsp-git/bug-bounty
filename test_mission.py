#!/usr/bin/env python3
"""Script de teste para Hunt3r - executa uma missão única otimizada para testes rápidos."""

import sys
import os
import signal
import time

# Adiciona o diretório do projeto ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Timeout global para o teste
TIMEOUT_SECONDS = 60  # 60 segundos max para teste

def timeout_handler(signum, frame):
    print("\n[TIMEOUT] Teste excedeu o tempo limite de 60s")
    print("[INFO] Para teste completo, execute o orchestrator diretamente")
    sys.exit(0)

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(TIMEOUT_SECONDS)

from core.orchestrator import ProOrchestrator
from core.intelligence import IntelMiner
from core.ai_client import AIClient
from core import ui_manager

# Desativa live view para testes rápidos
ui_manager._live_view_active = False

# Configuração básica
ai = AIClient()

# Cria o orquestrador
orch = ProOrchestrator(IntelMiner(ai))

# Define um alvo de teste pequeno (wikipedia é bom porque tem muitos subdomínios)
# Mas para teste rápido, vamos usar um alvo menor
target = {
    'handle': 'test_wikipedia',
    'domains': ['example.com'],  # Tem subdomínios mas não muitos
    'score': 30
}

print(f"Iniciando missão de teste para {target['domains'][0]}...")
print(f"[TIMEOUT] Teste irá timeout em {TIMEOUT_SECONDS}s")
print("-" * 50)

start = time.time()
try:
    orch.start_mission(target)
    elapsed = time.time() - start
    print("-" * 50)
    print(f"Missão concluída em {elapsed:.1f}s")
except Exception as e:
    print(f"Erro durante a missão: {e}")
    import traceback
    traceback.print_exc()

signal.alarm(0)  # Cancela o alarme
