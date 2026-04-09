#!/usr/bin/env python3
"""Script de teste para Hunt3r - executa uma missão única sem interação."""

import sys
import os

# Adiciona o diretório do projeto ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.orchestrator import ProOrchestrator
from core.intelligence import IntelMiner
from core.ai_client import AIClient

# Configuração básica
ai = AIClient()
if ai.api_key and not ai.selected_model:
    # Seleciona um modelo padrão (ou remove essa verificação para testes)
    pass

# Cria o orquestrador
orch = ProOrchestrator(IntelMiner(ai))

# Define um alvo de teste
target = {
    'handle': 'test_example',
    'domains': ['example.com'],
    'score': 30
}

print("Iniciando missão de teste para example.com...")
orch.start_mission(target)
print("Missão concluída.")