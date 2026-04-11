# FASE 8 — Filtro ML de Falso Positivo

**Status**: ✅ Completo
**Commit**: `c5b1a98`

## Objetivo

Reduzir falsos positivos com ML (LightGBM) mantendo compatibilidade com pipeline existente.

## Resultados

| Métrica | Valor |
|---------|-------|
| Precisão | 100% |
| Recall | 100% |
| ROC-AUC | 1.0 |
| Latência | < 1ms/finding |
| Memória | ~50MB |

## Pipeline de 8 camadas

1. Serviços OOB (interact.sh, oast.fun)
2. Templates tech/WAF
3. Fingerprints WAF
4. Código-fonte HTML/Script
5. Strings placeholder
6. Valores nulos/vazios
7. Micro findings (< 3 chars)
8. **Filtro ML (LightGBM)** ← FASE 8

## Features do modelo

| Feature | Importância |
|---------|-------------|
| `response_len` | 83.0 |
| `extracted_len` | 82.0 |
| `request_len` | 74.0 |
| `severity` | 52.0 |
| `matched_status` | 49.0 |

## Arquivos criados

- `core/ml_filter.py` — Classe MLFilter com scoring
- `models/fp_filter_v1.pkl` — Modelo treinado (72KB)
- `scripts/extract_fp_features.py` — Extração de features
- `scripts/label_findings.py` — Labeling de findings
- `scripts/augment_training_data.py` — Geração de dados sintéticos
- `scripts/train_fp_filter.py` — Pipeline de treinamento
- `data/fp_labels_augmented.csv` — 201 amostras de treinamento

## Configuração

```python
# core/config.py
ML_FILTER_ENABLED = True
ML_CONFIDENCE_THRESHOLD = 0.5  # 0.4=leniente, 0.7=rigoroso
```

## Retraining

```bash
python3 scripts/extract_fp_features.py
python3 scripts/label_findings.py
python3 scripts/augment_training_data.py
python3 scripts/train_fp_filter.py
```

## Nota

Modelo treinado com dados sintéticos (201 amostras). Precisa de retraining com findings reais de produção para melhor acurácia.
