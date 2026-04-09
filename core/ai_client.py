import os, json, requests, logging
from typing import Optional, List, Dict

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

class AIClient:
    MODELS_FILE = "config/selected_model.json"

    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY", "")
        self.base_url = "https://openrouter.ai/api/v1"
        self.selected_model = self._load_saved_model()
        self._cache = []
        # Create a session with explicit SSL verification
        self.session = requests.Session()
        self.session.verify = True  # Explicit: Always verify SSL certificates

    def _load_saved_model(self) -> Optional[str]:
        if os.path.exists(self.MODELS_FILE):
            try:
                with open(self.MODELS_FILE, 'r') as f:
                    data = json.load(f)
                    return data.get("model")
            except Exception as e:
                logger.debug(f"Failed to load saved model: {e}")
        return None

    def save_model(self, model_id: str):
        self.selected_model = model_id
        os.makedirs(os.path.dirname(self.MODELS_FILE), exist_ok=True)
        with open(self.MODELS_FILE, 'w') as f:
            json.dump({"model": model_id}, f)

    def fetch_curated_models(self) -> List[Dict]:
        if self._cache: return self._cache
        if not self.api_key:
            print("[!] OPENROUTER_API_KEY não configurada.")
            return []
        try:
            r = self.session.get(
                f"{self.base_url}/models",
                headers={"Authorization":f"Bearer {self.api_key}"},
                timeout=15,
                verify=True  # Explicit SSL verification
            )
            if r.status_code == 200:
                data = r.json()
                free = [m for m in data.get("data",[]) if m.get("pricing",{}).get("prompt","0")=="0"]
                free.sort(key=lambda x: x.get("context_length",0), reverse=True)
                self._cache = free[:15]
                return self._cache
        except Exception as e:
            logger.error(f"Failed to fetch models: {e}")
            print(f"[!] Erro: {e}")
        return []

    def complete(self, prompt, max_tokens=500) -> str:
        if not self.api_key or not self.selected_model: return "[AI Offline]"
        try:
            r = self.session.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization":f"Bearer {self.api_key}",
                    "Content-Type":"application/json"
                },
                json={
                    "model":self.selected_model,
                    "messages":[{"role":"user","content":prompt}],
                    "max_tokens":max_tokens
                },
                timeout=60,
                verify=True  # Explicit SSL verification
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
            return f"[API Error {r.status_code}]"
        except Exception as e:
            logger.error(f"AI completion failed: {e}")
            return f"[Error: {str(e)[:100]}]"


def select_model_interactive(ai_client) -> bool:
    """UI flow para selecionar e salvar modelo OpenRouter."""
    if not ai_client.api_key:
        return False
    models = ai_client.fetch_curated_models()
    if not models:
        return False
    from core.ui_manager import ui_model_selection_menu
    chosen = ui_model_selection_menu(models)
    if chosen:
        ai_client.save_model(chosen)
        return True
    return False
