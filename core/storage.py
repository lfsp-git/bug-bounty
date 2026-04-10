"""
Hunt3r — Unified storage layer: scan baselines, diff engine, and checkpoints.
"""
from __future__ import annotations

import os
import json
import time
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

BASELINES_DIR = "recon/baselines"
CHECKPOINT_DIR = os.path.expanduser("~/.hunt3r/checkpoints")


# ---------------------------------------------------------------------------
# Baseline diff engine
# ---------------------------------------------------------------------------
class ReconDiff:
    """Compare consecutive scans and detect asset changes."""

    @classmethod
    def _path(cls, handle: str) -> str:
        target_dir = os.path.join(BASELINES_DIR, handle)
        os.makedirs(target_dir, exist_ok=True)
        return os.path.join(target_dir, "baseline.json")

    @classmethod
    def load_baseline(cls, handle: str) -> Optional[Dict]:
        path = cls._path(handle)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"ReconDiff: cannot load baseline for {handle}: {e}")
            return None

    @classmethod
    def save_baseline(cls, handle: str, data: Dict) -> None:
        path = cls._path(handle)  # _path already creates target_dir
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except OSError as e:
            logger.error(f"ReconDiff: cannot save baseline for {handle}: {e}")

    @classmethod
    def compute_diff(
        cls,
        handle: str,
        new_subdomains: Set[str],
        new_endpoints: Set[str],
        new_js_secrets: Optional[Set[str]] = None,
    ) -> Dict:
        baseline = cls.load_baseline(handle)
        result: Dict = {
            "added_subs": set(),
            "removed_subs": set(),
            "added_endpoints": set(),
            "removed_endpoints": set(),
            "added_js_secrets": set(),
            "has_changes": False,
        }
        if baseline is None:
            return result

        old_subs = set(baseline.get("subdomains", []))
        old_ep = set(baseline.get("endpoints", []))
        old_sec = set(baseline.get("js_secrets", []))

        result["added_subs"] = new_subdomains - old_subs
        result["removed_subs"] = old_subs - new_subdomains
        result["added_endpoints"] = new_endpoints - old_ep
        result["removed_endpoints"] = old_ep - new_endpoints
        if new_js_secrets:
            result["added_js_secrets"] = new_js_secrets - old_sec
        result["has_changes"] = bool(
            result["added_subs"] or result["added_endpoints"] or result["added_js_secrets"]
        )
        return result


# ---------------------------------------------------------------------------
# Checkpoint manager (scan resume)
# ---------------------------------------------------------------------------
class CheckpointManager:
    """Save and restore mission progress for resume capability."""

    def __init__(self) -> None:
        os.makedirs(CHECKPOINT_DIR, exist_ok=True)

    def _filepath(self, mission_id: str) -> str:
        return os.path.join(CHECKPOINT_DIR, f"{mission_id}.json")

    def save(self, mission_id: str, data: Dict[str, Any]) -> bool:
        payload = {
            "mission_id": mission_id,
            "timestamp": datetime.now().isoformat(),
            "completed_targets": data.get("completed_targets", []),
            "findings": data.get("findings", []),
            "last_target": data.get("last_target"),
            "progress": data.get("progress", {}),
        }
        try:
            with open(self._filepath(mission_id), "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            return True
        except OSError as e:
            logger.error(f"Checkpoint save failed: {e}")
            return False

    def load(self, mission_id: str) -> Optional[Dict[str, Any]]:
        fp = self._filepath(mission_id)
        if not os.path.exists(fp):
            return None
        try:
            with open(fp, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"Checkpoint load failed: {e}")
            return None

    def delete(self, mission_id: str) -> None:
        fp = self._filepath(mission_id)
        if os.path.exists(fp):
            try:
                os.remove(fp)
            except OSError as e:
                logger.error(f"Checkpoint delete failed: {e}")

    def list_all(self) -> List[Dict[str, Any]]:
        results = []
        try:
            for fname in os.listdir(CHECKPOINT_DIR):
                if fname.endswith(".json"):
                    fp = os.path.join(CHECKPOINT_DIR, fname)
                    try:
                        with open(fp, "r", encoding="utf-8") as f:
                            results.append(json.load(f))
                    except (OSError, json.JSONDecodeError):
                        pass
        except OSError:
            pass
        return results

    def add_completed_target(
        self, mission_id: str, target_handle: str, findings: List[Dict]
    ) -> bool:
        data = self.load(mission_id) or {
            "mission_id": mission_id,
            "completed_targets": [],
            "findings": [],
        }
        if target_handle not in data["completed_targets"]:
            data["completed_targets"].append(target_handle)
        data["findings"].extend(findings)
        data["last_target"] = target_handle
        return self.save(mission_id, data)


def resume_mission(mission_id: str) -> None:
    """Display checkpoint info and exit (full resume wired in future iteration)."""
    from core.ui import ui_log, Colors  # deferred import avoids circular

    mgr = CheckpointManager()
    cp = mgr.load(mission_id)
    if not cp:
        ui_log("RESUME", f"No checkpoint found: {mission_id}", Colors.ERROR)
        return

    completed = cp.get("completed_targets", [])
    total = len(cp.get("findings", []))
    ui_log("RESUME", f"Checkpoint from {cp.get('timestamp', '?')}", Colors.SUCCESS)
    ui_log("RESUME", f"Completed: {len(completed)} targets, {total} findings", Colors.SUCCESS)
    for t in completed[:5]:
        print(f"  • {t}")
    if len(completed) > 5:
        print(f"  ...and {len(completed) - 5} more")
    print(f"\n{Colors.WARNING}Full resume wired in next iteration.{Colors.RESET}\n")
