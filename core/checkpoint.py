"""Checkpoint and resume capability for paused scans."""
import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class CheckpointManager:
    """Manages scan checkpoints for resume capability."""
    
    CHECKPOINT_DIR = os.path.expanduser("~/.hunt3r/checkpoints")
    
    def __init__(self):
        os.makedirs(self.CHECKPOINT_DIR, exist_ok=True)
    
    def save_checkpoint(self, mission_id: str, data: Dict[str, Any]) -> bool:
        """Save checkpoint for a mission."""
        try:
            checkpoint_file = os.path.join(self.CHECKPOINT_DIR, f"{mission_id}.json")
            checkpoint_data = {
                "mission_id": mission_id,
                "timestamp": datetime.now().isoformat(),
                "completed_targets": data.get("completed_targets", []),
                "findings": data.get("findings", []),
                "last_target": data.get("last_target"),
                "progress": data.get("progress", {}),
            }
            with open(checkpoint_file, 'w') as f:
                json.dump(checkpoint_data, f, indent=2)
            logger.info(f"Checkpoint saved for mission {mission_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")
            return False
    
    def load_checkpoint(self, mission_id: str) -> Optional[Dict[str, Any]]:
        """Load checkpoint for a mission."""
        try:
            checkpoint_file = os.path.join(self.CHECKPOINT_DIR, f"{mission_id}.json")
            if not os.path.exists(checkpoint_file):
                logger.warning(f"Checkpoint not found: {mission_id}")
                return None
            
            with open(checkpoint_file, 'r') as f:
                data = json.load(f)
            logger.info(f"Checkpoint loaded for mission {mission_id}")
            return data
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")
            return None
    
    def delete_checkpoint(self, mission_id: str) -> bool:
        """Delete checkpoint after scan completes."""
        try:
            checkpoint_file = os.path.join(self.CHECKPOINT_DIR, f"{mission_id}.json")
            if os.path.exists(checkpoint_file):
                os.remove(checkpoint_file)
                logger.info(f"Checkpoint deleted for mission {mission_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete checkpoint: {e}")
            return False
    
    def list_checkpoints(self) -> List[Dict[str, Any]]:
        """List all available checkpoints."""
        try:
            checkpoints = []
            for filename in os.listdir(self.CHECKPOINT_DIR):
                if filename.endswith('.json'):
                    filepath = os.path.join(self.CHECKPOINT_DIR, filename)
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    checkpoints.append(data)
            return checkpoints
        except Exception as e:
            logger.error(f"Failed to list checkpoints: {e}")
            return []
    
    def get_completed_targets(self, mission_id: str) -> List[str]:
        """Get list of completed targets for a mission."""
        checkpoint = self.load_checkpoint(mission_id)
        if checkpoint:
            return checkpoint.get("completed_targets", [])
        return []
    
    def add_completed_target(self, mission_id: str, target_handle: str, findings: List[Dict]) -> bool:
        """Add target to completed list and save findings."""
        try:
            checkpoint = self.load_checkpoint(mission_id) or {
                "mission_id": mission_id,
                "timestamp": datetime.now().isoformat(),
                "completed_targets": [],
                "findings": [],
            }
            
            if target_handle not in checkpoint["completed_targets"]:
                checkpoint["completed_targets"].append(target_handle)
            
            checkpoint["findings"].extend(findings)
            checkpoint["last_target"] = target_handle
            checkpoint["timestamp"] = datetime.now().isoformat()
            
            return self.save_checkpoint(mission_id, checkpoint)
        except Exception as e:
            logger.error(f"Failed to add completed target: {e}")
            return False


def resume_mission(mission_id: str):
    """Resume a paused mission from checkpoint."""
    from core.ui_manager import ui_log, Colors
    
    checkpoint_mgr = CheckpointManager()
    checkpoint = checkpoint_mgr.load_checkpoint(mission_id)
    
    if not checkpoint:
        ui_log("RESUME", f"No checkpoint found for mission {mission_id}", Colors.ERROR)
        return
    
    completed = checkpoint.get("completed_targets", [])
    total_findings = len(checkpoint.get("findings", []))
    
    ui_log("RESUME", f"Found checkpoint from {checkpoint.get('timestamp', 'unknown')}", Colors.SUCCESS)
    ui_log("RESUME", f"Completed targets: {len(completed)}", Colors.SUCCESS)
    ui_log("RESUME", f"Findings so far: {total_findings}", Colors.SUCCESS)
    
    if completed:
        print(f"\n{Colors.DIM}Completed targets:{Colors.RESET}")
        for target in completed[:5]:
            print(f"  • {target}")
        if len(completed) > 5:
            print(f"  ... and {len(completed)-5} more")
    
    # TODO: Implement actual resume logic (continue from last target)
    print(f"\n{Colors.WARNING}Resume functionality coming in next update.{Colors.RESET}\n")
