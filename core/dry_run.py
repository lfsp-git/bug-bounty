"""Dry run mode: preview scan targets without executing tools."""
import json
import logging
from datetime import datetime
from recon.platforms import PlatformManager
from core.ui_manager import ui_log, Colors
from core.diff_engine import ReconDiff

logger = logging.getLogger(__name__)

def run_dry_run():
    """Preview mode: Load targets from all platforms, show what would be scanned."""
    try:
        # Load targets from all platforms
        pm = PlatformManager()
        all_targets = []
        
        platforms = ['h1', 'bc', 'it']
        for platform in platforms:
            try:
                targets = pm.get_all_programs_from_platform(platform)
                all_targets.extend(targets)
                ui_log(f"DRY-RUN:{platform.upper()}", f"Loaded {len(targets)} targets", Colors.SUCCESS)
            except Exception as e:
                ui_log(f"DRY-RUN:{platform.upper()}", f"Failed: {str(e)[:50]}", Colors.WARNING)
        
        if not all_targets:
            ui_log("DRY-RUN", "No targets found across all platforms", Colors.ERROR)
            return
        
        # Apply diff engine to find new/modified targets
        diff = ReconDiff()
        new_targets = diff.identify_new_programs(all_targets)
        modified = diff.identify_modified_programs(all_targets)
        
        # Prepare report
        report = {
            "timestamp": datetime.now().isoformat(),
            "mode": "dry-run",
            "total_platforms": len([p for p in platforms]),
            "total_targets": len(all_targets),
            "new_targets": len(new_targets),
            "modified_targets": len(modified),
            "targets": [
                {
                    "handle": t.get("handle"),
                    "domains": t.get("domains", []),
                    "status": "new" if t in new_targets else "modified" if t in modified else "unchanged"
                }
                for t in all_targets
            ]
        }
        
        # Output report
        print("\n" + "="*60)
        print(f"DRY RUN REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        print(f"Total targets:    {report['total_targets']}")
        print(f"New targets:      {report['new_targets']}")
        print(f"Modified:         {report['modified_targets']}")
        print(f"Unchanged:        {report['total_targets'] - report['new_targets'] - report['modified_targets']}")
        print("="*60 + "\n")
        
        # Show targets to be scanned
        for target in report['targets']:
            status_color = Colors.SUCCESS if target['status'] == 'new' else Colors.WARNING if target['status'] == 'modified' else Colors.DIM
            status_label = f"[{target['status'].upper()}]"
            domains_str = ", ".join(target['domains'][:3])
            if len(target['domains']) > 3:
                domains_str += f", +{len(target['domains'])-3} more"
            ui_log("TARGET", f"{target['handle']} - {domains_str} {status_label}", status_color)
        
        # Save report to file
        report_file = f"./reports/dry_run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        import os
        os.makedirs(os.path.dirname(report_file), exist_ok=True)
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        ui_log("DRY-RUN", f"Report saved to {report_file}", Colors.SUCCESS)
        print()
        
    except Exception as e:
        logger.error(f"Dry run failed: {e}", exc_info=True)
        ui_log("DRY-RUN", f"Error: {str(e)[:60]}", Colors.ERROR)
