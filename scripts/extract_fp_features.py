#!/usr/bin/env python3
"""
FASE 8: Feature extraction from historical Nuclei findings
Goal: Parse all findings.jsonl files and extract ML features

Output: data/fp_features.csv with columns:
  - template_id, severity, response_len, extracted_results_len, host_type
  - template_tags, matched_status, response_content_type
"""

import json
import os
import csv
import sys
from pathlib import Path
from collections import defaultdict

# Add project root to path
sys.path.insert(0, '/home/leonardofsp/bug-bounty')

from core.ui import Colors, ui_log

class FeatureExtractor:
    """Extract ML features from Nuclei findings"""
    
    def __init__(self):
        self.findings_dir = "/home/leonardofsp/bug-bounty/recon/baselines"
        self.output_file = "/home/leonardofsp/bug-bounty/data/fp_features.csv"
        self.features = []
        self.stats = defaultdict(int)
    
    def extract_all(self):
        """Extract features from all baseline findings"""
        ui_log("EXTRACTOR", "Starting feature extraction...", Colors.INFO)
        
        # Iterate all baselines
        for baseline_dir in sorted(Path(self.findings_dir).iterdir()):
            if not baseline_dir.is_dir() or baseline_dir.name.startswith("_"):
                continue
            
            findings_file = baseline_dir / "findings.jsonl"
            if not findings_file.exists():
                continue
            
            self._extract_from_file(findings_file, baseline_dir.name)
        
        # Save CSV
        self._save_features()
        self._print_stats()
    
    def _extract_from_file(self, findings_file, target_name):
        """Extract features from single findings.jsonl"""
        try:
            with open(findings_file) as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Try JSON format first (Nuclei -o output)
                    try:
                        finding = json.loads(line)
                        feature = self._extract_feature(finding, target_name)
                        if feature:
                            self.features.append(feature)
                            self.stats["json_findings"] += 1
                    except json.JSONDecodeError:
                        # Fall back to plain text format (current Hunt3r)
                        # Format: [CVE-ID] [type] [severity] URL
                        feature = self._extract_feature_from_text(line, target_name)
                        if feature:
                            self.features.append(feature)
                            self.stats["text_findings"] += 1
        
        except Exception as e:
            ui_log("EXTRACTOR", f"Error reading {findings_file}: {e}", Colors.WARNING)
            self.stats["errors"] += 1
    
    def _extract_feature(self, finding, target_name):
        """Extract feature dict from Nuclei JSON finding"""
        try:
            # Extract basic fields
            template_id = finding.get("template-id", "unknown")
            severity = finding.get("info", {}).get("severity", "info")
            matched_at = finding.get("matched-at", "")
            host = finding.get("host", "")
            response = finding.get("response", "")
            request = finding.get("request", "")
            
            # Extract tags from info
            tags = finding.get("info", {}).get("tags", [])
            tags_str = ",".join(tags) if tags else ""
            
            # Response metrics
            response_len = len(response) if response else 0
            request_len = len(request) if request else 0
            
            # Extract results if present
            extracted_results = finding.get("extracted-results", [])
            extracted_len = len(str(extracted_results))
            
            # Response content type detection
            content_type = "unknown"
            if response:
                if "Content-Type: application/json" in response:
                    content_type = "json"
                elif "Content-Type: text/html" in response:
                    content_type = "html"
                elif "Content-Type: text/plain" in response:
                    content_type = "text"
                elif "Content-Type: application/xml" in response:
                    content_type = "xml"
                elif "Content-Type: image/" in response:
                    content_type = "image"
            
            # Host type detection
            host_type = self._detect_host_type(host)
            
            # Matched status (HTTP status code if in response)
            matched_status = "unknown"
            if response and "HTTP/1." in response:
                try:
                    status_line = response.split("\r\n")[0]
                    matched_status = status_line.split()[1] if len(status_line.split()) > 1 else "unknown"
                except:
                    matched_status = "unknown"
            
            return {
                "template_id": template_id,
                "severity": severity,
                "target": target_name,
                "response_len": response_len,
                "request_len": request_len,
                "extracted_len": extracted_len,
                "host": host,
                "matched_at": matched_at,
                "tags": tags_str,
                "content_type": content_type,
                "host_type": host_type,
                "matched_status": matched_status,
                "source": "json"
            }
        except Exception as e:
            self.stats["feature_errors"] += 1
            return None
    
    def _extract_feature_from_text(self, line, target_name):
        """Extract feature from plain text format (current Hunt3r)
        Format: [CVE-ID] [type] [severity] URL
        """
        try:
            parts = line.split("] ")
            if len(parts) < 3:
                return None
            
            # Parse: [CVE-ID]
            cve_id = parts[0].strip("[]")
            
            # Parse: [type]
            finding_type = parts[1].strip("[]") if len(parts) > 1 else "unknown"
            
            # Parse: [severity]
            severity = parts[2].strip("[]") if len(parts) > 2 else "info"
            
            # Extract URL (everything after severity)
            url = " ".join(parts[3:]).strip() if len(parts) > 3 else ""
            
            return {
                "template_id": cve_id,
                "severity": severity,
                "target": target_name,
                "response_len": 0,
                "request_len": 0,
                "extracted_len": 0,
                "host": url,
                "matched_at": url,
                "tags": finding_type,
                "content_type": "unknown",
                "host_type": self._detect_host_type(url),
                "matched_status": "200",
                "source": "text"
            }
        except Exception as e:
            self.stats["text_parse_errors"] += 1
            return None
    
    def _detect_host_type(self, host):
        """Detect host type: wordpress, docker, subdomain, etc."""
        host_lower = host.lower()
        
        if "wordpress" in host_lower or "wp-" in host_lower:
            return "wordpress"
        elif "docker" in host_lower or "container" in host_lower:
            return "docker"
        elif "aws" in host_lower or "ec2" in host_lower or ".amazonaws.com" in host_lower:
            return "aws"
        elif "azure" in host_lower or ".azurewebsites.net" in host_lower:
            return "azure"
        elif "github" in host_lower:
            return "github"
        elif "api" in host_lower:
            return "api"
        elif "admin" in host_lower:
            return "admin"
        elif "localhost" in host_lower or "127.0.0.1" in host_lower:
            return "local"
        elif ".dev" in host_lower or ".local" in host_lower:
            return "dev"
        else:
            return "standard"
    
    def _save_features(self):
        """Save extracted features to CSV"""
        if not self.features:
            ui_log("EXTRACTOR", "No features found!", Colors.WARNING)
            return
        
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        
        with open(self.output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.features[0].keys())
            writer.writeheader()
            writer.writerows(self.features)
        
        ui_log("EXTRACTOR", f"Saved {len(self.features)} features to {self.output_file}", Colors.SUCCESS)
    
    def _print_stats(self):
        """Print extraction statistics"""
        print("\n" + "="*60)
        print("FEATURE EXTRACTION STATISTICS")
        print("="*60)
        print(f"Total Features: {len(self.features)}")
        print(f"JSON Findings: {self.stats['json_findings']}")
        print(f"Text Findings: {self.stats['text_findings']}")
        print(f"Errors: {self.stats['errors']}")
        print(f"Feature Extraction Errors: {self.stats['feature_errors']}")
        print(f"Text Parse Errors: {self.stats['text_parse_errors']}")
        print("="*60 + "\n")

if __name__ == "__main__":
    extractor = FeatureExtractor()
    extractor.extract_all()
