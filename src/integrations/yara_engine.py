"""YARA rules engine for malware and phishing pattern detection."""

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import yara

logger = logging.getLogger(__name__)


class YaraEngine:
    """YARA rules engine for pattern matching."""
    
    def __init__(self, rules_directory: str = "data/yara_rules"):
        self.rules_directory = Path(rules_directory)
        self.compiled_rules: Optional[yara.Rules] = None
        self.rules_info: Dict[str, Dict] = {}
        
        # Ensure rules directory exists
        self.rules_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize with default rules
        self._create_default_rules()
        self._compile_rules()
    
    def _create_default_rules(self):
        """Create default YARA rules for phishing detection."""
        
        # Phishing patterns rule
        phishing_rules = '''
rule Phishing_Urgent_Action {
    meta:
        description = "Detects urgent action phishing patterns"
        category = "phishing"
        severity = "high"
    
    strings:
        $urgent1 = "urgent" nocase
        $urgent2 = "immediate action" nocase
        $urgent3 = "act now" nocase
        $urgent4 = "expires today" nocase
        $urgent5 = "limited time" nocase
        
        $action1 = "click here" nocase
        $action2 = "verify account" nocase
        $action3 = "update payment" nocase
        $action4 = "confirm identity" nocase
        
    condition:
        any of ($urgent*) and any of ($action*)
}

rule Phishing_Credential_Harvesting {
    meta:
        description = "Detects credential harvesting attempts"
        category = "phishing"
        severity = "critical"
    
    strings:
        $cred1 = "login" nocase
        $cred2 = "password" nocase
        $cred3 = "username" nocase
        $cred4 = "account suspended" nocase
        $cred5 = "verify credentials" nocase
        
        $brand1 = "microsoft" nocase
        $brand2 = "google" nocase
        $brand3 = "amazon" nocase
        $brand4 = "paypal" nocase
        $brand5 = "apple" nocase
        
    condition:
        any of ($cred*) and any of ($brand*)
}

rule Phishing_Financial_Scam {
    meta:
        description = "Detects financial scam patterns"
        category = "financial_scam"
        severity = "high"
    
    strings:
        $money1 = "wire transfer" nocase
        $money2 = "bitcoin" nocase
        $money3 = "cryptocurrency" nocase
        $money4 = "gift card" nocase
        $money5 = "western union" nocase
        
        $scam1 = "lottery winner" nocase
        $scam2 = "inheritance" nocase
        $scam3 = "tax refund" nocase
        $scam4 = "prize money" nocase
        
    condition:
        any of ($money*) and any of ($scam*)
}
'''
        
        # Malware patterns rule
        malware_rules = '''
rule Suspicious_Attachment_Extensions {
    meta:
        description = "Detects suspicious file extensions"
        category = "malware"
        severity = "medium"
    
    strings:
        $ext1 = ".exe" nocase
        $ext2 = ".scr" nocase
        $ext3 = ".bat" nocase
        $ext4 = ".cmd" nocase
        $ext5 = ".pif" nocase
        $ext6 = ".vbs" nocase
        $ext7 = ".js" nocase
        $ext8 = ".jar" nocase
        
    condition:
        any of them
}

rule Macro_Enabled_Documents {
    meta:
        description = "Detects macro-enabled documents"
        category = "malware"
        severity = "medium"
    
    strings:
        $macro1 = "enable macros" nocase
        $macro2 = "enable content" nocase
        $macro3 = "macro security" nocase
        
    condition:
        any of them
}
'''
        
        # Evasion techniques rule
        evasion_rules = '''
rule URL_Shortener_Evasion {
    meta:
        description = "Detects URL shortener evasion"
        category = "evasion"
        severity = "medium"
    
    strings:
        $short1 = "bit.ly" nocase
        $short2 = "tinyurl" nocase
        $short3 = "t.co" nocase
        $short4 = "goo.gl" nocase
        $short5 = "ow.ly" nocase
        
    condition:
        any of them
}

rule Base64_Encoded_Content {
    meta:
        description = "Detects base64 encoded suspicious content"
        category = "evasion"
        severity = "low"
    
    strings:
        $b64_pattern = /[A-Za-z0-9+\/]{20,}={0,2}/
        
    condition:
        #b64_pattern > 3
}
'''
        
        # Write rules to files
        rules_files = [
            ("phishing_patterns.yar", phishing_rules),
            ("malware_signatures.yar", malware_rules),
            ("evasion_techniques.yar", evasion_rules)
        ]
        
        for filename, content in rules_files:
            rule_file = self.rules_directory / filename
            if not rule_file.exists():
                rule_file.write_text(content)
                logger.info(f"Created default YARA rule file: {filename}")
    
    def _compile_rules(self):
        """Compile all YARA rules in the directory."""
        try:
            rule_files = {}
            
            # Find all .yar files
            for rule_file in self.rules_directory.glob("*.yar"):
                namespace = rule_file.stem
                rule_files[namespace] = str(rule_file)
                
                # Store rule info
                self.rules_info[namespace] = {
                    "file_path": str(rule_file),
                    "modified_time": rule_file.stat().st_mtime
                }
            
            if rule_files:
                self.compiled_rules = yara.compile(filepaths=rule_files)
                logger.info(f"Compiled {len(rule_files)} YARA rule files")
            else:
                logger.warning("No YARA rule files found")
                
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")
            self.compiled_rules = None
    
    def scan_text(self, text: str) -> Tuple[float, List[Dict]]:
        """Scan text content with YARA rules."""
        if not self.compiled_rules:
            return 0.0, []
        
        try:
            matches = self.compiled_rules.match(data=text.encode('utf-8', errors='ignore'))
            
            threat_score = 0.0
            match_details = []
            
            for match in matches:
                # Calculate threat score based on rule severity
                severity_scores = {
                    "low": 0.2,
                    "medium": 0.5,
                    "high": 0.8,
                    "critical": 1.0
                }
                
                severity = match.meta.get("severity", "medium")
                rule_score = severity_scores.get(severity, 0.5)
                threat_score = max(threat_score, rule_score)
                
                match_info = {
                    "rule_name": match.rule,
                    "category": match.meta.get("category", "unknown"),
                    "severity": severity,
                    "description": match.meta.get("description", ""),
                    "strings": [str(s) for s in match.strings],
                    "score": rule_score
                }
                
                match_details.append(match_info)
            
            return min(threat_score, 1.0), match_details
            
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            return 0.0, []
    
    def scan_file(self, file_data: bytes, filename: str = "") -> Tuple[float, List[Dict]]:
        """Scan file data with YARA rules."""
        if not self.compiled_rules:
            return 0.0, []
        
        try:
            matches = self.compiled_rules.match(data=file_data)
            
            threat_score = 0.0
            match_details = []
            
            for match in matches:
                severity_scores = {
                    "low": 0.2,
                    "medium": 0.5,
                    "high": 0.8,
                    "critical": 1.0
                }
                
                severity = match.meta.get("severity", "medium")
                rule_score = severity_scores.get(severity, 0.5)
                threat_score = max(threat_score, rule_score)
                
                match_info = {
                    "rule_name": match.rule,
                    "category": match.meta.get("category", "unknown"),
                    "severity": severity,
                    "description": match.meta.get("description", ""),
                    "filename": filename,
                    "score": rule_score
                }
                
                match_details.append(match_info)
            
            return min(threat_score, 1.0), match_details
            
        except Exception as e:
            logger.error(f"YARA file scan error: {e}")
            return 0.0, []
    
    def reload_rules(self):
        """Reload YARA rules if files have been modified."""
        try:
            needs_reload = False
            
            for namespace, info in self.rules_info.items():
                rule_file = Path(info["file_path"])
                if rule_file.exists():
                    current_mtime = rule_file.stat().st_mtime
                    if current_mtime > info["modified_time"]:
                        needs_reload = True
                        break
            
            if needs_reload:
                self._compile_rules()
                logger.info("YARA rules reloaded")
                
        except Exception as e:
            logger.error(f"Failed to reload YARA rules: {e}")
    
    def add_custom_rule(self, rule_name: str, rule_content: str):
        """Add a custom YARA rule."""
        try:
            rule_file = self.rules_directory / f"{rule_name}.yar"
            rule_file.write_text(rule_content)
            
            # Recompile rules
            self._compile_rules()
            logger.info(f"Added custom YARA rule: {rule_name}")
            
        except Exception as e:
            logger.error(f"Failed to add custom rule {rule_name}: {e}")
    
    def get_rule_statistics(self) -> Dict[str, any]:
        """Get statistics about loaded rules."""
        if not self.compiled_rules:
            return {"total_rules": 0, "rule_files": 0}
        
        total_rules = len(self.compiled_rules)
        rule_files = len(self.rules_info)
        
        categories = {}
        severities = {}
        
        # This would require iterating through rules, which isn't directly supported
        # by python-yara, so we'll provide basic stats
        
        return {
            "total_rules": total_rules,
            "rule_files": rule_files,
            "rules_directory": str(self.rules_directory),
            "last_compiled": max(info["modified_time"] for info in self.rules_info.values()) if self.rules_info else 0
        }
