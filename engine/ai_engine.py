"""
NetSage AI - AI Diagnostic Inference Engine
Performs structured network diagnostic reasoning based on problem statements and show outputs.
"""

import json
import re
from typing import Dict, Any, List

class AIDiagnosticEngine:
    """Generates structured network diagnoses adhering to the strict JSON schema."""

    def __init__(self, cases_db_path: str = None):
        self.cases_db = {}
        if cases_db_path:
            try:
                with open(cases_db_path, "r", encoding="utf-8") as f:
                    cases = json.load(f)
                    for c in cases:
                        self.cases_db[c["id"]] = c
            except Exception:
                pass

    def diagnose(self, case_id: str = None, symptom: str = "", topology: str = "", show_outputs: str = "", rule_violations: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Performs structured diagnosis combining case context, heuristic synthesis, and rule findings."""
        if case_id and case_id in self.cases_db:
            case = self.cases_db[case_id]
            diagnosis = dict(case["ai_diagnosis"])
            diagnosis["case_id"] = case_id
            diagnosis["title"] = case["title"]
            diagnosis["concept_tag"] = case["concept_tag"]
            diagnosis["severity"] = case["severity"]
            return diagnosis

        # Dynamic heuristic reasoning if custom input is submitted
        fault_summary = "General network misconfiguration detected."
        root_cause = "Analysis indicates a breakdown between configured parameters and expected protocol operation."
        osi_layer = "Layer 3 (Network)"
        confidence = "85%"
        evidence = "Review show command outputs for highlighted configuration discrepancies."
        next_cmd = "show running-config"
        fix_steps = ["Review device configuration and align IP addressing and protocol timers."]
        verif_cmd = "ping <gateway_or_destination>"

        # Leverage deterministic rule violations if present
        if rule_violations and len(rule_violations) > 0:
            top_rule = rule_violations[0]
            fault_summary = top_rule["title"]
            root_cause = top_rule["description"]
            osi_layer = f"{top_rule['osi_layer']}"
            confidence = "95%"
            evidence = top_rule["evidence"]
            fix_steps = top_rule["recommended_fix"]
            next_cmd = "show running-config"
            verif_cmd = "ping <target_ip>"
        elif "down" in show_outputs.lower() and "administratively" in show_outputs.lower():
            fault_summary = "Interface is administratively shut down."
            root_cause = "The target physical or virtual interface has 'shutdown' enabled."
            osi_layer = "Layer 1 (Physical)"
            confidence = "98%"
            evidence = [l for l in show_outputs.splitlines() if "administratively down" in l.lower()][0] if any("administratively down" in l.lower() for l in show_outputs.splitlines()) else "administratively down"
            next_cmd = "show ip interface brief"
            fix_steps = ["configure terminal", "interface <id>", "no shutdown", "end"]
            verif_cmd = "show ip interface brief"
        elif "mask" in symptom.lower() or "mask" in show_outputs.lower():
            fault_summary = "Subnet mask mismatch or off-subnet gateway."
            root_cause = "The host IP and default gateway reside in different broadcast domains due to mask mismatch."
            osi_layer = "Layer 3 (Network)"
            confidence = "92%"
            evidence = "Subnet mask disparity in show output/ipconfig."
            next_cmd = "show ip interface brief"
            fix_steps = ["Correct the subnet mask on the client or gateway router to match the designated CIDR block."]
            verif_cmd = "ping <default_gateway>"

        return {
            "case_id": case_id or "CUSTOM-CASE",
            "fault_summary": fault_summary,
            "root_cause": root_cause,
            "osi_layer": osi_layer,
            "confidence_level": confidence,
            "evidence_quote": evidence,
            "next_diagnostic_command": next_cmd,
            "step_by_step_fix": fix_steps,
            "verification_command": verif_cmd,
            "rollback_steps": ["no " + step for step in fix_steps if not step.startswith("config") and not step.startswith("end")]
        }
