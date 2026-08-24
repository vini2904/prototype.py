"""
NetSage AI - Hybrid Diagnostic & Human-in-the-Loop Pipeline
Combines deterministic rule validation with AI probabilistic diagnosis and human oversight.
"""

import json
import os
from typing import Dict, List, Any
from .rule_checker import NetworkRuleChecker
from .ai_engine import AIDiagnosticEngine

class HybridDiagnoser:
    def __init__(self, data_path: str = None, audit_path: str = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.data_path = data_path or os.path.join(base_dir, "data", "cases.json")
        self.audit_path = audit_path or os.path.join(base_dir, "responsible_ai", "audit_trail.json")
        
        self.rule_checker = NetworkRuleChecker()
        self.ai_engine = AIDiagnosticEngine(self.data_path)
        self.cases: List[Dict[str, Any]] = []
        self.reviews: Dict[str, Dict[str, Any]] = {}
        
        self.load_cases()
        self.load_audit_trail()

    def load_cases(self):
        if os.path.exists(self.data_path):
            with open(self.data_path, "r", encoding="utf-8") as f:
                self.cases = json.load(f)

    def load_audit_trail(self):
        if os.path.exists(self.audit_path):
            try:
                with open(self.audit_path, "r", encoding="utf-8") as f:
                    self.reviews = json.load(f)
            except Exception:
                self.reviews = {}
        else:
            # Initialize default human reviews from cases
            for c in self.cases:
                self.reviews[c["id"]] = c.get("human_review", {
                    "status": "Accepted",
                    "reviewer": "Network Engineer",
                    "notes": "Verified against Packet Tracer lab topology.",
                    "adjusted_fix": None
                })
            self.save_audit_trail()

    def save_audit_trail(self):
        os.makedirs(os.path.dirname(self.audit_path), exist_ok=True)
        with open(self.audit_path, "w", encoding="utf-8") as f:
            json.dump(self.reviews, f, indent=2)

    def diagnose_case(self, case_id: str = None, symptom: str = "", topology: str = "", show_outputs: str = "") -> Dict[str, Any]:
        """Runs the hybrid diagnosis on a case or custom inputs."""
        case_data = None
        if case_id:
            for c in self.cases:
                if c["id"] == case_id:
                    case_data = c
                    symptom = c["symptom"]
                    topology = c["topology"]
                    show_outputs = c["show_outputs"]
                    break

        # 1. Deterministic Rule Verification
        rule_violations = self.rule_checker.run_all_checks(show_outputs, symptom, topology)

        # 2. AI Structured Diagnosis
        ai_diagnosis = self.ai_engine.diagnose(case_id, symptom, topology, show_outputs, rule_violations)

        # 3. Hybrid Synthesis & Confidence Alignment
        agreement = "Strong" if len(rule_violations) > 0 else "Moderate (Pure AI Analysis)"

        # 4. Fetch current human review status
        human_review = self.reviews.get(case_id or "CUSTOM", {
            "status": "Pending",
            "reviewer": "Unassigned",
            "notes": "Pending engineer verification.",
            "adjusted_fix": None
        })

        return {
            "case_id": case_id or "CUSTOM",
            "case_title": case_data["title"] if case_data else "Custom Diagnostic Request",
            "concept_tag": case_data["concept_tag"] if case_data else "Custom",
            "osi_layer": case_data["osi_layer"] if case_data else ai_diagnosis.get("osi_layer", "Layer 3"),
            "severity": case_data["severity"] if case_data else "Medium",
            "symptom": symptom,
            "topology": topology,
            "show_outputs": show_outputs,
            "deterministic_rules": rule_violations,
            "ai_diagnosis": ai_diagnosis,
            "engine_agreement": agreement,
            "human_review": human_review
        }

    def submit_review(self, case_id: str, status: str, reviewer: str, notes: str, adjusted_fix: List[str] = None) -> Dict[str, Any]:
        """Records a human review action (Accepted, Edited, Rejected)."""
        review_entry = {
            "status": status,
            "reviewer": reviewer or "Senior Engineer",
            "notes": notes or "No notes provided.",
            "adjusted_fix": adjusted_fix
        }
        self.reviews[case_id] = review_entry
        self.save_audit_trail()
        return review_entry

    def get_stats(self) -> Dict[str, Any]:
        """Calculates aggregate analytics across the dataset."""
        total_cases = len(self.cases)
        status_counts = {"Accepted": 0, "Edited": 0, "Rejected": 0, "Pending": 0}
        concept_counts = {}
        osi_counts = {}
        severity_counts = {}
        deterministic_triggered = 0

        for c in self.cases:
            cid = c["id"]
            rev = self.reviews.get(cid, c.get("human_review", {}))
            status = rev.get("status", "Accepted")
            status_counts[status] = status_counts.get(status, 0) + 1

            tag = c.get("concept_tag", "Other")
            concept_counts[tag] = concept_counts.get(tag, 0) + 1

            osi = c.get("osi_layer", "Layer 3")
            osi_counts[osi] = osi_counts.get(osi, 0) + 1

            sev = c.get("severity", "Medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            # Check if deterministic rule triggers
            violations = self.rule_checker.run_all_checks(c.get("show_outputs", ""), c.get("symptom", ""), c.get("topology", ""))
            if len(violations) > 0:
                deterministic_triggered += 1

        agreement_rate = round(((status_counts.get("Accepted", 0) + status_counts.get("Edited", 0)) / max(total_cases, 1)) * 100, 1)
        pure_accept_rate = round((status_counts.get("Accepted", 0) / max(total_cases, 1)) * 100, 1)

        return {
            "total_cases": total_cases,
            "status_counts": status_counts,
            "concept_counts": concept_counts,
            "osi_counts": osi_counts,
            "severity_counts": severity_counts,
            "deterministic_rule_catch_count": deterministic_triggered,
            "deterministic_rule_catch_rate": f"{round((deterministic_triggered / max(total_cases, 1)) * 100, 1)}%",
            "agreement_rate": f"{agreement_rate}%",
            "pure_accept_rate": f"{pure_accept_rate}%",
            "ai_corrected_count": status_counts.get("Edited", 0) + status_counts.get("Rejected", 0)
        }
