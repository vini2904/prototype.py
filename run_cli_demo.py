"""
NetSage AI - Interactive CLI Demonstration Runner
Runs automated diagnosis, deterministic rule checks, and human review simulation in terminal.
"""

import sys
import os
import time

# Ensure UTF-8 output encoding on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from engine.hybrid_diagnoser import HybridDiagnoser

def print_banner():
    print("""
======================================================================
  _   _      _   ____                   _    ___ 
 | \\ | | ___| |_/ ___|  __ _  __ _  ___ / \\  |_ _|
 |  \\| |/ _ \\ __\\___ \\ / _` |/ _` |/ _ \\  /   | | 
 | |\\  |  __/ |_ ___) | (_| | (_| |  __/ /\\ \\  | | 
 |_| \\_|\\___|\\__|____/ \\__,_|\\__, |\\___/_/  \\_\\___|
                             |___/                  
 Packet Tracer AI Assistant - Rule Engine - Human-in-the-Loop
======================================================================
""")

def main():
    print_banner()
    diagnoser = HybridDiagnoser()
    cases = diagnoser.cases

    print(f"Loaded {len(cases)} Packet Tracer lab troubleshooting cases.")
    print("Available Sample Cases for Demonstration:")
    
    samples = [
        "NET-CASE-001", # VLAN mismatch
        "NET-CASE-002", # Router on stick shutdown
        "NET-CASE-005", # ACL Inverted wildcard
        "NET-CASE-006", # OSPF area mismatch
        "NET-CASE-008", # NAT inside missing
        "NET-CASE-012"  # DHCP snooping untrusted port
    ]

    for idx, cid in enumerate(samples, 1):
        c = next((item for item in cases if item["id"] == cid), None)
        if c:
            print(f" [{idx}] {c['id']} : {c['title']} ({c['concept_tag']}, {c['severity']})")

    print(" [0] Run All 32 Cases Automated Benchmark\n")

    if len(sys.argv) > 1:
        choice = sys.argv[1]
    else:
        try:
            choice = input("Select a case number to diagnose (1-6) or 0 for benchmark [default: 1]: ").strip()
        except EOFError:
            choice = "0"

    if not choice:
        choice = "1"

    if choice == "0" or choice == "benchmark":
        run_full_benchmark(diagnoser)
        return

    try:
        selected_index = int(choice) - 1
        selected_case_id = samples[selected_index]
    except Exception:
        selected_case_id = "NET-CASE-001"

    run_single_case_demo(diagnoser, selected_case_id)

def run_single_case_demo(diagnoser, case_id):
    print("\n" + "=" * 70)
    print(f"[RUNNING DIAGNOSIS] NetSage Hybrid Analysis on Case: {case_id}")
    print("=" * 70)

    result = diagnoser.diagnose_case(case_id)

    print(f"\n[TITLE]    : {result['case_title']}")
    print(f"[DOMAIN]   : {result['concept_tag']} | {result['osi_layer']} | Severity: {result['severity']}")
    print(f"[SYMPTOM]  : {result['symptom']}")
    print(f"[TOPOLOGY] : {result['topology']}")

    print("\n" + "-" * 40)
    print("[EVIDENCE] Cisco IOS Show Command Output:")
    print("-" * 40)
    print(result['show_outputs'])

    print("\n" + "-" * 40)
    print("[RULE ENGINE] Deterministic Python Rule Checks:")
    print("-" * 40)
    violations = result['deterministic_rules']
    if violations:
        for v in violations:
            print(f" -> TRIGGERED {v['rule_id']}: {v['title']} (Severity: {v['severity']})")
            print(f"    Evidence: {v['evidence']}")
    else:
        print(" -> PASS: No deterministic syntax violations.")

    print("\n" + "-" * 40)
    print("[AI DIAGNOSIS] NetSage Structured LLM Synthesis:")
    print("-" * 40)
    ai = result['ai_diagnosis']
    print(f" * Confidence       : {ai.get('confidence_level') or ai.get('confidence')}")
    print(f" * Root Cause       : {ai.get('root_cause')}")
    print(f" * Evidence Citation: {ai.get('evidence_quote')}")
    print(f" * Next Command     : {ai.get('next_diagnostic_command') or ai.get('next_command')}")

    print("\n[REMEDIATION] Proposed Cisco IOS Remediation Commands:")
    fix_steps = ai.get('step_by_step_fix') or []
    for step in fix_steps:
        print(f"   {step}")

    print(f"\n[VERIFICATION] Validation Command: {ai.get('verification_command')}")

    print("\n" + "-" * 40)
    print("[HUMAN OVERSIGHT] Mandatory Review Record:")
    print("-" * 40)
    hr = result['human_review']
    print(f" * Review Decision : [{hr.get('status')}] by {hr.get('reviewer')}")
    print(f" * Engineer Note   : {hr.get('notes')}")

    print("\n" + "=" * 70)
    print("[STATUS] NetSage AI Troubleshooting Cycle Completed Successfully.")
    print("=" * 70 + "\n")

def run_full_benchmark(diagnoser):
    print("\n" + "=" * 70)
    print("[BENCHMARK] Running Full 32-Case Accuracy & Rule Engine Evaluation")
    print("=" * 70)

    stats = diagnoser.get_stats()
    print(f"Total Cases Evaluated        : {stats['total_cases']}")
    print(f"Deterministic Rule Catch Rate : {stats['deterministic_rule_catch_rate']} ({stats['deterministic_rule_catch_count']}/{stats['total_cases']})")
    print(f"Human Agreement Rate          : {stats['agreement_rate']}")
    print(f"Pure Accept Rate             : {stats['pure_accept_rate']}")
    print(f"Human Corrections / Edits    : {stats['ai_corrected_count']}")

    print("\nHuman Review Outcomes:")
    for status, count in stats['status_counts'].items():
        print(f" * {status.ljust(10)}: {count} cases ({round((count/stats['total_cases'])*100, 1)}%)")

    print("\nTechnical Domain Breakdown:")
    for concept, count in stats['concept_counts'].items():
        print(f" * {concept.ljust(14)}: {count} cases")

    print("\n" + "=" * 70)

if __name__ == "__main__":
    main()
