# NetSage AI: AI-Assisted Cisco Packet Tracer Troubleshooter

> **Project**: NetSage AI — Intelligent Network Troubleshooting with Human Oversight  
> **Course / Track**: Applied AI + Network Troubleshooting (Cisco Packet Tracer)  
> **Architecture**: Dual-Tier Hybrid Engine (Deterministic Python Rules + Structured LLM Reasoning) + Mandatory Human-in-the-Loop (HITL)  
> **Deliverable Format**: Consolidated 2-File System (`prototype.py` + `README.md`)

---

## 1. Executive Summary & Problem Formulation

### 1.1 The Challenge
Junior network engineers and CCNA/CCNP students often understand individual Cisco IOS `show` commands (`show ip interface brief`, `show ip route`, `show access-lists`, `show vlan brief`) but struggle to systematically correlate high-level symptoms (e.g., *"PC gets an IP address but cannot reach a server in VLAN 30"*) to the precise root cause across the 7-layer OSI model.

Common diagnostic dilemmas in Packet Tracer environments:
- **Layer 2 (Data Link)**: Access ports left in default VLAN 1, native VLAN mismatches causing trunk loops/drops, or uncreated VLANs in the database.
- **Layer 3 (Network)**: Subnet mask typos (/26 vs /24) creating off-subnet default gateways, duplicate IP address conflicts (`%IP-4-DUPADDR`), missing default routes (`0.0.0.0 0.0.0.0`), or OSPF Area ID mismatches.
- **Layer 4 (Transport)**: Access Control Lists (ACLs) configured with inverted wildcard masks (`255.255.255.0` instead of `0.0.0.255`) triggering implicit deny drops.
- **NAT / PAT**: Missing `ip nat inside` or `ip nat outside` directives on router interfaces.
- **DHCP / Security**: DHCP Snooping untrusted port drops, Dynamic ARP Inspection (DAI) drops, or Guest SSID VLAN isolation bypasses.

### 1.2 The NetSage AI Solution
**NetSage AI** bridges this gap using a **Dual-Tier Hybrid Architecture**:
1. **Deterministic Rule Engine (Python)**: Zero-latency, zero-hallucination static checking for syntax, CIDR subnet math, interface admin status, and wildcard mask traps.
2. **Structured LLM Reasoning Engine**: Context-aware diagnosis generating evidence-grounded root-cause analysis, confidence ratings, next diagnostic commands, remediation steps, and rollback scripts.
3. **Mandatory Human-in-the-Loop (HITL) Gateway**: Enforces engineer review (Accept, Edit, or Reject) before any remediation command is applied.

---

## 2. System Architecture & Model Formation

```
+---------------------------------------------------------------------------------------------------+
|                                     NETSAGE AI DUAL-TIER ENGINE                                   |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|   [ Packet Tracer Lab Input ]                                                                     |
|    - Symptom & Observed Failure (Ping / Traceroute / Error)                                       |
|    - Network Topology Context                                                                     |
|    - Verbatim Cisco IOS Show Command Output                                                       |
|                               |                                                                   |
|                               v                                                                   |
|   +-------------------------------------------------------------------------------------------+   |
|   |                              HYBRID DIAGNOSTIC ORCHESTRATOR                               |   |
|   |                                                                                           |   |
|   |   +---------------------------------------+   +---------------------------------------+   |   |
|   |   |   Deterministic Rule Checker (Python) |   |    Structured LLM Reasoning Engine    |   |   |
|   |   | - 8 Rule Categories (20+ Regex Checks)|   | - Few-Shot Prompt Templates           |   |   |
|   |   | - Subnet / Gateway CIDR Verification  |   | - Strict JSON Output Constraints      |   |   |
|   |   | - Interface Admin Shutdown / Err-Dis  |   | - Evidence Citation & Confidence %    |   |   |
|   |   | - Inverted ACL Wildcard Mask Traps    |   | - Step-by-Step Cisco IOS Remediation  |   |   |
|   |   +---------------------------------------+   +---------------------------------------+   |   |
|   |                       \                                   /                               |   |
|   |                        \                                 /                                |   |
|   |                         v                               v                                 |   |
|   |                +-------------------------------------------------+                        |   |
|   |                |     Consolidated Diagnostic Synthesis (JSON)    |                        |   |
|   |                +-------------------------------------------------+                        |   |
|   +-------------------------------------------------------------------------------------------+   |
|                                               |                                                   |
|                                               v                                                   |
|   +-------------------------------------------------------------------------------------------+   |
|   |                          MANDATORY HUMAN-IN-THE-LOOP (HITL) GATEWAY                       |   |
|   |                                                                                           |   |
|   |   [ ACCEPT ] ---------> Approved without modification -> Deployable to Lab                |   |
|   |   [ EDIT   ] ---------> Engineer refines commands (e.g. security hardening) -> Stored     |   |
|   |   [ REJECT ] ---------> Flagged as AI Error -> Documented in Responsible AI Audit Trail   |   |
|   +-------------------------------------------------------------------------------------------+   |
|                                               |                                                   |
|                                               v                                                   |
|   +-------------------------------------------------------------------------------------------+   |
|   |               POST-FIX VERIFICATION & LIVE DASHBOARD / CLI REPORTING                      |   |
|   |   - Verification Command Execution Simulation (e.g., ping test, show ip int br)          |   |
|   |   - Dynamic Distribution Analytics (OSI Layers, Concept Tags, Agreement Rates)            |   |
|   +-------------------------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------------------------+
```

### 2.1 Core Data Models
Defined as typed data structures in [`prototype.py`](prototype.py):
- **`LabCase`**: Encapsulates `id`, `title`, `concept_tag`, `osi_layer`, `severity`, `symptom`, `topology`, `show_outputs`, `expected_fault`.
- **`RuleViolation`**: Captures `rule_id`, `rule_name`, `severity`, `matched_text`, `description`, `suggested_action`.
- **`AIDiagnosis`**: Structured output with `fault_summary`, `root_cause`, `osi_layer`, `confidence_level`, `evidence_quote`, `next_diagnostic_command`, `step_by_step_fix`, `verification_command`, `rollback_steps`.
- **`HumanReview`**: Tracks `status` (`Accepted`, `Edited`, `Rejected`), `reviewer`, `review_date`, `reviewer_notes`, `modified_fix_steps`.

---

## 3. Detailed Component Breakdown

### 3.1 Deterministic Rule Checker (8 Modules)
The rule engine (`NetworkRuleChecker` in `prototype.py`) evaluates verbatim Cisco CLI output:
1. **Interface Status (`RULE-INT-001` - `003`)**: Flags `administratively down` parent/subinterfaces, `err-disabled` states (Port Security), and `Half-duplex` collision spikes.
2. **IP Subnet & Gateway (`RULE-IP-001` - `002`)**: Performs CIDR subnet calculations via Python's `ipaddress` module to detect off-subnet gateways and duplicate IP conflicts (`%IP-4-DUPADDR`).
3. **VLAN & Trunking (`RULE-VLAN-001` - `002`)**: Detects access ports left in default `VLAN 1` and CDP Native VLAN mismatches across trunk links.
4. **Dynamic Routing (`RULE-OSPF-001`, `RULE-ROUT-001`)**: Identifies mismatched OSPF Area IDs and `passive-interface` statements on inter-router links.
5. **Access Control Lists (`RULE-ACL-001`)**: Uses regex to catch inverted wildcard masks (e.g., `255.255.255.0` instead of `0.0.0.255`).
6. **DHCP Snooping (`RULE-DHCP-001`)**: Detects untrusted uplink drops (`DHCP offer received on untrusted port`).
7. **Network Address Translation (`RULE-NAT-001`)**: Flags configurations lacking `ip nat inside` directives.
8. **Wireless LAN (`RULE-WLAN-001`)**: Detects Guest SSIDs bridged to internal management VLANs.

### 3.2 AI Reasoning Engine & Structured Output Schema
The AI reasoning engine enforces strict JSON formatting, mandatory direct quoting of CLI lines, and rollback safety commands:

```json
{
  "fault_summary": "Access port FastEthernet0/1 assigned to default VLAN 1 instead of Engineering VLAN 10.",
  "root_cause": "Switch SW1 has port FastEthernet0/1 configured with 'switchport access vlan 1', isolating PC-1 from its default gateway on subinterface Gig0/0.10.",
  "osi_layer": "Layer 2 (Data Link)",
  "confidence_level": "High (98%)",
  "evidence_quote": "SW1# show running-config interface FastEthernet0/1 -> 'switchport access vlan 1' while PC-1 is on 192.168.10.50.",
  "next_diagnostic_command": "show interfaces FastEthernet0/1 switchport",
  "step_by_step_fix": [
    "SW1# configure terminal",
    "SW1(config)# interface FastEthernet0/1",
    "SW1(config-if)# switchport access vlan 10",
    "SW1(config-if)# end",
    "SW1# write memory"
  ],
  "verification_command": "PC-1# ping 192.168.10.1",
  "rollback_steps": [
    "SW1# configure terminal",
    "SW1(config)# interface FastEthernet0/1",
    "SW1(config-if)# switchport access vlan 1",
    "SW1(config-if)# end"
  ]
}
```

---

## 4. Responsible AI: 5 Human-in-the-Loop Case Studies

In mission-critical enterprise networking, unverified AI outputs can trigger catastrophic outages. NetSage AI implements a mandatory review gate. Below are 5 real-world case studies from the system audit log:

| Case ID | Scenario | AI Initial Output | Review Status | Human Engineering Review & Correction |
| :--- | :--- | :--- | :---: | :--- |
| **`NET-CASE-005`** | Inverted Wildcard Mask in Extended ACL | Fixed port 80 (HTTP) rule only. | **EDITED** | Intranet web applications require HTTP (80), HTTPS (443), and DNS (UDP 53). Added ports 443 and 53 to prevent partial outages. |
| **`NET-CASE-024`** | OSPF Passive-Interface on Inter-Router Link | Recommended tearing down and rebuilding the OSPF process. | **EDITED** | Tearing down OSPF causes complete routing flap. Corrected to targeted `no passive-interface Gig0/0` under existing OSPF process. |
| **`NET-CASE-012`** | DHCP Snooping Dropping Offers | Correctly identified untrusted trunk port. | **ACCEPTED** | Verified that `ip dhcp snooping trust` is applied only to the upstream server port, preserving security on edge access ports. |
| **`NET-CASE-017`** | Wireless Guest SSID Bridged to Management VLAN | Proposed placing an access list on the AP. | **REJECTED** | ACL on AP is vulnerable to bypass. Correct remediation is re-mapping the Guest WLAN profile on the WLC to isolated VLAN 50. |
| **`NET-CASE-029`** | Dynamic ARP Inspection (DAI) Dropping ARP | Suggested disabling DAI globally. | **EDITED** | Disabling DAI leaves the network vulnerable to ARP spoofing/man-in-the-middle attacks. Corrected to `ip arp inspection trust` on trunk uplink. |

---

## 5. How to Run the Prototype

The entire prototype is self-contained in [`prototype.py`](prototype.py) and requires **zero external dependencies** (uses Python Standard Library).

### Option 1: Run Interactive Case Diagnosis
Diagnose a specific case with full telemetry, rule execution, AI synthesis, and verification simulation:
```powershell
python prototype.py --case NET-CASE-001
```

### Option 2: Run Automated 32-Case Benchmark
Execute automated diagnostics across all 32 Packet Tracer lab cases and print the evaluation matrix:
```powershell
python prototype.py --benchmark
```

### Option 3: Launch Web Server & Dashboard
Start the local HTTP server to view the web dashboard and JSON REST API:
```powershell
python prototype.py --serve --port 8000
```
Open your browser at `http://localhost:8000`.

---

## 6. Verification and Compliance Summary

| Requirement | Implementation in `prototype.py` & `README.md` | Status |
| :--- | :--- | :---: |
| **Case Dataset (30+ cases)** | 32 authentic Packet Tracer lab cases spanning 10 domains and 5 OSI layers. | ✅ Complete |
| **Evidence Quoting** | Verbatim show-command citations enforced in all AI diagnoses. | ✅ Complete |
| **Deterministic Rule Checker** | 8 inspection modules covering subnets, interfaces, VLANs, ACLs, OSPF, NAT, DHCP. | ✅ Complete |
| **Human-in-the-Loop Gateway** | Explicit Accept / Edit / Reject workflow with audit notes and modified fixes. | ✅ Complete |
| **Responsible AI Log** | 5 detailed case studies documenting why AI was corrected/rejected. | ✅ Complete |
| **Execution & Verification** | CLI demo runner, benchmark suite, verification command simulation, and web server. | ✅ Complete |
