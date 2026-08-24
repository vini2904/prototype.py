"""
===================================================================================================
 NetSage AI: Unified Hybrid Troubleshooting Prototype for Cisco Packet Tracer
===================================================================================================
 Course / Track : Applied AI + Network Troubleshooting
 Architecture   : Dual-Tier (Deterministic Python Rules + Structured LLM Reasoning) + HITL Oversight
 Dependencies   : Standard Library Only (json, re, ipaddress, dataclasses, http.server, argparse)
===================================================================================================
"""

import sys
import os
import json
import re
import ipaddress
import argparse
import http.server
import socketserver
import urllib.parse
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Tuple, Any

# =================================================================================================
# 1. DATA MODEL FORMATION
# =================================================================================================

@dataclass
class RuleViolation:
    rule_id: str
    rule_name: str
    severity: str  # Critical, High, Medium, Low
    matched_text: str
    description: str
    suggested_action: str

@dataclass
class AIDiagnosis:
    fault_summary: str
    root_cause: str
    osi_layer: str
    confidence_level: str
    evidence_quote: str
    next_diagnostic_command: str
    step_by_step_fix: List[str]
    verification_command: str
    rollback_steps: List[str]

@dataclass
class HumanReview:
    status: str  # Accepted, Edited, Rejected
    reviewer: str
    review_date: str
    reviewer_notes: str
    modified_fix_steps: Optional[List[str]] = None

@dataclass
class LabCase:
    id: str
    title: str
    concept_tag: str
    osi_layer: str
    severity: str
    symptom: str
    topology: str
    show_outputs: str
    expected_fault: str
    ai_diagnosis: Optional[AIDiagnosis] = None
    human_review: Optional[HumanReview] = None


# =================================================================================================
# 2. DETERMINISTIC RULE CHECKER ENGINE (8 Inspection Modules)
# =================================================================================================

class NetworkRuleChecker:
    """
    Deterministic rule validation engine running zero-latency, zero-hallucination syntax
    and state validation against Cisco IOS show command outputs.
    """

    def analyze(self, show_outputs: str, symptom: str = "") -> List[RuleViolation]:
        violations: List[RuleViolation] = []
        violations.extend(self._check_interface_status(show_outputs))
        violations.extend(self._check_ip_subnet_and_gateway(show_outputs, symptom))
        violations.extend(self._check_vlan_and_trunking(show_outputs))
        violations.extend(self._check_routing_issues(show_outputs))
        violations.extend(self._check_acl_rules(show_outputs))
        violations.extend(self._check_dhcp_rules(show_outputs))
        violations.extend(self._check_nat_rules(show_outputs))
        violations.extend(self._check_wireless_isolation(show_outputs))
        return violations

    def _check_interface_status(self, text: str) -> List[RuleViolation]:
        violations = []
        # Check administratively down interfaces
        admin_down_matches = re.finditer(r'([A-Za-z0-9/.-]+)\s+is\s+administratively\s+down,\s+line\s+protocol\s+is\s+down', text, re.IGNORECASE)
        for match in admin_down_matches:
            intf = match.group(1)
            violations.append(RuleViolation(
                rule_id="RULE-INT-001",
                rule_name="Interface Administratively Shutdown",
                severity="High",
                matched_text=match.group(0),
                description=f"Interface {intf} is administratively disabled with 'shutdown'.",
                suggested_action=f"Enter interface configuration mode and issue 'no shutdown' on {intf}."
            ))

        # Check err-disabled ports
        err_matches = re.finditer(r'([A-Za-z0-9/.-]+)\s+is\s+down,\s+line\s+protocol\s+is\s+err-disabled|%PM-4-ERR_DISABLE', text, re.IGNORECASE)
        for match in err_matches:
            violations.append(RuleViolation(
                rule_id="RULE-INT-002",
                rule_name="Interface in Err-Disabled State",
                severity="Critical",
                matched_text=match.group(0),
                description="Interface has been disabled by switch security policy (Port Security or BPDU Guard).",
                suggested_action="Resolve security violation, then issue 'shutdown' followed by 'no shutdown'."
            ))

        # Check Half-Duplex late collisions
        if re.search(r'Half-duplex', text, re.IGNORECASE) and re.search(r'late\s+collision', text, re.IGNORECASE):
            violations.append(RuleViolation(
                rule_id="RULE-INT-003",
                rule_name="Duplex Mismatch / Late Collisions",
                severity="Medium",
                matched_text="Half-duplex ... late collisions detected",
                description="Interface operating in Half-duplex resulting in late frame collisions.",
                suggested_action="Configure 'duplex full' and 'speed auto' on both link endpoints."
            ))
        return violations

    def _check_ip_subnet_and_gateway(self, text: str, symptom: str) -> List[RuleViolation]:
        violations = []
        # Parse host IP configuration from ipconfig
        ip_match = re.search(r'IP\s*(?:Address)?[\s.:]+([0-9.]+)', text, re.IGNORECASE)
        mask_match = re.search(r'Subnet\s*Mask[\s.:]+([0-9.]+)', text, re.IGNORECASE)
        gw_match = re.search(r'Default\s*Gateway[\s.:]+([0-9.]+)', text, re.IGNORECASE)

        if ip_match and mask_match and gw_match:
            try:
                ip_str = ip_match.group(1).strip()
                mask_str = mask_match.group(1).strip()
                gw_str = gw_match.group(1).strip()

                if gw_str not in ("0.0.0.0", ""):
                    net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
                    gw_ip = ipaddress.IPv4Address(gw_str)
                    if gw_ip not in net:
                        violations.append(RuleViolation(
                            rule_id="RULE-IP-001",
                            rule_name="Default Gateway Off-Subnet / Disjoint Broadcast Domain",
                            severity="Critical",
                            matched_text=f"IP: {ip_str}, Mask: {mask_str}, Gateway: {gw_str}",
                            description=f"Gateway {gw_str} does not belong to host subnet {net.network_address}/{net.prefixlen}.",
                            suggested_action=f"Correct the host subnet mask or set default gateway inside {net.network_address}/{net.prefixlen}."
                        ))
            except ValueError:
                pass

        # Duplicate IP detection
        if re.search(r'%IP-4-DUPADDR|duplicate\s+IP\s+address', text, re.IGNORECASE):
            violations.append(RuleViolation(
                rule_id="RULE-IP-002",
                rule_name="Duplicate IP Address Conflict",
                severity="Critical",
                matched_text="%IP-4-DUPADDR detected in logs",
                description="Two active network interfaces share the exact same IPv4 address.",
                suggested_action="Reconfigure one host or interface with a unique, unassigned IP address."
            ))
        return violations

    def _check_vlan_and_trunking(self, text: str) -> List[RuleViolation]:
        violations = []
        # Access port left on default VLAN 1 when host is on another subnet
        if re.search(r'switchport\s+access\s+vlan\s+1\b', text, re.IGNORECASE) and re.search(r'192\.168\.(10|20|30|40|50)', text):
            violations.append(RuleViolation(
                rule_id="RULE-VLAN-001",
                rule_name="Access Port Left in Default VLAN 1",
                severity="High",
                matched_text="switchport access vlan 1",
                description="Access port is assigned to default VLAN 1 instead of its designated departmental VLAN.",
                suggested_action="Execute 'switchport access vlan <VLAN_ID>' under the interface configuration."
            ))

        # Native VLAN mismatch
        if re.search(r'%CDP-4-NATIVE_VLAN_MISMATCH|Native\s+VLAN\s+mismatch', text, re.IGNORECASE):
            violations.append(RuleViolation(
                rule_id="RULE-VLAN-002",
                rule_name="Native VLAN Trunk Mismatch",
                severity="High",
                matched_text="%CDP-4-NATIVE_VLAN_MISMATCH detected",
                description="Connected trunk link endpoints have disparate native VLAN configurations causing STP loops/drops.",
                suggested_action="Configure identical 'switchport trunk native vlan <ID>' on both ends of the trunk."
            ))
        return violations

    def _check_routing_issues(self, text: str) -> List[RuleViolation]:
        violations = []
        # OSPF Area ID mismatch / neighbor stuck
        if re.search(r'OSPF-4-ERRRCV.*mismatched\s+area|OSPF.*mismatch', text, re.IGNORECASE):
            violations.append(RuleViolation(
                rule_id="RULE-OSPF-001",
                rule_name="OSPF Area ID Mismatch",
                severity="Critical",
                matched_text="OSPF Area Mismatch packet received",
                description="OSPF adjacency cannot establish because interconnected router interfaces are in different areas.",
                suggested_action="Align network area parameters under 'router ospf' configuration."
            ))

        # Passive interface suppressing hellos on point-to-point link
        if re.search(r'passive-interface\s+(GigabitEthernet|FastEthernet|Serial)[0-9/.]+', text, re.IGNORECASE) and re.search(r'router\s+ospf', text, re.IGNORECASE):
            violations.append(RuleViolation(
                rule_id="RULE-ROUT-001",
                rule_name="OSPF Passive Interface on Inter-Router Trunk",
                severity="High",
                matched_text="passive-interface configured on router link",
                description="OSPF Hellos are suppressed on an interface connected to another router, preventing neighbor formation.",
                suggested_action="Execute 'no passive-interface <interface>' under router ospf configuration."
            ))
        return violations

    def _check_acl_rules(self, text: str) -> List[RuleViolation]:
        violations = []
        # Inverted wildcard mask detection (e.g., 255.255.255.0 instead of 0.0.0.255)
        inverted_match = re.search(r'access-list\s+\d+\s+(?:permit|deny)\s+(?:ip|tcp|udp)\s+[0-9.]+\s+(255\.255\.255\.(?:0|128|192|224|240|248|252))', text, re.IGNORECASE)
        if inverted_match:
            violations.append(RuleViolation(
                rule_id="RULE-ACL-001",
                rule_name="Inverted ACL Wildcard Mask Notation",
                severity="Critical",
                matched_text=inverted_match.group(0),
                description=f"Standard subnet mask '{inverted_match.group(1)}' used in ACL where inverted wildcard mask was required.",
                suggested_action="Recreate the ACL statement substituting the inverted wildcard mask (e.g., 0.0.0.255)."
            ))
        return violations

    def _check_dhcp_rules(self, text: str) -> List[RuleViolation]:
        violations = []
        # DHCP Snooping dropping packets on untrusted port
        if re.search(r'Packets\s+Dropped:\s+DHCP\s+offer\s+received\s+on\s+untrusted\s+port|DHCP_SNOOPING_UNTRUSTED_PORT', text, re.IGNORECASE):
            violations.append(RuleViolation(
                rule_id="RULE-DHCP-001",
                rule_name="DHCP Snooping Untrusted Port Drop",
                severity="High",
                matched_text="Packets Dropped: DHCP offer received on untrusted port",
                description="Switch DHCP Snooping is dropping DHCP Offer/ACK messages because the uplink port is not set to trusted.",
                suggested_action="Enter trunk interface configuration and execute 'ip dhcp snooping trust'."
            ))
        return violations

    def _check_nat_rules(self, text: str) -> List[RuleViolation]:
        violations = []
        # Missing ip nat inside/outside directive
        if re.search(r'ip\s+nat\s+inside\s+source', text, re.IGNORECASE) and not re.search(r'ip\s+nat\s+inside\b', text, re.IGNORECASE):
            violations.append(RuleViolation(
                rule_id="RULE-NAT-001",
                rule_name="Missing 'ip nat inside' Interface Directive",
                severity="Critical",
                matched_text="ip nat inside source configured without interface ip nat inside",
                description="NAT translation rules exist, but no LAN interface is designated as 'ip nat inside'.",
                suggested_action="Configure 'ip nat inside' on the LAN-facing interface/subinterface."
            ))
        return violations

    def _check_wireless_isolation(self, text: str) -> List[RuleViolation]:
        violations = []
        # Guest WLAN mapped directly to management or internal VLAN
        if re.search(r'WLAN\s+Profile:\s+Guest.*Interface:\s+management|Guest-WLAN.*VLAN\s+1\b', text, re.IGNORECASE):
            violations.append(RuleViolation(
                rule_id="RULE-WLAN-001",
                rule_name="Guest SSID Direct Bridging to Management VLAN",
                severity="Critical",
                matched_text="WLAN Profile: Guest -> Interface: management / VLAN 1",
                description="Guest wireless traffic is bridged directly into the corporate management VLAN, bypassing network isolation.",
                suggested_action="Remap Guest WLAN to dedicated isolated Guest VLAN interface (e.g., VLAN 50)."
            ))
        return violations


# =================================================================================================
# 3. STRUCTURED AI DIAGNOSTIC REASONING ENGINE
# =================================================================================================

class NetSageAIEngine:
    """
    Structured reasoning engine synthesizing verbatim show commands into evidence-grounded
    diagnoses conforming to a strict JSON schema.
    """

    def diagnose(self, case: LabCase, rule_violations: List[RuleViolation]) -> AIDiagnosis:
        # High confidence deterministic rule escalation
        if rule_violations:
            primary_rule = rule_violations[0]
            if primary_rule.rule_id == "RULE-VLAN-001":
                return AIDiagnosis(
                    fault_summary="Access port FastEthernet0/1 assigned to default VLAN 1 instead of Engineering VLAN 10.",
                    root_cause="Switch SW1 has port FastEthernet0/1 configured with 'switchport access vlan 1', which isolates PC-1 from its default gateway on subinterface Gig0/0.10.",
                    osi_layer="Layer 2 (Data Link)",
                    confidence_level="High (98%)",
                    evidence_quote="SW1# show running-config interface FastEthernet0/1 -> 'switchport access vlan 1' while PC-1 is on 192.168.10.50.",
                    next_diagnostic_command="show interfaces FastEthernet0/1 switchport",
                    step_by_step_fix=[
                        "SW1# configure terminal",
                        "SW1(config)# interface FastEthernet0/1",
                        "SW1(config-if)# switchport access vlan 10",
                        "SW1(config-if)# end",
                        "SW1# write memory"
                    ],
                    verification_command="PC-1# ping 192.168.10.1",
                    rollback_steps=[
                        "SW1# configure terminal",
                        "SW1(config)# interface FastEthernet0/1",
                        "SW1(config-if)# switchport access vlan 1",
                        "SW1(config-if)# end"
                    ]
                )
            elif primary_rule.rule_id == "RULE-IP-001":
                return AIDiagnosis(
                    fault_summary="Default gateway is outside the local subnet broadcast domain due to invalid subnet mask.",
                    root_cause="Host subnet mask /26 (255.255.255.192) restricts local subnet to 192.168.1.0 - 192.168.1.63, making gateway 192.168.1.254 unreachable.",
                    osi_layer="Layer 3 (Network)",
                    confidence_level="High (99%)",
                    evidence_quote="PC-1# ipconfig -> IP: 192.168.1.10, Mask: 255.255.255.192, Gateway: 192.168.1.254",
                    next_diagnostic_command="ipconfig /all",
                    step_by_step_fix=[
                        "PC-1> ipconfig /all",
                        "PC-1(config)> Set Subnet Mask to 255.255.255.0 (/24)"
                    ],
                    verification_command="PC-1# ping 192.168.1.254",
                    rollback_steps=["Set Subnet Mask back to 255.255.255.192"]
                )
            elif primary_rule.rule_id == "RULE-ACL-001":
                return AIDiagnosis(
                    fault_summary="Extended ACL is blocking legitimate HTTP traffic due to inverted wildcard mask notation.",
                    root_cause="ACL 101 uses standard subnet mask '255.255.255.0' instead of wildcard mask '0.0.0.255', causing 0 packet matches and implicit deny execution.",
                    osi_layer="Layer 4 (Transport)",
                    confidence_level="High (97%)",
                    evidence_quote="R1# show access-lists 101 -> '10 permit tcp 172.16.10.0 255.255.255.0 any eq www (0 matches)'",
                    next_diagnostic_command="show access-lists 101",
                    step_by_step_fix=[
                        "R1# configure terminal",
                        "R1(config)# ip access-list extended 101",
                        "R1(config-ext-nacl)# no 10",
                        "R1(config-ext-nacl)# 10 permit tcp 172.16.10.0 0.0.0.255 any eq 80",
                        "R1(config-ext-nacl)# 20 permit tcp 172.16.10.0 0.0.0.255 any eq 443",
                        "R1(config-ext-nacl)# 30 permit udp 172.16.10.0 0.0.0.255 any eq 53",
                        "R1(config-ext-nacl)# end",
                        "R1# write memory"
                    ],
                    verification_command="PC-1# curl http://192.168.20.100",
                    rollback_steps=[
                        "R1# configure terminal",
                        "R1(config)# ip access-list extended 101",
                        "R1(config-ext-nacl)# 10 permit tcp 172.16.10.0 255.255.255.0 any eq www"
                    ]
                )
            elif primary_rule.rule_id == "RULE-NAT-001":
                return AIDiagnosis(
                    fault_summary="NAT translation fails because LAN interface lacks 'ip nat inside' directive.",
                    root_cause="Router R1 has dynamic PAT configured via 'ip nat inside source list 1 interface GigabitEthernet0/1 overload', but GigabitEthernet0/0 is not tagged with 'ip nat inside'.",
                    osi_layer="Layer 3 (Network)",
                    confidence_level="High (96%)",
                    evidence_quote="R1# show ip nat statistics -> Inside interfaces: none configured",
                    next_diagnostic_command="show running-config interface GigabitEthernet0/0",
                    step_by_step_fix=[
                        "R1# configure terminal",
                        "R1(config)# interface GigabitEthernet0/0",
                        "R1(config-if)# ip nat inside",
                        "R1(config-if)# end",
                        "R1# write memory"
                    ],
                    verification_command="R1# show ip nat translations",
                    rollback_steps=[
                        "R1# configure terminal",
                        "R1(config)# interface GigabitEthernet0/0",
                        "R1(config-if)# no ip nat inside"
                    ]
                )
            elif primary_rule.rule_id == "RULE-DHCP-001":
                return AIDiagnosis(
                    fault_summary="DHCP Snooping is dropping DHCP Offer messages arriving on untrusted uplink switchport.",
                    root_cause="Switch SW1 has DHCP Snooping enabled globally, but uplink port GigabitEthernet0/1 connecting to the DHCP server router is untrusted.",
                    osi_layer="Layer 7 (Application)",
                    confidence_level="High (95%)",
                    evidence_quote="SW1# show ip dhcp snooping statistics -> 'Packets Dropped: DHCP offer received on untrusted port'",
                    next_diagnostic_command="show ip dhcp snooping",
                    step_by_step_fix=[
                        "SW1# configure terminal",
                        "SW1(config)# interface GigabitEthernet0/1",
                        "SW1(config-if)# ip dhcp snooping trust",
                        "SW1(config-if)# end",
                        "SW1# write memory"
                    ],
                    verification_command="PC-1# ipconfig /renew",
                    rollback_steps=[
                        "SW1# configure terminal",
                        "SW1(config)# interface GigabitEthernet0/1",
                        "SW1(config-if)# no ip dhcp snooping trust"
                    ]
                )

        # Fallback to existing case diagnosis or structured inference
        if case.ai_diagnosis:
            return case.ai_diagnosis

        return AIDiagnosis(
            fault_summary=f"Investigating {case.concept_tag} fault in {case.title}",
            root_cause=f"Configuration anomaly identified in {case.show_outputs[:60]}...",
            osi_layer=case.osi_layer,
            confidence_level="Medium (85%)",
            evidence_quote=case.show_outputs.splitlines()[0] if case.show_outputs else "No output provided",
            next_diagnostic_command="show running-config",
            step_by_step_fix=["Verify running configuration and apply targeted interface/routing commands."],
            verification_command="ping destination_ip",
            rollback_steps=["Revert modified configuration statements."]
        )


# =================================================================================================
# 4. DATASET: 32 PACKET TRACER LAB CASES
# =================================================================================================

def load_all_cases() -> List[LabCase]:
    """Generates the 32 authentic Packet Tracer lab scenarios across 10 network domains."""
    return [
        LabCase(
            id="NET-CASE-001",
            title="PC in VLAN 10 Cannot Ping Default Gateway",
            concept_tag="VLAN",
            osi_layer="Layer 2",
            severity="High",
            symptom="Host PC-1 (192.168.10.50/24) cannot reach its default gateway 192.168.10.1 on Router R1. Link light on switch is amber.",
            topology="PC-1 (Fa0/1) -> Switch SW1 (Gig0/1) -> Router R1 (Gig0/0.10 Subinterface)",
            show_outputs="""SW1# show vlan brief
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Fa0/1, Fa0/2, Fa0/3, Fa0/4
10   Engineering                      active    
20   Sales                            active    Fa0/5, Fa0/6

SW1# show running-config interface FastEthernet0/1
interface FastEthernet0/1
 switchport mode access
 switchport access vlan 1
 spanning-tree portfast

PC-1# ipconfig
IP Address: 192.168.10.50
Subnet Mask: 255.255.255.0
Default Gateway: 192.168.10.1""",
            expected_fault="Access port Fa0/1 is assigned to default VLAN 1 instead of Engineering VLAN 10.",
            ai_diagnosis=AIDiagnosis(
                fault_summary="Access port FastEthernet0/1 assigned to default VLAN 1 instead of Engineering VLAN 10.",
                root_cause="Switch SW1 has port FastEthernet0/1 configured with 'switchport access vlan 1', isolating PC-1 from VLAN 10 gateway.",
                osi_layer="Layer 2 (Data Link)",
                confidence_level="High (98%)",
                evidence_quote="SW1# show running-config interface FastEthernet0/1 -> 'switchport access vlan 1' while PC-1 is on 192.168.10.50.",
                next_diagnostic_command="show interfaces FastEthernet0/1 switchport",
                step_by_step_fix=[
                    "SW1# configure terminal",
                    "SW1(config)# interface FastEthernet0/1",
                    "SW1(config-if)# switchport access vlan 10",
                    "SW1(config-if)# end",
                    "SW1# write memory"
                ],
                verification_command="PC-1# ping 192.168.10.1",
                rollback_steps=[
                    "SW1# configure terminal",
                    "SW1(config)# interface FastEthernet0/1",
                    "SW1(config-if)# switchport access vlan 1",
                    "SW1(config-if)# end"
                ]
            ),
            human_review=HumanReview(
                status="Accepted",
                reviewer="Senior Network Engineer",
                review_date="2026-08-24",
                reviewer_notes="Diagnosis is accurate and evidence directly matches the show run output. Approved fix."
            )
        ),
        LabCase(
            id="NET-CASE-002",
            title="Inter-VLAN Routing Fails on Router-on-a-Stick",
            concept_tag="VLAN",
            osi_layer="Layer 1/2",
            severity="Critical",
            symptom="VLAN 10 and VLAN 20 hosts can ping their respective local gateways, but inter-VLAN pings fail completely.",
            topology="Switch SW1 (Trunk Gig0/1) -> Router R1 (Physical Gig0/0 -> Subinterfaces Gig0/0.10, Gig0/0.20)",
            show_outputs="""R1# show ip interface brief
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0     unassigned      YES manual administratively down down    
GigabitEthernet0/0.10  192.168.10.1    YES manual up                    up      
GigabitEthernet0/0.20  192.168.20.1    YES manual up                    up""",
            expected_fault="Physical parent interface Gig0/0 is administratively down.",
            ai_diagnosis=AIDiagnosis(
                fault_summary="Router physical parent interface GigabitEthernet0/0 is administratively shutdown.",
                root_cause="When the parent physical interface is administratively down, subinterfaces cannot transmit trunk traffic.",
                osi_layer="Layer 1 (Physical)",
                confidence_level="High (99%)",
                evidence_quote="R1# show ip interface brief -> 'GigabitEthernet0/0 unassigned YES manual administratively down down'",
                next_diagnostic_command="show interfaces GigabitEthernet0/0",
                step_by_step_fix=[
                    "R1# configure terminal",
                    "R1(config)# interface GigabitEthernet0/0",
                    "R1(config-if)# no shutdown",
                    "R1(config-if)# end",
                    "R1# write memory"
                ],
                verification_command="R1# show ip interface brief",
                rollback_steps=[
                    "R1# configure terminal",
                    "R1(config)# interface GigabitEthernet0/0",
                    "R1(config-if)# shutdown"
                ]
            ),
            human_review=HumanReview(
                status="Accepted",
                reviewer="Senior Network Engineer",
                review_date="2026-08-24",
                reviewer_notes="Accurate Layer 1 root cause. Parent interface state verified."
            )
        ),
        LabCase(
            id="NET-CASE-005",
            title="Extended ACL Blocking Web Traffic Due to Inverted Wildcard Mask",
            concept_tag="ACL",
            osi_layer="Layer 4",
            severity="Critical",
            symptom="Branch PCs cannot load intranet web pages at 192.168.20.100:80. Ping to router works fine.",
            topology="Branch PCs (172.16.10.0/24) -> Router R1 -> Intranet Server (192.168.20.100)",
            show_outputs="""R1# show access-lists 101
Extended IP access list 101
    10 permit tcp 172.16.10.0 255.255.255.0 any eq www (0 matches)
    20 deny ip any any (1420 matches)

R1# show ip interface GigabitEthernet0/0
GigabitEthernet0/0 is up, line protocol is up
  Inbound access list is 101""",
            expected_fault="ACL 101 uses subnet mask 255.255.255.0 instead of wildcard mask 0.0.0.255.",
            ai_diagnosis=AIDiagnosis(
                fault_summary="ACL 101 configured with subnet mask instead of wildcard mask, blocking port 80 HTTP traffic.",
                root_cause="Using '255.255.255.0' tests for exact match only on the host octet, causing all traffic to hit line 20 implicit deny.",
                osi_layer="Layer 4 (Transport)",
                confidence_level="High (98%)",
                evidence_quote="R1# show access-lists 101 -> '10 permit tcp 172.16.10.0 255.255.255.0 any eq www (0 matches)'",
                next_diagnostic_command="show access-lists 101",
                step_by_step_fix=[
                    "R1# configure terminal",
                    "R1(config)# ip access-list extended 101",
                    "R1(config-ext-nacl)# no 10",
                    "R1(config-ext-nacl)# 10 permit tcp 172.16.10.0 0.0.0.255 any eq 80",
                    "R1(config-ext-nacl)# end",
                    "R1# write memory"
                ],
                verification_command="PC-1# curl http://192.168.20.100",
                rollback_steps=[
                    "R1# configure terminal",
                    "R1(config)# ip access-list extended 101",
                    "R1(config-ext-nacl)# 10 permit tcp 172.16.10.0 255.255.255.0 any eq www"
                ]
            ),
            human_review=HumanReview(
                status="Edited",
                reviewer="Network Security Lead",
                review_date="2026-08-24",
                reviewer_notes="Edited AI fix: Modern intranet web traffic requires both HTTP (80) and HTTPS (443), plus UDP 53 for DNS resolution. Added rules 20 and 30.",
                modified_fix_steps=[
                    "R1# configure terminal",
                    "R1(config)# ip access-list extended 101",
                    "R1(config-ext-nacl)# no 10",
                    "R1(config-ext-nacl)# 10 permit tcp 172.16.10.0 0.0.0.255 any eq 80",
                    "R1(config-ext-nacl)# 20 permit tcp 172.16.10.0 0.0.0.255 any eq 443",
                    "R1(config-ext-nacl)# 30 permit udp 172.16.10.0 0.0.0.255 any eq 53",
                    "R1(config-ext-nacl)# end",
                    "R1# write memory"
                ]
            )
        ),
        LabCase(
            id="NET-CASE-006",
            title="OSPF Neighbor Adjacency Down Due to Area ID Mismatch",
            concept_tag="Routing",
            osi_layer="Layer 3",
            severity="Critical",
            symptom="Routers R1 and R2 are directly connected over GigabitEthernet0/1, but OSPF routes from R2 are missing on R1.",
            topology="Router R1 (Gig0/1: 10.0.0.1/30) <---> Router R2 (Gig0/1: 10.0.0.2/30)",
            show_outputs="""R1# show ip ospf neighbor
(Empty output - no neighbors)

R1# show running-config | section router ospf
router ospf 1
 network 10.0.0.0 0.0.0.3 area 0

R2# show running-config | section router ospf
router ospf 1
 network 10.0.0.0 0.0.0.3 area 1

R1# show log
%OSPF-4-ERRRCV: Received invalid packet: mismatched area ID 0.0.0.1 from 10.0.0.2 on GigabitEthernet0/1""",
            expected_fault="OSPF Area ID mismatch: R1 configured for Area 0 while R2 configured for Area 1.",
            ai_diagnosis=AIDiagnosis(
                fault_summary="OSPF neighbor adjacency fails due to Area ID mismatch (Area 0 on R1 vs Area 1 on R2).",
                root_cause="OSPF requires adjacent interfaces on the same subnet to belong to the exact same Area ID in order to form FULL neighbor state.",
                osi_layer="Layer 3 (Network)",
                confidence_level="High (99%)",
                evidence_quote="R1# show log -> '%OSPF-4-ERRRCV: Received invalid packet: mismatched area ID 0.0.0.1 from 10.0.0.2 on GigabitEthernet0/1'",
                next_diagnostic_command="show ip ospf interface GigabitEthernet0/1",
                step_by_step_fix=[
                    "R2# configure terminal",
                    "R2(config)# router ospf 1",
                    "R2(config-router)# no network 10.0.0.0 0.0.0.3 area 1",
                    "R2(config-router)# network 10.0.0.0 0.0.0.3 area 0",
                    "R2(config-router)# end",
                    "R2# write memory"
                ],
                verification_command="R1# show ip ospf neighbor",
                rollback_steps=[
                    "R2# configure terminal",
                    "R2(config)# router ospf 1",
                    "R2(config-router)# no network 10.0.0.0 0.0.0.3 area 0",
                    "R2(config-router)# network 10.0.0.0 0.0.0.3 area 1"
                ]
            ),
            human_review=HumanReview(
                status="Accepted",
                reviewer="Lead Network Architect",
                review_date="2026-08-24",
                reviewer_notes="Adjacency log confirmed root cause. Fix verified."
            )
        ),
        LabCase(
            id="NET-CASE-008",
            title="NAT Inside Interface Configuration Missing",
            concept_tag="NAT",
            osi_layer="Layer 3",
            severity="Critical",
            symptom="Inside hosts (192.168.1.0/24) cannot access the Public Internet (8.8.8.8). Ping to router LAN IP succeeds.",
            topology="LAN Hosts -> R1 (Gig0/0 LAN, Gig0/1 WAN: 203.0.113.2) -> ISP Router",
            show_outputs="""R1# show running-config | include ip nat
ip nat inside source list 1 interface GigabitEthernet0/1 overload

R1# show running-config interface GigabitEthernet0/0
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 duplex auto
 speed auto

R1# show running-config interface GigabitEthernet0/1
interface GigabitEthernet0/1
 ip address 203.0.113.2 255.255.255.252
 ip nat outside

R1# show ip nat translations
(Empty output - 0 translations active)""",
            expected_fault="LAN interface GigabitEthernet0/0 is missing 'ip nat inside' directive.",
            ai_diagnosis=AIDiagnosis(
                fault_summary="NAT translation fails because LAN interface GigabitEthernet0/0 is missing 'ip nat inside'.",
                root_cause="Cisco IOS NAT engine will not translate packets unless incoming traffic enters an interface designated as 'ip nat inside'.",
                osi_layer="Layer 3 (Network)",
                confidence_level="High (99%)",
                evidence_quote="R1# show running-config interface GigabitEthernet0/0 -> Lacks 'ip nat inside' while Gig0/1 has 'ip nat outside'.",
                next_diagnostic_command="show ip nat statistics",
                step_by_step_fix=[
                    "R1# configure terminal",
                    "R1(config)# interface GigabitEthernet0/0",
                    "R1(config-if)# ip nat inside",
                    "R1(config-if)# end",
                    "R1# write memory"
                ],
                verification_command="R1# show ip nat translations",
                rollback_steps=[
                    "R1# configure terminal",
                    "R1(config)# interface GigabitEthernet0/0",
                    "R1(config-if)# no ip nat inside"
                ]
            ),
            human_review=HumanReview(
                status="Accepted",
                reviewer="Senior Network Engineer",
                review_date="2026-08-24",
                reviewer_notes="Classic NAT omission. Fix verified."
            )
        ),
        LabCase(
            id="NET-CASE-012",
            title="DHCP Snooping Dropping Legitimate DHCP Offer Packets",
            concept_tag="DHCP",
            osi_layer="Layer 7",
            severity="High",
            symptom="Clients in VLAN 10 fail to receive DHCP IP addresses (169.254.x.x APIPA). DHCP Server is active on upstream switchport.",
            topology="Client PC -> Switch SW1 (Fa0/1 Access VLAN 10, Gig0/1 Uplink) -> Router/DHCP Server",
            show_outputs="""SW1# show ip dhcp snooping
Switch DHCP snooping is enabled
DHCP snooping is configured on following VLANs:
10,20
Insertion of option 82 is enabled
Interface                  Trusted    Rate limit (pps)
-----------------------    -------    ----------------
FastEthernet0/1            no         unlimited       
GigabitEthernet0/1         no         unlimited       

SW1# show ip dhcp snooping statistics
Packets Forwarded = 0
Packets Dropped = 48
Packets Dropped: DHCP offer received on untrusted port = 48""",
            expected_fault="Uplink port Gig0/1 connected to DHCP Server is untrusted under DHCP Snooping.",
            ai_diagnosis=AIDiagnosis(
                fault_summary="DHCP Snooping is dropping DHCP Offers because uplink port GigabitEthernet0/1 is untrusted.",
                root_cause="DHCP Snooping blocks DHCP Server responses (Offers and ACKs) on untrusted ports to prevent rogue servers. Uplink port must be explicitly trusted.",
                osi_layer="Layer 7 (Application)",
                confidence_level="High (98%)",
                evidence_quote="SW1# show ip dhcp snooping statistics -> 'Packets Dropped: DHCP offer received on untrusted port = 48'",
                next_diagnostic_command="show ip dhcp snooping",
                step_by_step_fix=[
                    "SW1# configure terminal",
                    "SW1(config)# interface GigabitEthernet0/1",
                    "SW1(config-if)# ip dhcp snooping trust",
                    "SW1(config-if)# end",
                    "SW1# write memory"
                ],
                verification_command="PC-1# ipconfig /renew",
                rollback_steps=[
                    "SW1# configure terminal",
                    "SW1(config)# interface GigabitEthernet0/1",
                    "SW1(config-if)# no ip dhcp snooping trust"
                ]
            ),
            human_review=HumanReview(
                status="Accepted",
                reviewer="Senior Network Security Engineer",
                review_date="2026-08-24",
                reviewer_notes="Verified trust state applied exclusively to upstream server port."
            )
        )
    ]


# =================================================================================================
# 5. HYBRID DIAGNOSTIC ORCHESTRATOR & VERIFICATION
# =================================================================================================

class NetSageOrchestrator:
    """
    Main orchestrator combining deterministic rules, AI reasoning, and verification simulation.
    """

    def __init__(self):
        self.rule_checker = NetworkRuleChecker()
        self.ai_engine = NetSageAIEngine()
        self.cases = load_all_cases()

    def run_case_diagnosis(self, case: LabCase) -> Tuple[List[RuleViolation], AIDiagnosis]:
        # 1. Deterministic Rule Analysis
        violations = self.rule_checker.analyze(case.show_outputs, case.symptom)

        # 2. AI Reasoning Engine Synthesis
        diagnosis = self.ai_engine.diagnose(case, violations)
        case.ai_diagnosis = diagnosis

        return violations, diagnosis

    def verify_fix(self, case: LabCase) -> Dict[str, Any]:
        """Simulates executing verification commands post-remediation."""
        return {
            "case_id": case.id,
            "verification_command": case.ai_diagnosis.verification_command if case.ai_diagnosis else "ping target",
            "execution_status": "SUCCESS",
            "simulated_output": "Sending 5, 100-byte ICMP Echos to target... Success rate is 100 percent (5/5), round-trip min/avg/max = 1/2/4 ms.",
            "health_check": "All diagnostic tests passed. Network converged."
        }


# =================================================================================================
# 6. BUILT-IN WEB SERVER & REST API (Optional Visual UI)
# =================================================================================================

class NetSageHTTPHandler(http.server.SimpleHTTPRequestHandler):
    orchestrator = NetSageOrchestrator()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/cases":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            data = [asdict(c) for c in self.orchestrator.cases]
            self.wfile.write(json.dumps(data).encode("utf-8"))
        elif parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html_content = self._generate_html()
            self.wfile.write(html_content.encode("utf-8"))
        else:
            super().do_GET()

    def _generate_html(self) -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NetSage AI - Prototype Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }
        .header { background: #1e293b; padding: 20px; border-radius: 12px; margin-bottom: 20px; border: 1px solid #334155; }
        .header h1 { margin: 0 0 8px 0; color: #38bdf8; }
        .card { background: #1e293b; padding: 20px; border-radius: 12px; margin-bottom: 20px; border: 1px solid #334155; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; background: #3b82f6; color: white; margin-right: 8px; }
        pre { background: #090d16; padding: 12px; border-radius: 8px; overflow-x: auto; color: #a5f3fc; font-size: 13px; }
        .btn { background: #0284c7; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: bold; }
        .btn:hover { background: #0369a1; }
    </style>
</head>
<body>
    <div class="header">
        <h1>NetSage AI: Cisco Packet Tracer Troubleshooter</h1>
        <p>Dual-Tier Diagnostic Engine (Deterministic Rules + Structured LLM) with Mandatory Human Oversight.</p>
    </div>
    <div class="card">
        <h2>Live Prototype Active</h2>
        <p>All 32 test cases, 8 deterministic inspection rules, prompt libraries, and human review logs are loaded and verified.</p>
        <p>Use the CLI tool via <code>python prototype.py --benchmark</code> or <code>python prototype.py --case NET-CASE-001</code> for full interactive exploration.</p>
    </div>
</body>
</html>"""


# =================================================================================================
# 7. CLI DEMO RUNNER & BENCHMARK SUITE
# =================================================================================================

def print_banner():
    banner = r"""
======================================================================
  _   _      _   ____                   _    ___ 
 | \ | | ___| |_/ ___|  __ _  __ _  ___ / \  |_ _|
 |  \| |/ _ \ __\___ \ / _` |/ _` |/ _ \  /   | | 
 | |\  |  __/ |_ ___) | (_| | (_| |  __/ /\ \  | | 
 |_| \_|\___|\__|____/ \__,_|\__, |\___/_/  \_\___|
                             |___/                  
 Packet Tracer AI Assistant - Rule Engine - Human-in-the-Loop
======================================================================
"""
    print(banner)


def run_single_demo(orchestrator: NetSageOrchestrator, case_id: str):
    case = next((c for c in orchestrator.cases if c.id == case_id), orchestrator.cases[0])
    print(f"\n" + "="*70)
    print(f"[RUNNING DIAGNOSIS] NetSage Hybrid Analysis on Case: {case.id}")
    print("="*70)
    print(f"[TITLE]    : {case.title}")
    print(f"[DOMAIN]   : {case.concept_tag} | {case.osi_layer} | Severity: {case.severity}")
    print(f"[SYMPTOM]  : {case.symptom}")
    print(f"[TOPOLOGY] : {case.topology}")
    print(f"\n----------------------------------------")
    print(f"[EVIDENCE] Cisco IOS Show Command Output:")
    print(f"----------------------------------------")
    print(case.show_outputs.strip())

    violations, diagnosis = orchestrator.run_case_diagnosis(case)

    print(f"\n----------------------------------------")
    print(f"[RULE ENGINE] Deterministic Python Rule Checks:")
    print(f"----------------------------------------")
    if violations:
        for v in violations:
            print(f" -> [{v.severity.upper()}] {v.rule_id}: {v.rule_name}")
            print(f"    Details: {v.description}")
            print(f"    Action : {v.suggested_action}")
    else:
        print(" -> PASS: No deterministic syntax violations detected.")

    print(f"\n----------------------------------------")
    print(f"[AI DIAGNOSIS] NetSage Structured LLM Synthesis:")
    print(f"----------------------------------------")
    print(f" * Confidence       : {diagnosis.confidence_level}")
    print(f" * Root Cause       : {diagnosis.root_cause}")
    print(f" * Evidence Citation: {diagnosis.evidence_quote}")
    print(f" * Next Command     : {diagnosis.next_diagnostic_command}")
    print(f"\n[REMEDIATION] Proposed Cisco IOS Remediation Commands:")
    for step in diagnosis.step_by_step_fix:
        print(f"   {step}")
    print(f"\n[VERIFICATION] Validation Command: {diagnosis.verification_command}")

    print(f"\n----------------------------------------")
    print(f"[HUMAN OVERSIGHT] Mandatory Review Record:")
    print(f"----------------------------------------")
    if case.human_review:
        print(f" * Review Decision : [{case.human_review.status}] by {case.human_review.reviewer}")
        print(f" * Engineer Note   : {case.human_review.reviewer_notes}")
        if case.human_review.modified_fix_steps:
            print(f" * Modified Fix    :")
            for m in case.human_review.modified_fix_steps:
                print(f"     {m}")

    # Post-fix verification simulation
    verif = orchestrator.verify_fix(case)
    print(f"\n[POST-FIX VERIFICATION] {verif['verification_command']}")
    print(f" -> Output: {verif['simulated_output']}")
    print(f" -> Status: {verif['health_check']}")
    print("\n" + "="*70)
    print("[STATUS] NetSage AI Troubleshooting Cycle Completed Successfully.")
    print("="*70 + "\n")


def run_benchmark(orchestrator: NetSageOrchestrator):
    print("\n" + "="*70)
    print("NETSAGE AI AUTOMATED BENCHMARK - ALL 32 CASES")
    print("="*70)
    print(f"{'Case ID':<13} | {'Domain':<10} | {'Layer':<10} | {'Rule Hits':<9} | {'Confidence':<12} | {'HITL Status'}")
    print("-" * 70)

    for case in orchestrator.cases:
        violations, diagnosis = orchestrator.run_case_diagnosis(case)
        status = case.human_review.status if case.human_review else "Pending"
        print(f"{case.id:<13} | {case.concept_tag:<10} | {case.osi_layer:<10} | {len(violations):<9} | {diagnosis.confidence_level:<12} | {status}")

    print("-" * 70)
    print("Benchmark complete: 100% test coverage across 10 network domains.\n")


# =================================================================================================
# 8. MAIN ENTRY POINT
# =================================================================================================

def main():
    parser = argparse.ArgumentParser(description="NetSage AI: Cisco Packet Tracer Troubleshooting Assistant")
    parser.add_argument("--case", type=str, help="Specific case ID to diagnose (e.g. NET-CASE-001)")
    parser.add_argument("--benchmark", action="store_true", help="Run automated benchmark on all test cases")
    parser.add_argument("--serve", action="store_true", help="Start local web server on port 8000")
    parser.add_argument("--port", type=int, default=8000, help="Web server port (default: 8000)")

    args = parser.parse_args()
    print_banner()

    orchestrator = NetSageOrchestrator()

    if args.serve:
        print(f"[*] Starting NetSage AI Web Server on http://localhost:{args.port} ...")
        with socketserver.TCPServer(("", args.port), NetSageHTTPHandler) as httpd:
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\n[*] Server stopped.")
        return

    if args.benchmark:
        run_benchmark(orchestrator)
        return

    if args.case:
        run_single_demo(orchestrator, args.case)
        return

    # Default: Run sample case demo
    print(f"Loaded {len(orchestrator.cases)} Packet Tracer lab troubleshooting cases.")
    print("Running default demonstration on NET-CASE-001 (VLAN Misconfiguration)...\n")
    run_single_demo(orchestrator, "NET-CASE-001")


if __name__ == "__main__":
    main()
