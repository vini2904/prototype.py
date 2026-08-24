"""
NetSage AI - Deterministic Network Rule Checker
Validates common Cisco IOS network configuration faults using deterministic parsing and regex rules.
"""

import re
import ipaddress
from typing import Dict, List, Any, Optional

class RuleViolation:
    def __init__(self, rule_id: str, title: str, severity: str, osi_layer: str,
                 description: str, evidence: str, recommended_fix: List[str]):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.osi_layer = osi_layer
        self.description = description
        self.evidence = evidence
        self.recommended_fix = recommended_fix

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "osi_layer": self.osi_layer,
            "description": self.description,
            "evidence": self.evidence,
            "recommended_fix": self.recommended_fix
        }

class NetworkRuleChecker:
    """Deterministic validation engine for Packet Tracer lab outputs."""

    def __init__(self):
        pass

    def run_all_checks(self, show_outputs: str, symptom: str = "", topology: str = "") -> List[Dict[str, Any]]:
        """Runs all deterministic rules against provided show commands and symptoms."""
        violations: List[RuleViolation] = []
        
        # 1. Interface State Checks
        violations.extend(self.check_interface_status(show_outputs))
        
        # 2. IP Subnet & Gateway Checks
        violations.extend(self.check_ip_subnet_and_gateway(show_outputs, symptom))
        
        # 3. VLAN & Trunking Checks
        violations.extend(self.check_vlan_and_trunking(show_outputs))
        
        # 4. Routing Protocol Checks (OSPF / Static / RIP)
        violations.extend(self.check_routing_issues(show_outputs))
        
        # 5. ACL Misconfiguration Checks
        violations.extend(self.check_acl_rules(show_outputs))
        
        # 6. DHCP Checks
        violations.extend(self.check_dhcp_rules(show_outputs))
        
        # 7. NAT / PAT Checks
        violations.extend(self.check_nat_rules(show_outputs))
        
        # 8. Wireless & Guest Isolation Checks
        violations.extend(self.check_wireless_isolation(show_outputs, symptom))

        return [v.to_dict() for v in violations]

    def check_interface_status(self, text: str) -> List[RuleViolation]:
        violations = []
        
        # Match administratively down interfaces
        admin_down_matches = re.findall(r'([A-Za-z0-9/\.\-]+)\s+[\d\.]+|unassigned\s+YES\s+\w+\s+administratively down\s+down', text, re.IGNORECASE)
        admin_down_lines = [line.strip() for line in text.splitlines() if 'administratively down' in line.lower()]
        if admin_down_lines:
            for line in admin_down_lines:
                violations.append(RuleViolation(
                    rule_id="RULE-INT-001",
                    title="Interface Administratively Shutdown",
                    severity="Critical",
                    osi_layer="Layer 1",
                    description="Physical interface is disabled with 'shutdown' command, preventing any traffic or subinterfaces from operating.",
                    evidence=line,
                    recommended_fix=[
                        f"interface {line.split()[0]}",
                        "no shutdown"
                    ]
                ))

        # Match err-disabled ports
        err_disabled_lines = [line.strip() for line in text.splitlines() if 'err-disabled' in line.lower() or 'secure-shutdown' in line.lower()]
        if err_disabled_lines:
            violations.append(RuleViolation(
                rule_id="RULE-INT-002",
                title="Port in Err-Disabled State (Port Security Violation)",
                severity="High",
                osi_layer="Layer 2",
                description="Interface was automatically shutdown by port security or BPDU guard due to unauthorized MAC or STP event.",
                evidence="; ".join(err_disabled_lines[:2]),
                recommended_fix=[
                    "interface <interface_id>",
                    "shutdown",
                    "switchport port-security mac-address sticky",
                    "no shutdown"
                ]
            ))

        # Match Duplex Mismatch / Late Collisions
        if 'late collision' in text.lower() or ('half-duplex' in text.lower() and 'crc' in text.lower()):
            collision_line = [l.strip() for l in text.splitlines() if 'late collision' in l.lower() or 'half-duplex' in l.lower()]
            violations.append(RuleViolation(
                rule_id="RULE-INT-003",
                title="Duplex Mismatch / High Late Collisions Detected",
                severity="Medium",
                osi_layer="Layer 1/2",
                description="Interface is operating in Half-Duplex with high late collisions and CRC errors, indicating a speed/duplex mismatch with the connected endpoint.",
                evidence="; ".join(collision_line[:2]),
                recommended_fix=[
                    "interface <interface_id>",
                    "duplex full",
                    "speed 100"
                ]
            ))

        return violations

    def check_ip_subnet_and_gateway(self, text: str, symptom: str) -> List[RuleViolation]:
        violations = []
        
        # Subnet mask mismatch / gateway off-subnet
        # Look for Host IP, Mask, Gateway combinations
        ip_match = re.search(r'IP Address:\s*([0-9\.]+)', text)
        mask_match = re.search(r'Subnet Mask:\s*([0-9\.]+)', text)
        gw_match = re.search(r'Default Gateway:\s*([0-9\.]+)', text)

        if ip_match and mask_match and gw_match:
            try:
                ip_str = ip_match.group(1).strip()
                mask_str = mask_match.group(1).strip()
                gw_str = gw_match.group(1).strip()

                net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
                gw_ip = ipaddress.IPv4Address(gw_str)

                # Check if gateway is broadcast address
                if gw_ip == net.broadcast_address:
                    violations.append(RuleViolation(
                        rule_id="RULE-IP-002",
                        title="Default Gateway is Directed Broadcast Address",
                        severity="High",
                        osi_layer="Layer 3",
                        description=f"Configured default gateway {gw_str} matches the broadcast address of subnet {net.with_prefixlen}.",
                        evidence=f"IP: {ip_str}, Mask: {mask_str}, Gateway: {gw_str} (Subnet Broadcast: {net.broadcast_address})",
                        recommended_fix=[
                            f"Change default gateway from {gw_str} to valid router IP (e.g. {net.network_address + 1})"
                        ]
                    ))
                elif gw_ip not in net:
                    violations.append(RuleViolation(
                        rule_id="RULE-IP-001",
                        title="Default Gateway Not in Local Subnet",
                        severity="High",
                        osi_layer="Layer 3",
                        description=f"Host IP {ip_str} with mask {mask_str} belongs to network {net.network_address}/{net.prefixlen}, but default gateway {gw_str} is outside this network.",
                        evidence=f"Host: {ip_str}/{mask_str} (Network: {net.network_address}) vs Gateway: {gw_str}",
                        recommended_fix=[
                            f"Update Subnet Mask to match gateway network or reconfigure Gateway to belong to {net.network_address}/{net.prefixlen}"
                        ]
                    ))
            except Exception:
                pass

        # HSRP Virtual IP mismatch
        if 'DIFFVIP' in text or 'different to the locally configured address' in text:
            violations.append(RuleViolation(
                rule_id="RULE-IP-003",
                title="HSRP Virtual IP Mismatch Across Redundant Routers",
                severity="High",
                osi_layer="Layer 3",
                description="HSRP standby group peers are configured with conflicting Virtual IP addresses.",
                evidence=[l.strip() for l in text.splitlines() if 'DIFFVIP' in l or 'virtual ip' in l.lower()][0],
                recommended_fix=[
                    "interface <interface_id>",
                    "standby <group> ip <correct_virtual_ip>"
                ]
            ))

        return violations

    def check_vlan_and_trunking(self, text: str) -> List[RuleViolation]:
        violations = []

        # Native VLAN Mismatch
        if 'NATIVE_VLAN_MISMATCH' in text or ('Native vlan' in text and re.search(r'Native vlan\s*\n.*?\b(99|1)\b.*\n.*?\b(1|99)\b', text, re.DOTALL)):
            mismatch_line = [l.strip() for l in text.splitlines() if 'NATIVE_VLAN_MISMATCH' in l or 'Native vlan' in l]
            violations.append(RuleViolation(
                rule_id="RULE-VLAN-001",
                title="Trunk Native VLAN Mismatch",
                severity="High",
                osi_layer="Layer 2",
                description="802.1Q trunk peers have mismatched native VLAN configurations, causing spanning tree inconsistencies and frame leakage.",
                evidence="; ".join(mismatch_line[:2]),
                recommended_fix=[
                    "interface <trunk_interface>",
                    "switchport trunk native vlan <matching_vlan_id>"
                ]
            ))

        # Access Mode VLAN Inactive / Not in VLAN DB
        if 'Access Mode VLAN:' in text and 'inactive' in text:
            inactive_line = [l.strip() for l in text.splitlines() if 'Access Mode VLAN:' in l and 'inactive' in l][0]
            violations.append(RuleViolation(
                rule_id="RULE-VLAN-002",
                title="Access Port VLAN Missing in VLAN Database (Inactive)",
                severity="High",
                osi_layer="Layer 2",
                description="The VLAN assigned to an access switchport has not been declared in the switch VLAN database, rendering the port inactive.",
                evidence=inactive_line,
                recommended_fix=[
                    "vlan <vlan_id>",
                    "name <vlan_name>"
                ]
            ))

        # Dot1Q Subinterface Mismatch
        encap_matches = re.findall(r'interface GigabitEthernet0/0\.(\d+)\s+encapsulation dot1Q (\d+)', text, re.IGNORECASE)
        for subif_id, encap_id in encap_matches:
            if subif_id != encap_id:
                violations.append(RuleViolation(
                    rule_id="RULE-VLAN-003",
                    title="Subinterface Dot1Q VLAN ID Mismatch",
                    severity="High",
                    osi_layer="Layer 2",
                    description=f"Subinterface Gig0/0.{subif_id} specifies encapsulation dot1Q {encap_id} instead of matching tag {subif_id}.",
                    evidence=f"GigabitEthernet0/0.{subif_id} -> encapsulation dot1Q {encap_id}",
                    recommended_fix=[
                        f"interface GigabitEthernet0/0.{subif_id}",
                        f"encapsulation dot1Q {subif_id}"
                    ]
                ))

        return violations

    def check_routing_issues(self, text: str) -> List[RuleViolation]:
        violations = []

        # Missing Default Route
        if 'Gateway of last resort is not set' in text:
            violations.append(RuleViolation(
                rule_id="RULE-ROUTE-001",
                title="Missing Gateway of Last Resort (Default Route)",
                severity="High",
                osi_layer="Layer 3",
                description="Edge router has no default route (0.0.0.0/0) configured, dropping all packets destined for unknown/external subnets.",
                evidence="Gateway of last resort is not set",
                recommended_fix=[
                    "ip route 0.0.0.0 0.0.0.0 <next_hop_isp_ip>"
                ]
            ))

        # OSPF Area Mismatch
        if 'Area 1 mismatch Area 0' in text or 'mismatch Area' in text:
            mismatch_line = [l.strip() for l in text.splitlines() if 'mismatch Area' in l][0]
            violations.append(RuleViolation(
                rule_id="RULE-OSPF-001",
                title="OSPF Area ID Mismatch on Interconnecting Link",
                severity="Critical",
                osi_layer="Layer 3",
                description="Directly connected OSPF routers are configured in different areas on the same link, preventing adjacency formation.",
                evidence=mismatch_line,
                recommended_fix=[
                    "router ospf <process_id>",
                    "no network <subnet> <wildcard> area <wrong_area>",
                    "network <subnet> <wildcard> area <correct_area>"
                ]
            ))

        # OSPF Passive Interface on Core Link
        if 'No Hellos (Passive interface)' in text or ('passive-interface' in text and 'GigabitEthernet' in text):
            pass_line = [l.strip() for l in text.splitlines() if 'Passive interface' in l or 'passive-interface' in l][0]
            violations.append(RuleViolation(
                rule_id="RULE-OSPF-002",
                title="OSPF Passive-Interface Configured on Routed Link",
                severity="Critical",
                osi_layer="Layer 3",
                description="OSPF Hello transmission is suppressed by 'passive-interface' on an active inter-router link, preventing neighbor formation.",
                evidence=pass_line,
                recommended_fix=[
                    "router ospf <process_id>",
                    "no passive-interface <interface_id>"
                ]
            ))

        # OSPF MTU Mismatch
        if 'EXSTART' in text and 'MTU' in text:
            violations.append(RuleViolation(
                rule_id="RULE-OSPF-003",
                title="OSPF MTU Mismatch Stuck in EXSTART/EXCHANGE",
                severity="High",
                osi_layer="Layer 3",
                description="Interface MTU mismatch between OSPF neighbors causes Database Description (DBD) packets to be dropped.",
                evidence="Neighbor state EXSTART with mismatched MTU values in show interfaces",
                recommended_fix=[
                    "interface <interface_id>",
                    "mtu 1500"
                ]
            ))

        return violations

    def check_acl_rules(self, text: str) -> List[RuleViolation]:
        violations = []

        # Inverted Wildcard Mask in ACL (e.g. 255.255.255.0 used instead of 0.0.0.255)
        acl_mask_match = re.findall(r'permit\s+(?:ip|tcp|udp)\s+[\d\.]+\s+(255\.255\.255\.\d+)', text)
        if acl_mask_match:
            acl_line = [l.strip() for l in text.splitlines() if '255.255.255.' in l and 'permit' in l][0]
            violations.append(RuleViolation(
                rule_id="RULE-ACL-001",
                title="Inverted Wildcard Mask in Access List",
                severity="Critical",
                osi_layer="Layer 4",
                description="Standard subnet mask (255.255.255.x) was entered instead of an inverted wildcard mask (0.0.0.x), causing ACL statements to fail matching traffic.",
                evidence=acl_line,
                recommended_fix=[
                    "ip access-list extended <acl_name_or_number>",
                    "Replace 255.255.255.0 with 0.0.0.255 in permit statement"
                ]
            ))

        return violations

    def check_dhcp_rules(self, text: str) -> List[RuleViolation]:
        violations = []

        # DHCP Pool 100% Utilized
        if 'Utilization mark' in text and '100' in text:
            violations.append(RuleViolation(
                rule_id="RULE-DHCP-001",
                title="DHCP Address Pool Exhaustion (100% Leased)",
                severity="High",
                osi_layer="Layer 7",
                description="All available IP addresses in the configured DHCP pool scope are leased out, causing new clients to self-assign 169.254.x.x APIPA addresses.",
                evidence="Utilization mark (high/low): 100 / 0",
                recommended_fix=[
                    "ip dhcp pool <pool_name>",
                    "Expand subnet mask or clear expired bindings with 'clear ip dhcp binding *'"
                ]
            ))

        # DHCP Snooping Untrusted Port Dropping Offers
        if 'DHCP offer received on untrusted port' in text:
            snoop_line = [l.strip() for l in text.splitlines() if 'untrusted port' in l][0]
            violations.append(RuleViolation(
                rule_id="RULE-DHCP-002",
                title="DHCP Snooping Dropping Legitimate Server Offers",
                severity="High",
                osi_layer="Layer 2",
                description="DHCP Snooping is dropping server response packets because the uplink switchport connected to the DHCP server is marked untrusted.",
                evidence=snoop_line,
                recommended_fix=[
                    "interface <uplink_interface>",
                    "ip dhcp snooping trust"
                ]
            ))

        # Broadcast Helper Address
        if 'ip helper-address 255.255.255.255' in text:
            violations.append(RuleViolation(
                rule_id="RULE-DHCP-003",
                title="DHCP Relay Configured with Broadcast Instead of Unicast Server IP",
                severity="Medium",
                osi_layer="Layer 3",
                description="The 'ip helper-address' command is set to local broadcast 255.255.255.255 instead of the unicast IP of the remote DHCP server.",
                evidence="ip helper-address 255.255.255.255",
                recommended_fix=[
                    "interface <interface_id>",
                    "no ip helper-address 255.255.255.255",
                    "ip helper-address <unicast_dhcp_server_ip>"
                ]
            ))

        return violations

    def check_nat_rules(self, text: str) -> List[RuleViolation]:
        violations = []

        # Missing ip nat inside
        if 'Outside interfaces:' in text and 'Inside interfaces:' in text:
            if re.search(r'Inside interfaces:\s*\n', text):
                violations.append(RuleViolation(
                    rule_id="RULE-NAT-001",
                    title="Missing 'ip nat inside' Configuration on LAN Interface",
                    severity="Critical",
                    osi_layer="Layer 3",
                    description="No interface is designated with 'ip nat inside', preventing NAT from intercepting and translating private IP traffic.",
                    evidence="Inside interfaces: (empty)",
                    recommended_fix=[
                        "interface <lan_interface>",
                        "ip nat inside"
                    ]
                ))

        # NAT Pool IP address conflict
        if '%IP-4-DUPADDR' in text and 'ip nat pool' in text:
            violations.append(RuleViolation(
                rule_id="RULE-NAT-002",
                title="NAT Pool IP Overlaps with Router Physical Interface IP",
                severity="Critical",
                osi_layer="Layer 3",
                description="The dynamic NAT pool includes the router's own interface IP, creating duplicate IP conflicts during address translation.",
                evidence="Duplicate address reported on NAT outside interface with active NAT pool",
                recommended_fix=[
                    "ip nat pool <pool_name> <start_ip_plus_1> <end_ip> netmask <mask_or_prefix>"
                ]
            ))

        return violations

    def check_wireless_isolation(self, text: str, symptom: str) -> List[RuleViolation]:
        violations = []

        if 'Guest' in text and 'management (VLAN 1)' in text:
            violations.append(RuleViolation(
                rule_id="RULE-WIFI-001",
                title="Guest SSID Mapped to Default Corporate VLAN 1",
                severity="Critical",
                osi_layer="Layer 2 / Security",
                description="Guest wireless profile is bridged to the corporate management VLAN instead of an isolated guest dynamic VLAN.",
                evidence="SSID Guest-Public -> Interface: management (VLAN 1)",
                recommended_fix=[
                    "config wlan disable <wlan_id>",
                    "config wlan interface <wlan_id> <Guest_VLAN_Interface>",
                    "config wlan enable <wlan_id>"
                ]
            ))

        return violations


if __name__ == "__main__":
    checker = NetworkRuleChecker()
    sample_text = """
    SW1# show ip interface brief
    GigabitEthernet0/0     unassigned      YES manual administratively down down
    
    SW1# show interfaces trunk
    Port        Mode             Encapsulation  Status        Native vlan
    Gi0/1       on               802.1q         trunking      99
    
    R1# show access-lists 101
    10 permit tcp 172.16.10.0 255.255.255.0 host 10.10.10.80 eq www (0 matches)
    """
    results = checker.run_all_checks(sample_text)
    print(f"Detected {len(results)} deterministic rule violations:")
    for r in results:
        print(f"[{r['rule_id']}] {r['title']} ({r['severity']}) - {r['evidence']}")
