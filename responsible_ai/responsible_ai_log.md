# NetSage AI - Responsible AI & Human Oversight Audit Log

## Executive Summary
In mission-critical enterprise and lab networking environments, deploying generative AI without guardrails introduces severe operational and security risks. AI models frequently suffer from **context blindness**, **hallucination of missing commands**, **oversimplified remediation scripts**, and **silent failure modes** when interpreting nuanced Cisco IOS CLI outputs.

NetSage AI enforces a mandatory **Human-in-the-Loop (HITL)** architecture where no AI-generated configuration change can be deployed without explicit human verification, editing, or rejection.

This document analyzes **5 detailed case studies** where initial AI diagnoses were corrected or refined by human network engineers, highlighting failure mechanisms, safety interventions, and lessons learned.

---

## Case Study 1: Incomplete ACL Rule Set & Auxiliary Port Omission
- **Case Reference**: `NET-CASE-005`
- **Component**: Extended Access Control Lists (Layer 4)
- **Initial AI Output**:
  - *Diagnosis*: "Line 10 of ACL 101 uses subnet mask 255.255.255.0 instead of wildcard mask 0.0.0.255."
  - *Proposed Fix*:
    ```cisco
    R1(config)# ip access-list extended 101
    R1(config-ext-nacl)# no 10
    R1(config-ext-nacl)# 10 permit tcp 172.16.10.0 0.0.0.255 host 10.10.10.80 eq 80
    ```
- **Human Review Decision**: **EDITED**
- **Human Reviewer Rationale**:
  While the AI correctly identified the syntax error (inverted wildcard mask), its proposed remediation was overly narrow. In modern enterprise environments, web browsing to internal servers requires both HTTP (port 80) and HTTPS (port 443), as well as DNS resolution (UDP port 53). Applying only port 80 would leave encrypted web traffic and domain lookups broken.
- **Corrected Human Fix**:
  ```cisco
  R1(config)# ip access-list extended 101
  R1(config-ext-nacl)# no 10
  R1(config-ext-nacl)# 10 permit tcp 172.16.10.0 0.0.0.255 host 10.10.10.80 eq 80
  R1(config-ext-nacl)# 15 permit tcp 172.16.10.0 0.0.0.255 host 10.10.10.80 eq 443
  R1(config-ext-nacl)# 20 permit udp 172.16.10.0 0.0.0.255 host 10.10.10.2 eq domain
  R1(config-ext-nacl)# end
  ```
- **Responsible AI Lesson**: AI diagnoses tend to fix only the immediate micro-fault without considering auxiliary protocol dependencies.

---

## Case Study 2: Tactical Quick-Fix vs. Architectural Best Practice in OSPF
- **Case Reference**: `NET-CASE-024`
- **Component**: Dynamic Routing - OSPF Adjacency (Layer 3)
- **Initial AI Output**:
  - *Diagnosis*: "GigabitEthernet0/2 on R1 is configured as passive-interface, suppressing OSPF Hello exchanges with R3."
  - *Proposed Fix*:
    ```cisco
    R1(config)# router ospf 1
    R1(config-router)# no passive-interface GigabitEthernet0/2
    ```
- **Human Review Decision**: **EDITED**
- **Human Reviewer Rationale**:
  The AI's fix solves the immediate adjacency on Gig0/2 but fails enterprise security posture. Best practice in OSPF design is to configure `passive-interface default` (preventing accidental hello leakage and rogue router peering on access ports) and selectively issue `no passive-interface` on trusted backbone links.
- **Corrected Human Fix**:
  ```cisco
  R1(config)# router ospf 1
  R1(config-router)# passive-interface default
  R1(config-router)# no passive-interface GigabitEthernet0/1
  R1(config-router)# no passive-interface GigabitEthernet0/2
  R1(config-router)# end
  R1# write memory
  ```
- **Responsible AI Lesson**: LLMs prioritize minimal edits over defense-in-depth architectural standards.

---

## Case Study 3: Hallucinated Route Failure on DHCP Snooping Drop
- **Case Reference**: `NET-CASE-012`
- **Component**: Layer 2 Security - DHCP Snooping
- **Initial AI Output**:
  - *Diagnosis*: "Client PC-1 cannot reach DHCP server due to a missing IP route or IP helper-address between VLANs."
  - *Proposed Fix*: Add `ip helper-address 192.168.1.1` under interface.
- **Human Review Decision**: **REJECTED**
- **Human Reviewer Rationale**:
  The AI hallucinated a Layer 3 routing fault because clients received APIPA addresses. However, examining `show ip dhcp snooping statistics` clearly showed `Packets Dropped = 48, Reason: DHCP offer received on untrusted port GigabitEthernet0/24`. The DHCP server was in the same broadcast domain; adding a helper address would be redundant and ineffective.
- **Corrected Human Fix**:
  ```cisco
  SW-1(config)# interface GigabitEthernet0/24
  SW-1(config-if)# ip dhcp snooping trust
  SW-1(config-if)# end
  ```
- **Responsible AI Lesson**: AI models exhibit confirmation bias toward common textbook faults (e.g. `ip helper-address`) and overlook specialized security feature counters.

---

## Case Study 4: Overlooking Duplicate IP Conflict in NAT Overload Pool
- **Case Reference**: `NET-CASE-026`
- **Component**: Address Translation - NAT Overload Pool (Layer 3)
- **Initial AI Output**:
  - *Diagnosis*: "ISP upstream interface is dropping packets due to MTU blackhole or missing default route."
  - *Proposed Fix*: Configure `ip route 0.0.0.0 0.0.0.0 203.0.113.1`.
- **Human Review Decision**: **REJECTED**
- **Human Reviewer Rationale**:
  The console log clearly reported `%IP-4-DUPADDR: Duplicate address 203.0.113.1 on GigabitEthernet0/1`. The dynamic NAT pool `PUBLIC_POOL` was configured starting at `203.0.113.1`, which was already assigned to the router's physical WAN interface. The AI completely missed the `%IP-4-DUPADDR` syslog entry.
- **Corrected Human Fix**:
  ```cisco
  R-NAT(config)# no ip nat pool PUBLIC_POOL 203.0.113.1 203.0.113.6 netmask 255.255.255.248
  R-NAT(config)# ip nat pool PUBLIC_POOL 203.0.113.2 203.0.113.6 netmask 255.255.255.248
  R-NAT(config)# end
  ```
- **Responsible AI Lesson**: Multi-line CLI output contains subtle syslog alerts that standard prompt contexts can easily skim past without deterministic regex checking.

---

## Case Study 5: False Attribution to Host Firewall on Wireless Guest Leaking
- **Case Reference**: `NET-CASE-030`
- **Component**: Wireless LAN Controller (WLC) & Segmentation Security
- **Initial AI Output**:
  - *Diagnosis*: "Core switch firewall rules are missing; guest host operating system firewall is allowing inbound ping."
  - *Proposed Fix*: Enable Windows Defender Firewall on financial server.
- **Human Review Decision**: **REJECTED**
- **Human Reviewer Rationale**:
  The AI treated this as an endpoint security issue rather than a critical network segmentation flaw. The WLC CLI showed `SSID Guest-Public -> Interface: management (VLAN 1)`. Guest wireless devices were receiving management IP addresses and bypassing all perimeter security.
- **Corrected Human Fix**:
  ```cisco
  WLC(config)# config wlan disable 2
  WLC(config)# config wlan interface 2 Guest_Interface_VLAN90
  WLC(config)# config wlan enable 2
  ```
- **Responsible AI Lesson**: AI systems must not shift network architectural misconfigurations onto end-user client devices.

---

## Summary of Human Oversight Metrics
| Metric | Value | Meaning |
| :--- | :--- | :--- |
| **Total Test Cases Evaluated** | 32 | Comprehensive lab scenario coverage |
| **AI Diagnoses Fully Accepted** | 27 (84.4%) | Correct root cause, evidence, and remediation |
| **AI Diagnoses Edited by Reviewer** | 2 (6.2%) | Accurate root cause, expanded/hardened fix |
| **AI Diagnoses Rejected by Reviewer** | 3 (9.4%) | Hallucinated root cause or missed critical syslog |
| **Overall Safe Operation Rate** | **100%** | Zero erroneous commands deployed to production |
