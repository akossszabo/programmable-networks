# Project Implementation Plan: VLAN-Based Isolation Policy

**Author:** Ákos Szabó (OB2N1N)

## 1. Project Objective
This project proposes the design and implementation of a programmable data-plane switch using the **P4 programming language** to enforce inter-VLAN communication policies. The system will programmatically parse `802.1Q` VLAN tags, dynamically manipulate tags (add/remove) at the ingress and egress pipelines, and strictly apply L2-L4 access control policies.

## 2. System Design and Parameters
The project focuses on a targeted, programmatic approach to network segmentation, defined by the following core parameters operating on a BMv2 (Behavioral Model) software switch deployed within a **Kathará** containerized network scenario:

### Network Segmentation (3 VLAN IDs)
* **VLAN 10:** Client/User Segment
* **VLAN 20:** Guest Segment
* **VLAN 30:** Server/Services Segment

### Policy Enforcement (3 Types)
* `ALLOW_ALL`: Unrestricted bidirectional communication between designated VLANs.
* `DENY_ALL`: Explicit drop of cross-VLAN traffic to enforce isolation.
* `ALLOW_L4_PORT`: Conditional access. Specifically, allowing `UDP Port 53` to permit DNS traffic while blocking all other traffic between two otherwise isolated VLANs.

## 3. P4 Data Plane Architecture
The core logic will be implemented entirely within the P4 data plane to maximize packet processing efficiency.

### A. Packet Parsing Logic
A P4 state machine will be developed to sequentially extract network headers:
1. Parse the `Ethernet` header and check the `etherType` for `0x8100` (802.1Q).
2. If present, parse the `802.1Q` header to extract the `vid` (VLAN ID).
3. Parse the `IPv4` header to identify the L4 protocol (e.g., protocol `17` for UDP).
4. Parse the `UDP/TCP` headers to expose the `dst_port` for granular L4 policy matching.

### B. Match-Action Pipeline
The ingress and egress processing blocks will utilize three specific lookup tables:

* **Table 1: Ingress Tagging:** Matches on the physical `ingress_port`. If the traffic is untagged (originating from an access port), the action executes a `push_vlan` to append the appropriate 802.1Q tag.
* **Table 2: Policy Engine:** Matches on `hdr.vlan.vid` (Source VLAN), `hdr.ipv4.protocol`, and `hdr.udp.dst_port`. The action executes either `forward` or `drop` based on the designated policy rule.
* **Table 3: Egress Tagging:** Matches on the `egress_port`. The action executes `pop_vlan` to strip the tag before delivery to an end-host (access port behavior) or leaves the tag intact for switch-to-switch links (trunk port behavior).

## 4. Control Plane Configuration
A Python-based controller utilizing the **P4Runtime API** will be developed to dynamically populate the Match-Action tables on the Kathará switch node. This script will map the container's virtual switch ports to their respective VLAN IDs (10, 20, 30) and apply the exact-match or ternary routing policies to enforce the three required communication rules.

## 5. Evaluation and Validation Strategy
To provide rigorous and programmable validation of the data plane, **Scapy** will be utilized as the primary framework within the Kathará host containers to craft, inject, and sniff custom packets, bypassing the need for complex host-level routing configurations.

* **Test Case 1 (Isolation):** Scapy injects ICMP traffic originating from the VLAN 10 container directed to the VLAN 20 container. 
  * *Expected Result:* Switch drops the packet.
* **Test Case 2 (Conditional L4 Access):** Scapy injects a UDP Port 53 (DNS) packet from VLAN 10 to VLAN 20. 
  * *Expected Result:* Switch successfully forwards the packet to the correct egress port.
* **Test Case 3 (Tag Manipulation):** Scapy injects an untagged packet into Port 1. Scapy sniffs an internal switch trunk link to verify the 802.1Q tag was successfully pushed by the ingress pipeline, and sniffs the final egress access port to verify the tag was successfully popped via the egress pipeline.