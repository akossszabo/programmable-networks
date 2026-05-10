/* shared/vlan_policy.p4 */

#include <core.p4>
#include <v1model.p4>

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header vlan_t {
    bit<3>  pcp;
    bit<1>  cfi;
    bit<12> vid;       // VLAN ID
    bit<16> etherType; // Inner type
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;  // 17 for UDP
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;   // 53 for DNS
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {}

struct headers {
    ethernet_t ethernet;
    vlan_t     vlan;
    ipv4_t     ipv4;
    udp_t      udp;
}

parser MyParser(packet_in packet, 
                out headers hdr, 
                inout metadata meta, 
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x8100: parse_vlan; // Has 802.1Q Tag
            0x0800: parse_ipv4; // Untagged IPv4
            default: accept;
        }
    }

    state parse_vlan {
        packet.extract(hdr.vlan);
        transition select(hdr.vlan.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

// Dummy blocks to satisfy the compiler for now
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}
/* =========================================================================
 * 3. INGRESS PIPELINE (Tagging & Policy Engine)
 * ========================================================================= */
control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    
    // --- ACTIONS ---
    
    action push_vlan(bit<12> vid) {
        hdr.vlan.setValid();
        hdr.vlan.vid = vid;
        hdr.vlan.pcp = 0;
        hdr.vlan.cfi = 0;
        // Shift the original etherType (e.g., IPv4) into the VLAN header
        hdr.vlan.etherType = hdr.ethernet.etherType;
        // Set the main Ethernet header to show a VLAN tag follows (0x8100)
        hdr.ethernet.etherType = 0x8100;
    }

    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        // Decrease TTL since we are routing between different subnets/VLANs
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1; 
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    // --- TABLES ---

    // Table 1: Ingress Tagging
    table ingress_port_mapping {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            push_vlan;
            NoAction;
        }
        size = 256;
    }

    // Table 2: Policy Engine & Routing
    table policy_forwarding {
        key = {
            hdr.vlan.vid      : exact;    // Source VLAN ID
            hdr.ipv4.dstAddr  : lpm;      // Destination IP (Routing)
            hdr.ipv4.protocol : ternary;  // L4 Protocol (e.g., 17 for UDP)
            hdr.udp.dstPort   : ternary;  // L4 Port (e.g., 53 for DNS)
        }
        actions = {
            forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop; // Default security posture: drop everything
    }

    // --- PIPELINE LOGIC ---
    
    apply {
        // We only process IPv4 packets for this project
        if (hdr.ipv4.isValid()) {
            
            // 1. Tag the packet if it came from an untagged access port
            if (!hdr.vlan.isValid()) {
                ingress_port_mapping.apply();
            }
            
            // 2. Check the policy rules and route the packet
            policy_forwarding.apply();
        }
    }
}

/* =========================================================================
 * 4. EGRESS PIPELINE (Tag Stripping)
 * ========================================================================= */
control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    
    // --- ACTIONS ---
    
    action pop_vlan() {
        // Restore the inner etherType (IPv4) back to the main Ethernet header
        hdr.ethernet.etherType = hdr.vlan.etherType;
        // Remove the VLAN header entirely
        hdr.vlan.setInvalid();
    }

    // --- TABLES ---

    // Table 3: Egress Tagging
    table egress_port_mapping {
        key = {
            standard_metadata.egress_port : exact;
        }
        actions = {
            pop_vlan;
            NoAction;
        }
        size = 256;
    }

    // --- PIPELINE LOGIC ---

    apply {
        // If the packet has a VLAN tag, check if we need to strip it for the host
        if (hdr.vlan.isValid()) {
            egress_port_mapping.apply();
        }
    }
}
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;