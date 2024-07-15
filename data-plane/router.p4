/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const macAddr_t BROADCAST_ADDR  = 0xffffffffffff;
const ip4Addr_t ALLSPFROUTERS_ADDR = 0xe0000005;

const port_t CPU_PORT           = 2;
const bit<8> PROTO_OSPF          = 89;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_IPV4         = 0x0800;
const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;

const bit<16> MULTICAST_GRP = 1;

/*****     HEADERS     *****/

// standard Ethernet header
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// TODO - might be missing some data
// CPU header
header cpu_t {
    bit<16>     etherType;
    bit<7>      padding;
    port_t      ingress_port;
}

// ARP header
header arp_t {
  bit<16>   hw_type;
  bit<16>   prot_type;
  bit<8>    hw_len;
  bit<8>    prot_len;
  bit<16>   op_code;
  macAddr_t src_mac;
  ip4Addr_t src_ip;
  macAddr_t dst_mac;
  ip4Addr_t dst_ip;
}

// IPV4 header
header ipv4_t {
    bit<4>    version;
    bit<4>    IHL;
    bit<6>    DSCP;
    bit<2>    ECN;
    bit<16>   total_len;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   frag_offset;
    bit<8>    ttl;
    bit<8>    prot;
    bit<16>   hdr_checksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ospf_t {
    bit<8> version;
    bit<8> type;
    bit<16> length;
    ip4Addr_t router_id;
    ip4Addr_t area_id;
    bit<16> checksum;
    bit<16> auth_type;
    bit<64> auth;
}
// Packet headers
struct headers {
    ethernet_t          ethernet;
    cpu_t               cpu;
    arp_t               arp;
    ipv4_t              ipv4;
    ospf_t              ospf;
}

struct metadata {
    ip4Addr_t next_hop_ip_add;
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
            TYPE_IPV4:          parse_ipv4;
            TYPE_ARP:           parse_arp;
            TYPE_CPU_METADATA:  parse_cpu;
            default:            accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.prot) {
            PROTO_OSPF:         parse_ospf;
            default:            accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ospf {
        packet.extract(hdr.ospf);
        transition accept;
    }


    state parse_cpu {
        packet.extract(hdr.cpu);
        transition parse_ipv4;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(
            // Only perform checksum on ipv4 packets
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
            hdr.ipv4.IHL,
            hdr.ipv4.DSCP,
            hdr.ipv4.ECN,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.prot,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
        }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /*****     ACTIONS     *****/

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
        hdr.cpu.setValid();
        hdr.cpu.etherType = hdr.ethernet.etherType;
        hdr.cpu.ingress_port = standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
        meta.next_hop_ip_add = hdr.ipv4.dstAddr;
    }

    action flood() {
        standard_metadata.mcast_grp = MULTICAST_GRP;
        hdr.ethernet.etherType = hdr.cpu.etherType;
        meta.next_hop_ip_add = hdr.ipv4.dstAddr;
    }

    // this action changes our next hop based on the data from the routing table
    // the next hop address will determine the destination MAC address
    action ipv4_forward(ip4Addr_t next_hop, port_t port) {
        standard_metadata.egress_spec = port;
        meta.next_hop_ip_add = next_hop;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /*****     TABLES     *****/

    // Destination IP address -> next hop IP address, output port
    table routing_table {
        key = {hdr.ipv4.dstAddr: lpm; }

        actions = {
            ipv4_forward;
            flood;
            drop;
        }
        size = 256;
        default_action = drop;
    }


    /*****     APPLY     *****/

    apply {
        // Invalid packets
        if (!hdr.ethernet.isValid() || !hdr.ipv4.isValid()) {
            drop(); // makrked the packet to be dropped
            return;
        }
        if (hdr.cpu.isValid()) {
            flood();
            hdr.cpu.setInvalid();
            return;
        }
        if (hdr.ethernet.etherType == TYPE_ARP || hdr.ipv4.prot == PROTO_OSPF) {
            // Incoming OSPF and ARP packets are always sent to CPU
            send_to_cpu();
            return; // wont go to routing table
        }
        // If packet is not from CPU and not ARP/OSPF - apply routing
        routing_table.apply();
        // might need to apply arp table if arp
        // arp_table.apply();
    }
}

// Egress control used to determine the output port and mac address
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action set_dst_and_src_mac(macAddr_t dst_mac) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dst_mac;
    }

    action generate_arp_req() {
        standard_metadata.egress_spec = CPU_PORT;
    }

    action no_action() {}
    // this table entries may be populated using arp protocol implementation
    table forwarding_table {
        key = {meta.next_hop_ip_add: exact; }

        actions = {
            set_dst_and_src_mac;
            generate_arp_req;
            no_action;
        }
        size = 256;
        default_action = generate_arp_req();
    }
    apply {
        forwarding_table.apply();
     }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
            //first check if it is an ipv4 packet and check sum based on it's structure
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
            hdr.ipv4.IHL,
            hdr.ipv4.DSCP,
            hdr.ipv4.ECN,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.prot,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
        // can add more cases if we'll have more packets type with check sum
        }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ospf);
    }
    // apply {
    //     packet.emit(hdr.ethernet);
    //     if (hdr.arp.isValid()) {
    //         packet.emit(hdr.arp);
    //         return;
    //     }

    //     if (hdr.ipv4.isValid()) {
    //         packet.emit(hdr.ipv4);
    //         if (hdr.ospf.isValid()) {
    //             packet.emit(hdr.ospf);
    //         }
    //     }
    //     return;

        // packet.emit(hdr.ethernet);
        // switch (hdr.ethernet.etherType) {
        //     TYPE_IPV4:          { packet.emit(hdr.ipv4); }
        //     TYPE_ARP:           { packet.emit(hdr.arp); }
        //     TYPE_CPU_METADATA:  { packet.emit(hdr.cpu); }
        //     default:            { }
        // }
    //}
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
