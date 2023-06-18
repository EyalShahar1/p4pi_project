/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
//NAAMA TODO: maybe not needed
typedef bit<16> mcastGrp_t;

//NAAMA TODO: is this used?
const macAddr_t BROADCAST_ADDR  = 0xffffffffffff;
//NAAMA TODO: maybe not needed
const mcastGrp_t BROADCAST_MGID = 0x0001;

//NAAMA TODO: is this used?
const ip4Addr_t ALLSPFROUTERS_ADDR = 0xe0000005;

const port_t CPU_PORT           = 0x1;
//NAAMA TODO: is this used?
const bit<8> OSPF_PROT          = 89;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_IPV4         = 0x0800;
//const bit<16> TYPE_IPV6         = 0x86dd;
const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;

//NAAMA TODO: maybe not needed
const bit<4>  MAX_LSU_ADS_NUM   = 10;

const bit<16> ARP_REPLY = 2;


/*****     HEADERS     *****/

// standard Ethernet header
header ethernet_t {
    macAddr_t dst_addr;
    macAddr_t src_addr;
    bit<16>   ether_type;
}

//NAAMA TODO: might be missing some data and might not need src_addr, tbd
// CPU header
header cpu_metadata_t {
    macAddr_t   src_addr;
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
    ip4Addr_t src_addr;
    ip4Addr_t dst_addr;
}

// PWOSPF header - NAAMA TODO - maybe not needed
header pwospf_t {
    bit<8>      version;
    bit<8>      type;
    bit<16>     pkt_len;
    bit<32>     router_id;
    bit<32>     area_id;
    bit<16>     checksum;
    bit<16>     auth_type;
    bit<64>     auth;
}

// Packet headers
struct headers {
    ethernet_t          ethernet;
    cpu_metadata_t      cpu_metadata;
    arp_t               arp;
    ipv4_t              ipv4;          
}

// HELLO metadata - NAAMA TODO - maybe not needed
struct hello_metadata_t {
    bit<32>     network_mask;
    bit<16>     hello_int;
    bit<16>     padding;
}

// LSU ads - NAAMA TODO - maybe not needed
struct lsu_ad_t {
    bit<32>     subnet;
    bit<32>     mask;
    bit<32>     router_id;
}

// LSU metadata - NAAMA TODO - maybe not needed
struct lsu_metadata_t {
    bit<16>     seq_num;
    bit<16>     TTL;
    bit<32>     num_of_ads;
    lsu_ad_t[MAX_LSU_ADS_NUM] lsu_ads;
}

// PWOSPF metadata - NAAMA TODO - maybe not needed
struct pwospf_metadata_t {
    hello_metadata_t    hello_metadata;
    lsu_metadata_t      lsu_metadata;
}

// metadata struct - NAAMA TODO - maybe not needed
struct metadata {
    pwospf_metadata_t   pwospf_metadata;
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
            TYPE_ARP:           pase_arp;
            TYPE_CPU_METADATA:  parse_cpu;
            default:            reject;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_cpu {
        packet.extract(hdr.cpu_metadata);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(
            // Only perform checksum on ipv4 packets
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.DSCP,
            hdr.ipv4.ECN,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.prot,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
        }      
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    //NAAMA TODO - is this action used?
    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }

    action ipv4_forward(macAddr_t dst_addr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dst_addr = dst_addr;
    }

    //NAAMA TODO - is this needed?
    action no_action() {}

    action arp_reply(macAddr_t request_mac) {
        // Update operation code from request to reply
        hdr.arp.op_code = ARP_REPLY;
        
        //reply's dst_mac is the request's src mac
        hdr.arp.dst_mac = hdr.arp.src_mac;
        
        //reply's dst_ip is the request's src ip
        hdr.arp.src_mac = request_mac;

        //reply's src ip is the request's dst ip
        hdr.arp.src_ip = hdr.arp.dst_ip;

        //update ethernet header
        hdr.ethernet.dst_addr = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = request_mac;

        //send it back to the same port
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
  
    // arp table for exact ip address match - is this supposed to be a table?
    table arp_exact {
        key = {hdr.arp.dst_ip: exact; }

        actions = {
            arp_reply;
            drop;
        }
        size = 256; //can be changed but for now it's fine
        default_action = drop();
    }

    table routing_table {
        key = {hdr.ethernet.dst_ip: lpm; }

        actions = {
            ipv4_forward;
            arp_request;
        }
        size = 256;
        default_action = arp_request();
    }

    // table ip_protocol_exact {
    //     key = {hdr.ip.protocol: exact; }

    //     actions = {
    //         ospf_cpu;
    //         // can add more actions for more protocols
    //         drop;
    //     }

    //     size = 256;
    //     default_action = drop();
    // }

    apply {
        if (!hdr.ethernet.isValid()) {
            drop();
        }
        if (hdr.arp.isValid()) {
            
        }
        if (hdr.ethernet.isValid() && hdr.ipv4.isValid()) {
            ip_protocol_exact.apply();
        }
        standard_metadata.egress_spec = standard_metadata.ingress_port
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
            //first check if it is an ipv4 packet and check sum based on it's structure
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.DSCP,
            hdr.ipv4.ECN,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.prot,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);    
        // can add more cases if we'll have more packets type with check sum
        }            
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        switch (hdr.ethernet.etherType) {
            TYPE_IPV4:          { packet.emit(hdr.ipv4); }
            TYPE_ARP:           { packet.emit(hdr.arp); }
            TYPE_CPU_METADATA:  { packet.emit(hdr.cpu_metadata); }
            default:            { }
        }
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
