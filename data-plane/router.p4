/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
//TODO: do we need this? are we supporting IPv6?
typedef bit<128> ip6Addr_t;
//TODO: same - is this needed?
typedef bit<16> mcastGrp_t;

const macAddr_t BROADCAST_ADDR  = 0xffffffffffff;
const mcastGrp_t BROADCAST_MGID = 0x0001;

const ip4Addr_t ALLSPFROUTERS_ADDR = 0xe0000005;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_IPV4         = 0x0800;
const bit<16> TYPE_IPV6         = 0x86dd;
const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;

const bit<4>  MAX_LSU_ADS_NUM   = 10;

// standard Ethernet header
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

//TODO: is this enough data? am I missing something? what I added - info to update forwarding table
//Header for information sent to the CPU
header cpu_metadata_t {
    macAddr_t   src_addr;
    port_t      ingress_port;
}

//TODO: define all other headers required by the router.
header arp_t {
  bit<16>   h_type;
  bit<16>   p_type;
  bit<8>    h_len;
  bit<8>    p_len;
  bit<16>   op_code;
  macAddr_t src_mac;
  ip4Addr_t src_ip;
  macAddr_t dst_mac;
  ip4Addr_t dst_ip;
  }

header ipv4_t {
    bit<8>    versionihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header pwospf_t {
    bit<8>      version;
    bit<8>      type;
    bit<16>     pkt_len;
    bit<32>     router_id;
    bit<32>     area_id;
    bit<16>     checksum;
    bit<16>     au_type;
    bit<64>     auth;
}

struct headers {
    ethernet_t          ethernet;
    //TODO: is this needed?
    cpu_metadata_t      cpu_metadata;
    arp_t               arp;
    ipv4_t              ipv4;          
}

struct hello_metadata_t {
    bit<32>     network_mask;
    bit<16>     hello_int;
    bit<16>     padding;
}

struct lsu_ad_t {
    bit<32>     subnet;
    bit<32>     mask;
    bit<32>     router_id;
}

struct lsu_metadata_t {
    bit<16>     seq_num;
    bit<16>     TTL;
    bit<32>     num_of_ads;
    lsu_ad_t[MAX_LSU_ADS_NUM] lsu_ads;
}

struct pwospf_metadata_t {
    hello_metadata_t    hello_metadata;
    lsu_metadata_t      lsu_metadata;
}

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
            TYPE_IPV6:          accept;
            //TODO: should this be accept?
            default:            reject;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    //TODO: does this type have an ip header?
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_cpu {
        //TODO: not sure what to do here
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(
            //first check if it is an ipv4 packet and check sum based on it's structure
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);    
        // can add more cases if we'll have more packets type with check sum
        }      
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action send_to_cpu() {
      //TODO: What should you do here?
    }

    action arp_reply(macAddr_t request_mac) {
        //now creating an arp reply
        //update operation code from request to reply
        hdr.arp.op_code = ARP_REPLY;
        
        //reply's dst_mac is the request's src mac
        hdr.arp.dst_mac = hdr.arp.src_mac;
        
        //reply's dst_ip is the request's src ip
        hdr.arp.src_mac = request_mac;

        //reply's src ip is the request's dst ip
        hdr.arp.src_ip = hdr.arp.dst_ip;

        //update ethernet header
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = request_mac;

        //send it back to the same port
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
  
//TODO: Add all tables and actions
    // arp table for exact ip address match
    table arp_exact {
        key = {hdr.arp.dst_ip: exact; }

        actions = {
            arp_reply;
            drop;
        }
        size = 256; //can be changed but for now it's fine
        default_action = drop();
    }


    apply {
        //TODO: Add your control flow
        //The following is a dummy code that will return the packet "as is" to the source
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
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);    
        // can add more cases if we'll have more packets type with check sum
        }            
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
       //TODO: Add all other headers
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
