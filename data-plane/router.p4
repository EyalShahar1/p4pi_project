/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;
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

// standard Ethernet header
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

//Header for information sent to the CPU
header cpu_metadata_t {
 
 //TODO: Construct the header with the information to send to the CPU
 //This header should be added to all packets sent to the control plane
 
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

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t            ipv4;
    //TODO: add all other supported headers
}

struct metadata { }

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        // TODO: Parse all the headers supported by the project
        transition accept;
        }
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
