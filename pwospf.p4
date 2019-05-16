/* Camillo Malnati, 16.03.2019 */
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
const bit<16> TYPE_CPU_METADATA = 0x080a;


const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  IP_PROT_UDP  = 0x11;
const bit<8>  IP_PROT_OSPF = 0x59;
const bit<16> UDP_PORT     = 1234;

const bit<16> IP_RES_LENGTH = 34;

const bit<16> AUTYPE = 0;
const bit<64> AUTENTICATION = 0;

const bit<8>  PWSPF_VERSION = 2;
const bit<16> HELLO_LENGTH = 32;
const bit<16> LSUPDATE_LENGTH = 36;
const bit<8>  HELLO_TYPE = 1;
const bit<8>  LSUPDATE_TYPE = 4;

const port_t CPU_PORT           = 0x1;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8> fromCPU;
    bit<16> origEtherType;
    bit<16> srcPort;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
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

header udp_t {
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<16>   length_;
    bit<16>   checksum;
}

header ospf_t {
    bit<8>      version;
    bit<8>      type;
    bit<16>     packet_length;
    bit<32>     router_ID;
    bit<32>     area_ID;
    bit<16>     checksum;
    bit<16>     autype;
    bit<64>     autentication;
}

header hello_t {
    bit<32>     network_mask;
    bit<16>     hello_int;
    bit<16>     padding;
}

header lsupdate_t {
    bit<8>      version;
    bit<8>      type;
    bit<16>     packet_length;
    bit<32>     router_ID;
    bit<32>     area_ID;
    bit<16>     checksum;
    bit<16>     autype;
    bit<64>     autentication;
    bit<16>     sequence;
    bit<16>     ttl;
    bit<32>     adv_number;
    bit<32>     adv;
}

struct metadata { }

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    cpu_metadata_t cpu_metadata;
    udp_t        udp;
    ospf_t       ospf_header;
    hello_t      ospf_hello;
    lsupdate_t   ospf_update;
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
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            default: accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            IP_PROT_UDP: parse_udp;
            IP_PROT_OSPF: parse_ospf;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_ospf {
        packet.extract(hdr.ospf_header);
        transition select(hdr.ospf_header.type){
            HELLO_TYPE: parse_hello;
            LSUPDATE_TYPE: parse_update;
            default: accept;
        }
    }

    state parse_hello {
        packet.extract(hdr.ospf_hello);
        transition accept;
    }

    state parse_update {
        packet.extract(hdr.ospf_update);
        transition accept;
    }

}


control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr; // is this correct?
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

     action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
}

    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
    }

    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            set_mgid;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {

        if (standard_metadata.ingress_port == CPU_PORT){
            cpu_meta_decap();
            ipv4_lpm.apply();
        } 
        else if (hdr.ospf_header.isValid() && standard_metadata.ingress_port != CPU_PORT) {
            send_to_cpu();
        }
        else if (hdr.ethernet.isValid()){
            ipv4_lpm.apply();
        }

    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action rewrite_dst(macAddr_t mac, ip4Addr_t ip) {
        hdr.ethernet.dstAddr = mac;
        hdr.ipv4.dstAddr = ip;
    }
    action drop() {
        mark_to_drop();
    }
    table send_frame {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            rewrite_dst;
            drop;
            NoAction;
        }
        size = 256;
        default_action = NoAction();
    }
    apply {
        if (hdr.ipv4.isValid()) {
          send_frame.apply();
        }
    }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
                { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr },
                hdr.ipv4.hdrChecksum,
                HashAlgorithm.csum16); 
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.ospf_header);
        packet.emit(hdr.ospf_hello);
        packet.emit(hdr.ospf_update);
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
