/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
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
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct Metadata {
    bit<16> global_offset;
    bit<16> local_length;
    bit<16> local_offset;
    bit<16> final_offset;
    bit<32> masked_dst_ip;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout Metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.masked_dst_ip = hdr.ipv4.dstAddr & 0x000000ff;
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout Metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout Metadata metadata,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_local_offset(){
        bit<16> base = 0;
        /*
        hash(metadata.local_offset,
	    HashAlgorithm.crc16,
        base,
	    { hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
              hdr.ipv4.protocol,
              hdr.tcp.srcPort,
              hdr.tcp.dstPort },
        metadata.local_length
              );
        */ 
        hash(metadata.local_offset,
	    HashAlgorithm.crc16,
        base,
	    { 
            hdr.tcp.srcPort
           },
        metadata.local_length
              );
    }

    action set_sub_table_offset(bit<16> offset){
        metadata.global_offset = offset;
    }
     
    action set_sub_table_size(bit<16> len){
        metadata.local_length = len;
    }   

    action set_nhop(bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action cal_final_offset(){
        metadata.final_offset = metadata.global_offset + metadata.local_offset;
    }

    table routing_table {
        key = {
            metadata.final_offset: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 1024;
    }

    table sub_table_size{
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_sub_table_size;
        }
    }
    table sub_table_offset{
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_sub_table_offset;
        }
        size = 1024;
    }

    table post_fix_table{
        key = {
            metadata.masked_dst_ip: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            sub_table_size.apply();
            sub_table_offset.apply();
            set_local_offset();
            cal_final_offset();
            if(routing_table.apply().hit){}
            else{
                post_fix_table.apply();
            } 
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout Metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout Metadata meta) {
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
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
