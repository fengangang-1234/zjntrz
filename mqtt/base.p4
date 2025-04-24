// ------------------------------------------------------tocken_conf---------------------
// Include Files
// ---------------------------------------------------------------------------

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"

// ---------------------------------------------------------------------------
// Data Struction
// ---------------------------------------------------------------------------

struct metadata_t {
    bit<16> total_len;
    bit<8> tcp_flags;

    bit<16> ipv4_header_offset;
    bit<16> tcp_header_offset;
    bit<4> mqtt_type;
    bit<1> blacklist_in;


    bit<32> timestamp_32;
    bit<16> timestamp_16;

    bit<1> access_flag;
}

struct digesta_t {
    ipv4_addr_t src_addr;
    bit<16> src_port;
    bit<8> ttl;
}

struct digestb_t {
    ipv4_addr_t dst_addr;
    bit<16> dst_port;
}

struct digestc_t {
    ipv4_addr_t src_addr;
    bit<16> src_port;
    bit<8> ttl;
}

struct digestd_t {
    ipv4_addr_t src_addr;
    bit<16> src_port;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl) {
            5: parse_ipv4_ihl_5;
            6: parse_ipv4_ihl_6;
            7: parse_ipv4_ihl_7;
            8: parse_ipv4_ihl_8;
            9: parse_ipv4_ihl_9;
            10: parse_ipv4_ihl_10;
            11: parse_ipv4_ihl_11;
            12: parse_ipv4_ihl_12;
            13: parse_ipv4_ihl_13;
            14: parse_ipv4_ihl_14;
            15: parse_ipv4_ihl_15;
            default: accept;
        }
    }

    state parse_ipv4_ihl_5 {
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_ipv4_ihl_6 {
        pkt.extract(hdr.ipv4_option6);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_ipv4_ihl_7 {
        pkt.extract(hdr.ipv4_option6);
        pkt.extract(hdr.ipv4_option7);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_ipv4_ihl_8 {
        pkt.extract(hdr.ipv4_option6);
        pkt.extract(hdr.ipv4_option7);
        pkt.extract(hdr.ipv4_option8);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_ipv4_ihl_9 {
        pkt.extract(hdr.ipv4_option6);
        pkt.extract(hdr.ipv4_option7);
        pkt.extract(hdr.ipv4_option8);
        pkt.extract(hdr.ipv4_option9);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_ipv4_ihl_10 {
        pkt.extract(hdr.ipv4_option6);
        pkt.extract(hdr.ipv4_option7);
        pkt.extract(hdr.ipv4_option8);
        pkt.extract(hdr.ipv4_option9);
        pkt.extract(hdr.ipv4_option10);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_ipv4_ihl_11 {
        pkt.extract(hdr.ipv4_option6);
        pkt.extract(hdr.ipv4_option7);
        pkt.extract(hdr.ipv4_option8);
        pkt.extract(hdr.ipv4_option9);
        pkt.extract(hdr.ipv4_option10);
        pkt.extract(hdr.ipv4_option11);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_ipv4_ihl_12 {
        pkt.extract(hdr.ipv4_option6);
        pkt.extract(hdr.ipv4_option7);
        pkt.extract(hdr.ipv4_option8);
        pkt.extract(hdr.ipv4_option9);
        pkt.extract(hdr.ipv4_option10);
        pkt.extract(hdr.ipv4_option11);
        pkt.extract(hdr.ipv4_option12);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_ipv4_ihl_13 {
        pkt.extract(hdr.ipv4_option6);
        pkt.extract(hdr.ipv4_option7);
        pkt.extract(hdr.ipv4_option8);
        pkt.extract(hdr.ipv4_option9);
        pkt.extract(hdr.ipv4_option10);
        pkt.extract(hdr.ipv4_option11);
        pkt.extract(hdr.ipv4_option12);
        pkt.extract(hdr.ipv4_option13);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_ipv4_ihl_14 {
        pkt.extract(hdr.ipv4_option6);
        pkt.extract(hdr.ipv4_option7);
        pkt.extract(hdr.ipv4_option8);
        pkt.extract(hdr.ipv4_option9);
        pkt.extract(hdr.ipv4_option10);
        pkt.extract(hdr.ipv4_option11);
        pkt.extract(hdr.ipv4_option12);
        pkt.extract(hdr.ipv4_option13);
        pkt.extract(hdr.ipv4_option14);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_ipv4_ihl_15 {
        pkt.extract(hdr.ipv4_option6);
        pkt.extract(hdr.ipv4_option7);
        pkt.extract(hdr.ipv4_option8);
        pkt.extract(hdr.ipv4_option9);
        pkt.extract(hdr.ipv4_option10);
        pkt.extract(hdr.ipv4_option11);
        pkt.extract(hdr.ipv4_option12);
        pkt.extract(hdr.ipv4_option13);
        pkt.extract(hdr.ipv4_option14);
        pkt.extract(hdr.ipv4_option15);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition check_mqtt_port;
    }

    state check_mqtt_port {
        transition select( hdr.tcp.src_port, hdr.tcp.dst_port) {
            (MQTT_PORT,_) : parse_tcp_options; 
            (_,MQTT_PORT) : parse_tcp_options;  
            default: accept;
        }
    }

    state parse_tcp_options {
        transition select(hdr.tcp.data_offset) {
            5: parse_tcp_offset_5;
            6: parse_tcp_offset_6;
            7: parse_tcp_offset_7;
            8: parse_tcp_offset_8;
            9: parse_tcp_offset_9;
            10: parse_tcp_offset_10;
            11: parse_tcp_offset_11;
            12: parse_tcp_offset_12;
            13: parse_tcp_offset_13;
            14: parse_tcp_offset_14;
            15: parse_tcp_offset_15;
            default: accept;
        }
    }

    state parse_tcp_offset_5 {
        transition parse_mqtt_static_header;
    }

    state parse_tcp_offset_6 {
        pkt.extract(hdr.tcp_option6);
        transition parse_mqtt_static_header;
    }

    state parse_tcp_offset_7 {
        pkt.extract(hdr.tcp_option6);
        pkt.extract(hdr.tcp_option7);
        transition parse_mqtt_static_header;
    }

    state parse_tcp_offset_8 {
        pkt.extract(hdr.tcp_option6);
        pkt.extract(hdr.tcp_option7);
        pkt.extract(hdr.tcp_option8);
        transition parse_mqtt_static_header;
    }

    state parse_tcp_offset_9 {
        pkt.extract(hdr.tcp_option6);
        pkt.extract(hdr.tcp_option7);
        pkt.extract(hdr.tcp_option8);
        pkt.extract(hdr.tcp_option9);
        transition parse_mqtt_static_header;
    }

    state parse_tcp_offset_10 {
        pkt.extract(hdr.tcp_option6);
        pkt.extract(hdr.tcp_option7);
        pkt.extract(hdr.tcp_option8);
        pkt.extract(hdr.tcp_option9);
        pkt.extract(hdr.tcp_option10);
        transition parse_mqtt_static_header;
    }

    state parse_tcp_offset_11 {
        pkt.extract(hdr.tcp_option6);
        pkt.extract(hdr.tcp_option7);
        pkt.extract(hdr.tcp_option8);
        pkt.extract(hdr.tcp_option9);
        pkt.extract(hdr.tcp_option10);
        pkt.extract(hdr.tcp_option11);
        transition parse_mqtt_static_header;
    }

    state parse_tcp_offset_12 {
        pkt.extract(hdr.tcp_option6);
        pkt.extract(hdr.tcp_option7);
        pkt.extract(hdr.tcp_option8);
        pkt.extract(hdr.tcp_option9);
        pkt.extract(hdr.tcp_option10);
        pkt.extract(hdr.tcp_option11);
        pkt.extract(hdr.tcp_option12);
        transition parse_mqtt_static_header;
    }

    state parse_tcp_offset_13 {
        pkt.extract(hdr.tcp_option6);
        pkt.extract(hdr.tcp_option7);
        pkt.extract(hdr.tcp_option8);
        pkt.extract(hdr.tcp_option9);
        pkt.extract(hdr.tcp_option10);
        pkt.extract(hdr.tcp_option11);
        pkt.extract(hdr.tcp_option12);
        pkt.extract(hdr.tcp_option13);
        transition parse_mqtt_static_header;
    }

    state parse_tcp_offset_14 {
        pkt.extract(hdr.tcp_option6);
        pkt.extract(hdr.tcp_option7);
        pkt.extract(hdr.tcp_option8);
        pkt.extract(hdr.tcp_option9);
        pkt.extract(hdr.tcp_option10);
        pkt.extract(hdr.tcp_option11);
        pkt.extract(hdr.tcp_option12);
        pkt.extract(hdr.tcp_option13);
        pkt.extract(hdr.tcp_option14);
        transition parse_mqtt_static_header;
    }

    state parse_tcp_offset_15 {
        pkt.extract(hdr.tcp_option6);
        pkt.extract(hdr.tcp_option7);
        pkt.extract(hdr.tcp_option8);
        pkt.extract(hdr.tcp_option9);
        pkt.extract(hdr.tcp_option10);
        pkt.extract(hdr.tcp_option11);
        pkt.extract(hdr.tcp_option12);
        pkt.extract(hdr.tcp_option13);
        pkt.extract(hdr.tcp_option14);
        pkt.extract(hdr.tcp_option15);
        transition parse_mqtt_static_header;
    }

    state parse_mqtt_static_header {
        pkt.extract(hdr.mqtt);  
        transition select(hdr.mqtt.packet_type) {
            MQTT_CONNACK: parse_mqtt_connack;  
            default: accept;
        }
    }   

    state parse_mqtt_connack {
        pkt.extract(hdr.mqtt_ack);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

// ---------------------------------------------------------------------------
// Ingress
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {


    action get_phv_value(){
        ig_md.ipv4_header_offset = (bit<16>)hdr.ipv4.ihl;
        ig_md.tcp_header_offset = (bit<16>)hdr.tcp.data_offset;
        ig_md.total_len = hdr.ipv4.total_len;
        ig_md.tcp_flags = hdr.tcp.flags;
        ig_md.mqtt_type = hdr.mqtt.packet_type;
    }

    action NoAction(){}

    action forward(bit<9> mac_port){
        ig_tm_md.ucast_egress_port = mac_port;
        ig_tm_md.bypass_egress=1;
    }

    table forward_decision_tb{
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            forward;
            NoAction;
        }
        size = 512;
        default_action = NoAction();
    }

    action get_timestamp(){
        ig_md.timestamp_32 = ig_intr_md.ingress_mac_tstamp[47:16];
        ig_md.timestamp_16 = ig_intr_md.ingress_mac_tstamp[43:28];
    }

    action pkt_access(){
        ig_md.access_flag = 1;
    }

    action pkt_no_access(){
        ig_md.access_flag = 0;
    }

    action is_in_blacklist(){
        ig_md.blacklist_in = 1;
    }

    action is_not_in_blacklist(){
        ig_md.blacklist_in = 0;
    }

    table mqtt_connect_blacklist_tb {
        key = {
            hdr.ipv4.src_addr : exact;
            hdr.tcp.src_port : exact;
        }
        actions = {
            is_in_blacklist;
            is_not_in_blacklist;
        }
        size = 512;
        default_action =is_not_in_blacklist;
    }

    apply {
        //MQTT Packets Process
        if (hdr.tcp.isValid() && hdr.mqtt.isValid()){         
            get_timestamp();
            get_phv_value();

            mqtt_connect_blacklist_tb.apply();

            if (ig_md.blacklist_in == 1){
                pkt_no_access();
            }
            else{
                pkt_access();
            }

        }
        else{
            pkt_access();
        }

        if (ig_md.access_flag == 1){    
            forward_decision_tb.apply();
        }
    }          
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;
