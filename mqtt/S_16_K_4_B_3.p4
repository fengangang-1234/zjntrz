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

    bit<16> ipv4_tcp_header_size;
    bit<16> ipv4_header_offset;
    bit<16> ipv4_header_size;
    bit<16> tcp_header_offset;
    bit<16> tcp_header_size;
    bit<4> mqtt_type;
    bit<1> is_mqtt_packet;

    bit<32> timestamp_32;
    bit<16> timestamp_16;

    bit<1> src_key;
        
    bit<32> hash_key1;
    bit<16> hash_key2;
    bit<48> hash_key3;

    bit<1> update_flag1;
    bit<1> update_flag2;
    bit<1> update_flag3;
    bit<1> update_flag_all;

    bit<16> hasha_16_val1;
    bit<16> hasha_16_val2;
    bit<16> hashb_16_val1;
    bit<16> hashb_16_val2;
    bit<16> hashb_16_val3;
    bit<12> hasha_12_val;
    
    bit<1> set_tocken;  
    bit<1> set_tocken_all;  
    bit<8> tocken_conf;
    bit<16> tocken_conf_all;
    
    bit<1> ret1;
    bit<1> ret2;
    bit<1> ret3;

    bit<1> has_tocken;
    bit<1> has_tocken_all;

    bit<1> ack_vaild1;
    bit<1> ack_vaild2;

    bit<1> current_state;
    bit<1> tcp_state_flag;

    bit<1> hb_vaild1;
    bit<1> hb_vaild2;

    bit<1> in_cache1;
    bit<1> in_cache2;
    bit<1> in_cache3;

    bit<1> blacklist_in;
    bit<1> session_record;
    bit<1> session_alive;
    bit<1> access_flag;

    bit<8> is_mtu;
    bit<8> remain_len_ret;
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
    Digest<digesta_t>() digesta;
    Digest<digestb_t>() digestb;
    Digest<digestc_t>() digestc;
    Digest<digestd_t>() digestd;

    apply {
        if (ig_dprsr_md.digest_type == 1) {
            digesta.pack({hdr.ipv4.src_addr, hdr.tcp.src_port, hdr.ipv4.ttl});
        }
        else if (ig_dprsr_md.digest_type == 2) {
            digestb.pack({hdr.ipv4.dst_addr, hdr.tcp.dst_port});
        }
        else if (ig_dprsr_md.digest_type == 3) {
            digestc.pack({hdr.ipv4.src_addr, hdr.tcp.src_port, hdr.ipv4.ttl});
        }
        else if (ig_dprsr_md.digest_type == 4) {
            digestd.pack({hdr.ipv4.src_addr, hdr.tcp.src_port});
        }
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

// ---------------------------------------------------------------------------
// Hash Fuctions
// --------------------------------------------------------------------------- 

    CRCPolynomial<bit<16>>(16w0x1021, // polynomial
                           false,        // reversed
                           false,        // use msb?
                           false,        // extended?
                           16w0xFFFF,    // initial shift register value
                           16w0x0000     // result xor
                           ) polya1;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, polya1) crca16_1;

    CRCPolynomial<bit<16>>(16w0xA001, // polynomial
                           false,        // reversed
                           false,        // use msb?
                           false,        // extended?
                           16w0xFFFF,    // initial shift register value
                           16w0x0000     // result xor
                           ) polya2;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, polya2) crca16_2;

    CRCPolynomial<bit<12>>(12w0xB03, // polynomial
                           false,        // reversed
                           false,        // use msb?
                           false,        // extended?
                           12w0xFFF,    // initial shift register value
                           12w0x000     // result xor
                           ) polya3;
    Hash<bit<12>>(HashAlgorithm_t.CUSTOM, polya3) crca16_3;

  
    action apply_hasha1() {
        ig_md.hasha_16_val1 = crca16_1.get({ig_md.hash_key1, ig_md.hash_key2, ig_md.hash_key3}); 
    }
    action apply_hasha2() {
        ig_md.hasha_16_val2 = crca16_2.get({ig_md.hash_key1, ig_md.hash_key2, ig_md.hash_key3}); 
    }
    action apply_hasha3() {
        ig_md.hasha_12_val = crca16_3.get({ig_md.hash_key1, ig_md.hash_key2, ig_md.hash_key3}); 
    }

    table tbl_hasha1 {
        actions = {
            apply_hasha1;
        }
        size = 1;
        const default_action = apply_hasha1();
    }
    table tbl_hasha2 {
        actions = {
            apply_hasha2;
        }
        size = 1;
        const default_action = apply_hasha2();
    }
    table tbl_hasha3 {
        actions = {
            apply_hasha3;
        }
        size = 1;
        const default_action = apply_hasha3();
    }
 

    action get_client_hash_keys(){  
        ig_md.hash_key1 = hdr.ipv4.src_addr;
        ig_md.hash_key2 = hdr.tcp.src_port;
        ig_md.hash_key3 = hdr.ethernet.src_addr;   
        ig_md.src_key=1; 
    }
        
    action get_server_hash_keys(){
        ig_md.hash_key1 = hdr.ipv4.dst_addr;
        ig_md.hash_key2 = hdr.tcp.dst_port;
        ig_md.hash_key3 = hdr.ethernet.dst_addr;   
        ig_md.src_key=0;
    }

    table get_hash_flags_tb{
        key = {
            hdr.tcp.src_port : ternary;
            hdr.tcp.dst_port : ternary;
        }
        actions = {
            get_client_hash_keys;
            get_server_hash_keys;
            NoAction;
        }
        default_action=NoAction;
        size = 4;
        const entries={
            (_, 1883): get_client_hash_keys(); 
            (1883, _): get_server_hash_keys();         
        }
    }


    CRCPolynomial<bit<16>>(16w0x1791, // polynomial
                           false,        // reversed
                           false,        // use msb?
                           false,        // extended?
                           16w0xFFFF,    // initial shift register value
                           16w0x0000     // result xor
                           ) polyb1;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, polyb1) crcb16_1;

    CRCPolynomial<bit<16>>(16w0x4401, // polynomial
                           false,        // reversed
                           false,        // use msb?
                           false,        // extended?
                           16w0xFFFF,    // initial shift register value
                           16w0x0000     // result xor
                           ) polyb2;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, polyb2) crcb16_2;

    CRCPolynomial<bit<16>>(16w0x8295, // polynomial
                           false,        // reversed
                           false,        // use msb?
                           false,        // extended?
                           16w0xFFFF,    // initial shift register value
                           16w0x0000     // result xor
                           ) polyb3;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, polyb3) crcb16_3;

  
    action apply_hashb1() {
        ig_md.hashb_16_val1 = crcb16_1.get({ig_md.hash_key1, ig_md.hash_key3}); 
    }
    action apply_hashb2() {
        ig_md.hashb_16_val2 = crcb16_2.get({ig_md.hash_key1, ig_md.hash_key3}); 
    }
    action apply_hashb3() {
        ig_md.hashb_16_val3 = crcb16_3.get({ig_md.hash_key1, ig_md.hash_key3});       
    }

    table tbl_hashb1 {
        actions = {
            apply_hashb1;
        }
        size = 1;
        const default_action = apply_hashb1();
    }

    table tbl_hashb2 {
        actions = {
            apply_hashb2;
        }
        size = 1;
        const default_action = apply_hashb2();
    }

    table tbl_hashb3 {
        actions = {
            apply_hashb3;
        }
        size = 1;
        const default_action = apply_hashb3();
    } 

// ---------------------------------------------------------------------------
// Base Fuctions
// --------------------------------------------------------------------------- 
    action get_phv_value(){
        ig_md.ipv4_header_offset = (bit<16>)hdr.ipv4.ihl;
        ig_md.tcp_header_offset = (bit<16>)hdr.tcp.data_offset;
        ig_md.total_len = hdr.ipv4.total_len;
        ig_md.tcp_flags = hdr.tcp.flags;
        ig_md.mqtt_type = hdr.mqtt.packet_type;
    }

    action check_ipv4_header_size(){
        ig_md.ipv4_header_size = ig_md.ipv4_header_offset << 2;
    }

    action check_tcp_header_size(){
        ig_md.tcp_header_size = ig_md.tcp_header_offset << 2;
    }

    action check_ipv4_tcp_header_size(){
        ig_md.ipv4_tcp_header_size = ig_md.ipv4_header_size + ig_md.tcp_header_size;
    }

    action drop(){
        ig_dprsr_md.drop_ctl=1;
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

    action digest_type_isvaild(bit<3> flag){
        ig_dprsr_md.digest_type = flag;
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
    

// ---------------------------------------------------------------------------
// Flow Limit Module
// ---------------------------------------------------------------------------
    action set_tocken_isvaild(){
        ig_md.set_tocken = 1;
    }

    action init_token_conf(){
        ig_md.tocken_conf = 200;
        ig_md.tocken_conf_all = 200;
    }

    action set_token_conf(bit<8> n, bit<16> n_all){
        ig_md.tocken_conf = n;
        ig_md.tocken_conf_all = n_all;
    }

    table connect_token_conf_tb {
        key = {
            ig_md.set_tocken : exact;
        }
        actions = {
            init_token_conf;
            set_token_conf;
        }
        size = 2;
        default_action = init_token_conf;
    }

    Register<bit<16>,_>(65536) token_bucket_update_time_reg1;
    Register<bit<8>,_>(65536) connect_token_bucket_reg1;

    RegisterAction<bit<16>, _, bit<1>>(token_bucket_update_time_reg1) check_last_update_time_regact1 = {
        void apply(inout bit<16> value, out bit<1> read_value){
            read_value = 0;
            if(ig_md.timestamp_16-value > 5){
                read_value = 1;
                value=ig_md.timestamp_16; 
            }
        }
    };

    RegisterAction<bit<8>, _, bit<1>>(connect_token_bucket_reg1) check_token_bucket_regact1 = {
        void apply(inout bit<8> value, out bit<1> read_value){
            read_value = 0;
            if(ig_md.update_flag1 == 1){
                value = ig_md.tocken_conf - 1;
                read_value = 1;          
            }
            else{
                if (value > 0){
                    value = value - 1;
                    read_value = 1;
                }
                else{
                    read_value=0;
                }
            }  
        }
    };

    Register<bit<16>,_>(65536) token_bucket_update_time_reg2;
    Register<bit<8>,_>(65536) connect_token_bucket_reg2;

    RegisterAction<bit<16>, _, bit<1>>(token_bucket_update_time_reg2) check_last_update_time_regact2 = {
        void apply(inout bit<16> value, out bit<1> read_value){
            read_value =0;
            if(ig_md.timestamp_16-value > 5){
                read_value = 1;
                value=ig_md.timestamp_16; 
            }
        }
    };

    RegisterAction<bit<8>, _, bit<1>>(connect_token_bucket_reg2) check_token_bucket_regact2 = {
        void apply(inout bit<8> value, out bit<1> read_value){
            read_value = 0;
            if(ig_md.update_flag2 == 1){
                value = ig_md.tocken_conf -1;
                read_value = 1;          
            }
            else{
                if (value > 0){
                    value = value - 1;
                    read_value = 1;
                }
                else{
                    read_value=0;
                }
            }  
        }
    };

    Register<bit<16>,_>(65536) token_bucket_update_time_reg3;
    Register<bit<8>,_>(65536) connect_token_bucket_reg3;

    RegisterAction<bit<16>, _, bit<1>>(token_bucket_update_time_reg3) check_last_update_time_regact3 = {
        void apply(inout bit<16> value, out bit<1> read_value){
            read_value =0;
            if(ig_md.timestamp_16-value > 5){
                read_value = 1;
                value=ig_md.timestamp_16; 
            }
        }
    };

    RegisterAction<bit<8>, _, bit<1>>(connect_token_bucket_reg3) check_token_bucket_regact3 = {
        void apply(inout bit<8> value, out bit<1> read_value){
            read_value = 0;
            if(ig_md.update_flag3 == 1){
                value = ig_md.tocken_conf -1;
                read_value = 1;          
            }
            else{
                if (value > 0){
                    value = value - 1;
                    read_value = 1;
                }
                else{
                    read_value=0;
                }
            }  
        }
    };



    Register<bit<32>,_>(1) token_bucket_update_time_all_reg;
    Register<bit<16>,_>(1) connect_token_bucket_all_reg;

    RegisterAction<bit<32>, _, bit<1>>(token_bucket_update_time_all_reg) check_last_update_time_all_regact = {
        void apply(inout bit<32> value, out bit<1> read_value){
            read_value =0;
            if(ig_md.timestamp_32-value > 20000){
                read_value = 1;
                value=ig_md.timestamp_32; 
            }
        }
    };

    RegisterAction<bit<8>, _, bit<1>>(connect_token_bucket_all_reg) check_token_bucket_all_regact = {
        void apply(inout bit<8> value, out bit<1> read_value){
            read_value = 0;
            if(ig_md.update_flag_all == 1){
                value = value + ig_md.tocken_conf;
                read_value = 1;          
            }
            else{
                if (value > 0){
                    value = value - 1;
                    read_value = 1;
                }
                else{
                    read_value=0;
                }
            }  
        }
    };



    action check_tocken_bucket_update_all(){
        ig_md.update_flag_all = check_last_update_time_all_regact.execute(0);
    }
    action check_token_num_all(){
        ig_md.has_tocken_all = check_token_bucket_all_regact.execute(0);
    }

    action check_tocken_bucket_update1(){
        ig_md.update_flag1 = check_last_update_time_regact1.execute(ig_md.hashb_16_val1);
    }
    action check_token_num1(){
        ig_md.ret1=check_token_bucket_regact1.execute(ig_md.hashb_16_val1);
    }

    action check_tocken_bucket_update2(){
        ig_md.update_flag2 = check_last_update_time_regact2.execute(ig_md.hashb_16_val2);
    }
    action check_token_num2(){
        ig_md.ret2=check_token_bucket_regact2.execute(ig_md.hashb_16_val2);
    }

    action check_tocken_bucket_update3(){
        ig_md.update_flag3 = check_last_update_time_regact3.execute(ig_md.hashb_16_val3);
    }
    action check_token_num3(){
        ig_md.ret3=check_token_bucket_regact3.execute(ig_md.hashb_16_val3);
    }

// ---------------------------------------------------------------------------
// Session Tracking Module
// --------------------------------------------------------------------------- 
    Register<bit<8>,_>(65536) tcp_session_state_reg;

    action set_current_state(bit<1> state){
        ig_md.current_state = state;
    }

    RegisterAction<bit<8>, _, bit<1>>(tcp_session_state_reg) update_tcp_SYN_session_state_regact = {
        void apply(inout bit<8> value, out bit<1> read_value){
            value =(bit<8>) ig_md.current_state;
            read_value =1;
        }
    };

    RegisterAction<bit<8>, _, bit<1>>(tcp_session_state_reg) update_tcp_SYNACK_session_state_regact = {
        void apply(inout bit<8> value, out bit<1> read_value){
            read_value = 1;
            if (value == 1){
                value = 2;
            }  
        }
    };

    RegisterAction<bit<8>, _, bit<1>>(tcp_session_state_reg) check_tcp_session_state_regact = {
        void apply(inout bit<8> value, out bit<1> read_value){
            if (value == 2){
                read_value = 1;
                value=0;
            }
            else{
                read_value = 0;
            }   
        }
    };

    action update_tcp_syn_session_state(){
        update_tcp_SYN_session_state_regact.execute(ig_md.hasha_16_val1);
    }

    action update_tcp_synack_session_state(){
        update_tcp_SYNACK_session_state_regact.execute(ig_md.hasha_16_val1);
    }

    action check_tcp_session_state(){
        ig_md.tcp_state_flag = check_tcp_session_state_regact.execute(ig_md.hasha_16_val1);
    }
   
    Register<bit<32>,_>(65536) connect_request_cache_reg1;
    Register<bit<32>,_>(65536) connect_request_cache_reg2;
    
    RegisterAction<bit<32>, _, bit<1>>(connect_request_cache_reg1) update_mqtt_connect_time_regact1 = {
        void apply(inout bit<32> value, out bit<1> read_value){
            value = ig_md.timestamp_32;  
            read_value = 1;
        }
    };
    RegisterAction<bit<32>, _, bit<1>>(connect_request_cache_reg2) update_mqtt_connect_time_regact2 = {
        void apply(inout bit<32> value, out bit<1> read_value){
            value = ig_md.timestamp_32;  
            read_value = 1;
        }
    };


    action record_mqtt_connect_time1(){
        update_mqtt_connect_time_regact1.execute(ig_md.hasha_16_val1);
    }
    action record_mqtt_connect_time2(){
        update_mqtt_connect_time_regact2.execute(ig_md.hasha_16_val2);
    }

    RegisterAction<bit<32>, _, bit<1>>(connect_request_cache_reg1) check_mqtt_connect_time_regact1 = {
        void apply(inout bit<32> value, out bit<1> read_value){
            if (value == 0){
                read_value = 0;
            }
            else{
                if (ig_md.timestamp_32 - value < 20000){
                    read_value=1;
                }
                else{
                    read_value=0;
                } 
            }  
        }
    };
    
    RegisterAction<bit<32>, _, bit<1>>(connect_request_cache_reg2) check_mqtt_connect_time_regact2 = {
        void apply(inout bit<32> value, out bit<1> read_value){
            if (value == 0){
                read_value = 0;
            }
            else{
                if (ig_md.timestamp_32 - value < 20000){
                    read_value=1;
                }
                else{
                    read_value=0;
                } 
            }  
        }
    };

    action check_mqtt_connect_time1(){
        ig_md.ack_vaild1=check_mqtt_connect_time_regact1.execute(ig_md.hasha_16_val1);  
    }
    action check_mqtt_connect_time2(){
        ig_md.ack_vaild2=check_mqtt_connect_time_regact2.execute(ig_md.hasha_16_val2);  
    }

    Register<bit<16>,_>(65536) hb_request_cache_reg1;
    Register<bit<16>,_>(65536) hb_request_cache_reg2;
    
    RegisterAction<bit<16>, _, bit<1>>(hb_request_cache_reg1) update_mqtt_hb_time_regact1 = {
        void apply(inout bit<16> value, out bit<1> read_value){
            value = ig_md.timestamp_16;  
            read_value = 1;
        }
    };
    RegisterAction<bit<16>, _, bit<1>>(hb_request_cache_reg2) update_mqtt_hb_time_regact2 = {
        void apply(inout bit<16> value, out bit<1> read_value){
            value = ig_md.timestamp_16;  
            read_value = 1;
        }
    };


    action record_mqtt_hb_time1(){
        update_mqtt_hb_time_regact1.execute(ig_md.hasha_16_val1);
    }
    action record_mqtt_hb_time2(){
        update_mqtt_hb_time_regact2.execute(ig_md.hasha_16_val1);
    }

    RegisterAction<bit<16>, _, bit<1>>(hb_request_cache_reg1) check_mqtt_hb_time_regact1 = {
        void apply(inout bit<16> value, out bit<1> read_value){
            if (value == 0){
                read_value = 0;
            }
            else{
                if (ig_md.timestamp_16 - value < 40){
                    read_value=1;
                }
                else{
                    read_value=0;
                } 
            }  
        }
    };
    RegisterAction<bit<16>, _, bit<1>>(hb_request_cache_reg2) check_mqtt_hb_time_regact2 = {
        void apply(inout bit<16> value, out bit<1> read_value){
            if (value == 0){
                read_value = 0;
            }
            else{
                if (ig_md.timestamp_16 - value < 40){
                    read_value=1;
                }
                else{
                    read_value=0;
                } 
            }  
        }
    };

    action check_mqtt_hb_time1(){
        ig_md.hb_vaild1=check_mqtt_hb_time_regact1.execute(ig_md.hasha_16_val1);  
    }
    action check_mqtt_hb_time2(){
        ig_md.hb_vaild2=check_mqtt_hb_time_regact2.execute(ig_md.hasha_16_val2);  
    }



// ---------------------------------------------------------------------------
// Flow Access Control Module
// ---------------------------------------------------------------------------  
    action session_record(){
        ig_md.session_record = 1;
    }

    action session_no_record(){
        ig_md.session_record = 0;
    }
    table mqtt_acl_tb {
        key = {
            hdr.ipv4.src_addr : exact;
            hdr.tcp.src_port : exact;
            hdr.ipv4.ttl : exact;
        }
        actions = {
            session_record;
            session_no_record;
        }
        size = 16384;
        default_action = session_no_record;
    }

    Register<bit<32>,_>(4096) ip_cache_reg;
    Register<bit<16>,_>(4096) port_cache_reg;
    Register<bit<16>,_>(4096) time_cache_reg;
    
    RegisterAction<bit<32>, _, bit<1>>(ip_cache_reg) update_ip_cache_regact = {
        void apply(inout bit<32> value, out bit<1> read_value){
            value = hdr.ipv4.dst_addr;
            read_value = 1;
        }
    };

    RegisterAction<bit<16>, _, bit<1>>(port_cache_reg) update_port_cache_regact = {
        void apply(inout bit<16> value, out bit<1> read_value){
            value = hdr.tcp.dst_port;  
            read_value = 1;
        }
    };

    RegisterAction<bit<16>, _, bit<1>>(time_cache_reg) update_time_cache_regact = {
        void apply(inout bit<16> value, out bit<1> read_value){
            value = ig_md.timestamp_16;  
            read_value = 1;
        }
    };

    RegisterAction<bit<32>, _, bit<1>>(ip_cache_reg) check_ip_cache_regact = {
        void apply(inout bit<32> value, out bit<1> read_value){
            read_value = 0;
            if(value == hdr.ipv4.src_addr){
                read_value = 1;
            }    
        }
    };
    RegisterAction<bit<16>, _, bit<1>>(port_cache_reg) check_port_cache_regact = {
        void apply(inout bit<16> value, out bit<1> read_value){
            read_value = 0;
            if(value == hdr.tcp.src_port){
                read_value = 1;
            }  
        }
    };
    RegisterAction<bit<16>, _, bit<1>>(time_cache_reg) check_time_cache_regact = {
        void apply(inout bit<16> value, out bit<1> read_value){
            read_value = 0;
            if(ig_md.timestamp_16 - value < 40){
                read_value = 1;
            }  
        }
    };
    
    action update_ip_cache(){
        update_ip_cache_regact.execute(ig_md.hasha_12_val);
    }
    action update_port_cache(){
        update_port_cache_regact.execute(ig_md.hasha_12_val);
    }
    action update_time_cache(){
        update_time_cache_regact.execute(ig_md.hasha_12_val);
    }
   
    action check_ip_cache(){
        ig_md.in_cache1 = check_ip_cache_regact.execute(ig_md.hasha_12_val);
    }
    action check_port_cache(){
        ig_md.in_cache2 = check_port_cache_regact.execute(ig_md.hasha_12_val);
    }
    action check_time_cache(){
        ig_md.in_cache3 = check_time_cache_regact.execute(ig_md.hasha_12_val);
    }


// ---------------------------------------------------------------------------
// Check Pkt Spliting Lenth
// ---------------------------------------------------------------------------  
 
    Register<bit<8>,_>(65536) remain_len_cache_reg;
    
    RegisterAction<bit<8>, _, bit<1>>(remain_len_cache_reg) set_remain_len_regact = {
        void apply(inout bit<8> value, out bit<1> read_value){
            value= ig_md.is_mtu;;
        }
    };

    action set_remain_len(){
        set_remain_len_regact.execute(ig_md.hasha_16_val1);
    }

    RegisterAction<bit<8>, _, bit<8>>(remain_len_cache_reg) check_remain_len_regact = {
        void apply(inout bit<8> value, out bit<8> read_value){
            read_value = value;
            value = ig_md.is_mtu;      
        }
    };

    action check_remain_len(){
        ig_md.remain_len_ret=check_remain_len_regact.execute(ig_md.hasha_16_val1);
    }
 
    action is_mtu(){
        ig_md.is_mtu = 1;
    }

    action is_not_mtu(){
        ig_md.is_mtu = 0;
    }

    table check_pkt_split_tb {
        key = {
            hdr.ipv4.total_len : exact;
        }
        actions = {
            is_mtu;
            is_not_mtu;
        }
        size = 2;
        default_action =is_not_mtu;
        const entries={
            1500: is_mtu();    
        }
    }

    // action get_result(){
    //     ig_md.remain_len=ig_md.session_alive & ig_md.is_mtu;
    // }

// ---------------------------------------------------------------------------
// Main Flow Process
// --------------------------------------------------------------------------- 
    apply {
        //MQTT Packets Process
        if (hdr.tcp.isValid() && hdr.mqtt.isValid()){         
            get_timestamp();
            get_phv_value();


            get_hash_flags_tb.apply();
            tbl_hasha1.apply();
            tbl_hasha2.apply();
            tbl_hasha3.apply();
            //BlackList Check
            mqtt_connect_blacklist_tb.apply();

            if (ig_md.blacklist_in == 1){
                pkt_no_access();
            }
            else if(ig_md.tcp_flags == TCP_FLAGS_S){
                tbl_hashb1.apply();
                tbl_hashb2.apply();
                tbl_hashb3.apply();

                set_tocken_isvaild();
                connect_token_conf_tb.apply();       
                
                check_tocken_bucket_update1();   
                check_token_num1();
                check_tocken_bucket_update2();
                check_token_num2();
                check_tocken_bucket_update3();
                check_token_num3();

                if (ig_md.ret1 == 1 || ig_md.ret2 == 1 || ig_md.ret3 ==1){
                    check_tocken_bucket_update_all();
                    check_token_num_all(); 
                    if(ig_md.has_tocken_all == 1){ 
                        set_current_state(1);                               
                        pkt_access();
                    }
                    else{
                        set_current_state(0);
                        pkt_no_access();
                    }
                }
                else{
                    set_current_state(0);
                    pkt_no_access();                     
                }
                update_tcp_syn_session_state();
            }
            else if(ig_md.tcp_flags == TCP_FLAGS_S_A){
                update_tcp_synack_session_state();
                pkt_access();
            }
            else if(ig_md.tcp_flags[0:0] == 1 || ig_md.tcp_flags[2:2] == 1){
                digest_type_isvaild(4);
                pkt_access();
            }
            else{
                
                check_ipv4_header_size();
                check_tcp_header_size();
                check_ipv4_tcp_header_size();

                check_pkt_split_tb.apply();
                
                
                if (ig_md.ipv4_tcp_header_size == hdr.ipv4.total_len){
                    pkt_access();
                }

                else if (ig_md.mqtt_type == MQTT_CONNECT){
                    check_tcp_session_state();  
                    if (ig_md.tcp_state_flag == 1){ 
                        record_mqtt_connect_time1();
                        record_mqtt_connect_time2();
                        digest_type_isvaild(1);
                        pkt_access();
                        check_remain_len();
                    }
                    else{
                        pkt_access();
                    }

                    
                }
                else if (ig_md.mqtt_type == MQTT_PINGREQ){
                        record_mqtt_hb_time1();
                        record_mqtt_hb_time2(); 
                        digest_type_isvaild(3);
                        pkt_access(); 
                }

                else if (ig_md.src_key == 1){
                    mqtt_acl_tb.apply();
                
                    if(ig_md.session_record==0){
                        check_ip_cache();
                        check_port_cache();
                        check_time_cache();
                        if(ig_md.in_cache1 == 1 && ig_md.in_cache2 == 1 && ig_md.in_cache3 == 1){
                            ig_md.session_alive=1;
                        }
                        else{
                            ig_md.session_alive=0;
                        }
                    }
                    else{
                        ig_md.session_alive=1;
                    }
                    check_remain_len();

                    if(ig_md.session_alive == 1 || ig_md.remain_len_ret == 1){
                        if(ig_md.mqtt_type == MQTT_DISCONNECT){
                            digest_type_isvaild(4);
                        }
                        pkt_access();
                    }
                }   
                else if (ig_md.src_key == 0){
                    if (ig_md.mqtt_type == MQTT_CONNACK){
                        if (hdr.mqtt_ack.return_code == 0){     
                            check_mqtt_connect_time1();
                            check_mqtt_connect_time2();
                            if (ig_md.ack_vaild1 == 1 && ig_md.ack_vaild2 == 1){
                                update_ip_cache();
                                update_port_cache();
                                update_time_cache();
                                digest_type_isvaild(2);    
                            }
                        }
                    }
                    else if (ig_md.mqtt_type == MQTT_PINGRESP){
                        if (hdr.mqtt_ack.return_code == 0){     
                            check_mqtt_hb_time1();
                            check_mqtt_hb_time2();
                            if (ig_md.hb_vaild1 == 1 && ig_md.hb_vaild2 == 1){
                                digest_type_isvaild(3);
                            }
                        }
                    }
                    pkt_access();
                }                  
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
