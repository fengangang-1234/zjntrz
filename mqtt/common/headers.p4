
#ifndef _HEADERS_
#define _HEADERS_

// ---------------------------------------------------------------------------
// Constants Defined
// ---------------------------------------------------------------------------

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12> vlan_id_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

typedef bit<32> header_len_t;
const header_len_t IPV4_MIN_LEN = 20;
const header_len_t TCP_MIN_LEN = 20;

typedef bit<8> tcp_flags_t;
const tcp_flags_t TCP_FLAGS_F = 1;
const tcp_flags_t TCP_FLAGS_S = 2;
const tcp_flags_t TCP_FLAGS_R = 4;
const tcp_flags_t TCP_FLAGS_P = 8;
const tcp_flags_t TCP_FLAGS_A = 16;
const tcp_flags_t TCP_FLAGS_S_A = 18;

typedef bit<16> port_type_t;
const port_type_t MQTT_PORT = 1883;

typedef bit<4> mqtt_type_t;
const mqtt_type_t MQTT_RESERVEDA = 0;
const mqtt_type_t MQTT_RESERVEDB = 15;
const mqtt_type_t MQTT_CONNECT = 1;
const mqtt_type_t MQTT_CONNACK = 2;
const mqtt_type_t MQTT_PINGREQ = 12;
const mqtt_type_t MQTT_PINGRESP = 13;
const mqtt_type_t MQTT_DISCONNECT = 14;

const mqtt_type_t MQTT_TYPE_COMM_RANGE = 11;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv4_option_h {
    bit<32> option;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header tcp_option_h {
    bit<32> option;
}

header mqtt_fixed_header_t {
    bit<4> packet_type;  
    bit<1> dup;    
    bit<2> Qos; 
    bit<1> retain;
    bit<8> remain_lenth;
}

header mqtt_connack_rep_t {
    bit<8> flags;          
    bit<8> return_code;  
}

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    ipv4_option_h ipv4_option6;
    ipv4_option_h ipv4_option7;
    ipv4_option_h ipv4_option8;
    ipv4_option_h ipv4_option9;
    ipv4_option_h ipv4_option10;
    ipv4_option_h ipv4_option11;
    ipv4_option_h ipv4_option12;
    ipv4_option_h ipv4_option13;            
    ipv4_option_h ipv4_option14;
    ipv4_option_h ipv4_option15;
    tcp_h tcp;
    tcp_option_h tcp_option6;
    tcp_option_h tcp_option7;
    tcp_option_h tcp_option8;
    tcp_option_h tcp_option9;
    tcp_option_h tcp_option10;
    tcp_option_h tcp_option11;
    tcp_option_h tcp_option12;
    tcp_option_h tcp_option13;
    tcp_option_h tcp_option14;
    tcp_option_h tcp_option15;
    mqtt_fixed_header_t mqtt;
    mqtt_connack_rep_t mqtt_ack;
}

struct empty_header_t {}

struct empty_metadata_t {}

#endif /* _HEADERS_ */
