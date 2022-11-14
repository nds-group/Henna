/* -*- P4_16 -*- */

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t   dst_addr;
    mac_addr_t   src_addr;
    ether_type_t ether_type;
}

/* IPV4 header */
header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

/* TCP header */
header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

/* UDP header */
header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

/***********************  H E A D E R S  ************************/
struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    tcp_h        tcp;
    udp_h        udp;
}

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
struct my_ingress_metadata_t {

    // selected features
    bit<1>  flag_ack;
    bit<1>  flag_push;
    bit<8>  ip_proto;
    bit<16> total_len;
    bit<16> hdr_srcport;
    bit<16> hdr_dstport;
    
    // classification results of different trees
    bit<3> class_s1_t0;
    bit<3> class_s1_t1;
    bit<3> class_s1_t2;
    
    // final classification result
    bit<3> class_s1_final;

    // returned certainty values to assist in deciding final result
    int<8> cert_s1_t0;
    int<8> cert_s1_t1;
    int<8> cert_s1_t2;

    // code words of individual trees
    bit<479> cw_s1_t0;
    bit<479> cw_s1_t1;
    bit<479> cw_s1_t2;

}

