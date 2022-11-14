/* -*- P4_16 -*- */

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    tcp_h        tcp;
    udp_h        udp;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    
    // classification result of the first stage
    bit<8> group_class;

    // selected features for second stage models
    bit<1>  flag_ack;
    bit<1>  flag_push;
    bit<8>  ip_proto;
    bit<16> total_len;
    bit<16> hdr_srcport;
    bit<16> hdr_dstport;

    // classification results of second stage trees
    bit<8> class_s2_g0; 
    bit<8> class_s2_g1; 
    bit<8> class_s2_g2;  
    bit<8> class_s2_g3; 
    bit<8> class_s2_g4; 

    // code words of second stage trees
    bit<471> cw_s2_g4;
    bit<111> cw_s2_g3;
    bit<199> cw_s2_g2;
    bit<11>  cw_s2_g1;
    bit<29>  cw_s2_g0;
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        // transition accept;
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        // initialize features
        meta.group_class = hdr.ipv4.ttl;    // 1st stage model result 
        meta.total_len = hdr.ipv4.total_len;
        meta.ip_proto = hdr.ipv4.protocol;
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP:  parse_tcp;
            TYPE_UDP:  parse_udp;
            default: accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        // initialize features
        meta.hdr_dstport = hdr.tcp.dst_port;
        meta.hdr_srcport = hdr.tcp.src_port;
        meta.flag_ack    = hdr.tcp.ack;
        meta.flag_push   = hdr.tcp.psh;
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        // initialize features
        meta.hdr_dstport = hdr.udp.dst_port;
        meta.hdr_srcport = hdr.udp.src_port;
        meta.flag_ack    = 0;
        meta.flag_push   = 0;
        transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{

    /* Custom Do Nothing Action */
    action nop(){}

    /* Feature table actions for second stage DT*/
    // computers - g4
    action SetCode_s2_g4_f0(bit<73> code0) {
        meta.cw_s2_g4[470:398] = code0;
    }
    action SetCode_s2_g4_f1(bit<266> code0) {
        meta.cw_s2_g4[397:132] = code0;
    }
    action SetCode_s2_g4_f2(bit<121> code0) {
        meta.cw_s2_g4[131:11] = code0;
    }
    action SetCode_s2_g4_f3(bit<11> code0) {
        meta.cw_s2_g4[10:0] = code0;
    }

    // appliances - g3
    action SetCode_s2_g3_f0(bit<31> code0) {
        meta.cw_s2_g3[110:80] = code0;
    }
    action SetCode_s2_g3_f1(bit<26> code0) {
        meta.cw_s2_g3[79:54] = code0;
    }
    action SetCode_s2_g3_f2(bit<51> code0) {
        meta.cw_s2_g3[53:3] = code0;
    }
    action SetCode_s2_g3_f3(bit<1> code0) {
        meta.cw_s2_g3[2:2] = code0;
    }
    action SetCode_s2_g3_f4(bit<2> code0) {
        meta.cw_s2_g3[1:0] = code0;
    }

    // video - g2
    action SetCode_s2_g2_f0(bit<66> code0) {
        meta.cw_s2_g2[198:133] = code0;
    }
    action SetCode_s2_g2_f1(bit<87> code0) {
        meta.cw_s2_g2[132:46] = code0;
    }
    action SetCode_s2_g2_f2(bit<1> code0) {
        meta.cw_s2_g2[45:45] = code0;
    }
    action SetCode_s2_g2_f3(bit<45> code0) {
        meta.cw_s2_g2[44:0] = code0;
    }

    // sensors - g1
    action SetCode_s2_g1_f0(bit<6> code0) {
        meta.cw_s2_g1[10:5] = code0;
    }
    action SetCode_s2_g1_f1(bit<5> code0) {
        meta.cw_s2_g1[4:0] = code0;
    }

    // plugs - g0
    action SetCode_s2_g0_f0(bit<16> code0) {
        meta.cw_s2_g0[28:13] = code0;
    }
    action SetCode_s2_g0_f1(bit<13> code0) {
        meta.cw_s2_g0[12:0] = code0;
    }

/* Feature tables for the second stage DT's */
    // computers - g4
    table tbl_s2_g4_f0{
	    key = {meta.total_len: range @name("s2_g4_f0");}
	    actions = {@defaultonly nop; SetCode_s2_g4_f0;}
	    size = 60;
        const default_action = nop();
	}
	table tbl_s2_g4_f1{
        key = {meta.hdr_dstport: range @name("s2_g4_f1");}
	    actions = {@defaultonly nop; SetCode_s2_g4_f1;}
	    size = 260;
        const default_action = nop();
	}
	table tbl_s2_g4_f2{
	    key = {meta.hdr_srcport: range @name("s2_g4_f2");}
	    actions = {@defaultonly nop; SetCode_s2_g4_f2;}
	    size = 120;
        const default_action = nop();
	}
	table tbl_s2_g4_f3{
	    key = {meta.ip_proto: range @name("s2_g4_f3");}
	    actions = {@defaultonly nop; SetCode_s2_g4_f3;}
	    size = 2;
        const default_action = nop();
	}    

    // appliances - g3
    table tbl_s2_g3_f0{
	    key = {meta.hdr_srcport: range @name("s2_g3_f0");}
	    actions = {@defaultonly nop; SetCode_s2_g3_f0;}
	    size = 30;
        const default_action = nop();
	}
	table tbl_s2_g3_f1{
        key = {meta.hdr_dstport: range @name("s2_g3_f1");}
	    actions = {@defaultonly nop; SetCode_s2_g3_f1;}
	    size = 30;
        const default_action = nop();
	}
	table tbl_s2_g3_f2{
	    key = {meta.total_len: range @name("s2_g3_f2");}
	    actions = {@defaultonly nop; SetCode_s2_g3_f2;}
	    size = 45;
        const default_action = nop();
	}
	table tbl_s2_g3_f3{
	    key = {meta.ip_proto: range @name("s2_g3_f3");}
	    actions = {@defaultonly nop; SetCode_s2_g3_f3;}
	    size = 2;
        const default_action = nop();
	} 
	table tbl_s2_g3_f4{
	    key = {meta.flag_push: range @name("s2_g3_f4");}
	    actions = {@defaultonly nop; SetCode_s2_g3_f4;}
	    size = 2;
        const default_action = nop();
	} 

    // video - g2
    table tbl_s2_g2_f0{
	    key = {meta.total_len: range @name("s2_g2_f0");}
	    actions = {@defaultonly nop; SetCode_s2_g2_f0;}
	    size = 70;
        const default_action = nop();
	}
	table tbl_s2_g2_f1{
        key = {meta.hdr_srcport: range @name("s2_g2_f1");}
	    actions = {@defaultonly nop; SetCode_s2_g2_f1;}
	    size = 80;
        const default_action = nop();
	}
	table tbl_s2_g2_f2{
	    key = {meta.flag_ack: range @name("s2_g2_f2");}
	    actions = {@defaultonly nop; SetCode_s2_g2_f2;}
	    size = 2;
        const default_action = nop();
	}
	table tbl_s2_g2_f3{
	    key = {meta.hdr_dstport: range @name("s2_g2_f3");}
	    actions = {@defaultonly nop; SetCode_s2_g2_f3;}
	    size = 50;
        const default_action = nop();
	} 

    // sensors - g1
    table tbl_s2_g1_f0{
	    key = {meta.hdr_srcport: range @name("s2_g1_f0");}
	    actions = {@defaultonly nop; SetCode_s2_g1_f0;}
	    size = 10;
        const default_action = nop();
	}
	table tbl_s2_g1_f1{
        key = {meta.hdr_dstport: range @name("s2_g1_f1");}
	    actions = {@defaultonly nop; SetCode_s2_g1_f1;}
	    size = 10;
        const default_action = nop();
	}

    // plugs - g0
    table tbl_s2_g0_f0{
	    key = {meta.hdr_srcport: range @name("s2_g0_f0");}
	    actions = {@defaultonly nop; SetCode_s2_g0_f0;}
	    size = 20;
        const default_action = nop();
	}
	table tbl_s2_g0_f1{
        key = {meta.hdr_dstport: range @name("s2_g0_f1");}
	    actions = {@defaultonly nop; SetCode_s2_g0_f1;}
	    size = 20;
        const default_action = nop();
	}

    /* Actions to assign a final class to each DT */
    action SetClass_s2_g0(bit<8> classe) {
        meta.class_s2_g0 = classe;
        hdr.ipv4.ttl = meta.class_s2_g0;
    }
    action SetClass_s2_g1(bit<8> classe) {
        meta.class_s2_g1 = classe;
        hdr.ipv4.ttl = meta.class_s2_g1;
    }
    action SetClass_s2_g2(bit<8> classe) {
        meta.class_s2_g2 = classe;
        hdr.ipv4.ttl = meta.class_s2_g2;
    }
    action SetClass_s2_g3(bit<8> classe) {
        meta.class_s2_g3 = classe ;
        hdr.ipv4.ttl = meta.class_s2_g3;
    }
    action SetClass_s2_g4(bit<8> classe) {
        meta.class_s2_g4 = classe ;
        hdr.ipv4.ttl = meta.class_s2_g4;
    }

    /* Code tables for second stage DT's*/
    // g4
	table tbl_s2_g4{
	    key = {meta.cw_s2_g4: ternary;}
	    actions = {@defaultonly nop; SetClass_s2_g4;}
	    size = 490;
        const default_action = nop();
	}
    // g3
	table tbl_s2_g3{
	    key = {meta.cw_s2_g3: ternary;}
	    actions = {@defaultonly nop; SetClass_s2_g3;}
	    size = 116;
        const default_action = nop();
	}
    // g2
	table tbl_s2_g2{
	    key = {meta.cw_s2_g2: ternary;}
	    actions = {@defaultonly nop; SetClass_s2_g2;}
	    size = 210;
        const default_action = nop();
	}
    // g1
	table tbl_s2_g1{
	    key = {meta.cw_s2_g1: ternary;}
	    actions = {@defaultonly nop; SetClass_s2_g1;}
	    size = 16;
        const default_action = nop();
	}
    // g0
	table tbl_s2_g0{
	    key = {meta.cw_s2_g0: ternary;}
	    actions = {@defaultonly nop; SetClass_s2_g0;}
	    size = 35;
        const default_action = nop();
	}

    apply {

        // check result of first stage to determine which 2nd stage model to apply

        if (meta.group_class == 5){ //computers
            // apply the feature tables
            tbl_s2_g4_f0.apply();
            tbl_s2_g4_f1.apply();
            tbl_s2_g4_f2.apply();
            tbl_s2_g4_f3.apply();
            // apply the code tables
            tbl_s2_g4.apply();  
        }
        else if(meta.group_class == 4){//appliances
            // apply the feature tables
            tbl_s2_g3_f0.apply();
            tbl_s2_g3_f1.apply();
            tbl_s2_g3_f2.apply();
            tbl_s2_g3_f3.apply();
            tbl_s2_g3_f4.apply();
            // apply the code tables
            tbl_s2_g3.apply(); 
        }
        else if(meta.group_class == 3){ //video
            // apply the feature tables
            tbl_s2_g2_f0.apply();
            tbl_s2_g2_f1.apply();
            tbl_s2_g2_f2.apply();
            tbl_s2_g2_f3.apply();
            // apply the code tables
            tbl_s2_g2.apply(); 
        }
        else if(meta.group_class == 2){ //sensors
            // apply the feature tables
            tbl_s2_g1_f0.apply();
            tbl_s2_g1_f1.apply();
            // apply the code tables
            tbl_s2_g1.apply(); 
        }
        else if(meta.group_class == 1){//plugs
            // apply the feature tables
            tbl_s2_g0_f0.apply();
            tbl_s2_g0_f1.apply();
            // apply the code tables
            tbl_s2_g0.apply(); 
        }

    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}
