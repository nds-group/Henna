/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

#include "./include/types.p4"
#include "./include/headers.p4"
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }
    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }
    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
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

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
/***************** M A T C H - A C T I O N  *********************/
control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    /* Forward to a port upon classification */
    action ipv4_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }
    /* Custom Do Nothing Action */
    action nop(){}

    /* Assign classes and certainty values for stage 1 RF trees */
    action SetClass_s1_t0(bit<3> classe, int<8> cert) {
        meta.class_s1_t0 = classe;
        meta.cert_s1_t0 = cert;
    }
    action SetClass_s1_t1(bit<3> classe, int<8> cert) {
        meta.class_s1_t1 = classe;
        meta.cert_s1_t1 = cert;
    }
    action SetClass_s1_t2(bit<3> classe, int<8> cert) {
        meta.class_s1_t2 = classe;
        meta.cert_s1_t2 = cert;
    }

    /* Set the final class after vote of RF trees */
    action set_final_class(bit<3> class_result) {
        hdr.ipv4.ttl = (bit<8>)class_result; /* We store the classification result in the ttl field 
        of the ipv4 header which we read in the end host for statistical purposes */
        ipv4_forward(260);
    }

    /* Feature table actions for first stage RF */
    action SetCode_s1_f0(bit<120> code0, bit<161> code1, bit<157> code2) {
        meta.cw_s1_t0[478:359] = code0;
        meta.cw_s1_t1[478:318] = code1;
        meta.cw_s1_t2[478:322] = code2;
    }
    action SetCode_s1_f1(bit<139> code0, bit<162> code1, bit<175> code2) {
        meta.cw_s1_t0[358:220] = code0;
        meta.cw_s1_t1[317:156] = code1;
        meta.cw_s1_t2[321:147] = code2;
    }
    action SetCode_s1_f2(bit<168> code0, bit<111> code1, bit<144> code2) {
        meta.cw_s1_t0[219:52] = code0;
        meta.cw_s1_t1[155:45] = code1;
        meta.cw_s1_t2[146:3]  = code2;
    }
    action SetCode_s1_f3(bit<16> code0, bit<21> code1, bit<1> code2) {
        meta.cw_s1_t0[51:36] = code0;
        meta.cw_s1_t1[44:24] = code1;
        meta.cw_s1_t2[2:2]   = code2;
    }
    action SetCode_s1_f4(bit<20> code0, bit<10> code1, bit<1> code2) {
        meta.cw_s1_t0[35:16] = code0;
        meta.cw_s1_t1[23:14] = code1;
        meta.cw_s1_t2[1:1]   = code2;
    }
    action SetCode_s1_f5(bit<16> code0, bit<14> code1, bit<1> code2) {
        meta.cw_s1_t0[15:0] = code0;
        meta.cw_s1_t1[13:0] = code1;
        meta.cw_s1_t2[0:0]  = code2;
    }

    /* Feature tables for first stage RF*/
	table tbl_s1_f0{
	    key = {meta.hdr_srcport: range @name("s1_f0");}
	    actions = {@defaultonly nop; SetCode_s1_f0;}
	    size = 350;
        const default_action = nop();
	}
	table tbl_s1_f1{
        key = {meta.hdr_dstport: range @name("s1_f1");}
	    actions = {@defaultonly nop; SetCode_s1_f1;}
	    size = 350;
        const default_action = nop();
	}
	table tbl_s1_f2{
	    key = {meta.total_len: range @name("s1_f2");}
	    actions = {@defaultonly nop; SetCode_s1_f2;}
	    size = 250;
        const default_action = nop();
	}
	table tbl_s1_f3{
	    key = {meta.flag_push: range @name("s1_f3");}
	    actions = {@defaultonly nop; SetCode_s1_f3;}
	    size = 2;
        const default_action = nop();
	}
	table tbl_s1_f4{
	    key = {meta.ip_proto: range @name("s1_f4");}
	    actions = {@defaultonly nop; SetCode_s1_f4;}
	    size = 2;
        const default_action = nop();
	}
	table tbl_s1_f5{
	    key = {meta.flag_ack: range @name("s1_f5");}
	    actions = {@defaultonly nop; SetCode_s1_f5;}
	    size = 2;
        const default_action = nop();
	}

    /* Code tables for first stage RF*/
	table tbl_s1_cw0{
	    key = {meta.cw_s1_t0: ternary;}
	    actions = {@defaultonly nop; SetClass_s1_t0;}
	    size = 490;
        const default_action = nop();
	}
	table tbl_s1_cw1{
        key = {meta.cw_s1_t1: ternary;}
	    actions = {@defaultonly nop; SetClass_s1_t1;} //
	    size = 490;
        const default_action = nop();
	}
	table tbl_s1_cw2{
        key = {meta.cw_s1_t2: ternary;}
	    actions = {@defaultonly nop; SetClass_s1_t2;} //
	    size = 490;
        const default_action = nop();
	}

    /* Determine classification result by majority vote of RF trees */
    table voting_table {
        key = {
            meta.class_s1_t0: exact;
            meta.class_s1_t1: exact;
            meta.class_s1_t2: exact;
        }
        actions = {set_final_class; @defaultonly nop;}
        size = 10000;
        const default_action = nop();
    }

    /* When there is no majority from voting table, we use 
    the certainty values returned by the trees to decide.
    We take the tree result with the highest certainty value.
    */
    int<8> diff_0_1;
    int<8> diff_0_2;
    int<8> diff_1_0;
    int<8> diff_1_2;
    int<8> diff_2_0;
    int<8> diff_2_1;

    /* Action computes difference between certainty values to help 
    identify which one was the highest and hence the final result.
    */
    action diff_x_y(){
        diff_0_1 = (meta.cert_s1_t1 - meta.cert_s1_t0);
        diff_0_2 = (meta.cert_s1_t2 - meta.cert_s1_t0);
        diff_1_0 = (meta.cert_s1_t0 - meta.cert_s1_t1);
        diff_1_2 = (meta.cert_s1_t2 - meta.cert_s1_t1);
        diff_2_0 = (meta.cert_s1_t0 - meta.cert_s1_t2);
        diff_2_1 = (meta.cert_s1_t1 - meta.cert_s1_t2);
    }

    apply {
        // apply feature tables of 1st stage
        tbl_s1_f0.apply();
        tbl_s1_f1.apply();
        tbl_s1_f2.apply();
        tbl_s1_f3.apply();
        tbl_s1_f4.apply();
        tbl_s1_f5.apply();

        // apply code tables of 1st stage
        tbl_s1_cw0.apply();
        tbl_s1_cw1.apply();
        tbl_s1_cw2.apply();

        if (voting_table.apply().hit) {
            // If there is a hit on the voting table, the class is set and packet leaves ingress
        } else {
            // If voting table experienced a miss, we find the difference between the certainty values
            diff_x_y();
            
            /* Next we find which tree has the highest certainty value and take its result as final.
               We assign this value to the ttl field for statistical purposes as mentioned above.
            */
            if ((diff_0_1[7:7] == 1) && (diff_0_2[7:7] == 1)){
                hdr.ipv4.ttl = (bit<8>)meta.class_s1_t0;
            }
            else if ((diff_1_0[7:7] == 1) && (diff_1_2[7:7] == 1)){
                hdr.ipv4.ttl = (bit<8>)meta.class_s1_t1;
            }
            else if ((diff_2_0[7:7] == 1) && (diff_2_1[7:7] == 1)){
                hdr.ipv4.ttl = (bit<8>)meta.class_s1_t2;
            }
            else{
                /* this is the case where no tree has a higher certainty - this hardly occurs.
                If it does occur, we mark such packets witt value of 255 for statistical purposes.*/
                hdr.ipv4.ttl = 255;
            }
            // End of first stage model - packet is forwarded.
            ipv4_forward(260);
        }

    } //END OF APPLY

} //END OF INGRESS CONTROL

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        /* we do not compute checksums because we used the ttl field for stats*/
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
#include "./include/egress.p4"

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;