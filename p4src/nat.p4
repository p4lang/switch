/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.

 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 * $Id: $
 *
 ******************************************************************************/
/*
 * NAT processing
 */

header_type nat_metadata_t {
    fields {
        ingress_nat_mode : 2;          /* 0: none, 1: inside, 2: outside */
        egress_nat_mode : 2;           /* nat mode of egress_bd */
        nat_nexthop : 16;              /* next hop from nat */
        nat_nexthop_type : 2;          /* ecmp or nexthop */
        nat_hit : 1;                   /* fwd and rewrite info from nat */
        nat_rewrite_index : 14;        /* NAT rewrite index */
        update_checksum : 1;           /* update tcp/udp checksum */
        update_inner_checksum : 1;     /* update inner tcp/udp checksum */
        l4_len : 16;                   /* l4 length */
    }
}

metadata nat_metadata_t nat_metadata;

#ifndef NAT_DISABLE
/*****************************************************************************/
/* Ingress NAT lookup - src, dst, twice                                      */
/*****************************************************************************/
/*
 * packet has matched source nat binding, provide rewrite index for source
 * ip/port rewrite
 */
action set_src_nat_rewrite_index(nat_rewrite_index) {
    modify_field(nat_metadata.nat_rewrite_index, nat_rewrite_index);
}

/*
 * packet has matched destination nat binding, provide nexthop index for
 * forwarding and rewrite index for destination ip/port rewrite
 */
action set_dst_nat_nexthop_index(nexthop_index, nexthop_type,
                                 nat_rewrite_index) {
    modify_field(nat_metadata.nat_nexthop, nexthop_index);
    modify_field(nat_metadata.nat_nexthop_type, nexthop_type);
    modify_field(nat_metadata.nat_rewrite_index, nat_rewrite_index);
    modify_field(nat_metadata.nat_hit, TRUE);
}

/*
 * packet has matched twice nat binding, provide nexthop index for forwarding,
 * and rewrite index for source and destination ip/port rewrite
 */
action set_twice_nat_nexthop_index(nexthop_index, nexthop_type,
                                   nat_rewrite_index) {
    modify_field(nat_metadata.nat_nexthop, nexthop_index);
    modify_field(nat_metadata.nat_nexthop_type, nexthop_type);
    modify_field(nat_metadata.nat_rewrite_index, nat_rewrite_index);
    modify_field(nat_metadata.nat_hit, TRUE);
}

table nat_src {
    reads {
        l3_metadata.vrf : exact;
        ipv4_metadata.lkp_ipv4_sa : exact;
        l3_metadata.lkp_ip_proto : exact;
        l3_metadata.lkp_l4_sport : exact;
    }
    actions {
        on_miss;
        set_src_nat_rewrite_index;
    }
    size : IP_NAT_TABLE_SIZE;
}

table nat_dst {
    reads {
        l3_metadata.vrf : exact;
        ipv4_metadata.lkp_ipv4_da : exact;
        l3_metadata.lkp_ip_proto : exact;
        l3_metadata.lkp_l4_dport : exact;
    }
    actions {
        on_miss;
        set_dst_nat_nexthop_index;
    }
    size : IP_NAT_TABLE_SIZE;
}

table nat_twice {
    reads {
        l3_metadata.vrf : exact;
        ipv4_metadata.lkp_ipv4_sa : exact;
        ipv4_metadata.lkp_ipv4_da : exact;
        l3_metadata.lkp_ip_proto : exact;
        l3_metadata.lkp_l4_sport : exact;
        l3_metadata.lkp_l4_dport : exact;
    }
    actions {
        on_miss;
        set_twice_nat_nexthop_index;
    }
    size : IP_NAT_TABLE_SIZE;
}

table nat_flow {
    reads {
        l3_metadata.vrf : ternary;
        ipv4_metadata.lkp_ipv4_sa : ternary;
        ipv4_metadata.lkp_ipv4_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        l3_metadata.lkp_l4_sport : ternary;
        l3_metadata.lkp_l4_dport : ternary;
    }
    actions {
        nop;
        set_src_nat_rewrite_index;
        set_dst_nat_nexthop_index;
        set_twice_nat_nexthop_index;
    }
    size : IP_NAT_FLOW_TABLE_SIZE;
}
#endif /* NAT_DISABLE */

control process_ingress_nat {
#ifndef NAT_DISABLE
    apply(nat_twice) {
        on_miss {
            apply(nat_dst) {
                on_miss {
                    apply(nat_src) {
                        on_miss {
                            apply(nat_flow);
                        }
                    }
                }
            }
        }
    }
#endif /* NAT DISABLE */
}


/*****************************************************************************/
/* Egress NAT rewrite                                                        */
/*****************************************************************************/
#ifndef NAT_DISABLE
action nat_update_l4_checksum() {
    modify_field(nat_metadata.update_checksum, 1);
    add(nat_metadata.l4_len, ipv4.totalLen, -20);
}

action set_nat_src_rewrite(src_ip) {
    modify_field(ipv4.srcAddr, src_ip);
    nat_update_l4_checksum();
}

action set_nat_dst_rewrite(dst_ip) {
    modify_field(ipv4.dstAddr, dst_ip);
    nat_update_l4_checksum();
}

action set_nat_src_dst_rewrite(src_ip, dst_ip) {
    modify_field(ipv4.srcAddr, src_ip);
    modify_field(ipv4.dstAddr, dst_ip);
    nat_update_l4_checksum();
}

action set_nat_src_udp_rewrite(src_ip, src_port) {
    modify_field(ipv4.srcAddr, src_ip);
    modify_field(udp.srcPort, src_port);
    nat_update_l4_checksum();
}

action set_nat_dst_udp_rewrite(dst_ip, dst_port) {
    modify_field(ipv4.dstAddr, dst_ip);
    modify_field(udp.dstPort, dst_port);
    nat_update_l4_checksum();
}

action set_nat_src_dst_udp_rewrite(src_ip, dst_ip, src_port, dst_port) {
    modify_field(ipv4.srcAddr, src_ip);
    modify_field(ipv4.dstAddr, dst_ip);
    modify_field(udp.srcPort, src_port);
    modify_field(udp.dstPort, dst_port);
    nat_update_l4_checksum();
}

action set_nat_src_tcp_rewrite(src_ip, src_port) {
    modify_field(ipv4.srcAddr, src_ip);
    modify_field(tcp.srcPort, src_port);
    nat_update_l4_checksum();
}

action set_nat_dst_tcp_rewrite(dst_ip, dst_port) {
    modify_field(ipv4.dstAddr, dst_ip);
    modify_field(tcp.dstPort, dst_port);
    nat_update_l4_checksum();
}

action set_nat_src_dst_tcp_rewrite(src_ip, dst_ip, src_port, dst_port) {
    modify_field(ipv4.srcAddr, src_ip);
    modify_field(ipv4.dstAddr, dst_ip);
    modify_field(tcp.srcPort, src_port);
    modify_field(tcp.dstPort, dst_port);
    nat_update_l4_checksum();
}

table egress_nat {
    reads {
        nat_metadata.nat_rewrite_index : exact;
    }
    actions {
        nop;
        set_nat_src_rewrite;
        set_nat_dst_rewrite;
        set_nat_src_dst_rewrite;
        set_nat_src_udp_rewrite;
        set_nat_dst_udp_rewrite;
        set_nat_src_dst_udp_rewrite;
        set_nat_src_tcp_rewrite;
        set_nat_dst_tcp_rewrite;
        set_nat_src_dst_tcp_rewrite;
    }
    size : EGRESS_NAT_TABLE_SIZE;
}
#endif /* NAT_DISABLE */

control process_egress_nat {
#ifndef NAT_DISABLE
    if ((nat_metadata.ingress_nat_mode != NAT_MODE_NONE) and
        (nat_metadata.ingress_nat_mode != nat_metadata.egress_nat_mode)) {
        apply(egress_nat);
    }
#endif /* NAT_DISABLE */
}
