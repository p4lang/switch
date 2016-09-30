/*
Copyright 2013-present Barefoot Networks, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * ACL processing : MAC, IPv4, IPv6, RACL/PBR
 */

/*
 * ACL metadata
 */
header_type acl_metadata_t {
    fields {
        acl_deny : 1;                          /* ifacl/vacl deny action */
        racl_deny : 1;                         /* racl deny action */
        acl_nexthop : 16;                      /* next hop from ifacl/vacl */
        racl_nexthop : 16;                     /* next hop from racl */
        acl_nexthop_type : 2;                  /* ecmp or nexthop */
        racl_nexthop_type : 2;                 /* ecmp or nexthop */
        acl_redirect :   1;                    /* ifacl/vacl redirect action */
        racl_redirect : 1;                     /* racl redirect action */
        if_label : 16;                         /* if label for acls */
        bd_label : 16;                         /* bd label for acls */
        acl_stats_index : 14;                  /* acl stats index */
        egress_if_label : 16;                  /* if label for egress acls */
        egress_bd_label : 16;                  /* bd label for egress acls */
        ingress_src_port_range_id : 8;         /* ingress src port range id */
        ingress_dst_port_range_id : 8;         /* ingress dst port range id */
        egress_src_port_range_id : 8;          /* egress src port range id */
        egress_dst_port_range_id : 8;          /* egress dst port range id */
    }
}

header_type i2e_metadata_t {
    fields {
        ingress_tstamp    : 32;
        mirror_session_id : 16;
    }
}

metadata acl_metadata_t acl_metadata;
metadata i2e_metadata_t i2e_metadata;

/*****************************************************************************/
/* Egress ACL l4 port range                                                  */
/*****************************************************************************/
#ifdef EGRESS_ACL_ENABLE
action set_egress_tcp_port_fields() {
    modify_field(l3_metadata.egress_l4_sport, tcp.srcPort);
    modify_field(l3_metadata.egress_l4_dport, tcp.dstPort);
}

action set_egress_udp_port_fields() {
    modify_field(l3_metadata.egress_l4_sport, udp.srcPort);
    modify_field(l3_metadata.egress_l4_dport, udp.dstPort);
}

action set_egress_icmp_port_fields() {
    modify_field(l3_metadata.egress_l4_sport, icmp.typeCode);
}

table egress_l4port_fields {
    reads {
        tcp : valid;
        udp : valid;
        icmp : valid;
    }
    actions {
        nop;
        set_egress_tcp_port_fields;
        set_egress_udp_port_fields;
        set_egress_icmp_port_fields;
    }
    size: EGRESS_PORT_LKP_FIELD_SIZE;
}

#ifndef ACL_RANGE_DISABLE
action set_egress_src_port_range_id(range_id) {
    modify_field(acl_metadata.egress_src_port_range_id, range_id);
}

table egress_l4_src_port {
    reads {
        l3_metadata.egress_l4_sport : range;
    }
    actions {
        nop;
        set_egress_src_port_range_id;
    }
    size: EGRESS_ACL_RANGE_TABLE_SIZE;
}

action set_egress_dst_port_range_id(range_id) {
    modify_field(acl_metadata.egress_dst_port_range_id, range_id);
}

table egress_l4_dst_port {
    reads {
        l3_metadata.egress_l4_dport : range;
    }
    actions {
        nop;
        set_egress_dst_port_range_id;
    }
    size: EGRESS_ACL_RANGE_TABLE_SIZE;
}

#endif /* ACL_RANGE_DISABLE */
#endif /* EGRESS_ACL_ENABLE */

control process_egress_l4port {
#ifdef EGRESS_ACL_ENABLE
    apply(egress_l4port_fields);
#ifndef ACL_RANGE_DISABLE
    apply(egress_l4_src_port);
    apply(egress_l4_dst_port);
#endif /* ACL_RANGE_DISABLE */
#endif /* EGRESS_ACL_ENABLE */
}

/*****************************************************************************/
/* Ingress ACL l4 port range                                                 */
/*****************************************************************************/
#ifndef ACL_RANGE_DISABLE
action set_ingress_src_port_range_id(range_id) {
    modify_field(acl_metadata.ingress_src_port_range_id, range_id);
}

table ingress_l4_src_port {
    reads {
        l3_metadata.lkp_l4_sport : range;
    }
    actions {
        nop;
        set_ingress_src_port_range_id;
    }
    size: INGRESS_ACL_RANGE_TABLE_SIZE;
}

action set_ingress_dst_port_range_id(range_id) {
    modify_field(acl_metadata.ingress_dst_port_range_id, range_id);
}

table ingress_l4_dst_port {
    reads {
        l3_metadata.lkp_l4_dport : range;
    }
    actions {
        nop;
        set_ingress_dst_port_range_id;
    }
    size: INGRESS_ACL_RANGE_TABLE_SIZE;
}
#endif /* ACL_RANGE_DISABLE */

control process_ingress_l4port {
#ifndef ACL_RANGE_DISABLE
    apply(ingress_l4_src_port);
    apply(ingress_l4_dst_port);
#endif /* ACL_RANGE_DISABLE */
}

/*****************************************************************************/
/* ACL Actions                                                               */
/*****************************************************************************/
action acl_deny(acl_stats_index, acl_meter_index, acl_copy_reason,
                nat_mode, ingress_cos, tc, color) {
    modify_field(acl_metadata.acl_deny, TRUE);
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
    modify_field(meter_metadata.meter_index, acl_meter_index);
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
    modify_field(nat_metadata.ingress_nat_mode, nat_mode);
#ifndef QOS_DISABLE
    modify_field(intrinsic_metadata.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* QOS_DISABLE */

}

action acl_permit(acl_stats_index, acl_meter_index, acl_copy_reason,
                  nat_mode, ingress_cos, tc, color) {
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
    modify_field(meter_metadata.meter_index, acl_meter_index);
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
    modify_field(nat_metadata.ingress_nat_mode, nat_mode);
#ifndef QOS_DISABLE
    modify_field(intrinsic_metadata.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* QOS_DISABLE */
}

field_list i2e_mirror_info {
    i2e_metadata.ingress_tstamp;
    i2e_metadata.mirror_session_id;
}

field_list e2e_mirror_info {
    i2e_metadata.ingress_tstamp;
    i2e_metadata.mirror_session_id;
}

action acl_mirror(session_id, acl_stats_index, acl_meter_index, nat_mode,
                  ingress_cos, tc, color) {
    modify_field(i2e_metadata.mirror_session_id, session_id);
    clone_ingress_pkt_to_egress(session_id, i2e_mirror_info);
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
    modify_field(meter_metadata.meter_index, acl_meter_index);
    modify_field(nat_metadata.ingress_nat_mode, nat_mode);
#ifndef QOS_DISABLE
    modify_field(intrinsic_metadata.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* QOS_DISABLE */
}

action acl_redirect_nexthop(nexthop_index, acl_stats_index, acl_meter_index,
                            acl_copy_reason, nat_mode,
                            ingress_cos, tc, color) {
    modify_field(acl_metadata.acl_redirect, TRUE);
    modify_field(acl_metadata.acl_nexthop, nexthop_index);
    modify_field(acl_metadata.acl_nexthop_type, NEXTHOP_TYPE_SIMPLE);
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
    modify_field(meter_metadata.meter_index, acl_meter_index);
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
    modify_field(nat_metadata.ingress_nat_mode, nat_mode);
#ifndef QOS_DISABLE
    modify_field(intrinsic_metadata.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* QOS_DISABLE */
}

action acl_redirect_ecmp(ecmp_index, acl_stats_index, acl_meter_index,
                         acl_copy_reason, nat_mode,
                         ingress_cos, tc, color) {
    modify_field(acl_metadata.acl_redirect, TRUE);
    modify_field(acl_metadata.acl_nexthop, ecmp_index);
    modify_field(acl_metadata.acl_nexthop_type, NEXTHOP_TYPE_ECMP);
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
    modify_field(meter_metadata.meter_index, acl_meter_index);
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
    modify_field(nat_metadata.ingress_nat_mode, nat_mode);
#ifndef QOS_DISABLE
    modify_field(intrinsic_metadata.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* QOS_DISABLE */
}



/*****************************************************************************/
/* MAC ACL                                                                   */
/*****************************************************************************/
#ifndef L2_DISABLE
table mac_acl {
    reads {
        acl_metadata.if_label : ternary;
        acl_metadata.bd_label : ternary;

        l2_metadata.lkp_mac_sa : ternary;
        l2_metadata.lkp_mac_da : ternary;
        l2_metadata.lkp_mac_type : ternary;
    }
    actions {
        nop;
        acl_deny;
        acl_permit;
        acl_redirect_nexthop;
        acl_redirect_ecmp;
#ifndef MIRROR_DISABLE
        acl_mirror;
#endif /* MIRROR_DISABLE */
    }
    size : INGRESS_MAC_ACL_TABLE_SIZE;
}
#endif /* L2_DISABLE */

control process_mac_acl {
#ifndef L2_DISABLE
    if (DO_LOOKUP(ACL)) {
        apply(mac_acl);
    }
#endif /* L2_DISABLE */
}

/*****************************************************************************/
/* IPv4 ACL                                                                  */
/*****************************************************************************/
#ifndef IPV4_DISABLE
table ip_acl {
    reads {
        acl_metadata.if_label : ternary;
        acl_metadata.bd_label : ternary;

        ipv4_metadata.lkp_ipv4_sa : ternary;
        ipv4_metadata.lkp_ipv4_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        acl_metadata.ingress_src_port_range_id : exact;
        acl_metadata.ingress_dst_port_range_id : exact;

        tcp.flags : ternary;
        l3_metadata.lkp_ip_ttl : ternary;
    }
    actions {
        nop;
        acl_deny;
        acl_permit;
        acl_redirect_nexthop;
        acl_redirect_ecmp;
#ifndef MIRROR_DISABLE
        acl_mirror;
#endif /* MIRROR_DISABLE */
    }
    size : INGRESS_IP_ACL_TABLE_SIZE;
}
#endif /* IPV4_DISABLE */


/*****************************************************************************/
/* IPv6 ACL                                                                  */
/*****************************************************************************/
#ifndef IPV6_DISABLE
table ipv6_acl {
    reads {
        acl_metadata.if_label : ternary;
        acl_metadata.bd_label : ternary;

        ipv6_metadata.lkp_ipv6_sa : ternary;
        ipv6_metadata.lkp_ipv6_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        acl_metadata.ingress_src_port_range_id : exact;
        acl_metadata.ingress_dst_port_range_id : exact;

        tcp.flags : ternary;
        l3_metadata.lkp_ip_ttl : ternary;
    }
    actions {
        nop;
        acl_deny;
        acl_permit;
        acl_redirect_nexthop;
        acl_redirect_ecmp;
#ifndef MIRROR_DISABLE
        acl_mirror;
#endif /* MIRROR_DISABLE */
    }
    size : INGRESS_IPV6_ACL_TABLE_SIZE;
}
#endif /* IPV6_DISABLE */


/*****************************************************************************/
/* ACL Control flow                                                          */
/*****************************************************************************/
control process_ip_acl {
    if (DO_LOOKUP(ACL)) {
        if (l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
#ifndef IPV4_DISABLE
            apply(ip_acl);
#endif /* IPV4_DISABLE */
        } else {
            if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
#ifndef IPV6_DISABLE
                apply(ipv6_acl);
#endif /* IPV6_DISABLE */
            }
        }
    }
}

/*****************************************************************************/
/* RACL actions                                                              */
/*****************************************************************************/
action racl_deny(acl_stats_index, acl_copy_reason,
                 ingress_cos, tc, color) {
    modify_field(acl_metadata.racl_deny, TRUE);
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#ifndef QOS_DISABLE
    modify_field(intrinsic_metadata.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* QOS_DISABLE */
}

action racl_permit(acl_stats_index, acl_copy_reason,
                   ingress_cos, tc, color) {
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#ifndef QOS_DISABLE
    modify_field(intrinsic_metadata.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* QOS_DISABLE */
}

action racl_redirect_nexthop(nexthop_index, acl_stats_index,
                             acl_copy_reason,
                             ingress_cos, tc, color) {
    modify_field(acl_metadata.racl_redirect, TRUE);
    modify_field(acl_metadata.racl_nexthop, nexthop_index);
    modify_field(acl_metadata.racl_nexthop_type, NEXTHOP_TYPE_SIMPLE);
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#ifndef QOS_DISABLE
    modify_field(intrinsic_metadata.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* QOS_DISABLE */
}

action racl_redirect_ecmp(ecmp_index, acl_stats_index,
                          acl_copy_reason,
                          ingress_cos, tc, color) {
    modify_field(acl_metadata.racl_redirect, TRUE);
    modify_field(acl_metadata.racl_nexthop, ecmp_index);
    modify_field(acl_metadata.racl_nexthop_type, NEXTHOP_TYPE_ECMP);
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#ifndef QOS_DISABLE
    modify_field(intrinsic_metadata.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* QOS_DISABLE */
}


/*****************************************************************************/
/* IPv4 RACL                                                                 */
/*****************************************************************************/
#ifndef IPV4_DISABLE
table ipv4_racl {
    reads {
        acl_metadata.bd_label : ternary;

        ipv4_metadata.lkp_ipv4_sa : ternary;
        ipv4_metadata.lkp_ipv4_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        acl_metadata.ingress_src_port_range_id : exact;
        acl_metadata.ingress_dst_port_range_id : exact;
    }
    actions {
        nop;
        racl_deny;
        racl_permit;
        racl_redirect_nexthop;
        racl_redirect_ecmp;
    }
    size : INGRESS_IP_RACL_TABLE_SIZE;
}
#endif /* IPV4_DISABLE */

control process_ipv4_racl {
#ifndef IPV4_DISABLE
    apply(ipv4_racl);
#endif /* IPV4_DISABLE */
}

/*****************************************************************************/
/* IPv6 RACL                                                                 */
/*****************************************************************************/
#ifndef IPV6_DISABLE
table ipv6_racl {
    reads {
        acl_metadata.bd_label : ternary;

        ipv6_metadata.lkp_ipv6_sa : ternary;
        ipv6_metadata.lkp_ipv6_da : ternary;
        l3_metadata.lkp_ip_proto : ternary;
        acl_metadata.ingress_src_port_range_id : exact;
        acl_metadata.ingress_dst_port_range_id : exact;
    }
    actions {
        nop;
        racl_deny;
        racl_permit;
        racl_redirect_nexthop;
        racl_redirect_ecmp;
    }
    size : INGRESS_IPV6_RACL_TABLE_SIZE;
}
#endif /* IPV6_DISABLE */

control process_ipv6_racl {
#ifndef IPV6_DISABLE
    apply(ipv6_racl);
#endif /* IPV6_DISABLE */
}

/*****************************************************************************/
/* ACL stats                                                                 */
/*****************************************************************************/
#ifndef STATS_DISABLE
counter acl_stats {
    type : packets_and_bytes;
    instance_count : ACL_STATS_TABLE_SIZE;
    min_width : 16;
}

action acl_stats_update() {
    count(acl_stats, acl_metadata.acl_stats_index);
}

table acl_stats {
    actions {
        acl_stats_update;
    }
    size : ACL_STATS_TABLE_SIZE;
}
#endif /* STATS_DISABLE */

control process_ingress_acl_stats {
#ifndef STATS_DISABLE
    apply(acl_stats);
#endif /* STATS_DISABLE */
}

/*****************************************************************************/
/* CoPP                                                                      */
/*****************************************************************************/
#ifndef METER_DISABLE
meter copp {
    type: bytes;
    static: system_acl;
    result: intrinsic_metadata.packet_color;
    instance_count: COPP_TABLE_SIZE;
}
#endif /* METER_DISABLE */

/*****************************************************************************/
/* System ACL                                                                */
/*****************************************************************************/
counter drop_stats {
    type : packets;
    instance_count : DROP_STATS_TABLE_SIZE;
}

counter drop_stats_2 {
    type : packets;
    instance_count : DROP_STATS_TABLE_SIZE;
}

field_list mirror_info {
    ingress_metadata.ifindex;
    ingress_metadata.drop_reason;
}

action negative_mirror(session_id) {
#ifndef __TARGET_BMV2__
    clone_ingress_pkt_to_egress(session_id, mirror_info);
#endif
    drop();
}

action redirect_to_cpu_with_reason(reason_code, qid, meter_id, icos) {
    copy_to_cpu_with_reason(reason_code, qid, meter_id, icos);
    drop();
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
}

action redirect_to_cpu(qid, meter_id, icos) {
    copy_to_cpu(qid, meter_id, icos);
    drop();
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
}

field_list cpu_info {
    ingress_metadata.bd;
    ingress_metadata.ifindex;
    fabric_metadata.reason_code;
    ingress_metadata.ingress_port;
#ifdef __TARGET_BMV2__
    standard_metadata.instance_type;
#endif
}

action copy_to_cpu(qid, meter_id, icos) {
    modify_field(intrinsic_metadata.qid, qid);
    modify_field(intrinsic_metadata.ingress_cos, icos); 
    clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, cpu_info);
    execute_meter(copp, meter_id, intrinsic_metadata.packet_color);
}

action copy_to_cpu_with_reason(reason_code, qid, meter_id, icos) {
    modify_field(fabric_metadata.reason_code, reason_code);
    copy_to_cpu(qid, meter_id, icos);
}

action drop_packet() {
    drop();
}

action drop_packet_with_reason(drop_reason) {
    count(drop_stats, drop_reason);
    drop();
}

table system_acl {
    reads {
        acl_metadata.if_label : ternary;
        acl_metadata.bd_label : ternary;

        ingress_metadata.ifindex : ternary;

        /* drop reasons */
        l2_metadata.lkp_mac_type : ternary;
        l2_metadata.port_vlan_mapping_miss : ternary;
        security_metadata.ipsg_check_fail : ternary;
        acl_metadata.acl_deny : ternary;
        acl_metadata.racl_deny: ternary;
        l3_metadata.urpf_check_fail : ternary;
        ingress_metadata.drop_flag : ternary;

        l3_metadata.l3_copy : ternary;

        l3_metadata.rmac_hit : ternary;

        /*
         * other checks, routed link_local packet, l3 same if check,
         * expired ttl
         */
        l3_metadata.routed : ternary;
        ipv6_metadata.ipv6_src_is_link_local : ternary;
        l2_metadata.same_if_check : ternary;
        tunnel_metadata.tunnel_if_check : ternary;
        l3_metadata.same_bd_check : ternary;
        l3_metadata.lkp_ip_ttl : ternary;
        l2_metadata.stp_state : ternary;
        ingress_metadata.control_frame: ternary;
        ipv4_metadata.ipv4_unicast_enabled : ternary;
        ipv6_metadata.ipv6_unicast_enabled : ternary;

        /* egress information */
        ingress_metadata.egress_ifindex : ternary;

        fabric_metadata.reason_code : ternary;

    }
    actions {
        nop;
        redirect_to_cpu;
        redirect_to_cpu_with_reason;
        copy_to_cpu;
        copy_to_cpu_with_reason;
        drop_packet;
        drop_packet_with_reason;
        negative_mirror;
    }
    size : SYSTEM_ACL_SIZE;
}

action drop_stats_update() {
    count(drop_stats_2, ingress_metadata.drop_reason);
}

table drop_stats {
    actions {
        drop_stats_update;
    }
    size : DROP_STATS_TABLE_SIZE;
}

control process_system_acl {
    if (DO_LOOKUP(SYSTEM_ACL)) {
        apply(system_acl);
        if (ingress_metadata.drop_flag == TRUE) {
            apply(drop_stats);
        }
    }
}

/*****************************************************************************/
/* Egress ACL                                                                */
/*****************************************************************************/

#ifdef EGRESS_ACL_ENABLE

/*****************************************************************************/
/* Egress ACL Actions                                                        */
/*****************************************************************************/
action egress_acl_deny(acl_copy_reason) {
    modify_field(acl_metadata.acl_deny, TRUE);
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
}

action egress_acl_permit(acl_copy_reason) {
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
}

/*****************************************************************************/
/* Egress Mac ACL                                                            */
/*****************************************************************************/

#ifndef L2_DISABLE
table egress_mac_acl {
    reads {
        acl_metadata.egress_if_label : ternary;
        acl_metadata.egress_bd_label : ternary;

        ethernet.srcAddr : ternary;
        ethernet.dstAddr : ternary;
        ethernet.etherType: ternary;
    }
    actions {
        nop;
        egress_acl_deny;
        egress_acl_permit;
    }
    size : EGRESS_MAC_ACL_TABLE_SIZE;
}
#endif /* L2_DISABLE */

/*****************************************************************************/
/* Egress IPv4 ACL                                                           */
/*****************************************************************************/
#ifndef IPV4_DISABLE
table egress_ip_acl {
    reads {
        acl_metadata.egress_if_label : ternary;
        acl_metadata.egress_bd_label : ternary;

        ipv4.srcAddr : ternary;
        ipv4.dstAddr : ternary;
        ipv4.protocol : ternary;
        acl_metadata.egress_src_port_range_id : exact;
        acl_metadata.egress_dst_port_range_id : exact;
    }
    actions {
        nop;
        egress_acl_deny;
        egress_acl_permit;
    }
    size : EGRESS_IP_ACL_TABLE_SIZE;
}
#endif /* IPV4_DISABLE */

/*****************************************************************************/
/* Egress IPv6 ACL                                                           */
/*****************************************************************************/
#ifndef IPV6_DISABLE
table egress_ipv6_acl {
    reads {
        acl_metadata.egress_if_label : ternary;
        acl_metadata.egress_bd_label : ternary;

        ipv6.srcAddr : ternary;
        ipv6.dstAddr : ternary;
        ipv6.nextHdr : ternary;
        acl_metadata.egress_src_port_range_id : exact;
        acl_metadata.egress_dst_port_range_id : exact;
    }
    actions {
        nop;
        egress_acl_deny;
        egress_acl_permit;
    }
    size : EGRESS_IPV6_ACL_TABLE_SIZE;
}

#endif /* IPV6_DISABLE */
#endif /* EGRESS_ACL_ENABLE */

control process_egress_acl {
#ifdef EGRESS_ACL_ENABLE
    if (valid(ipv4)) {
#ifndef IPV4_DISABLE
        apply(egress_ip_acl);
#endif /* IPV4_DISABLE */
    } else {
        if (valid(ipv6)) {
#ifndef IPV6_DISABLE
            apply(egress_ipv6_acl);
#endif /* IPV6_DISABLE */
        } else {
            apply(egress_mac_acl);
        }
    }
#endif /* EGRESS_ACL_ENABLE */
}

action egress_mirror(session_id) {
    modify_field(i2e_metadata.mirror_session_id, session_id);
    clone_egress_pkt_to_egress(session_id, e2e_mirror_info);
}

action egress_mirror_drop(session_id) {
    egress_mirror(session_id);
    drop();
}

action egress_copy_to_cpu() {
    clone_egress_pkt_to_egress(CPU_MIRROR_SESSION_ID, cpu_info);
}

action egress_redirect_to_cpu() {
    egress_copy_to_cpu();
    drop();
}

action egress_copy_to_cpu_with_reason(reason_code) {
    modify_field(fabric_metadata.reason_code, reason_code);
    egress_copy_to_cpu();
}

action egress_redirect_to_cpu_with_reason(reason_code) {
    egress_copy_to_cpu_with_reason(reason_code);
    drop();
}
table egress_system_acl {
    reads {
        fabric_metadata.reason_code : ternary;
        standard_metadata.egress_port : ternary;
        intrinsic_metadata.deflection_flag : ternary;
        l3_metadata.l3_mtu_check : ternary;
        acl_metadata.acl_deny : ternary;
    }
    actions {
        nop;
        drop_packet;
        egress_copy_to_cpu;
        egress_redirect_to_cpu;
        egress_copy_to_cpu_with_reason;
        egress_redirect_to_cpu_with_reason;
        egress_mirror;
        egress_mirror_drop;
    }
    size : EGRESS_ACL_TABLE_SIZE;
}

control process_egress_system_acl {
    if (egress_metadata.bypass == FALSE) {
        apply(egress_system_acl);
    }
}
