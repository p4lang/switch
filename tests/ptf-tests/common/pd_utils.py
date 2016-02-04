from ptf.testutils import *
from ptf.thriftutils import *
import ptf.dataplane as dataplane
import pd_base_tests

from p4_pd_rpc.ttypes import *
from res_pd_rpc.ttypes import *
from mc_pd_rpc.ttypes import *

default_entries = {}
stats_enabled = 1

def port_to_pipe(port):
    return port >> 7

def port_to_pipe_local_id(port):
    return port & 0x7F

def port_to_bit_idx(port):
    pipe = port_to_pipe(port)
    index = port_to_pipe_local_id(port)
    return 72 * pipe + index

def pipe_port_to_asic_port(pipe, port):
    return (pipe << 7) | port

def init_pre(mc, sess_hdl, num_pipes, start_mcidx, chan_per_port, flood_mcidx):
    dev_id = 0
    lag_map = set_port_or_lag_bitmap(256, [])
    for pipe in range(0, num_pipes):
        for port in range(0, 72):
            asic_port = pipe_port_to_asic_port(pipe, port)
            mcidx = start_mcidx + asic_port
            mc_grp_hdl = mc.mc_mgrp_create(sess_hdl, dev_id, mcidx)
            port_map = set_port_or_lag_bitmap(288, [asic_port])
            mc_node_hdl = mc.mc_node_create(sess_hdl, dev_id, 0, port_map,
                                            lag_map)
            mc.mc_associate_node(sess_hdl, dev_id, mc_grp_hdl, mc_node_hdl, 0, 0)

    # program flood mcidx
    flood_ports = []
    for pipe in range(0, num_pipes):
        flood_ports += range((pipe << 7), ((pipe << 7)+64), 4/chan_per_port)

    mc_grp_hdl = mc.mc_mgrp_create(sess_hdl, dev_id, flood_mcidx)
    port_map = set_port_or_lag_bitmap(288, flood_ports)
    mc_node_hdl = mc.mc_node_create(sess_hdl, dev_id, 0, port_map, lag_map)
    mc.mc_associate_node(sess_hdl, dev_id, mc_grp_hdl, mc_node_hdl, 0, 0)

def set_port_or_lag_bitmap(bit_map_size, indicies):
    bit_map = [0] * ((bit_map_size+7)/8)
    for i in indicies:
        index = port_to_bit_idx(i)
        bit_map[index/8] = (bit_map[index/8] | (1 << (index%8))) & 0xFF
    return bytes_to_string(bit_map)


def populate_default_fabric_entries(client, sess_hdl, dev_tgt, ipv6_enabled=0,
                                    acl_enabled=0, tunnel_enabled=0):
    client.validate_outer_ethernet_set_default_action_set_valid_outer_unicast_packet_untagged(
        sess_hdl, dev_tgt)
    client.validate_outer_ipv4_packet_set_default_action_set_valid_outer_ipv4_packet(
        sess_hdl, dev_tgt)
    if ipv6_enabled:
        client.validate_outer_ipv6_packet_set_default_action_set_valid_outer_ipv6_packet(
            sess_hdl, dev_tgt)
    client.smac_set_default_action_smac_miss(sess_hdl, dev_tgt)
    client.learn_notify_set_default_action_nop(sess_hdl, dev_tgt)
    client.dmac_set_default_action_dmac_miss(sess_hdl, dev_tgt)
    client.rmac_set_default_action_rmac_miss(sess_hdl, dev_tgt)
    client.ipv4_fib_set_default_action_on_miss(sess_hdl, dev_tgt)
    client.fwd_result_set_default_action_nop(sess_hdl, dev_tgt)
    client.nexthop_set_default_action_nop(sess_hdl, dev_tgt)
    #client.egress_internal_header_rewrite_set_default_action_strip_internal_header(
    #    sess_hdl, dev_tgt)
    client.fabric_ingress_dst_lkp_set_default_action_nop(sess_hdl, dev_tgt)
    client.fabric_ingress_src_lkp_set_default_action_nop(sess_hdl, dev_tgt)
    mbr_hdl = client.fabric_lag_action_profile_add_member_with_nop(
        sess_hdl, dev_tgt)
    client.fabric_lag_set_default_entry(sess_hdl, dev_tgt, mbr_hdl)
    mbr_hdl = client.lag_action_profile_add_member_with_set_lag_miss(
        sess_hdl, dev_tgt)
    client.lag_group_set_default_entry(sess_hdl, dev_tgt, mbr_hdl)
    client.vlan_decap_set_default_action_nop(sess_hdl, dev_tgt)
    if acl_enabled:
        client.ip_acl_set_default_action_nop(sess_hdl, dev_tgt)
        client.ipv4_racl_set_default_action_nop(sess_hdl, dev_tgt)
        client.egress_acl_set_default_action_nop(sess_hdl, dev_tgt)
        client.qos_set_default_action_nop(sess_hdl, dev_tgt)
    client.validate_packet_set_default_action_nop(sess_hdl, dev_tgt)
    if tunnel_enabled:
        client.outer_rmac_set_default_action_on_miss(sess_hdl, dev_tgt)
        client.ipv4_src_vtep_set_default_action_on_miss(sess_hdl, dev_tgt)
        client.ipv4_dest_vtep_set_default_action_nop(sess_hdl, dev_tgt)
        client.tunnel_src_rewrite_set_default_action_nop(sess_hdl, dev_tgt)
        client.tunnel_dst_rewrite_set_default_action_nop(sess_hdl, dev_tgt)
        client.tunnel_smac_rewrite_set_default_action_nop(sess_hdl, dev_tgt)
        client.tunnel_dmac_rewrite_set_default_action_nop(sess_hdl, dev_tgt)
        client.tunnel_miss_set_default_action_tunnel_lookup_miss(
            sess_hdl, dev_tgt)
    if ipv6_enabled and tunnel_enabled:
        client.ipv6_src_vtep_set_default_action_nop(sess_hdl, dev_tgt)
        client.ipv6_dest_vtep_set_default_action_nop(sess_hdl, dev_tgt)
    if ipv6_enabled and acl_enabled:
        client.ipv6_acl_set_default_action_nop(sess_hdl, dev_tgt)
        client.ipv6_racl_set_default_action_nop(sess_hdl, dev_tgt)
    match_spec = dc_compute_ipv4_hashes_match_spec_t(
        ingress_metadata_drop_flag=0)
    client.compute_ipv4_hashes_table_add_with_compute_lkp_ipv4_hash(
        sess_hdl, dev_tgt, match_spec)
    if ipv6_enabled == 1:
        match_spec = dc_compute_ipv6_hashes_match_spec_t(
            ingress_metadata_drop_flag=0)
        client.compute_ipv6_hashes_table_add_with_compute_lkp_ipv6_hash(
            sess_hdl, dev_tgt, match_spec)
    match_spec = dc_compute_non_ip_hashes_match_spec_t(
        ingress_metadata_drop_flag=0)
    client.compute_non_ip_hashes_table_add_with_compute_lkp_non_ip_hash(
        sess_hdl, dev_tgt, match_spec)
    client.egress_vni_set_default_action_nop(sess_hdl, dev_tgt)
    client.system_acl_set_default_action_nop(sess_hdl, dev_tgt)
    client.outer_ipv4_multicast_set_default_action_nop(sess_hdl, dev_tgt)
    #client.storm_control_set_default_action_nop(sess_hdl, dev_tgt)
    client.egress_vlan_xlate_set_default_action_set_egress_packet_vlan_untagged(
        sess_hdl, dev_tgt)
    client.egress_filter_set_default_action_set_egress_filter_drop(
        sess_hdl, dev_tgt)
    if stats_enabled:
        client.ingress_bd_stats_set_default_action_update_ingress_bd_stats(
            sess_hdl, dev_tgt)

def populate_default_entries(client, sess_hdl, dev_tgt, ipv6_enabled,
    acl_enabled, tunnel_enabled, multicast_enabled, int_enabled):
    index = 0
    action_spec = dc_set_config_parameters_action_spec_t(
                                    action_enable_dod=0)
    client.switch_config_params_set_default_action_set_config_parameters(
                                     sess_hdl, dev_tgt, action_spec)
    client.validate_outer_ethernet_set_default_action_set_valid_outer_unicast_packet_untagged(
                                     sess_hdl, dev_tgt)
    client.validate_outer_ipv4_packet_set_default_action_set_valid_outer_ipv4_packet(
                                     sess_hdl, dev_tgt)
    if ipv6_enabled:
        client.validate_outer_ipv6_packet_set_default_action_set_valid_outer_ipv6_packet(
                                     sess_hdl, dev_tgt)
    client.smac_set_default_action_smac_miss(
                                     sess_hdl, dev_tgt)
    client.dmac_set_default_action_dmac_miss(
                                     sess_hdl, dev_tgt)
    client.learn_notify_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.rmac_set_default_action_rmac_miss(
                                     sess_hdl, dev_tgt)
    client.ipv4_fib_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
    client.fwd_result_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.nexthop_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.rid_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.rewrite_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.egress_vlan_xlate_set_default_action_set_egress_packet_vlan_untagged(
                                     sess_hdl, dev_tgt)
    client.egress_filter_set_default_action_set_egress_filter_drop(
                                     sess_hdl, dev_tgt)
    client.validate_packet_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.storm_control_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.storm_control_stats_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    meter_spec = dc_bytes_meter_spec_t(
                                     cir_kbps=0,
                                     cburst_kbits=0,
                                     pir_kbps=0,
                                     pburst_kbits=0,
                                     color_aware=False)
    client.meter_index_set_default_action_nop(
                                     sess_hdl, dev_tgt, meter_spec)
    client.meter_action_set_default_action_meter_permit(
                                     sess_hdl, dev_tgt)

    client.vlan_decap_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.replica_type_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    client.rewrite_set_default_action_set_l2_rewrite(
                                     sess_hdl, dev_tgt)
    client.egress_port_mapping_set_default_action_egress_port_type_normal(
                                     sess_hdl, dev_tgt)
    client.mtu_set_default_action_mtu_miss(
                                     sess_hdl, dev_tgt)

    mbr_hdl = client.fabric_lag_action_profile_add_member_with_nop(
                                     sess_hdl, dev_tgt)
    client.fabric_lag_set_default_entry(
                                     sess_hdl, dev_tgt, mbr_hdl)
    entry_hdl = client.compute_ipv4_hashes_set_default_action_compute_lkp_ipv4_hash(
                                     sess_hdl, dev_tgt)
    entry_hdl = client.compute_ipv6_hashes_set_default_action_compute_lkp_ipv6_hash(
                                     sess_hdl, dev_tgt)
    entry_hdl = client.compute_non_ip_hashes_set_default_action_compute_lkp_non_ip_hash(
                                     sess_hdl, dev_tgt)
    entry_hdl = client.compute_other_hashes_set_default_action_computed_two_hashes(
                                     sess_hdl, dev_tgt)
    client.system_acl_set_default_action_nop(
                                     sess_hdl, dev_tgt)

    if acl_enabled:
        client.ip_acl_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.ipv4_racl_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.egress_acl_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.qos_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.acl_stats_set_default_action_acl_stats_update(
                                     sess_hdl, dev_tgt)
    if tunnel_enabled:
        client.outer_rmac_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
        client.ipv4_src_vtep_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
        client.ipv4_dest_vtep_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.tunnel_mtu_set_default_action_tunnel_mtu_miss(
                                     sess_hdl, dev_tgt)
        client.tunnel_miss_set_default_action_tunnel_lookup_miss(
                                     sess_hdl, dev_tgt)
    client.egress_bd_map_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    if ipv6_enabled and tunnel_enabled:
        client.ipv6_src_vtep_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
        client.ipv6_dest_vtep_set_default_action_nop(
                                     sess_hdl, dev_tgt)
    if ipv6_enabled and acl_enabled:
        client.ipv6_acl_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.ipv6_racl_set_default_action_nop(
                                     sess_hdl, dev_tgt)

    if multicast_enabled:
        client.outer_ipv4_multicast_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
        client.outer_ipv4_multicast_star_g_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.ipv4_multicast_bridge_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
        client.ipv4_multicast_bridge_star_g_set_default_action_nop(
                                     sess_hdl, dev_tgt)
        client.ipv4_multicast_route_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
        client.ipv4_multicast_route_star_g_set_default_action_multicast_route_star_g_miss(
                                     sess_hdl, dev_tgt)
        if ipv6_enabled:
            client.outer_ipv6_multicast_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
            client.outer_ipv6_multicast_star_g_set_default_action_nop(
                                     sess_hdl, dev_tgt)
            client.ipv6_multicast_bridge_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
            client.ipv6_multicast_bridge_star_g_set_default_action_nop(
                                     sess_hdl, dev_tgt)
            client.ipv6_multicast_route_set_default_action_on_miss(
                                     sess_hdl, dev_tgt)
            client.ipv6_multicast_route_star_g_set_default_action_multicast_route_star_g_miss(
                                     sess_hdl, dev_tgt)

    if stats_enabled:
        client.ingress_bd_stats_set_default_action_update_ingress_bd_stats(
                                     sess_hdl, dev_tgt)
        client.egress_bd_stats_set_default_action_nop(
                                     sess_hdl, dev_tgt)

    if int_enabled:
        client.int_terminate_set_default_action_int_no_sink(sess_hdl, dev_tgt)
        client.int_sink_update_outer_set_default_action_nop(sess_hdl, dev_tgt)
        client.int_insert_set_default_action_int_reset(sess_hdl, dev_tgt)
        # following table are not applied to non-int packet.. but set the
        # default actions for future
        client.int_source_set_default_action_int_set_no_src(sess_hdl, dev_tgt)
        client.int_meta_header_update_set_default_action_int_update_total_hop_cnt(sess_hdl,
                                                                                  dev_tgt)
        client.int_outer_encap_set_default_action_nop(sess_hdl, dev_tgt)

def delete_default_entries(client, sess_hdl, dev_id):
    return

def populate_init_fabric_entries(client, sess_hdl, dev_tgt, inner_rmac_group,
    outer_rmac_group, rmac, rewrite_index, tunnel_enabled=0,
    unicast_tunnel_index=0, multicast_tunnel_index=0, fabric_mgid=0):
    match_spec = dc_smac_rewrite_match_spec_t(
        egress_metadata_smac_idx=rewrite_index)
    action_spec = dc_rewrite_smac_action_spec_t(
        action_smac=macAddr_to_string(rmac))
    client.smac_rewrite_table_add_with_rewrite_smac(
        sess_hdl, dev_tgt, match_spec, action_spec)

    match_spec = dc_fwd_result_match_spec_t(
        l2_metadata_l2_redirect=0,
        l2_metadata_l2_redirect_mask=0,
        acl_metadata_acl_redirect=0,
        acl_metadata_acl_redirect_mask=0,
        acl_metadata_racl_redirect=0,
        acl_metadata_racl_redirect_mask=0,
        l3_metadata_rmac_hit=1,
        l3_metadata_rmac_hit_mask=1,
        l3_metadata_fib_hit=1,
        l3_metadata_fib_hit_mask=1,
        l2_metadata_lkp_pkt_type=0,
        l2_metadata_lkp_pkt_type_mask=0,
        l3_metadata_lkp_ip_type=0,
        l3_metadata_lkp_ip_type_mask=0,
        multicast_metadata_igmp_snooping_enabled=0,
        multicast_metadata_igmp_snooping_enabled_mask=0,
        multicast_metadata_mld_snooping_enabled=0,
        multicast_metadata_mld_snooping_enabled_mask=0,
        multicast_metadata_mcast_route_hit=0,
        multicast_metadata_mcast_route_hit_mask=0,
        multicast_metadata_mcast_bridge_hit=0,
        multicast_metadata_mcast_bridge_hit_mask=0,
        multicast_metadata_mcast_rpf_group=0,
        multicast_metadata_mcast_rpf_group_mask=0,
        multicast_metadata_mcast_mode=0,
        multicast_metadata_mcast_mode_mask=0)
    client.fwd_result_table_add_with_set_fib_redirect_action(sess_hdl, dev_tgt,
                                                             match_spec, 1000)

    match_spec = dc_fwd_result_match_spec_t(
        l2_metadata_l2_redirect=1,
        l2_metadata_l2_redirect_mask=1,
        acl_metadata_acl_redirect=0,
        acl_metadata_acl_redirect_mask=0,
        acl_metadata_racl_redirect=0,
        acl_metadata_racl_redirect_mask=0,
        l3_metadata_rmac_hit=0,
        l3_metadata_rmac_hit_mask=0,
        l3_metadata_fib_hit=0,
        l3_metadata_fib_hit_mask=0,
        l2_metadata_lkp_pkt_type=0,
        l2_metadata_lkp_pkt_type_mask=0,
        l3_metadata_lkp_ip_type=0,
        l3_metadata_lkp_ip_type_mask=0,
        multicast_metadata_igmp_snooping_enabled=0,
        multicast_metadata_igmp_snooping_enabled_mask=0,
        multicast_metadata_mld_snooping_enabled=0,
        multicast_metadata_mld_snooping_enabled_mask=0,
        multicast_metadata_mcast_route_hit=0,
        multicast_metadata_mcast_route_hit_mask=0,
        multicast_metadata_mcast_bridge_hit=0,
        multicast_metadata_mcast_bridge_hit_mask=0,
        multicast_metadata_mcast_rpf_group=0,
        multicast_metadata_mcast_rpf_group_mask=0,
        multicast_metadata_mcast_mode=0,
        multicast_metadata_mcast_mode_mask=0)
    client.fwd_result_table_add_with_set_l2_redirect_action(sess_hdl, dev_tgt,
                                                            match_spec, 1000)

    # add default inner rmac entry
    match_spec = dc_rmac_match_spec_t(
        l3_metadata_rmac_group=inner_rmac_group,
        l2_metadata_lkp_mac_da=macAddr_to_string(rmac))
    client.rmac_table_add_with_rmac_hit(sess_hdl, dev_tgt, match_spec)

    if tunnel_enabled:
        # add default outer rmac entry
        match_spec = dc_outer_rmac_match_spec_t(
            l3_metadata_rmac_group=outer_rmac_group,
            l2_metadata_lkp_mac_da=macAddr_to_string(rmac))
        client.outer_rmac_table_add_with_outer_rmac_hit(
            sess_hdl, dev_tgt, match_spec)

    # initialize fabric tunnel rewrite table for unicast
    match_spec = dc_tunnel_encap_process_outer_match_spec_t(
        tunnel_metadata_egress_tunnel_type = 15,
        tunnel_metadata_egress_header_count=0,
        multicast_metadata_replica=0)
    action_spec = dc_fabric_rewrite_action_spec_t(
        action_tunnel_index=unicast_tunnel_index)
    client.tunnel_encap_process_outer_table_add_with_fabric_rewrite(
        sess_hdl, dev_tgt, match_spec, action_spec)

    match_spec = dc_tunnel_rewrite_match_spec_t(
        tunnel_metadata_tunnel_index=unicast_tunnel_index)
    client.tunnel_rewrite_table_add_with_fabric_unicast_rewrite(
        sess_hdl, dev_tgt, match_spec)

    # initialize fabric tunnel rewrite table for multicast
    match_spec = dc_tunnel_encap_process_outer_match_spec_t(
        tunnel_metadata_egress_tunnel_type = 15,
        tunnel_metadata_egress_header_count=0,
        multicast_metadata_replica=1)
    action_spec = dc_fabric_rewrite_action_spec_t(
        action_tunnel_index=multicast_tunnel_index)
    client.tunnel_encap_process_outer_table_add_with_fabric_rewrite(
        sess_hdl, dev_tgt, match_spec, action_spec)

    match_spec = dc_tunnel_rewrite_match_spec_t(
        tunnel_metadata_tunnel_index=multicast_tunnel_index)
    action_spec = dc_fabric_multicast_rewrite_action_spec_t(
        action_fabric_mgid=fabric_mgid)
    client.tunnel_rewrite_table_add_with_fabric_multicast_rewrite(
        sess_hdl, dev_tgt, match_spec, action_spec)

    # initalize l3 rewrite table
    match_spec = dc_l3_rewrite_match_spec_t(
        ipv4_valid=1,
        ipv4_dstAddr=0,
        ipv4_dstAddr_mask=0)
    client.l3_rewrite_table_add_with_ipv4_unicast_rewrite(
        sess_hdl, dev_tgt, match_spec, 100)

def populate_init_entries(client, sess_hdl, dev_tgt, rewrite_index, rmac,
    inner_rmac_group, outer_rmac_group, ipv6_enabled, tunnel_enabled):
    ret = []
    match_spec = dc_smac_rewrite_match_spec_t(
                            egress_metadata_smac_idx=rewrite_index)
    action_spec = dc_rewrite_smac_action_spec_t(
                            action_smac=macAddr_to_string(rmac))
    ret.append(client.smac_rewrite_table_add_with_rewrite_smac(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec))

    match_spec = dc_fwd_result_match_spec_t(
                            l2_metadata_l2_redirect=0,
                            l2_metadata_l2_redirect_mask=0,
                            acl_metadata_acl_redirect=0,
                            acl_metadata_acl_redirect_mask=0,
                            acl_metadata_racl_redirect=0,
                            acl_metadata_racl_redirect_mask=0,
                            l3_metadata_fib_hit=1,
                            l3_metadata_fib_hit_mask=1,
                            l3_metadata_rmac_hit=0,
                            l3_metadata_rmac_hit_mask=0,
                            l2_metadata_lkp_pkt_type=0,
                            l2_metadata_lkp_pkt_type_mask=0,
                            l3_metadata_lkp_ip_type=0,
                            l3_metadata_lkp_ip_type_mask=0,
                            multicast_metadata_igmp_snooping_enabled=0,
                            multicast_metadata_igmp_snooping_enabled_mask=0,
                            multicast_metadata_mld_snooping_enabled=0,
                            multicast_metadata_mld_snooping_enabled_mask=0,
                            multicast_metadata_mcast_route_hit=0,
                            multicast_metadata_mcast_route_hit_mask=0,
                            multicast_metadata_mcast_bridge_hit=0,
                            multicast_metadata_mcast_bridge_hit_mask=0,
                            multicast_metadata_mcast_rpf_group=0,
                            multicast_metadata_mcast_rpf_group_mask=0,
                            multicast_metadata_mcast_mode=0,
                            multicast_metadata_mcast_mode_mask=0)
    ret.append(client.fwd_result_table_add_with_set_fib_redirect_action(
                            sess_hdl, dev_tgt,
                            match_spec, 1000))

    match_spec = dc_fwd_result_match_spec_t(
                            l2_metadata_l2_redirect=1,
                            l2_metadata_l2_redirect_mask=1,
                            acl_metadata_acl_redirect=0,
                            acl_metadata_acl_redirect_mask=0,
                            acl_metadata_racl_redirect=0,
                            acl_metadata_racl_redirect_mask=0,
                            l3_metadata_fib_hit=0,
                            l3_metadata_fib_hit_mask=0,
                            l3_metadata_rmac_hit=0,
                            l3_metadata_rmac_hit_mask=0,
                            l2_metadata_lkp_pkt_type=0,
                            l2_metadata_lkp_pkt_type_mask=0,
                            l3_metadata_lkp_ip_type=0,
                            l3_metadata_lkp_ip_type_mask=0,
                            multicast_metadata_igmp_snooping_enabled=0,
                            multicast_metadata_igmp_snooping_enabled_mask=0,
                            multicast_metadata_mld_snooping_enabled=0,
                            multicast_metadata_mld_snooping_enabled_mask=0,
                            multicast_metadata_mcast_route_hit=0,
                            multicast_metadata_mcast_route_hit_mask=0,
                            multicast_metadata_mcast_bridge_hit=0,
                            multicast_metadata_mcast_bridge_hit_mask=0,
                            multicast_metadata_mcast_rpf_group=0,
                            multicast_metadata_mcast_rpf_group_mask=0,
                            multicast_metadata_mcast_mode=0,
                            multicast_metadata_mcast_mode_mask=0)
    ret.append(client.fwd_result_table_add_with_set_l2_redirect_action(
                            sess_hdl, dev_tgt,
                            match_spec, 1000))

    #Add default inner rmac entry
    match_spec = dc_rmac_match_spec_t(
                           l3_metadata_rmac_group=inner_rmac_group,
                           l2_metadata_lkp_mac_da=macAddr_to_string(rmac))
    ret.append(client.rmac_table_add_with_rmac_hit(
                           sess_hdl, dev_tgt,
                           match_spec))

    #Initialize vlan decap table
    match_spec = dc_vlan_decap_match_spec_t(
                            vlan_tag__0__valid=1,
                            vlan_tag__1__valid=0)
    ret.append(client.vlan_decap_table_add_with_remove_vlan_single_tagged(
                           sess_hdl, dev_tgt,
                           match_spec))
    match_spec = dc_vlan_decap_match_spec_t(
                            vlan_tag__0__valid=1,
                            vlan_tag__1__valid=1)
    ret.append(client.vlan_decap_table_add_with_remove_vlan_double_tagged(
                           sess_hdl, dev_tgt,
                           match_spec))

    #Initialize L3 rewrite table
    match_spec = dc_l3_rewrite_match_spec_t(
                            ipv4_valid=1,
                            ipv6_valid=0,
                            mpls_0__valid=0,
                            ipv4_dstAddr=0,
                            ipv4_dstAddr_mask=0,
                            ipv6_dstAddr=ipv6Addr_to_string('::'),
                            ipv6_dstAddr_mask=ipv6Addr_to_string('::'))
    ret.append(client.l3_rewrite_table_add_with_ipv4_unicast_rewrite(
                            sess_hdl, dev_tgt, match_spec, 100))
    match_spec = dc_l3_rewrite_match_spec_t(
                            ipv4_valid=0,
                            ipv6_valid=1,
                            mpls_0__valid=0,
                            ipv4_dstAddr=0,
                            ipv4_dstAddr_mask=0,
                            ipv6_dstAddr=ipv6Addr_to_string('::'),
                            ipv6_dstAddr_mask=ipv6Addr_to_string('::'))
    if ipv6_enabled:
        ret.append(client.l3_rewrite_table_add_with_ipv6_unicast_rewrite(
                            sess_hdl, dev_tgt, match_spec, 200))

    if tunnel_enabled:
        #Add default outer rmac entry
        match_spec = dc_outer_rmac_match_spec_t(
                            l3_metadata_rmac_group=outer_rmac_group,
                            l2_metadata_lkp_mac_da=macAddr_to_string(rmac))
        ret.append(client.outer_rmac_table_add_with_outer_rmac_hit(
                            sess_hdl, dev_tgt,
                            match_spec))
    return ret

def delete_init_entries(client, sess_hdl, dev, ret_list, tunnel_enabled):
    client.smac_rewrite_table_delete(sess_hdl, dev, ret_list[0])
    client.fwd_result_table_delete(sess_hdl, dev, ret_list[1])
    client.fwd_result_table_delete(sess_hdl, dev, ret_list[2])
    client.rmac_table_delete(sess_hdl, dev, ret_list[3])
    client.vlan_decap_table_delete(sess_hdl, dev, ret_list[4])
    client.vlan_decap_table_delete(sess_hdl, dev, ret_list[5])
    client.l3_rewrite_table_delete(sess_hdl, dev, ret_list[6])
    client.l3_rewrite_table_delete(sess_hdl, dev, ret_list[7])
    if tunnel_enabled:
        client.outer_rmac_table_delete(sess_hdl, dev, ret_list[8])

def add_fabric_lag(client, sess_hdl, dev_tgt, src_device, port_list):
    grp_hdl = client.fabric_lag_action_profile_create_group(
        sess_hdl, dev_tgt, len(port_list))
    for port in port_list:
        action_spec = dc_set_fabric_lag_port_action_spec_t(action_port=port)
        mbr_hdl = \
            client.fabric_lag_action_profile_add_member_with_set_fabric_lag_port(
            sess_hdl, dev_tgt, action_spec)
        client.fabric_lag_action_profile_add_member_to_group(sess_hdl,
                                                             dev_tgt.dev_id,
                                                             grp_hdl, mbr_hdl)
    return grp_hdl

def program_ports(client, sess_hdl, dev_tgt, port_count):
    count = 1
    ret = []
    while (count <= port_count):
        match_spec = \
            dc_ingress_port_mapping_match_spec_t(
                standard_metadata_ingress_port=count)
        action_spec = dc_set_ifindex_action_spec_t(
                            action_ifindex=count,
                            action_if_label=count,
                            action_port_type=0)
        port_hdl = client.ingress_port_mapping_table_add_with_set_ifindex(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)

        action_spec = dc_set_lag_port_action_spec_t(
                              action_port=count)
        mbr_hdl = client.lag_action_profile_add_member_with_set_lag_port(
                             sess_hdl, dev_tgt,
                             action_spec)

        match_spec = dc_lag_group_match_spec_t(
                             ingress_metadata_egress_ifindex=count)
        lag_hdl = client.lag_group_add_entry(
                              sess_hdl, dev_tgt,
                              match_spec, mbr_hdl)
        ret.append({ 'port': port_hdl, 'mbr' : mbr_hdl, 'lag' : lag_hdl})

        match_spec = dc_egress_lag_match_spec_t(
            standard_metadata_egress_port=count)
        action_spec = dc_set_egress_ifindex_action_spec_t(
            action_egress_ifindex=count)
        client.egress_lag_table_add_with_set_egress_ifindex(
            sess_hdl, dev_tgt, match_spec, action_spec)

        count = count + 1
    return ret

def program_emulation_ports(client, sess_hdl, dev_tgt, port_count):
    count = 0
    ret = []
    while (count < port_count):
        match_spec = \
            dc_ingress_port_mapping_match_spec_t(
                standard_metadata_ingress_port=count)
        action_spec = dc_set_ifindex_action_spec_t(
                            action_ifindex=count+1,
                            action_if_label=count,
                            action_port_type=0)
        port_hdl = client.ingress_port_mapping_table_add_with_set_ifindex(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)

        action_spec = dc_set_lag_port_action_spec_t(
                              action_port=count)
        mbr_hdl = client.lag_action_profile_add_member_with_set_lag_port(
                             sess_hdl, dev_tgt,
                             action_spec)

        match_spec = dc_lag_group_match_spec_t(
                             ingress_metadata_egress_ifindex=count+1)
        lag_hdl = client.lag_group_add_entry(
                              sess_hdl, dev_tgt,
                              match_spec, mbr_hdl)
        ret.append({ 'port': port_hdl, 'mbr' : mbr_hdl, 'lag' : lag_hdl})
        count = count + 1
    return ret

def enum(**enums):
    return type('Enum', (), enums)

PortType = enum(Normal=0, Fabric=1)

def add_ports(client, sess_hdl, dev_tgt, port_list, port_type, l2xid):
    #print port_list
    for i in port_list:
        ifindex = i + 1
        match_spec = dc_ingress_port_mapping_match_spec_t(
            standard_metadata_ingress_port=i)
        action_spec = dc_set_ifindex_action_spec_t(
            action_ifindex=ifindex, action_if_label=0,
            action_port_type=port_type)
        client.ingress_port_mapping_table_add_with_set_ifindex(
            sess_hdl, dev_tgt, match_spec, action_spec)

        action_spec = dc_set_lag_port_action_spec_t(action_port=i)
        mbr_hdl = client.lag_action_profile_add_member_with_set_lag_port(
            sess_hdl, dev_tgt, action_spec)
        match_spec = dc_lag_group_match_spec_t(
            ingress_metadata_egress_ifindex=ifindex)
        client.lag_group_add_entry(sess_hdl, dev_tgt, match_spec, mbr_hdl)

        match_spec = dc_egress_port_mapping_match_spec_t(
           standard_metadata_egress_port=i)
        if port_type == PortType.Normal:
            client.egress_port_mapping_table_add_with_egress_port_type_normal(
                sess_hdl, dev_tgt, match_spec)
        elif port_type == PortType.Fabric:
            client.egress_port_mapping_table_add_with_egress_port_type_fabric(
                sess_hdl, dev_tgt, match_spec)

def delete_ports(client, sess_hdl, dev, port_count, ret_list):
    count = 0
    while (count < port_count):
        client.lag_group_table_delete(
                              sess_hdl, dev,
                             ret_list[count]['lag'])
        client.lag_action_profile_del_member(
                             sess_hdl, dev,
                             ret_list[count]['mbr'])
        client.ingress_port_mapping_table_delete(
                             sess_hdl, dev, ret_list[count]['port'])
        count = count + 1

def program_bd(client, sess_hdl, dev_tgt, vlan, mc_index):
    match_spec = dc_bd_flood_match_spec_t(
                            ingress_metadata_bd=vlan,
                            l2_metadata_lkp_pkt_type=0x1)
    action_spec = dc_set_bd_flood_mc_index_action_spec_t(
                            action_mc_index=mc_index)
    hdl = client.bd_flood_table_add_with_set_bd_flood_mc_index(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec)
    return hdl


def delete_bd(client, sess_hdl, dev, hdl):
    client.bd_flood_table_delete(sess_hdl, dev, hdl)
    return 0

def program_vlan(client, sess_hdl, dev_tgt, vrf, inner_rmac_group,
                 vlan, ifindex,
                 v4_enabled, v6_enabled, uuc_mc_index):
    action_spec = dc_set_bd_properties_action_spec_t(
        action_bd=vlan,
        action_vrf=vrf,
        action_rmac_group=inner_rmac_group,
        action_bd_label=0,
        action_ipv4_unicast_enabled=v4_enabled,
        action_ipv6_unicast_enabled=v6_enabled,
        action_ipv4_multicast_enabled=0,
        action_ipv6_multicast_enabled=0,
        action_igmp_snooping_enabled=0,
        action_mld_snooping_enabled=0,
        action_ipv4_urpf_mode=0,
        action_ipv6_urpf_mode=0,
        action_stp_group=0,
        action_mrpf_group=0,
        action_ipv4_mcast_key_type=0,
        action_ipv4_mcast_key=0,
        action_ipv6_mcast_key_type=0,
        action_ipv6_mcast_key=0,
        action_stats_idx=0,
        action_learning_enabled=0)
    mbr_hdl = client.bd_action_profile_add_member_with_set_bd_properties(
        sess_hdl, dev_tgt, action_spec)

    match_spec = dc_bd_flood_match_spec_t(ingress_metadata_bd=vlan,
                                          l2_metadata_lkp_pkt_type=0x1)
    action_spec = dc_set_bd_flood_mc_index_action_spec_t(
        action_mc_index=uuc_mc_index)
    client.bd_flood_table_add_with_set_bd_flood_mc_index(sess_hdl, dev_tgt,
                                                         match_spec,
                                                         action_spec)

    match_spec = dc_port_vlan_mapping_match_spec_t(
        ingress_metadata_ifindex=ifindex,
        vlan_tag__0__valid=0,
        vlan_tag__0__vid=0,
        vlan_tag__1__valid=0,
        vlan_tag__1__vid=0)
    hdl = client.port_vlan_mapping_add_entry(sess_hdl, dev_tgt, match_spec,
                                             mbr_hdl)

    return hdl, mbr_hdl

def program_egress_bd_map(client, sess_hdl, dev_tgt, smac_index, vlan):
    match_spec = dc_egress_bd_map_match_spec_t(egress_metadata_bd=vlan)
    action_spec = dc_set_egress_bd_properties_action_spec_t(
        action_smac_idx=smac_index)
    client.egress_bd_map_table_add_with_set_egress_bd_properties(
        sess_hdl, dev_tgt, match_spec, action_spec)


def program_vlan_mapping(client, sess_hdl, dev_tgt, vrf, vlan, port,
                         v4_enabled, v6_enabled, rmac, learning_enabled,
                         ctag=None, stag=None, rid=0):
    action_spec = dc_set_bd_properties_action_spec_t(
                            action_bd=vlan,
                            action_vrf=vrf,
                            action_rmac_group=rmac,
                            action_ipv4_unicast_enabled=v4_enabled,
                            action_ipv6_unicast_enabled=v6_enabled,
                            action_bd_label=0,
                            action_igmp_snooping_enabled=0,
                            action_mld_snooping_enabled=0,
                            action_ipv4_urpf_mode=0,
                            action_ipv6_urpf_mode=0,
                            action_stp_group=0,
                            action_ipv4_multicast_enabled=0,
                            action_ipv6_multicast_enabled=0,
                            action_mrpf_group=0,
                            action_ipv4_mcast_key_type=0,
                            action_ipv4_mcast_key=0,
                            action_ipv6_mcast_key_type=0,
                            action_ipv6_mcast_key=0,
                            action_stats_idx=0,
                            action_learning_enabled=learning_enabled)
    mbr_hdl = client.bd_action_profile_add_member_with_set_bd_properties(
                            sess_hdl, dev_tgt,
                            action_spec)
    vlan_id = [0, 0]
    vlan_valid = [0, 0]
    idx = 0
    if stag is not None:
        vlan_id[idx] = stag
        vlan_valid[idx] = 1
        idx = idx + 1

    if ctag is not None:
        vlan_id[idx] = ctag
        vlan_valid[idx] = 1

    match_spec = dc_port_vlan_mapping_match_spec_t(
                            ingress_metadata_ifindex=port,
                            vlan_tag__0__valid=vlan_valid[0],
                            vlan_tag__0__vid=vlan_id[0],
                            vlan_tag__1__valid=vlan_valid[1],
                            vlan_tag__1__vid=vlan_id[1])
    hdl = client.port_vlan_mapping_add_entry(
                            sess_hdl, dev_tgt,
                            match_spec, mbr_hdl)
    return hdl, mbr_hdl

def delete_vlan_mapping(client, sess_hdl, dev, hdl, mbr_hdl):
    client.port_vlan_mapping_table_delete(
                            sess_hdl, dev,
                            hdl)
    client.bd_action_profile_del_member(
                            sess_hdl, dev,
                            mbr_hdl)


def program_tunnel_ethernet_vlan(client, sess_hdl, dev_tgt, vrf, vlan, port, vni,
                                 ttype, v4_enabled, inner_rmac):
    match_spec = dc_tunnel_match_spec_t(
                             tunnel_metadata_tunnel_vni=vni,
                             tunnel_metadata_ingress_tunnel_type=ttype,
                             inner_ipv4_valid=1,
                             inner_ipv6_valid=0)
    action_spec = dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t(
                            action_bd=vlan,
                            action_vrf=vrf,
                            action_rmac_group=inner_rmac,
                            action_mrpf_group=0,
                            action_bd_label=0,
                            action_ipv4_unicast_enabled=v4_enabled,
                            action_ipv4_multicast_enabled=0,
                            action_igmp_snooping_enabled=0,
                            action_ipv4_urpf_mode=0,
                            action_stats_idx=0)
    hdl = client.tunnel_table_add_with_terminate_tunnel_inner_ethernet_ipv4(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec)
    return hdl

def delete_tunnel_ethernet_vlan(client, sess_hdl, dev, hdl):
    client.tunnel_table_delete(
                            sess_hdl, dev,
                            hdl)
    return hdl

def program_tunnel_ipv4_vlan(client, sess_hdl, dev_tgt, vlan, port, vni, ttype,
                            v4_enabled, inner_rmac, vrf):
    match_spec = dc_tunnel_match_spec_t(
                             tunnel_metadata_tunnel_vni=vni,
                             tunnel_metadata_ingress_tunnel_type=ttype,
                             inner_ipv4_valid=1,
                             inner_ipv6_valid=0)
    action_spec = dc_terminate_tunnel_inner_ipv4_action_spec_t(
                            action_vrf=vrf,
                            action_rmac_group=inner_rmac,
                            action_mrpf_group=0,
                            action_ipv4_unicast_enabled=v4_enabled,
                            action_ipv4_multicast_enabled=0,
                            action_ipv4_urpf_mode=0)
    hdl = client.tunnel_table_add_with_terminate_tunnel_inner_ipv4(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec)
    return hdl

def delete_tunnel_ipv4_vlan(client, sess_hdl, dev, hdl):
    client.tunnel_table_delete(
                            sess_hdl, dev,
                            hdl)

def program_mac(client, sess_hdl, dev_tgt, vlan, mac, port):
    match_spec = dc_dmac_match_spec_t(
                            l2_metadata_lkp_mac_da=macAddr_to_string(mac),
                            ingress_metadata_bd=vlan)
    action_spec = dc_dmac_hit_action_spec_t(
                            action_ifindex=port)
    dmac_hdl = client.dmac_table_add_with_dmac_hit(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec, 0)

    match_spec = dc_smac_match_spec_t(
                            l2_metadata_lkp_mac_sa=macAddr_to_string(mac),
                            ingress_metadata_bd=vlan)
    action_spec = dc_smac_hit_action_spec_t(
                            action_ifindex=port)
    smac_hdl = client.smac_table_add_with_smac_hit(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec)
    return dmac_hdl, smac_hdl

def program_mac_with_nexthop(client, sess_hdl, dev_tgt, vlan, mac, port, nhop):
    match_spec = dc_dmac_match_spec_t(
                            l2_metadata_lkp_mac_da=macAddr_to_string(mac),
                            ingress_metadata_bd=vlan)
    action_spec = dc_dmac_redirect_nexthop_action_spec_t(
                            action_nexthop_index=nhop)
    dmac_hdl = client.dmac_table_add_with_dmac_redirect_nexthop(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec, 0)

    match_spec = dc_smac_match_spec_t(
                            l2_metadata_lkp_mac_sa=macAddr_to_string(mac),
                            ingress_metadata_bd=vlan)
    action_spec = dc_smac_hit_action_spec_t(
                            action_ifindex=port)
    smac_hdl = client.smac_table_add_with_smac_hit(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec)
    return dmac_hdl, smac_hdl

def program_multicast_mac(client, sess_hdl, dev_tgt, vlan, mac, port,
                          start_mcidx):
    mcidx = start_mcidx + port
    match_spec = dc_dmac_match_spec_t(
                            l2_metadata_lkp_mac_da=macAddr_to_string(mac),
                            ingress_metadata_bd=vlan)
    action_spec = dc_dmac_multicast_hit_action_spec_t(
                            action_mc_index=mcidx)
    dmac_hdl = client.dmac_table_add_with_dmac_multicast_hit(
                            sess_hdl, dev_tgt,
                            match_spec, action_spec, 0)
    return dmac_hdl

def delete_dmac(client, sess_hdl, dev, dmac_hdl):
    client.dmac_table_delete(
                            sess_hdl, dev,
                            dmac_hdl)

def delete_mac(client, sess_hdl, dev, dmac_hdl, smac_hdl):
    client.dmac_table_delete(
                            sess_hdl, dev,
                            dmac_hdl)

    client.smac_table_delete(
                            sess_hdl, dev,
                            smac_hdl)

def program_ipv4_route(client, sess_hdl, dev_tgt, vrf, ip, prefix, nhop):
    if prefix == 32:
        match_spec = dc_ipv4_fib_match_spec_t(
                             l3_metadata_vrf=vrf,
                             ipv4_metadata_lkp_ipv4_da=ip)
        action_spec = dc_fib_hit_nexthop_action_spec_t(
                             action_nexthop_index=nhop)
        hdl = client.ipv4_fib_table_add_with_fib_hit_nexthop(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    else:
        match_spec = dc_ipv4_fib_lpm_match_spec_t(
                             l3_metadata_vrf=vrf,
                             ipv4_metadata_lkp_ipv4_da=ip,
                             ipv4_metadata_lkp_ipv4_da_prefix_length=prefix)
        action_spec = dc_fib_hit_nexthop_action_spec_t(
                             action_nexthop_index=nhop)
        hdl = client.ipv4_fib_lpm_table_add_with_fib_hit_nexthop(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    return hdl

def delete_ipv4_route(client, sess_hdl, dev, prefix, hdl):
    if prefix == 32:
        client.ipv4_fib_table_delete(
                             sess_hdl, dev,
                             hdl)
    else:
        client.ipv4_fib_lpm_table_delete(
                             sess_hdl, dev,
                             hdl)

def program_ipv6_route(client, sess_hdl, dev_tgt, vrf, ip, prefix, nhop,
                       ipv6_enabled):
    if ipv6_enabled == 0:
        return
    if prefix == 128:
        match_spec = dc_ipv6_fib_match_spec_t(
                             l3_metadata_vrf=vrf,
                             ipv6_metadata_lkp_ipv6_da=ipv6Addr_to_string(ip))
        action_spec = dc_fib_hit_nexthop_action_spec_t(
                             action_nexthop_index=nhop)
        hdl = client.ipv6_fib_table_add_with_fib_hit_nexthop(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    else:
        match_spec = dc_ipv6_fib_lpm_match_spec_t(
                             l3_metadata_vrf=vrf,
                             ipv6_metadata_lkp_ipv6_da=ipv6Addr_to_string(ip),
                             ipv6_metadata_lkp_ipv6_da_prefix_length=prefix)
        action_spec = dc_fib_hit_nexthop_action_spec_t(
                             action_nexthop_index=nhop)
        hdl = client.ipv6_fib_lpm_table_add_with_fib_hit_nexthop(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    return hdl

def delete_ipv6_route(client, sess_hdl, dev, prefix, hdl, ipv6_enabled):
    if ipv6_enabled == 0:
        return
    if prefix == 128:
        client.ipv6_fib_table_delete(
                             sess_hdl, dev,
                             hdl)
    else:
        client.ipv6_fib_lpm_table_delete(
                             sess_hdl, dev,
                             hdl)

def program_nexthop(client, sess_hdl, dev_tgt, nhop, vlan, ifindex, tunnel):
    match_spec = dc_nexthop_match_spec_t(
                             l3_metadata_nexthop_index=nhop)
    action_spec = dc_set_nexthop_details_action_spec_t(
                             action_ifindex=ifindex,
                             action_bd=vlan,
                             action_tunnel=tunnel)
    hdl = client.nexthop_table_add_with_set_nexthop_details(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    return hdl

def delete_nexthop(client, sess_hdl, dev, hdl):
    client.nexthop_table_delete(
                             sess_hdl, dev,
                             hdl)

def program_ipv4_unicast_rewrite(client, sess_hdl, dev_tgt, bd, nhop, dmac):
    match_spec = dc_rewrite_match_spec_t(
                             l3_metadata_nexthop_index=nhop)
    action_spec = dc_set_l3_rewrite_action_spec_t(
                             action_dmac=macAddr_to_string(dmac),
                             action_bd=bd,
                             action_mtu_index=0)
    hdl = client.rewrite_table_add_with_set_l3_rewrite(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    return hdl

def delete_ipv4_unicast_rewrite(client, sess_hdl, dev, hdl):
    client.rewrite_table_delete(
                             sess_hdl, dev,
                             hdl)

def program_ipv6_unicast_rewrite(client, sess_hdl, dev_tgt, bd, nhop, dmac,
                                ipv6_enabled):
    if ipv6_enabled == 0:
        return
    match_spec = dc_rewrite_match_spec_t(
                             l3_metadata_nexthop_index=nhop)
    action_spec = dc_set_l3_rewrite_action_spec_t(
                             action_dmac=macAddr_to_string(dmac),
                             action_bd=bd,
                             action_mtu_index=0)
    hdl = client.rewrite_table_add_with_set_l3_rewrite(
                             sess_hdl, dev_tgt,
                             match_spec, action_spec)
    return hdl

def delete_ipv6_unicast_rewrite(client, sess_hdl, dev, hdl, ipv6_enabled):
    if ipv6_enabled == 0:
        return
    client.rewrite_table_delete(
                             sess_hdl, dev,
                             hdl)

def program_tunnel_l2_unicast_rewrite(client, sess_hdl, dev_tgt, tunnel_index,
                                      tunnel_type, nhop, core_vlan):
    #Egress Tunnel Encap - Rewrite information
    match_spec = dc_rewrite_match_spec_t(
                                  l3_metadata_nexthop_index=nhop)
    action_spec = dc_set_l2_rewrite_with_tunnel_action_spec_t(
                                  action_tunnel_index=tunnel_index,
                                  action_tunnel_type=tunnel_type)
    hdl = client.rewrite_table_add_with_set_l2_rewrite_with_tunnel(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl

def delete_tunnel_l2_unicast_rewrite(client, sess_hdl, dev, hdl):
    client.rewrite_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_tunnel_l3_unicast_rewrite(client, sess_hdl, dev_tgt, tunnel_index,
                                      tunnel_type, nhop, core_vlan, dmac):
    #Egress Tunnel Encap - Rewrite information
    match_spec = dc_rewrite_match_spec_t(
                                  l3_metadata_nexthop_index=nhop)
    action_spec = dc_set_l3_rewrite_with_tunnel_action_spec_t(
                                  action_bd=core_vlan,
                                  action_tunnel_index=tunnel_index,
                                  action_dmac=macAddr_to_string(dmac),
                                  action_tunnel_type=tunnel_type)
    hdl = client.rewrite_table_add_with_set_l3_rewrite_with_tunnel(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl

def delete_tunnel_l3_unicast_rewrite(client, sess_hdl, dev, hdl):
    client.rewrite_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def enable_learning(client, sess_hdl, dev_tgt):
    match_spec = dc_learn_notify_match_spec_t(
                             l2_metadata_l2_src_miss=1,
                             l2_metadata_l2_src_miss_mask=1,
                             l2_metadata_l2_src_move=0,
                             l2_metadata_l2_src_move_mask=0,
                             l2_metadata_stp_state=0,
                             l2_metadata_stp_state_mask=0)

    client.learn_notify_table_add_with_generate_learn_notify(
                             sess_hdl, dev_tgt,
                             match_spec, 1000)

def program_tunnel_ipv4_src_vtep(client, sess_hdl, dev_tgt, vrf, src_ip,
                                 ifindex):
    #Ingress Tunnel Decap - src vtep entry
    match_spec = dc_ipv4_src_vtep_match_spec_t(
                                  l3_metadata_vrf=vrf,
                                  ipv4_metadata_lkp_ipv4_sa=src_ip)
    action_spec = dc_src_vtep_hit_action_spec_t(
                                  action_ifindex=ifindex)
    hdl = client.ipv4_src_vtep_table_add_with_src_vtep_hit(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl

def delete_tunnel_ipv4_src_vtep(client, sess_hdl, dev, hdl):
    client.ipv4_src_vtep_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_tunnel_ipv4_dst_vtep(client, sess_hdl, dev_tgt, vrf, dst_ip,
                                 tunnel_type):
    #Ingress Tunnel Decap - dest vtep entry
    match_spec = dc_ipv4_dest_vtep_match_spec_t(
                                  l3_metadata_vrf=vrf,
                                  ipv4_metadata_lkp_ipv4_da=dst_ip,
                                  tunnel_metadata_ingress_tunnel_type=tunnel_type)
    hdl = client.ipv4_dest_vtep_table_add_with_set_tunnel_termination_flag(
                                  sess_hdl, dev_tgt,
                                  match_spec)
    return hdl

def delete_tunnel_ipv4_dst_vtep(client, sess_hdl, dev, hdl):
    client.ipv4_dest_vtep_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_tunnel_encap(client, sess_hdl, dev_tgt):
    match_spec = dc_tunnel_encap_process_outer_match_spec_t(
                                  tunnel_metadata_egress_tunnel_type=1,
                                  tunnel_metadata_egress_header_count=0,
                                  multicast_metadata_replica=0)
    hdl1 = client.tunnel_encap_process_outer_table_add_with_ipv4_vxlan_rewrite(
                                  sess_hdl, dev_tgt,
                                  match_spec)

    match_spec = dc_tunnel_encap_process_inner_match_spec_t(
                                  ipv4_valid=1, ipv6_valid=0,
                                  tcp_valid=1, udp_valid=0,
                                  icmp_valid=0)
    hdl2 = \
        client.tunnel_encap_process_inner_table_add_with_inner_ipv4_tcp_rewrite(
                                  sess_hdl, dev_tgt,
                                  match_spec)
    return hdl1, hdl2

def delete_tunnel_encap(client, sess_hdl, dev, hdl1, hdl2):
    client.tunnel_encap_process_outer_table_delete(
                                  sess_hdl, dev,
                                  hdl1)

    client.tunnel_encap_process_inner_table_delete(
                                  sess_hdl, dev,
                                  hdl2)

def program_tunnel_decap(client, sess_hdl, dev_tgt):
    match_spec = dc_tunnel_decap_process_outer_match_spec_t(
                                  tunnel_metadata_ingress_tunnel_type=1,
                                  inner_ipv4_valid=1,
                                  inner_ipv6_valid=0)
    hdl1 = \
        client.tunnel_decap_process_outer_table_add_with_decap_vxlan_inner_ipv4(
                                  sess_hdl, dev_tgt,
                                  match_spec)

    match_spec = dc_tunnel_decap_process_inner_match_spec_t(
                                  inner_tcp_valid=1, inner_udp_valid=0,
                                  inner_icmp_valid=0)
    hdl2 = client.tunnel_decap_process_inner_table_add_with_decap_inner_tcp(
                                  sess_hdl, dev_tgt,
                                  match_spec)
    return (hdl1, hdl2)

def delete_tunnel_decap(client, sess_hdl, dev, hdl1, hdl2):
    client.tunnel_decap_process_outer_table_delete(
                                  sess_hdl, dev,
                                  hdl1)

    client.tunnel_decap_process_inner_table_delete(
                                  sess_hdl, dev,
                                  hdl2)

def program_tunnel_src_ipv4_rewrite(client, sess_hdl, dev_tgt, src_index,
                                    src_ip):
    #Egress Tunnel Encap - Source IP rewrite
    match_spec = dc_tunnel_src_rewrite_match_spec_t(
                                  tunnel_metadata_tunnel_src_index=src_index)
    action_spec = dc_rewrite_tunnel_ipv4_src_action_spec_t(
                                  action_ip=src_ip)
    hdl = client.tunnel_src_rewrite_table_add_with_rewrite_tunnel_ipv4_src(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl

def delete_tunnel_src_ipv4_rewrite(client, sess_hdl, dev, hdl):
    client.tunnel_src_rewrite_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_tunnel_dst_ipv4_rewrite(client, sess_hdl, dev_tgt, dst_index,
                                    dst_ip):
    #Egress Tunnel Encap - Destination IP rewrite
    match_spec = dc_tunnel_dst_rewrite_match_spec_t(
                                  tunnel_metadata_tunnel_dst_index=dst_index)
    action_spec = dc_rewrite_tunnel_ipv4_dst_action_spec_t(
                                  action_ip=dst_ip)
    hdl = client.tunnel_dst_rewrite_table_add_with_rewrite_tunnel_ipv4_dst(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl

def delete_tunnel_dst_ipv4_rewrite(client, sess_hdl, dev, hdl):
    client.tunnel_dst_rewrite_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_tunnel_src_mac_rewrite(client, sess_hdl, dev_tgt, src_index, smac):
    match_spec = dc_tunnel_smac_rewrite_match_spec_t(
                                  tunnel_metadata_tunnel_smac_index=src_index)
    action_spec = dc_rewrite_tunnel_smac_action_spec_t(
                                  action_smac=macAddr_to_string(smac))
    hdl = client.tunnel_smac_rewrite_table_add_with_rewrite_tunnel_smac(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl

def delete_tunnel_src_mac_rewrite(client, sess_hdl, dev, hdl):
    client.tunnel_smac_rewrite_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_tunnel_dst_mac_rewrite(client, sess_hdl, dev_tgt, dst_index, dmac):
    match_spec = dc_tunnel_dmac_rewrite_match_spec_t(
                                  tunnel_metadata_tunnel_dmac_index=dst_index)
    action_spec = dc_rewrite_tunnel_dmac_action_spec_t(
                                  action_dmac=macAddr_to_string(dmac))
    hdl = client.tunnel_dmac_rewrite_table_add_with_rewrite_tunnel_dmac(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl

def delete_tunnel_dst_mac_rewrite(client, sess_hdl, dev, hdl):
    client.tunnel_dmac_rewrite_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_tunnel_rewrite(client, sess_hdl, dev_tgt, tunnel_index, sip_index,
                           dip_index, smac_index, dmac_index, core_vlan):
    match_spec = dc_tunnel_rewrite_match_spec_t(
                                  tunnel_metadata_tunnel_index=tunnel_index)
    action_spec = dc_set_tunnel_rewrite_details_action_spec_t(
                                  action_smac_idx=smac_index,
                                  action_dmac_idx=dmac_index,
                                  action_sip_index=sip_index,
                                  action_dip_index=dip_index,
                                  action_outer_bd=core_vlan)
    hdl = client.tunnel_rewrite_table_add_with_set_tunnel_rewrite_details(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl


def delete_tunnel_rewrite(client, sess_hdl, dev, hdl):
    client.tunnel_rewrite_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_egress_vni(client, sess_hdl, dev_tgt, egress_tunnel_type,
                       tenant_vlan, vnid):
    #Egress Tunnel Encap - Derive vnid from egress bd mapping
    match_spec = dc_egress_vni_match_spec_t(
                                  egress_metadata_bd=tenant_vlan,
                                  tunnel_metadata_egress_tunnel_type=egress_tunnel_type)
    action_spec = dc_set_egress_tunnel_vni_action_spec_t(
                                  action_vnid=vnid)
    hdl = client.egress_vni_table_add_with_set_egress_tunnel_vni(
                                  sess_hdl, dev_tgt,
                                  match_spec, action_spec)
    return hdl

def delete_egress_vni(client, sess_hdl, dev, hdl):
    client.egress_vni_table_delete(
                                  sess_hdl, dev,
                                  hdl)

def program_egress_vlan_xlate(client, sess_hdl, dev_tgt, port, bd,
                              ctag=None, stag=None):
    match_spec = dc_egress_vlan_xlate_match_spec_t(
                                standard_metadata_egress_port=port,
                                egress_metadata_bd=bd)
    if ((ctag is not None) and (stag is None)):
        action_spec = dc_set_egress_packet_vlan_tagged_action_spec_t(
                                action_vlan_id=ctag)
        hdl = \
            client.egress_vlan_xlate_table_add_with_set_egress_packet_vlan_tagged(
                                sess_hdl, dev_tgt, match_spec, action_spec)
    elif ((ctag is not None) and (stag is not None)):
        action_spec = dc_set_egress_packet_vlan_double_tagged_action_spec_t(
                                action_s_tag=stag, action_c_tag=ctag)
        hdl = \
            client.egress_vlan_xlate_table_add_with_set_egress_packet_vlan_double_tagged(
                                sess_hdl, dev_tgt, match_spec, action_spec)
    return hdl

def delete_egress_vlan_xlate(client, sess_hdl, dev, hdl):
    client.egress_vlan_xlate_table_delete(sess_hdl, dev, hdl)

def program_egress_bd_properties(client, sess_hdl, dev_tgt, bd, rewrite_index):
    match_spec = dc_egress_bd_map_match_spec_t(
                                egress_metadata_bd=bd)
    action_spec = dc_set_egress_bd_properties_action_spec_t(
                                action_smac_idx=rewrite_index)
    hdl = client.egress_bd_map_table_add_with_set_egress_bd_properties(
                                sess_hdl, dev_tgt, match_spec, action_spec)
    return hdl

def delete_egress_bd_properties(client, sess_hdl, dev, hdl):
    client.egress_bd_map_table_delete(sess_hdl, dev, hdl)

def program_rid(client, sess_hdl, dev_tgt, rid, inner_replica, bd,
                tunnel_index, tunnel_type, header_count):
    match_spec = dc_rid_match_spec_t(intrinsic_metadata_egress_rid=rid)
    if inner_replica:
        action_spec = dc_inner_replica_from_rid_action_spec_t(
            action_bd=bd, action_tunnel_index=tunnel_index,
            action_tunnel_type=tunnel_type, action_header_count=header_count)
        hdl = client.rid_table_add_with_inner_replica_from_rid(
            sess_hdl, dev_tgt, match_spec, action_spec)
    else:
        action_spec = dc_outer_replica_from_rid_action_spec_t(
            action_bd=bd, action_tunnel_index=tunnel_index,
            action_tunnel_type=tunnel_type, action_header_count=header_count)
        hdl = client.rid_table_add_with_outer_replica_from_rid(
            sess_hdl, dev_tgt, match_spec, action_spec)
    return hdl

def delete_rid(client, sess_hdl, dev, hdl):
    client.rid_table_delete(sess_hdl, dev, hdl)

def client_init(client, sess_hdl, dev_tgt):
    print "Cleaning state"
    client.clean_all(sess_hdl, dev_tgt)
    return 0
