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
#include "p4features.h"
#include "switch_pd.h"
#include "switch_defines.h"

extern p4_pd_sess_hdl_t g_sess_hdl;

p4_pd_status_t switch_pd_nat_init(switch_device_t device) {
  p4_pd_status_t status = 0;
#ifndef P4_NAT_DISABLE
  p4_pd_entry_hdl_t entry_hdl;

  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

  /* ingress tables */
  status = p4_pd_dc_nat_twice_set_default_action_on_miss(
      g_sess_hdl, p4_pd_device, &entry_hdl);
  status = p4_pd_dc_nat_dst_set_default_action_on_miss(
      g_sess_hdl, p4_pd_device, &entry_hdl);
  status = p4_pd_dc_nat_src_set_default_action_on_miss(
      g_sess_hdl, p4_pd_device, &entry_hdl);
  status = p4_pd_dc_nat_flow_set_default_action_nop(
      g_sess_hdl, p4_pd_device, &entry_hdl);

  /* egress tables */
  status = p4_pd_dc_egress_nat_set_default_action_nop(
      g_sess_hdl, p4_pd_device, &entry_hdl);

#endif /* P4_NAT_DISABLE */
  p4_pd_complete_operations(g_sess_hdl);
  return status;
}

p4_pd_status_t switch_pd_nat_table_add_entry(switch_device_t device,
                                             switch_interface_info_t *intf_info,
                                             switch_nat_info_t *nat_info,
                                             p4_pd_entry_hdl_t *entry_hdl) {
  p4_pd_status_t status = 0;
#ifndef P4_NAT_DISABLE
  p4_pd_dev_target_t p4_pd_device;
  switch_api_nat_info_t *api_nat_info = NULL;

  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

  api_nat_info = &nat_info->api_nat_info;
  switch (api_nat_info->nat_rw_type) {
    case SWITCH_NAT_RW_TYPE_SRC: {
      p4_pd_dc_nat_flow_match_spec_t match_spec;
      p4_pd_dc_set_src_nat_rewrite_index_action_spec_t action_spec;

      memset(&match_spec, 0, sizeof(match_spec));
      memset(&action_spec, 0, sizeof(action_spec));

      match_spec.l3_metadata_vrf = handle_to_id(api_nat_info->vrf_handle);
      match_spec.ipv4_metadata_lkp_ipv4_sa = SWITCH_NAT_SRC_IP(api_nat_info);
      match_spec.l3_metadata_vrf_mask = 0xFFFF;
      match_spec.ipv4_metadata_lkp_ipv4_sa_mask = 0xFFFFFFFF;
      action_spec.action_nat_rewrite_index = nat_info->nat_rw_index;

      status = p4_pd_dc_nat_flow_table_add_with_set_src_nat_rewrite_index(
          g_sess_hdl, p4_pd_device, &match_spec, 0, &action_spec, entry_hdl);
    } break;
    case SWITCH_NAT_RW_TYPE_SRC_TCP:
    case SWITCH_NAT_RW_TYPE_SRC_UDP: {
      p4_pd_dc_nat_src_match_spec_t match_spec;
      p4_pd_dc_set_src_nat_rewrite_index_action_spec_t action_spec;

      memset(&match_spec, 0, sizeof(match_spec));
      memset(&action_spec, 0, sizeof(action_spec));

      match_spec.l3_metadata_vrf = handle_to_id(api_nat_info->vrf_handle);
      match_spec.ipv4_metadata_lkp_ipv4_sa = SWITCH_NAT_SRC_IP(api_nat_info);
      match_spec.l3_metadata_lkp_ip_proto = api_nat_info->protocol;
      match_spec.l3_metadata_lkp_l4_sport = api_nat_info->src_port;
      action_spec.action_nat_rewrite_index = nat_info->nat_rw_index;

      status = p4_pd_dc_nat_src_table_add_with_set_src_nat_rewrite_index(
          g_sess_hdl, p4_pd_device, &match_spec, &action_spec, entry_hdl);
    } break;
    case SWITCH_NAT_RW_TYPE_DST: {
      p4_pd_dc_nat_flow_match_spec_t match_spec;
      p4_pd_dc_set_dst_nat_nexthop_index_action_spec_t action_spec;

      memset(&match_spec, 0, sizeof(match_spec));
      memset(&action_spec, 0, sizeof(action_spec));

      match_spec.l3_metadata_vrf = api_nat_info->vrf_handle;
      match_spec.ipv4_metadata_lkp_ipv4_da = SWITCH_NAT_DST_IP(api_nat_info);
      match_spec.l3_metadata_vrf_mask = 0xFFFF;
      match_spec.ipv4_metadata_lkp_ipv4_da_mask = 0xFFFFFFFF;
      action_spec.action_nexthop_index =
          handle_to_id(api_nat_info->nhop_handle);
      action_spec.action_nat_rewrite_index = nat_info->nat_rw_index;

      status = p4_pd_dc_nat_flow_table_add_with_set_dst_nat_nexthop_index(
          g_sess_hdl, p4_pd_device, &match_spec, 0, &action_spec, entry_hdl);
    } break;
    case SWITCH_NAT_RW_TYPE_DST_TCP:
    case SWITCH_NAT_RW_TYPE_DST_UDP: {
      p4_pd_dc_nat_dst_match_spec_t match_spec;
      p4_pd_dc_set_dst_nat_nexthop_index_action_spec_t action_spec;

      memset(&match_spec, 0, sizeof(match_spec));
      memset(&action_spec, 0, sizeof(action_spec));

      match_spec.l3_metadata_vrf = api_nat_info->vrf_handle;
      match_spec.ipv4_metadata_lkp_ipv4_da = SWITCH_NAT_DST_IP(api_nat_info);
      match_spec.l3_metadata_lkp_ip_proto = api_nat_info->protocol;
      match_spec.l3_metadata_lkp_l4_dport = api_nat_info->dst_port;
      action_spec.action_nexthop_index =
          handle_to_id(api_nat_info->nhop_handle);
      action_spec.action_nat_rewrite_index = nat_info->nat_rw_index;

      status = p4_pd_dc_nat_dst_table_add_with_set_dst_nat_nexthop_index(
          g_sess_hdl, p4_pd_device, &match_spec, &action_spec, entry_hdl);
    } break;
    case SWITCH_NAT_RW_TYPE_SRC_DST: {
      p4_pd_dc_nat_flow_match_spec_t match_spec;
      p4_pd_dc_set_twice_nat_nexthop_index_action_spec_t action_spec;

      memset(&match_spec, 0, sizeof(match_spec));
      memset(&action_spec, 0, sizeof(action_spec));

      match_spec.l3_metadata_vrf = handle_to_id(api_nat_info->vrf_handle);
      match_spec.ipv4_metadata_lkp_ipv4_sa = SWITCH_NAT_SRC_IP(api_nat_info);
      match_spec.ipv4_metadata_lkp_ipv4_da = SWITCH_NAT_DST_IP(api_nat_info);
      match_spec.l3_metadata_vrf_mask = 0xFFFF;
      match_spec.ipv4_metadata_lkp_ipv4_sa_mask = 0xFFFFFFFF;
      match_spec.ipv4_metadata_lkp_ipv4_da_mask = 0xFFFFFFFF;
      action_spec.action_nexthop_index =
          handle_to_id(api_nat_info->nhop_handle);
      action_spec.action_nat_rewrite_index = nat_info->nat_rw_index;

      status = p4_pd_dc_nat_flow_table_add_with_set_twice_nat_nexthop_index(
          g_sess_hdl, p4_pd_device, &match_spec, 0, &action_spec, entry_hdl);
    } break;
    case SWITCH_NAT_RW_TYPE_SRC_DST_TCP:
    case SWITCH_NAT_RW_TYPE_SRC_DST_UDP: {
      p4_pd_dc_nat_twice_match_spec_t match_spec;
      p4_pd_dc_set_twice_nat_nexthop_index_action_spec_t action_spec;

      memset(&match_spec, 0, sizeof(match_spec));
      memset(&action_spec, 0, sizeof(action_spec));

      match_spec.l3_metadata_vrf = handle_to_id(api_nat_info->vrf_handle);
      match_spec.ipv4_metadata_lkp_ipv4_sa = SWITCH_NAT_SRC_IP(api_nat_info);
      match_spec.ipv4_metadata_lkp_ipv4_da = SWITCH_NAT_DST_IP(api_nat_info);
      match_spec.l3_metadata_lkp_ip_proto = api_nat_info->protocol;
      match_spec.l3_metadata_lkp_l4_sport = api_nat_info->src_port;
      match_spec.l3_metadata_lkp_l4_dport = api_nat_info->dst_port;
      action_spec.action_nexthop_index =
          handle_to_id(api_nat_info->nhop_handle);
      action_spec.action_nat_rewrite_index = nat_info->nat_rw_index;

      status = p4_pd_dc_nat_twice_table_add_with_set_twice_nat_nexthop_index(
          g_sess_hdl, p4_pd_device, &match_spec, &action_spec, entry_hdl);
    } break;
  }
#endif /* P4_NAT_DISABLE */

  p4_pd_complete_operations(g_sess_hdl);
  return status;
}

p4_pd_status_t switch_pd_nat_table_delete_entry(switch_device_t device,
                                                switch_nat_info_t *nat_info,
                                                p4_pd_entry_hdl_t entry_hdl) {
  p4_pd_status_t status = 0;
#ifndef P4_NAT_DISABLE
  switch_api_nat_info_t *api_nat_info = NULL;

  api_nat_info = &nat_info->api_nat_info;
  switch (api_nat_info->nat_rw_type) {
    case SWITCH_NAT_RW_TYPE_SRC:
    case SWITCH_NAT_RW_TYPE_DST:
    case SWITCH_NAT_RW_TYPE_SRC_DST:
      status = p4_pd_dc_nat_flow_table_delete(g_sess_hdl, device, entry_hdl);
      break;
    case SWITCH_NAT_RW_TYPE_SRC_TCP:
    case SWITCH_NAT_RW_TYPE_SRC_UDP:
      status = p4_pd_dc_nat_src_table_delete(g_sess_hdl, device, entry_hdl);
      break;
    case SWITCH_NAT_RW_TYPE_DST_TCP:
    case SWITCH_NAT_RW_TYPE_DST_UDP:
      status = p4_pd_dc_nat_dst_table_delete(g_sess_hdl, device, entry_hdl);
      break;
    case SWITCH_NAT_RW_TYPE_SRC_DST_TCP:
    case SWITCH_NAT_RW_TYPE_SRC_DST_UDP:
      status = p4_pd_dc_nat_twice_table_delete(g_sess_hdl, device, entry_hdl);
      break;
  }
#endif /* P4_NAT_DISABLE */

  p4_pd_complete_operations(g_sess_hdl);
  return status;
}

p4_pd_status_t switch_pd_nat_rewrite_table_add_entry(
    switch_device_t device,
    switch_nat_info_t *nat_info,
    p4_pd_entry_hdl_t *entry_hdl) {
  p4_pd_status_t status = 0;
#ifndef P4_NAT_DISABLE
  p4_pd_dc_egress_nat_match_spec_t match_spec;
  p4_pd_dev_target_t p4_pd_device;
  switch_api_nat_info_t *api_nat_info = NULL;

  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

  memset(&match_spec, 0, sizeof(match_spec));
  match_spec.nat_metadata_nat_rewrite_index = nat_info->nat_rw_index;

  api_nat_info = &nat_info->api_nat_info;
  switch (api_nat_info->nat_rw_type) {
    case SWITCH_NAT_RW_TYPE_SRC: {
      p4_pd_dc_set_nat_src_rewrite_action_spec_t action_spec;
      memset(&action_spec, 0, sizeof(action_spec));
      action_spec.action_src_ip = SWITCH_NAT_RW_SRC_IP(api_nat_info);
      status = p4_pd_dc_egress_nat_table_add_with_set_nat_src_rewrite(
          g_sess_hdl, p4_pd_device, &match_spec, &action_spec, entry_hdl);
    } break;
    case SWITCH_NAT_RW_TYPE_DST: {
      p4_pd_dc_set_nat_dst_rewrite_action_spec_t action_spec;
      memset(&action_spec, 0, sizeof(action_spec));
      action_spec.action_dst_ip = SWITCH_NAT_RW_DST_IP(api_nat_info);
      status = p4_pd_dc_egress_nat_table_add_with_set_nat_dst_rewrite(
          g_sess_hdl, p4_pd_device, &match_spec, &action_spec, entry_hdl);
    } break;
    case SWITCH_NAT_RW_TYPE_SRC_DST: {
      p4_pd_dc_set_nat_src_dst_rewrite_action_spec_t action_spec;
      memset(&action_spec, 0, sizeof(action_spec));
      action_spec.action_src_ip = SWITCH_NAT_RW_SRC_IP(api_nat_info);
      action_spec.action_dst_ip = SWITCH_NAT_RW_DST_IP(api_nat_info);
      status = p4_pd_dc_egress_nat_table_add_with_set_nat_src_dst_rewrite(
          g_sess_hdl, p4_pd_device, &match_spec, &action_spec, entry_hdl);
    } break;
    case SWITCH_NAT_RW_TYPE_SRC_UDP: {
      p4_pd_dc_set_nat_src_udp_rewrite_action_spec_t action_spec;
      memset(&action_spec, 0, sizeof(action_spec));
      action_spec.action_src_ip = SWITCH_NAT_RW_SRC_IP(api_nat_info);
      action_spec.action_src_port = api_nat_info->rw_src_port;
      status = p4_pd_dc_egress_nat_table_add_with_set_nat_src_udp_rewrite(
          g_sess_hdl, p4_pd_device, &match_spec, &action_spec, entry_hdl);
    } break;
    case SWITCH_NAT_RW_TYPE_DST_UDP: {
      p4_pd_dc_set_nat_dst_udp_rewrite_action_spec_t action_spec;
      memset(&action_spec, 0, sizeof(action_spec));
      action_spec.action_dst_ip = SWITCH_NAT_RW_DST_IP(api_nat_info);
      action_spec.action_dst_port = api_nat_info->rw_dst_port;
      status = p4_pd_dc_egress_nat_table_add_with_set_nat_dst_udp_rewrite(
          g_sess_hdl, p4_pd_device, &match_spec, &action_spec, entry_hdl);
    } break;
    case SWITCH_NAT_RW_TYPE_SRC_DST_UDP: {
      p4_pd_dc_set_nat_src_dst_udp_rewrite_action_spec_t action_spec;
      memset(&action_spec, 0, sizeof(action_spec));
      action_spec.action_src_ip = SWITCH_NAT_RW_SRC_IP(api_nat_info);
      action_spec.action_src_port = api_nat_info->rw_src_port;
      action_spec.action_dst_ip = SWITCH_NAT_RW_DST_IP(api_nat_info);
      action_spec.action_dst_port = api_nat_info->rw_dst_port;
      status = p4_pd_dc_egress_nat_table_add_with_set_nat_src_dst_udp_rewrite(
          g_sess_hdl, p4_pd_device, &match_spec, &action_spec, entry_hdl);
    } break;
    case SWITCH_NAT_RW_TYPE_SRC_TCP: {
      p4_pd_dc_set_nat_src_tcp_rewrite_action_spec_t action_spec;
      memset(&action_spec, 0, sizeof(action_spec));
      action_spec.action_src_ip = SWITCH_NAT_RW_SRC_IP(api_nat_info);
      action_spec.action_src_port = api_nat_info->rw_src_port;
      status = p4_pd_dc_egress_nat_table_add_with_set_nat_src_tcp_rewrite(
          g_sess_hdl, p4_pd_device, &match_spec, &action_spec, entry_hdl);
    } break;
    case SWITCH_NAT_RW_TYPE_DST_TCP: {
      p4_pd_dc_set_nat_dst_tcp_rewrite_action_spec_t action_spec;
      memset(&action_spec, 0, sizeof(action_spec));
      action_spec.action_dst_ip = SWITCH_NAT_RW_DST_IP(api_nat_info);
      action_spec.action_dst_port = api_nat_info->rw_dst_port;
      status = p4_pd_dc_egress_nat_table_add_with_set_nat_dst_tcp_rewrite(
          g_sess_hdl, p4_pd_device, &match_spec, &action_spec, entry_hdl);
    } break;
    case SWITCH_NAT_RW_TYPE_SRC_DST_TCP: {
      p4_pd_dc_set_nat_src_dst_tcp_rewrite_action_spec_t action_spec;
      memset(&action_spec, 0, sizeof(action_spec));
      action_spec.action_src_ip = SWITCH_NAT_RW_SRC_IP(api_nat_info);
      action_spec.action_src_port = api_nat_info->rw_src_port;
      action_spec.action_dst_ip = SWITCH_NAT_RW_DST_IP(api_nat_info);
      action_spec.action_dst_port = api_nat_info->rw_dst_port;
      status = p4_pd_dc_egress_nat_table_add_with_set_nat_src_dst_tcp_rewrite(
          g_sess_hdl, p4_pd_device, &match_spec, &action_spec, entry_hdl);
    } break;
  }
#endif /* P4_NAT_DISABLE */

  p4_pd_complete_operations(g_sess_hdl);
  return status;
}

p4_pd_status_t switch_pd_nat_rewrite_table_delete_entry(
    switch_device_t device, p4_pd_entry_hdl_t entry_hdl) {
  p4_pd_status_t status = 0;

#ifndef P4_NAT_DISABLE
  status = p4_pd_dc_egress_nat_table_delete(g_sess_hdl, device, entry_hdl);
#endif /* P4_NAT_DISABLE */

  p4_pd_complete_operations(g_sess_hdl);
  return status;
}
