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

p4_pd_status_t switch_pd_qos_default_entry_add(switch_device_t device) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;

#ifndef P4_QOS_DISABLE

  p4_pd_dev_target_t p4_pd_device;
  p4_pd_entry_hdl_t entry_hdl;

  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  p4_pd_dc_ingress_qos_map_dscp_set_default_action_nop(
      g_sess_hdl, p4_pd_device, &entry_hdl);

  p4_pd_dc_ingress_qos_map_pcp_set_default_action_nop(
      g_sess_hdl, p4_pd_device, &entry_hdl);

  p4_pd_dc_traffic_class_set_default_action_nop(
      g_sess_hdl, p4_pd_device, &entry_hdl);

  p4_pd_dc_egress_qos_map_set_default_action_nop(
      g_sess_hdl, p4_pd_device, &entry_hdl);
#endif /* P4_QOS_DISABLE */

  return status;
}

p4_pd_status_t switch_pd_qos_map_ingress_entry_add(
    switch_device_t device,
    switch_qos_map_ingress_t qos_map_type,
    switch_qos_group_t qos_group_id,
    switch_qos_map_t *qos_map,
    p4_pd_entry_hdl_t *entry_hdl) {
  p4_pd_status_t status = 0;
#ifndef P4_QOS_DISABLE
  p4_pd_dev_target_t p4_pd_device;

  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  switch (qos_map_type) {
    case SWITCH_QOS_MAP_INGRESS_DSCP_TO_TC: {
      p4_pd_dc_ingress_qos_map_dscp_match_spec_t match_spec;
      memset(
          &match_spec, 0, sizeof(p4_pd_dc_ingress_qos_map_dscp_match_spec_t));
      match_spec.qos_metadata_ingress_qos_group = qos_group_id;
      match_spec.qos_metadata_ingress_qos_group_mask = 0xFF;
      match_spec.l3_metadata_lkp_dscp = qos_map->dscp;
      match_spec.l3_metadata_lkp_dscp_mask = 0xFF;
      p4_pd_dc_set_ingress_tc_action_spec_t action_spec;
      memset(&action_spec, 0, sizeof(p4_pd_dc_set_ingress_tc_action_spec_t));
      action_spec.action_tc = qos_map->tc;
      status = p4_pd_dc_ingress_qos_map_dscp_table_add_with_set_ingress_tc(
          g_sess_hdl, p4_pd_device, &match_spec, 1000, &action_spec, entry_hdl);
    } break;
    case SWITCH_QOS_MAP_INGRESS_PCP_TO_TC: {
      p4_pd_dc_ingress_qos_map_pcp_match_spec_t match_spec;
      memset(&match_spec, 0, sizeof(p4_pd_dc_ingress_qos_map_pcp_match_spec_t));
      match_spec.qos_metadata_ingress_qos_group = qos_group_id;
      match_spec.qos_metadata_ingress_qos_group_mask = 0xFF;
      match_spec.l2_metadata_lkp_pcp = qos_map->pcp;
      match_spec.l2_metadata_lkp_pcp_mask = 0xFF;
      p4_pd_dc_set_ingress_tc_action_spec_t action_spec;
      memset(&action_spec, 0, sizeof(p4_pd_dc_set_ingress_tc_action_spec_t));
      action_spec.action_tc = qos_map->tc;
      status = p4_pd_dc_ingress_qos_map_pcp_table_add_with_set_ingress_tc(
          g_sess_hdl, p4_pd_device, &match_spec, 1000, &action_spec, entry_hdl);
    } break;
    case SWITCH_QOS_MAP_INGRESS_DSCP_TO_COLOR: {
      p4_pd_dc_ingress_qos_map_dscp_match_spec_t match_spec;
      memset(
          &match_spec, 0, sizeof(p4_pd_dc_ingress_qos_map_dscp_match_spec_t));
      match_spec.qos_metadata_ingress_qos_group = qos_group_id;
      match_spec.qos_metadata_ingress_qos_group_mask = 0xFF;
      match_spec.l3_metadata_lkp_dscp = qos_map->dscp;
      match_spec.l3_metadata_lkp_dscp_mask = 0xFF;
      p4_pd_dc_set_ingress_color_action_spec_t action_spec;
      memset(&action_spec, 0, sizeof(p4_pd_dc_set_ingress_color_action_spec_t));
      action_spec.action_color = qos_map->color;
      status = p4_pd_dc_ingress_qos_map_dscp_table_add_with_set_ingress_color(
          g_sess_hdl, p4_pd_device, &match_spec, 1000, &action_spec, entry_hdl);
    } break;
    case SWITCH_QOS_MAP_INGRESS_PCP_TO_COLOR: {
      p4_pd_dc_ingress_qos_map_pcp_match_spec_t match_spec;
      memset(&match_spec, 0, sizeof(p4_pd_dc_ingress_qos_map_pcp_match_spec_t));
      match_spec.qos_metadata_ingress_qos_group = qos_group_id;
      match_spec.qos_metadata_ingress_qos_group_mask = 0xFF;
      match_spec.l2_metadata_lkp_pcp = qos_map->pcp;
      match_spec.l2_metadata_lkp_pcp_mask = 0xFF;
      p4_pd_dc_set_ingress_color_action_spec_t action_spec;
      memset(&action_spec, 0, sizeof(p4_pd_dc_set_ingress_color_action_spec_t));
      action_spec.action_color = qos_map->color;
      status = p4_pd_dc_ingress_qos_map_pcp_table_add_with_set_ingress_color(
          g_sess_hdl, p4_pd_device, &match_spec, 1000, &action_spec, entry_hdl);
    } break;
    case SWITCH_QOS_MAP_INGRESS_DSCP_TO_TC_AND_COLOR: {
      p4_pd_dc_ingress_qos_map_dscp_match_spec_t match_spec;
      memset(
          &match_spec, 0, sizeof(p4_pd_dc_ingress_qos_map_dscp_match_spec_t));
      match_spec.qos_metadata_ingress_qos_group = qos_group_id;
      match_spec.qos_metadata_ingress_qos_group_mask = 0xFF;
      match_spec.l3_metadata_lkp_dscp = qos_map->dscp;
      match_spec.l3_metadata_lkp_dscp_mask = 0xFF;
      p4_pd_dc_set_ingress_tc_and_color_action_spec_t action_spec;
      memset(&action_spec,
             0,
             sizeof(p4_pd_dc_set_ingress_tc_and_color_action_spec_t));
      action_spec.action_tc = qos_map->tc;
      action_spec.action_color = qos_map->color;
      status =
          p4_pd_dc_ingress_qos_map_dscp_table_add_with_set_ingress_tc_and_color(
              g_sess_hdl,
              p4_pd_device,
              &match_spec,
              1000,
              &action_spec,
              entry_hdl);
    } break;
    case SWITCH_QOS_MAP_INGRESS_PCP_TO_TC_AND_COLOR: {
      p4_pd_dc_ingress_qos_map_pcp_match_spec_t match_spec;
      memset(&match_spec, 0, sizeof(p4_pd_dc_ingress_qos_map_pcp_match_spec_t));
      match_spec.qos_metadata_ingress_qos_group = qos_group_id;
      match_spec.qos_metadata_ingress_qos_group_mask = 0xFF;
      match_spec.l2_metadata_lkp_pcp = qos_map->pcp;
      match_spec.l2_metadata_lkp_pcp_mask = 0xFF;
      p4_pd_dc_set_ingress_tc_and_color_action_spec_t action_spec;
      memset(&action_spec,
             0,
             sizeof(p4_pd_dc_set_ingress_tc_and_color_action_spec_t));
      action_spec.action_tc = qos_map->tc;
      action_spec.action_color = qos_map->color;
      status =
          p4_pd_dc_ingress_qos_map_pcp_table_add_with_set_ingress_tc_and_color(
              g_sess_hdl,
              p4_pd_device,
              &match_spec,
              1000,
              &action_spec,
              entry_hdl);
    } break;

    case SWITCH_QOS_MAP_INGRESS_TC_TO_ICOS: {
      p4_pd_dc_traffic_class_match_spec_t match_spec;
      memset(&match_spec, 0x0, sizeof(match_spec));
      p4_pd_dc_set_icos_action_spec_t action_spec;
      memset(&action_spec, 0x0, sizeof(action_spec));
      match_spec.qos_metadata_tc_qos_group = qos_group_id;
      match_spec.qos_metadata_tc_qos_group_mask = 0xFF;
      match_spec.qos_metadata_lkp_tc = qos_map->tc;
      match_spec.qos_metadata_lkp_tc_mask = 0xFF;
      action_spec.action_icos = qos_map->icos;
      status = p4_pd_dc_traffic_class_table_add_with_set_icos(
          g_sess_hdl, p4_pd_device, &match_spec, 1000, &action_spec, entry_hdl);
    } break;
    case SWITCH_QOS_MAP_INGRESS_TC_TO_QUEUE: {
      p4_pd_dc_traffic_class_match_spec_t match_spec;
      memset(&match_spec, 0x0, sizeof(match_spec));
      p4_pd_dc_set_queue_action_spec_t action_spec;
      memset(&action_spec, 0x0, sizeof(action_spec));
      match_spec.qos_metadata_tc_qos_group = qos_group_id;
      match_spec.qos_metadata_tc_qos_group_mask = 0xFF;
      match_spec.qos_metadata_lkp_tc = qos_map->tc;
      match_spec.qos_metadata_lkp_tc_mask = 0xFF;
      action_spec.action_qid = qos_map->qid;
      status = p4_pd_dc_traffic_class_table_add_with_set_queue(
          g_sess_hdl, p4_pd_device, &match_spec, 1000, &action_spec, entry_hdl);
    } break;
    case SWITCH_QOS_MAP_INGRESS_TC_TO_ICOS_AND_QUEUE: {
      p4_pd_dc_traffic_class_match_spec_t match_spec;
      memset(&match_spec, 0x0, sizeof(match_spec));
      p4_pd_dc_set_icos_and_queue_action_spec_t action_spec;
      memset(&action_spec, 0x0, sizeof(action_spec));
      match_spec.qos_metadata_tc_qos_group = qos_group_id;
      match_spec.qos_metadata_tc_qos_group_mask = 0xFF;
      match_spec.qos_metadata_lkp_tc = qos_map->tc;
      match_spec.qos_metadata_lkp_tc_mask = 0xFF;
      action_spec.action_qid = qos_map->qid;
      action_spec.action_icos = qos_map->icos;
      status = p4_pd_dc_traffic_class_table_add_with_set_icos_and_queue(
          g_sess_hdl, p4_pd_device, &match_spec, 1000, &action_spec, entry_hdl);
    } break;

    default:
      return SWITCH_STATUS_FAILURE;
  }
#endif /* P4_QOS_DISABLE */
  return status;
}

p4_pd_status_t switch_pd_qos_map_ingress_entry_delete(
    switch_device_t device,
    switch_qos_map_ingress_t qos_map_type,
    p4_pd_entry_hdl_t entry_hdl) {
  p4_pd_status_t status = 0;
#ifndef P4_QOS_DISABLE
  switch (qos_map_type) {
    case SWITCH_QOS_MAP_INGRESS_DSCP_TO_TC:
    case SWITCH_QOS_MAP_INGRESS_DSCP_TO_COLOR:
    case SWITCH_QOS_MAP_INGRESS_DSCP_TO_TC_AND_COLOR:
      status = p4_pd_dc_ingress_qos_map_dscp_table_delete(
          g_sess_hdl, device, entry_hdl);
      break;
    case SWITCH_QOS_MAP_INGRESS_PCP_TO_TC:
    case SWITCH_QOS_MAP_INGRESS_PCP_TO_COLOR:
    case SWITCH_QOS_MAP_INGRESS_PCP_TO_TC_AND_COLOR:
      status = p4_pd_dc_ingress_qos_map_pcp_table_delete(
          g_sess_hdl, device, entry_hdl);
      break;
    case SWITCH_QOS_MAP_INGRESS_TC_TO_ICOS:
    case SWITCH_QOS_MAP_INGRESS_TC_TO_QUEUE:
    case SWITCH_QOS_MAP_INGRESS_TC_TO_ICOS_AND_QUEUE:
      status =
          p4_pd_dc_traffic_class_table_delete(g_sess_hdl, device, entry_hdl);
    default:
      break;
  }
#endif /* P4_QOS_DISABLE */
  return status;
}

p4_pd_status_t switch_pd_qos_map_egress_entry_add(
    switch_device_t device,
    switch_qos_map_egress_t qos_map_type,
    switch_qos_group_t qos_group_id,
    switch_qos_map_t *qos_map,
    p4_pd_entry_hdl_t *entry_hdl) {
  p4_pd_status_t status = 0;
#ifndef P4_QOS_DISABLE
  p4_pd_dc_egress_qos_map_match_spec_t match_spec;
  p4_pd_dev_target_t p4_pd_device;

  p4_pd_device.device_id = device;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

  memset(&match_spec, 0, sizeof(p4_pd_dc_egress_qos_map_match_spec_t));
  match_spec.qos_metadata_egress_qos_group = qos_group_id;
  match_spec.qos_metadata_egress_qos_group_mask = 0xFF;
  match_spec.qos_metadata_lkp_tc = qos_map->tc;
  match_spec.qos_metadata_lkp_tc_mask = 0xFF;

  switch (qos_map_type) {
    case SWITCH_QOS_MAP_EGRESS_TC_TO_DSCP:
    case SWITCH_QOS_MAP_EGRESS_COLOR_TO_DSCP:
    case SWITCH_QOS_MAP_EGRESS_TC_AND_COLOR_TO_DSCP: {
      p4_pd_dc_set_ip_dscp_marking_action_spec_t action_spec;
      memset(
          &action_spec, 0, sizeof(p4_pd_dc_set_ip_dscp_marking_action_spec_t));
      action_spec.action_dscp = qos_map->dscp;
      status = p4_pd_dc_egress_qos_map_table_add_with_set_ip_dscp_marking(
          g_sess_hdl, p4_pd_device, &match_spec, 1000, &action_spec, entry_hdl);
    } break;
    case SWITCH_QOS_MAP_EGRESS_TC_TO_PCP:
    case SWITCH_QOS_MAP_EGRESS_COLOR_TO_PCP:
    case SWITCH_QOS_MAP_EGRESS_TC_AND_COLOR_TO_PCP: {
      p4_pd_dc_set_vlan_pcp_marking_action_spec_t action_spec;
      memset(
          &action_spec, 0, sizeof(p4_pd_dc_set_vlan_pcp_marking_action_spec_t));
      action_spec.action_pcp = qos_map->pcp;
      status = p4_pd_dc_egress_qos_map_table_add_with_set_vlan_pcp_marking(
          g_sess_hdl, p4_pd_device, &match_spec, 1000, &action_spec, entry_hdl);
    } break;
    default:
      return SWITCH_STATUS_FAILURE;
  }
#endif /* P4_QOS_DISABLE */
  return status;
}

p4_pd_status_t switch_pd_qos_map_egress_entry_delete(
    switch_device_t device,
    switch_qos_map_egress_t qos_map_type,
    p4_pd_entry_hdl_t entry_hdl) {
  p4_pd_status_t status = 0;
#ifndef P4_QOS_DISABLE
  status = p4_pd_dc_egress_qos_map_table_delete(g_sess_hdl, device, entry_hdl);
#endif /* P4_QOS_DISABLE */
  return status;
}
