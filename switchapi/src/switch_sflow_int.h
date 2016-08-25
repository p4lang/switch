/*
 * Copyright 2015-present Barefoot Networks, Inc.
 */

#include "switchapi/switch_sflow.h"
#include "switch_pd_types.h"

#ifndef _SWITCH_SFLOW_INT_H_
#define _SWITCH_SFLOW_INT_H_

typedef struct switch_sflow_match__key_ {
  switch_handle_t port;
  uint16_t vlan;
  uint32_t sip;
  uint32_t sip_mask;
  uint32_t dip;
  uint32_t dip_mask;
} switch_sflow_match_key_t;

typedef struct switch_sflow_match_entry_ {
  tommy_node node;
  p4_pd_entry_hdl_t ingress_sflow_ent_hdl;
  switch_handle_t sflow_ace_hdl;
} switch_sflow_match_entry_t;

typedef struct switch_sflow_info_ {
  switch_api_sflow_session_info_t api_info;
  uint8_t session_id;
  switch_handle_t mirror_hdl;
  p4_pd_entry_hdl_t mirror_table_ent_hdl;
  p4_pd_entry_hdl_t ing_take_sample_table_ent_hdl;

  // use tommy list to store all the match key_value_pairs
  // using this sflow_session
  tommy_list match_list;
} switch_sflow_info_t;

void switch_sflow_init(switch_device_t device);
#endif /*_SWITCH_SFLOW_INT_H_*/
