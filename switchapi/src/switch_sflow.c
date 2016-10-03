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
#include "assert.h"
#include "switchapi/switch_base_types.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_mirror.h"
#include "switchapi/switch_sflow.h"
#include "switch_sflow_int.h"
#include "switch_pd.h"
#include "switch_port_int.h"
#include "switch_interface_int.h"

#ifdef P4_SFLOW_ENABLE

static void *switch_sflow_array = NULL;
static void *switch_sflow_ace_array = NULL;

#endif  // P4_SFLOW_ENABLE

void switch_sflow_init(switch_device_t device) {
#ifdef P4_SFLOW_ENABLE
  switch_sflow_array = NULL;
  switch_handle_type_allocator_init(SWITCH_HANDLE_TYPE_SFLOW,
                                    SWITCH_MAX_SFLOW_SESSIONS,
                                    false /*grow*/,
                                    false /*zero_based*/);

  switch_sflow_ace_array = NULL;
  switch_handle_type_allocator_init(SWITCH_HANDLE_TYPE_SFLOW_ACE,
                                    SWITCH_MAX_SFLOW_ACES,
                                    false /*grow*/,
                                    false /*zero_based*/);
  return;
#else
  (void)device;
#endif  // P4_SFLOW_ENABLE
}

#ifdef P4_SFLOW_ENABLE
static switch_handle_t switch_sflow_handle_create() {
  switch_handle_t sflow_handle = SWITCH_API_INVALID_HANDLE;
  _switch_handle_create(SWITCH_HANDLE_TYPE_SFLOW,
                        switch_sflow_info_t,
                        switch_sflow_array,
                        NULL,
                        sflow_handle);
  return sflow_handle;
}

void switch_sflow_handle_delete(switch_handle_t sflow_handle) {
  _switch_handle_delete(switch_sflow_info_t, switch_sflow_array, sflow_handle);
}

switch_sflow_info_t *switch_sflow_info_get(switch_handle_t sflow_handle) {
  switch_sflow_info_t *sflow_info = NULL;
  _switch_handle_get(
      switch_sflow_info_t, switch_sflow_array, sflow_handle, sflow_info);
  return sflow_info;
}

static switch_handle_t switch_sflow_ace_handle_create() {
  switch_handle_t sflow_ace_handle = SWITCH_API_INVALID_HANDLE;
  _switch_handle_create(SWITCH_HANDLE_TYPE_SFLOW_ACE,
                        switch_sflow_match_entry_t,
                        switch_sflow_ace_array,
                        NULL,
                        sflow_ace_handle);
  return sflow_ace_handle;
}

void switch_sflow_ace_handle_delete(switch_handle_t sflow_ace_handle) {
  _switch_handle_delete(
      switch_sflow_match_entry_t, switch_sflow_ace_array, sflow_ace_handle);
}

switch_sflow_match_entry_t *switch_sflow_ace_entry_get(
    switch_handle_t sflow_ace_handle) {
  switch_sflow_match_entry_t *sflow_ace_info = NULL;
  _switch_handle_get(switch_sflow_match_entry_t,
                     switch_sflow_ace_array,
                     sflow_ace_handle,
                     sflow_ace_info);
  return sflow_ace_info;
}
#endif  // P4_SFLOW_ENABLE

switch_handle_t switch_api_sflow_session_create(
    switch_device_t device, switch_api_sflow_session_info_t *api_sflow_info) {
#ifdef P4_SFLOW_ENABLE
  switch_handle_t sflow_handle = SWITCH_API_INVALID_HANDLE;
  switch_sflow_info_t *sflow_info = NULL;
  switch_status_t status = SWITCH_STATUS_FAILURE;

  // Parameter validation
  if (api_sflow_info->collector_type != SFLOW_COLLECTOR_TYPE_CPU) {
    // Only sflow via cpu is supported at this time
    return SWITCH_API_INVALID_HANDLE;
  } else if (!switch_port_is_cpu_port(api_sflow_info->egress_port_hdl)) {
    return SWITCH_API_INVALID_HANDLE;
  }
  if (api_sflow_info->sample_mode != SWITCH_SFLOW_SAMPLE_PKT) {
    // single packet per notificaiton - other modes are TBD
    return SWITCH_API_INVALID_HANDLE;
  }
  if (api_sflow_info->sample_rate == 0) {
    return SWITCH_API_INVALID_HANDLE;
  }
  sflow_handle = switch_sflow_handle_create();
  if (sflow_handle == SWITCH_API_INVALID_HANDLE) {
    return sflow_handle;
  }
  sflow_info = switch_sflow_info_get(sflow_handle);
  if (!sflow_info) {
    return SWITCH_API_INVALID_HANDLE;
  }
  sflow_info->session_id = handle_to_id(sflow_handle);
  sflow_info->api_info = *api_sflow_info;
  tommy_list_init(&sflow_info->match_list);

  sflow_info->mirror_hdl = SWITCH_API_INVALID_HANDLE;
  sflow_info->mirror_table_ent_hdl = SWITCH_HW_INVALID_HANDLE;
  sflow_info->ing_take_sample_table_ent_hdl = SWITCH_HW_INVALID_HANDLE;

  // Create a mirror session to send sampled pkts to CPU.
  // SWITCH_CPU_MIRROR_SESSION_ID mirror-session can be used, except
  // it does not truncate the packet. sFlow may not need entire packet.
  // CPU can perform tuncation as well, but this makes it a bit easier
  // for CPU
  if (api_sflow_info->collector_type == SFLOW_COLLECTOR_TYPE_CPU) {
    switch_api_mirror_info_t api_mirror_info;

    memset(&api_mirror_info, 0, sizeof(switch_api_mirror_info_t));
    api_mirror_info.mirror_type = SWITCH_MIRROR_TYPE_LOCAL;
    // mirror session id is allocated by the mirroring api
    api_mirror_info.session_type = SWITCH_MIRROR_SESSION_TYPE_SIMPLE;
    api_mirror_info.egress_port = CPU_PORT_ID;
    api_mirror_info.direction = SWITCH_API_DIRECTION_BOTH;
    api_mirror_info.max_pkt_len = api_sflow_info->extract_len;

    sflow_info->mirror_hdl =
        switch_api_mirror_session_create(device, &api_mirror_info);
    if (sflow_info->mirror_hdl == SWITCH_API_INVALID_HANDLE) {
      goto error_return;
    }
  } else {
    assert(0);
  }

  status = switch_pd_sflow_session_create(device, sflow_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    goto error_return;
  }

  return sflow_handle;

error_return:
  switch_api_sflow_session_delete(device, sflow_handle, false);
  return SWITCH_API_INVALID_HANDLE;

#else
  (void)device;
  (void)api_sflow_info;
  return SWITCH_API_INVALID_HANDLE;
#endif
}

switch_status_t switch_api_sflow_session_delete(switch_device_t device,
                                                switch_handle_t sflow_hdl,
                                                bool all_cleanup) {
#ifdef P4_SFLOW_ENABLE
  switch_sflow_info_t *sflow_info;

  sflow_info = switch_sflow_info_get(sflow_hdl);
  if (!sflow_info) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }
  if (!tommy_list_empty(&sflow_info->match_list) && !all_cleanup) {
    return SWITCH_STATUS_RESOURCE_IN_USE;
  }
  if (all_cleanup) {
    switch_sflow_match_entry_t *entry;
    tommy_node *node = NULL;
    while ((node = tommy_list_head(&sflow_info->match_list)) && node) {
      entry = (switch_sflow_match_entry_t *)node->data;
      // could be ingress or egress match entry
      switch_pd_sflow_match_table_delete(device, entry);
      tommy_list_remove_existing(&sflow_info->match_list, node);
      switch_sflow_ace_handle_delete(entry->sflow_ace_hdl);
    }
  }

  switch_pd_sflow_session_delete(device, sflow_info);

  if (sflow_info->mirror_hdl != SWITCH_API_INVALID_HANDLE) {
    switch_api_mirror_session_delete(device, sflow_info->mirror_hdl);
  }

  switch_sflow_handle_delete(sflow_hdl);

  return SWITCH_STATUS_SUCCESS;
#else
  (void)device;
  (void)sflow_hdl;
  (void)all_cleanup;
  return SWITCH_STATUS_FAILURE;
#endif  // P4_SFLOW_ENABLE
}

// TBD - sflow_session_update()

#ifdef P4_SFLOW_ENABLE
switch_status_t switch_sflow_match_key_from_tlv(
    unsigned int key_value_count,
    switch_sflow_match_key_value_pair_t *kvp,
    switch_sflow_match_key_t *match_key) {
  unsigned int k;
  bool key_found = false;
  for (k = 0; k < key_value_count; k++) {
    switch (kvp[k].field) {
      case SWITCH_SFLOW_MATCH_PORT:
        match_key->port = kvp[k].value.port;
        key_found = true;
        break;
      case SWITCH_SFLOW_MATCH_VLAN:
        match_key->vlan = kvp[k].value.vlan;
        // key_found = true; - not supported
        break;
      case SWITCH_SFLOW_MATCH_SIP:
        match_key->sip = kvp[k].value.sip;
        // no range mask supported
        match_key->sip_mask = (uint32_t)kvp[k].mask.u.mask;
        key_found = true;
        break;
      case SWITCH_SFLOW_MATCH_DIP:
        match_key->dip = kvp[k].value.dip;
        match_key->dip_mask = (uint32_t)kvp[k].mask.u.mask;
        key_found = true;
        break;
      default:
        assert(0);
        break;
    }
  }
  if (!key_found) {
    return SWITCH_STATUS_INVALID_PARAMETER;
  }
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_sflow_match_entry_remove(switch_sflow_info_t *sflow_info,
                                                switch_handle_t entry_hdl) {
  tommy_node *node = tommy_list_head(&sflow_info->match_list);
  while (node) {
    switch_sflow_match_entry_t *obj = (switch_sflow_match_entry_t *)node->data;
    if (obj->sflow_ace_hdl == entry_hdl) {
      break;
    }
    node = node->next;
  }
  if (node) {
    tommy_list_remove_existing(&sflow_info->match_list, node);
    return SWITCH_STATUS_SUCCESS;
  }
  return SWITCH_STATUS_ITEM_NOT_FOUND;
}
#endif

switch_status_t switch_api_sflow_session_attach(
    switch_device_t device,
    switch_handle_t sflow_hdl,
    switch_direction_t direction,
    unsigned int priority,
    unsigned int
        sample_rate, /* != 0 can override sampling rate of the session */
    unsigned int key_value_count,
    switch_sflow_match_key_value_pair_t *kvp,
    switch_handle_t *entry_hdl) {
#ifdef P4_SFLOW_ENABLE
  switch_sflow_match_key_t match_key;
  switch_sflow_match_entry_t *match_entry = NULL;
  switch_status_t status = SWITCH_STATUS_FAILURE;
  switch_sflow_info_t *sflow_info;

  sflow_info = switch_sflow_info_get(sflow_hdl);
  if (!sflow_info) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }
  // key-value pairs are used to specify the match-criteria for enabling sflow
  // For ingress sflow, ternary match on ingress port, sip, dip are supported
  // TBD - check if the match_spec is already used - callers responsibilty for
  // now

  if (!kvp || key_value_count > SWITCH_SFLOW_MATCH_FIELD_MAX) {
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  memset(&match_key, 0, sizeof(switch_sflow_match_key_t));
  match_key.port = SWITCH_API_INVALID_HANDLE;

  status = switch_sflow_match_key_from_tlv(key_value_count, kvp, &match_key);
  if (status != SWITCH_STATUS_SUCCESS) {
    goto error_return;
  }

  // create handle for match entry
  *entry_hdl = switch_sflow_ace_handle_create();
  match_entry = switch_sflow_ace_entry_get(*entry_hdl);
  match_entry->sflow_ace_hdl = *entry_hdl;

  if (direction == SWITCH_API_DIRECTION_INGRESS) {
    status = switch_pd_sflow_ingress_table_add(
        device, &match_key, priority, sample_rate, sflow_info, match_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
      goto error_return;
    }
    // add the match entry to the list
    tommy_list_insert_tail(
        &sflow_info->match_list, &match_entry->node, match_entry);

  } else if (direction == SWITCH_API_DIRECTION_EGRESS) {
    status = SWITCH_STATUS_NOT_SUPPORTED;
    goto error_return;
  } else {
    status = SWITCH_STATUS_INVALID_PARAMETER;
    goto error_return;
  }
  return SWITCH_STATUS_SUCCESS;

error_return:
  *entry_hdl = SWITCH_API_INVALID_HANDLE;
  return status;

#else
  (void)device;
  (void)sflow_hdl;
  (void)direction;
  (void)priority;
  (void)key_value_count;
  (void)kvp;
  (void)entry_hdl;
  return SWITCH_STATUS_FAILURE;
#endif  // P4_SFLOW_ENABLE
}

switch_status_t switch_api_sflow_session_detach(switch_device_t device,
                                                switch_handle_t sflow_hdl,
                                                switch_handle_t entry_hdl) {
#ifdef P4_SFLOW_ENABLE
  switch_sflow_match_entry_t *match_entry = NULL;
  switch_status_t status = SWITCH_STATUS_FAILURE;
  switch_sflow_info_t *sflow_info;

  sflow_info = switch_sflow_info_get(sflow_hdl);
  if (!sflow_info) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }
  if ((match_entry = switch_sflow_ace_entry_get(entry_hdl)) == NULL) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }
  if ((status = switch_sflow_match_entry_remove(sflow_info, entry_hdl)) !=
      SWITCH_STATUS_SUCCESS) {
    return SWITCH_STATUS_FAILURE;
  }
  status = switch_pd_sflow_match_table_delete(device, match_entry);
  switch_sflow_ace_handle_delete(entry_hdl);
  return status;
#else
  (void)device;
  (void)sflow_hdl;
  (void)entry_hdl;
  return SWITCH_STATUS_FAILURE;
#endif  // P4_SFLOW_ENABLE
}

switch_status_t switch_api_sflow_session_sample_count_get(
    switch_device_t device,
    switch_handle_t sflow_hdl,
    switch_handle_t entry_hdl,
    switch_counter_t *sample_pool) {
#ifdef P4_SFLOW_ENABLE
  switch_sflow_match_entry_t *match_entry = NULL;
  switch_status_t status = SWITCH_STATUS_FAILURE;
  switch_sflow_info_t *sflow_info;

  sflow_info = switch_sflow_info_get(sflow_hdl);
  if (!sflow_info) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }
  if ((match_entry = switch_sflow_ace_entry_get(entry_hdl)) == NULL) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }
  status = switch_pd_sflow_counter_read(device, match_entry, sample_pool);
  return status;

#else
  (void)device;
  (void)sflow_hdl;
  (void)entry_hdl;
  return SWITCH_STATUS_FAILURE;
#endif  // P4_SFLOW_ENABLE
}

switch_status_t switch_api_sflow_session_sample_count_reset(
    switch_device_t device,
    switch_handle_t sflow_hdl,
    switch_handle_t entry_hdl) {
#ifdef P4_SFLOW_ENABLE
  switch_sflow_match_entry_t *match_entry = NULL;
  switch_status_t status = SWITCH_STATUS_FAILURE;
  switch_sflow_info_t *sflow_info;
  switch_counter_t val;

  sflow_info = switch_sflow_info_get(sflow_hdl);
  if (!sflow_info) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }
  if ((match_entry = switch_sflow_ace_entry_get(entry_hdl)) == NULL) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }
  memset(&val, 0, sizeof(val));
  status = switch_pd_sflow_counter_write(device, match_entry, val);
  return status;
#else
  (void)device;
  (void)sflow_hdl;
  (void)entry_hdl;
  return SWITCH_STATUS_FAILURE;
#endif  // P4_SFLOW_ENABLE
}
