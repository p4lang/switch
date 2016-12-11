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

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_port.h"
#include "switch_pd.h"
#include "switch_log.h"
#include "switch_port_int.h"

static switch_port_info_t switch_port_info[SWITCH_API_MAX_PORTS];
static switch_port_info_t null_port_info;
static switch_port_info_t dummy_port_info;
static void *switch_ppg_array;

switch_status_t switch_port_init(switch_device_t device) {
  switch_port_info_t *port_info = NULL;
  int index = 0;

  memset(
      switch_port_info, 0, sizeof(switch_port_info_t) * SWITCH_API_MAX_PORTS);

  for (index = 0; index < SWITCH_API_MAX_PORTS; index++) {
    port_info = &switch_port_info[index];
    SWITCH_PORT_ID(port_info) = index;
    port_info->ifindex = index + 1;
    port_info->port_type = SWITCH_PORT_TYPE_NORMAL;
    port_info->tc = SWITCH_QOS_DEFAULT_TC;
    port_info->ingress_qos_group = 0;
    port_info->egress_qos_group = 0;
    port_info->tc_qos_group = 0;
    port_info->trust_dscp = FALSE;
    port_info->trust_pcp = FALSE;
    port_info->if_label = index + 1;
    if (index == CPU_PORT_ID) {
      port_info->port_type = SWITCH_PORT_TYPE_CPU;
    }
    port_info->lag_handle = 0;

#ifdef SWITCH_PD
    switch_pd_lag_group_table_add_entry(device,
                                        port_info->ifindex,
                                        SWITCH_PORT_ID(port_info),
                                        &(port_info->mbr_hdl),
                                        &(port_info->lg_entry));
    port_info->hw_entry[0] = SWITCH_HW_INVALID_HANDLE;
    port_info->hw_entry[1] = SWITCH_HW_INVALID_HANDLE;
    switch_pd_ingress_port_mapping_table_add_entry(
        device, port_info->ifindex, port_info->if_label, port_info);
    port_info->eg_port_entry = SWITCH_HW_INVALID_HANDLE;
    switch_pd_egress_port_mapping_table_add_entry(device,
                                                  SWITCH_PORT_ID(port_info),
                                                  port_info->ifindex,
                                                  port_info->if_label,
                                                  port_info->port_type,
                                                  port_info->egress_qos_group,
                                                  &(port_info->eg_port_entry));
    port_info->port_handle = id_to_handle(SWITCH_HANDLE_TYPE_PORT, index);
#endif
  }
  return SWITCH_STATUS_SUCCESS;
}

switch_port_info_t *switch_api_port_get_internal(switch_port_t port) {
  port = handle_to_id(port);
  if (port < SWITCH_API_MAX_PORTS)
    return &switch_port_info[port];
  else if (port == NULL_PORT_ID) {
    return &null_port_info;
  } else {
    return &dummy_port_info;
  }
}

switch_status_t switch_api_port_set(switch_device_t device,
                                    switch_api_port_info_t *api_port_info) {
  switch_port_info_t *port_info =
      switch_api_port_get_internal(api_port_info->port_number);
  UNUSED(device);
  if (port_info) {
    // blindly overwrite the values - may need to get a modify later!
    memcpy(&(port_info->api_port_info),
           api_port_info,
           sizeof(switch_api_port_info_t));
    return SWITCH_STATUS_SUCCESS;
  }
  return SWITCH_STATUS_FAILURE;
}

switch_status_t switch_api_port_get(switch_device_t device,
                                    switch_api_port_info_t *api_port_info) {
  switch_port_info_t *port_info =
      switch_api_port_get_internal(api_port_info->port_number);
  if (!port_info) {
    api_port_info = NULL;
    return SWITCH_STATUS_FAILURE;
  }
  memcpy(
      api_port_info, &port_info->api_port_info, sizeof(switch_api_port_info_t));
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_port_delete(switch_device_t device,
                                       uint16_t port_number) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_port_info_t *port_info = switch_api_port_get_internal(port_number);
  status = switch_pd_lag_group_table_delete_entry(device, port_info->lg_entry);
  status = switch_pd_ingress_port_mapping_table_delete_entry(
      device, port_info->hw_entry);
  return status;
}

// stubs for linking, fill in when functionality is present in p4

switch_status_t switch_api_port_state_get(switch_device_t device,
                                          switch_port_t port,
                                          bool *up) {
  *up = TRUE;
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_port_enable_set(switch_device_t device,
                                           switch_port_t port,
                                           bool enable) {
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_port_enable_get(switch_device_t device,
                                           switch_port_t port,
                                           bool *enable) {
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_port_speed_set(switch_device_t device,
                                          switch_port_t port,
                                          switch_port_speed_t speed) {
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_port_speed_get(switch_device_t device,
                                          switch_port_t port,
                                          switch_port_speed_t *speed) {
  return SWITCH_STATUS_SUCCESS;
}

// end of stubs for linking

switch_status_t switch_api_port_print_entry(switch_port_t port) {
  switch_port_info_t *port_info = NULL;

  port_info = &switch_port_info[port];
  printf("\n\nport number: %d", SWITCH_PORT_ID(port_info));
  printf("\n\tifindex: %x", port_info->ifindex);
  printf("\n");
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_port_print_all(void) {
  switch_port_t port = 0;
  for (port = 0; port < SWITCH_API_MAX_PORTS; port++) {
    switch_api_port_print_entry(port);
  }
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_port_storm_control_set(
    switch_device_t device,
    switch_port_t port,
    switch_packet_type_t pkt_type,
    switch_handle_t meter_handle) {
  switch_port_info_t *port_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  port = handle_to_id(port);
  if (port > SWITCH_API_MAX_PORTS) {
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  port_info = &switch_port_info[port];
  port_info->meter_handle[pkt_type] = meter_handle;
  if (meter_handle) {
    status = switch_pd_storm_control_table_add_entry(
        device,
        port,
        1000,
        pkt_type,
        handle_to_id(meter_handle),
        &port_info->meter_pd_hdl[pkt_type]);
  } else {
    if (port_info->meter_pd_hdl) {
      status = switch_pd_storm_control_table_delete_entry(
          device, port_info->meter_pd_hdl[pkt_type]);
    }
  }
  return status;
}

switch_status_t switch_api_port_storm_control_get(
    switch_device_t device,
    switch_port_t port,
    switch_packet_type_t pkt_type,
    switch_handle_t *meter_handle) {
  switch_port_info_t *port_info = NULL;

  port = handle_to_id(port);
  if (port > SWITCH_API_MAX_PORTS) {
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  port_info = &switch_port_info[port];
  *meter_handle = port_info->meter_handle[pkt_type];
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_storm_control_stats_get(
    switch_device_t device,
    switch_handle_t meter_handle,
    uint8_t count,
    switch_meter_stats_t *counter_ids,
    switch_counter_t *counters) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_meter_info_t *meter_info = NULL;
  switch_meter_stats_info_t *stats_info = NULL;
  int index = 0;
  switch_bd_stats_id_t counter_id = 0;

  meter_info = switch_meter_info_get(meter_handle);
  if (!meter_info) {
    return SWITCH_STATUS_ITEM_NOT_FOUND;
  }

  stats_info = meter_info->stats_info;
  status = switch_pd_storm_control_stats_get(device, meter_info);
  for (index = 0; index < count; index++) {
    counter_id = counter_ids[index];
    counters[index] = stats_info->counters[counter_id];
  }
  return status;
}

bool switch_port_is_cpu_port(switch_handle_t port_hdl) {
  uint32_t port_id = handle_to_id(port_hdl);
  return port_id == CPU_PORT_ID;
}

switch_handle_t switch_ppg_handle_create() {
  switch_handle_t ppg_handle;
  _switch_handle_create(SWITCH_HANDLE_TYPE_PRIORITY_GROUP,
                        switch_port_priority_group_t,
                        switch_ppg_array,
                        NULL,
                        ppg_handle);
  return ppg_handle;
}

switch_port_priority_group_t *switch_ppg_get(switch_handle_t ppg_handle) {
  switch_port_priority_group_t *ppg_info = NULL;
  _switch_handle_get(
      switch_port_priority_group_t, switch_ppg_array, ppg_handle, ppg_info);
  return ppg_info;
}

switch_status_t switch_ppg_handle_delete(switch_handle_t ppg_handle) {
  _switch_handle_delete(
      switch_port_priority_group_t, switch_ppg_array, ppg_handle);
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_ppg_create(switch_device_t device,
                                      switch_handle_t port_handle) {
  switch_port_info_t *port_info = NULL;
  switch_handle_t ppg_handle = SWITCH_API_INVALID_HANDLE;
  switch_port_priority_group_t *ppg_info = NULL;
  uint32_t index = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return status;
  }

  for (index = 0; index < port_info->max_ppg; index++) {
    ppg_handle = switch_ppg_handle_create();
    ppg_info = switch_ppg_get(ppg_handle);
    if (!ppg_info) {
      SWITCH_API_ERROR("failed to allocate port_priority group");
      return status;
    }

    ppg_info->port_handle = port_handle;
    ppg_info->ppg_handle = ppg_handle;

    status =
        switch_pd_ppg_create(device, port_handle, &ppg_info->tm_ppg_handle);
    if (status != SWITCH_STATUS_SUCCESS) {
      SWITCH_API_ERROR("failed to allocate port_priority group");
      return status;
    }
    port_info->ppg_handles[index] = ppg_handle;
  }
  return status;
}

switch_status_t switch_api_ppg_delete(switch_device_t device,
                                      switch_handle_t port_handle) {
  switch_port_info_t *port_info = NULL;
  switch_handle_t ppg_handle = SWITCH_API_INVALID_HANDLE;
  switch_port_priority_group_t *ppg_info = NULL;
  uint32_t index = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return status;
  }

  for (index = 0; index < port_info->max_ppg; index++) {
    ppg_handle = port_info->ppg_handles[index];
    ppg_info = switch_ppg_get(ppg_handle);
    if (!ppg_info) {
      SWITCH_API_ERROR("failed to allocate port_priority group");
      return SWITCH_STATUS_INVALID_HANDLE;
    }

    status = switch_pd_ppg_delete(device, ppg_handle);
    switch_ppg_handle_delete(ppg_handle);
    port_info->ppg_handles[index] = 0;
  }

  return status;
}

switch_status_t switch_api_ppg_get(switch_device_t device,
                                   switch_handle_t port_handle,
                                   uint8_t *num_ppg,
                                   switch_handle_t *ppg_handles) {
  switch_port_info_t *port_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  uint32_t index = 0;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  for (index = 0; index < port_info->max_ppg; index++) {
    ppg_handles[index] = port_info->ppg_handles[index];
  }
  *num_ppg = port_info->max_ppg;

  return status;
}

switch_status_t switch_api_port_cos_mapping(switch_device_t device,
                                            switch_handle_t port_handle,
                                            switch_handle_t ppg_handle,
                                            uint8_t cos_bitmap) {
  switch_port_priority_group_t *ppg_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  ppg_info = switch_ppg_get(ppg_handle);
  if (!ppg_info) {
    SWITCH_API_ERROR("failed to allocate port_priority group");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status = switch_pd_port_ppg_tc_mapping(
      device, ppg_info->tm_ppg_handle, cos_bitmap);
  return status;
}

switch_status_t switch_api_ppg_lossless_enable(switch_device_t device,
                                               switch_handle_t ppg_handle,
                                               bool enable) {
  switch_port_priority_group_t *ppg_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  ppg_info = switch_ppg_get(ppg_handle);
  if (!ppg_info) {
    SWITCH_API_ERROR("failed to allocate port_priority group");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status =
      switch_pd_ppg_lossless_enable(device, ppg_info->tm_ppg_handle, enable);
  return status;
}

switch_status_t switch_api_port_qos_group_ingress_set(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_handle_t qos_handle) {
  switch_port_info_t *port_info = NULL;
  switch_qos_map_list_t *qos_map_list = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  port_info->ingress_qos_group = 0;

  if (qos_handle) {
    qos_map_list = switch_qos_map_get(qos_handle);
    if (!qos_map_list) {
      SWITCH_API_ERROR("qos map get failed\n");
      return SWITCH_STATUS_INVALID_HANDLE;
    }
    port_info->ingress_qos_group = qos_map_list->qos_group;
  }

  status = switch_pd_ingress_port_mapping_table_add_entry(
      device, port_info->ifindex, port_info->if_label, port_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("port qos group ingress set failed");
  }
  return status;
}

switch_status_t switch_api_port_qos_group_tc_set(switch_device_t device,
                                                 switch_handle_t port_handle,
                                                 switch_handle_t qos_handle) {
  switch_port_info_t *port_info = NULL;
  switch_qos_map_list_t *qos_map_list = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  port_info->tc_qos_group = 0;

  if (qos_handle) {
    qos_map_list = switch_qos_map_get(qos_handle);
    if (!qos_map_list) {
      SWITCH_API_ERROR("qos map get failed\n");
      return SWITCH_STATUS_INVALID_HANDLE;
    }
    port_info->tc_qos_group = qos_map_list->qos_group;
  }

  status = switch_pd_ingress_port_mapping_table_add_entry(
      device, port_info->ifindex, port_info->if_label, port_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("port qos group tc set failed");
  }
  return status;
}

switch_status_t switch_api_port_qos_group_egress_set(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_handle_t qos_handle) {
  switch_port_info_t *port_info = NULL;
  switch_qos_map_list_t *qos_map_list = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  port_info->egress_qos_group = 0;

  if (qos_handle) {
    qos_map_list = switch_qos_map_get(qos_handle);
    if (!qos_map_list) {
      SWITCH_API_ERROR("qos map get failed\n");
      return SWITCH_STATUS_INVALID_HANDLE;
    }
    port_info->egress_qos_group = qos_map_list->qos_group;
  }

  status = switch_pd_egress_port_mapping_table_add_entry(
      device,
      SWITCH_PORT_ID(port_info),
      port_info->ifindex,
      port_info->if_label,
      port_info->port_type,
      port_info->egress_qos_group,
      &(port_info->eg_port_entry));
  return status;
}

switch_status_t switch_api_port_tc_default_set(switch_device_t device,
                                               switch_handle_t port_handle,
                                               uint16_t tc) {
  switch_port_info_t *port_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  port_info->tc = tc;

  status = switch_pd_ingress_port_mapping_table_add_entry(
      device, port_info->ifindex, port_info->if_label, port_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("port tc default set failed");
  }
  return status;
}

switch_status_t switch_api_port_color_default_set(switch_device_t device,
                                                  switch_handle_t port_handle,
                                                  switch_color_t color) {
  switch_port_info_t *port_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  port_info->color = color;

  status = switch_pd_ingress_port_mapping_table_add_entry(
      device, port_info->ifindex, port_info->if_label, port_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("port color default set failed");
  }
  return status;
}

switch_status_t switch_api_port_trust_dscp_set(switch_device_t device,
                                               switch_handle_t port_handle,
                                               bool trust_dscp) {
  switch_port_info_t *port_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  if (port_info->trust_pcp && trust_dscp) {
    SWITCH_API_ERROR("dscp trust cannot be enabled when pcp is enabled");
    return SWITCH_STATUS_INVALID_ATTRIBUTE;
  }

  port_info->trust_dscp = trust_dscp;

  status = switch_pd_ingress_port_mapping_table_add_entry(
      device, port_info->ifindex, port_info->if_label, port_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("port trust dscp set failed");
  }
  return status;
}

switch_status_t switch_api_port_trust_pcp_set(switch_device_t device,
                                              switch_handle_t port_handle,
                                              bool trust_pcp) {
  switch_port_info_t *port_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  if (port_info->trust_dscp && trust_pcp) {
    SWITCH_API_ERROR("pcp trust cannot be enabled when dscp is enabled");
    return SWITCH_STATUS_INVALID_ATTRIBUTE;
  }

  port_info->trust_pcp = trust_pcp;

  status = switch_pd_ingress_port_mapping_table_add_entry(
      device, port_info->ifindex, port_info->if_label, port_info);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("port trust pcp set failed");
  }
  return status;
}

switch_status_t switch_api_ppg_guaranteed_limit_set(switch_device_t device,
                                                    switch_handle_t ppg_handle,
                                                    uint32_t num_bytes) {
  switch_port_priority_group_t *ppg_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  ppg_info = switch_ppg_get(ppg_handle);
  if (!ppg_info) {
    SWITCH_API_ERROR("failed to allocate port_priority group");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status = switch_pd_ppg_guaranteed_limit_set(
      device, ppg_info->tm_ppg_handle, num_bytes);
  return status;
}

switch_status_t switch_api_ppg_skid_limit_set(switch_device_t device,
                                              switch_handle_t ppg_handle,
                                              uint32_t num_bytes) {
  switch_port_priority_group_t *ppg_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  ppg_info = switch_ppg_get(ppg_handle);
  if (!ppg_info) {
    SWITCH_API_ERROR("failed to allocate port_priority group");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status =
      switch_pd_ppg_skid_limit_set(device, ppg_info->tm_ppg_handle, num_bytes);
  return status;
}

switch_status_t switch_api_ppg_skid_hysteresis_set(switch_device_t device,
                                                   switch_handle_t ppg_handle,
                                                   uint32_t num_bytes) {
  switch_port_priority_group_t *ppg_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  ppg_info = switch_ppg_get(ppg_handle);
  if (!ppg_info) {
    SWITCH_API_ERROR("failed to allocate port_priority group");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status = switch_pd_ppg_skid_hysteresis_set(
      device, ppg_info->tm_ppg_handle, num_bytes);
  return status;
}

switch_status_t switch_api_port_drop_limit_set(switch_device_t device,
                                               switch_handle_t port_handle,
                                               uint32_t num_bytes) {
  switch_port_info_t *port_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status = switch_pd_port_drop_limit_set(device, port_handle, num_bytes);

  return status;
}

switch_status_t switch_api_port_drop_hysteresis_set(switch_device_t device,
                                                    switch_handle_t port_handle,
                                                    uint32_t num_bytes) {
  switch_port_info_t *port_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status = switch_pd_port_drop_hysteresis_set(device, port_handle, num_bytes);
  return status;
}

switch_status_t switch_api_port_pfc_cos_mapping(switch_device_t device,
                                                switch_handle_t port_handle,
                                                uint8_t *cos_to_icos) {
  switch_port_info_t *port_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status = switch_pd_port_pfc_cos_mapping(device, port_handle, cos_to_icos);
  return status;
}

switch_status_t switch_api_port_flowcontrol_mode_set(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_flowcontrol_type_t flow_control) {
  switch_port_info_t *port_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status =
      switch_pd_port_flowcontrol_mode_set(device, port_handle, flow_control);
  return status;
}
