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
#include "switchapi/switch_interface.h"
#include "switchapi/switch_l3.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_port.h"
#include "switchapi/switch_vlan.h"
#include "switchapi/switch_nhop.h"
#include "switchapi/switch_rmac.h"
#include "switch_rmac_int.h"
#include "switch_lag_int.h"
#include "switch_pd.h"
#include "switch_hostif_int.h"
#include "switch_log_int.h"
#include "switch_capability_int.h"

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static void *switch_interface_array;

switch_status_t switch_interface_init(switch_device_t device) {
  UNUSED(device);
  return switch_handle_type_init(SWITCH_HANDLE_TYPE_INTERFACE, (16 * 1024));
}

switch_status_t switch_interface_free(switch_device_t device) {
  UNUSED(device);
  switch_handle_type_free(SWITCH_HANDLE_TYPE_INTERFACE);
  return SWITCH_STATUS_SUCCESS;
}

switch_handle_t switch_interface_handle_create() {
  switch_handle_t handle;
  _switch_handle_create(SWITCH_HANDLE_TYPE_INTERFACE,
                        switch_interface_info_t,
                        switch_interface_array,
                        NULL,
                        handle);
  return handle;
}

switch_interface_info_t *switch_api_interface_get(
    switch_handle_t interface_handle) {
  switch_interface_info_t *interface_info = NULL;
  _switch_handle_get(switch_interface_info_t,
                     switch_interface_array,
                     interface_handle,
                     interface_info);
  return interface_info;
}

switch_status_t switch_api_interface_get_type(switch_handle_t intf_handle,
                                              switch_interface_type_t *type) {
  switch_interface_info_t *intf_info = NULL;
  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  *type = SWITCH_INTF_TYPE(intf_info);
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_interface_get_port_handle(
    switch_handle_t intf_handle, switch_handle_t *port_handle) {
  switch_interface_info_t *intf_info = NULL;
  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_L2_PORT_VLAN) {
    *port_handle = SWITCH_INTF_PV_PORT_HANDLE(intf_info);
  } else {
    *port_handle = SWITCH_INTF_PORT_HANDLE(intf_info);
  }
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_interface_get_vlan_handle(
    switch_handle_t intf_handle, switch_handle_t *vlan_handle) {
  switch_interface_info_t *intf_info = NULL;
  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  *vlan_handle = intf_info->bd_handle;
  return SWITCH_STATUS_SUCCESS;
}

switch_handle_t switch_api_interface_get_from_ifindex(
    switch_ifindex_t ifindex, switch_handle_t bd_handle) {
  switch_handle_t intf_handle = 0;
  switch_handle_t port_lag_handle = 0;
  uint16_t tunnel_id = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (SWITCH_INTF_IS_TUNNEL_IFINDEX(ifindex)) {
    tunnel_id = SWITCH_INTF_TUNNEL_ID(ifindex);
    intf_handle = id_to_handle(SWITCH_HANDLE_TYPE_INTERFACE, tunnel_id);
  } else {
    if (SWITCH_IS_LAG_IFINDEX(ifindex)) {
      port_lag_handle = id_to_handle(SWITCH_HANDLE_TYPE_LAG,
                                     SWITCH_LAG_ID_FROM_IFINDEX(ifindex));
    } else {
      port_lag_handle = id_to_handle(SWITCH_HANDLE_TYPE_PORT, (ifindex - 1));
    }

    status =
        switch_interface_handle_get(port_lag_handle, bd_handle, &intf_handle);
    if (status != SWITCH_STATUS_SUCCESS) {
      SWITCH_API_ERROR("interface handle get failed for port_lag_handle %lx",
                       port_lag_handle);
    }
  }
  return intf_handle;
}

switch_status_t switch_api_interface_create_l2(
    switch_device_t device,
    switch_handle_t intf_handle,
    switch_interface_info_t *intf_info) {
  switch_port_info_t *port_info = NULL;
  switch_lag_info_t *lag_info = NULL;
  switch_handle_t port_lag_handle = 0;
  switch_handle_t tmp_intf_handle = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  UNUSED(device);
  if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_L2_PORT_VLAN) {
    port_lag_handle = SWITCH_INTF_PV_PORT_HANDLE(intf_info);
  } else {
    port_lag_handle = SWITCH_INTF_PORT_HANDLE(intf_info);
  }
  if (SWITCH_HANDLE_IS_LAG(port_lag_handle)) {
    lag_info = switch_api_lag_get_internal(port_lag_handle);
    if (!lag_info) {
      return SWITCH_STATUS_INVALID_HANDLE;
    }
    intf_info->ifindex = lag_info->ifindex;
  } else {
    port_info =
        switch_api_port_get_internal(SWITCH_INTF_PORT_HANDLE(intf_info));
    if (!port_info) {
      return SWITCH_STATUS_INVALID_PORT_NUMBER;
    }
    port_lag_handle = id_to_handle(SWITCH_HANDLE_TYPE_PORT, port_lag_handle);
    intf_info->ifindex = port_info->ifindex;
  }
  SWITCH_INTF_FLOOD_ENABLED(intf_info) = TRUE;

  if (handle_to_id(port_lag_handle) != CPU_PORT_ID) {
    status =
        switch_interface_handle_get(port_lag_handle, 0x0, &tmp_intf_handle);
    if (status != SWITCH_STATUS_ITEM_NOT_FOUND) {
      status = SWITCH_STATUS_INVALID_PARAMETER;
      SWITCH_API_ERROR(
          "interface create failed. "
          "one interface per l2 port is allowed");
      return status;
    }

    status = switch_interface_array_insert(port_lag_handle, intf_handle);
    if (status != SWITCH_STATUS_SUCCESS) {
      SWITCH_API_ERROR("interface array insert failed");
      return status;
    }
  }

  // TODO: should we add the l2 port to default vlan ?
  // TODO: Will the application remove the port from
  // default vlan when adding it to new vlan ?
  /*
  vlan_handle = switch_api_default_vlan_internal();
  status = switch_api_add_ports_to_vlan(vlan_handle, 1, &intf_handle);
  if (status != SWITCH_STATUS_SUCCESS) {
  // TODO: Do the intf_handle cleanup
  return status;
  }
  */
  return status;
}

switch_status_t switch_api_interface_create_l3(
    switch_device_t device,
    switch_handle_t intf_handle,
    switch_interface_info_t *intf_info) {
  switch_handle_t port_lag_handle = 0;
  switch_logical_network_t ln_info_tmp;
  switch_logical_network_t *ln_info = NULL;
  switch_port_info_t *port_info = NULL;
  switch_bd_info_t *bd_info = NULL;
  switch_lag_info_t *lag_info = NULL;
  switch_api_interface_info_t *api_intf_info = NULL;
  switch_vlan_t vlan_id = 0;
  switch_handle_t tmp_intf_handle = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  tommy_list_init(&(intf_info->ip_addr));
  api_intf_info = &intf_info->api_intf_info;

  switch (SWITCH_INTF_TYPE(intf_info)) {
    case SWITCH_API_INTERFACE_L3:
      vlan_id = 0;
      port_lag_handle = SWITCH_INTF_PORT_HANDLE(intf_info);
      break;
    case SWITCH_API_INTERFACE_L3_PORT_VLAN:
      vlan_id = SWITCH_INTF_PV_VLAN_ID(intf_info);
      port_lag_handle = SWITCH_INTF_PV_PORT_HANDLE(intf_info);
      break;

    default:
      SWITCH_API_ERROR(
          "%s:%d: unsupported interface type!", __FUNCTION__, __LINE__);
      return SWITCH_STATUS_UNSUPPORTED_TYPE;
  }

  if (SWITCH_HANDLE_IS_LAG(port_lag_handle)) {
    lag_info = switch_api_lag_get_internal(port_lag_handle);
    if (!lag_info) {
      return SWITCH_STATUS_INVALID_HANDLE;
    }
    intf_info->ifindex = lag_info->ifindex;
  } else {
    port_info =
        switch_api_port_get_internal(SWITCH_INTF_PORT_HANDLE(intf_info));
    if (!port_info) {
      return SWITCH_STATUS_INVALID_PORT_NUMBER;
    }
    port_lag_handle = id_to_handle(SWITCH_HANDLE_TYPE_PORT, port_lag_handle);
    intf_info->ifindex = port_info->ifindex;
  }

  if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_L3) {
    status =
        switch_interface_handle_get(port_lag_handle, 0x0, &tmp_intf_handle);
    if (status != SWITCH_STATUS_ITEM_NOT_FOUND) {
      status = SWITCH_STATUS_INVALID_PARAMETER;
      SWITCH_API_ERROR(
          "interface create failed. "
          "one interface per l3 port is allowed\n");
      return status;
    }
  }

  ln_info = &ln_info_tmp;
  memset(ln_info, 0, sizeof(switch_logical_network_t));
  ln_info->type = SWITCH_LOGICAL_NETWORK_TYPE_L3;
  ln_info->vrf_handle = api_intf_info->vrf_handle;
  ln_info->rmac_handle = api_intf_info->rmac_handle;
  ln_info->flags.ipv4_unicast_enabled = TRUE;
  ln_info->flags.ipv6_unicast_enabled = TRUE;
  ln_info->flags.ipv4_multicast_enabled = api_intf_info->ipv4_multicast_enabled;
  ln_info->flags.ipv6_multicast_enabled = api_intf_info->ipv6_multicast_enabled;
  if (!api_intf_info->rmac_handle) {
    if (api_intf_info->mac_valid) {
      api_intf_info->rmac_handle = switch_api_router_mac_group_create(device);
      status = switch_api_router_mac_add(
          device, api_intf_info->rmac_handle, &api_intf_info->mac);
    } else {
      api_intf_info->rmac_handle = switch_api_capability_rmac_handle_get();
    }
  }
  ln_info->rmac_handle = api_intf_info->rmac_handle;
  intf_info->bd_handle = switch_api_logical_network_create(device, ln_info);

  if (intf_info->bd_handle == SWITCH_API_INVALID_HANDLE) {
    status = SWITCH_STATUS_INVALID_HANDLE;
    SWITCH_API_ERROR(
        "interface create failed. "
        "bd allocation failed");
    return status;
  }

  switch_api_interface_ipv4_urpf_mode_set(intf_handle,
                                          api_intf_info->ipv4_urpf_mode);
  switch_api_interface_nat_mode_set(intf_handle, api_intf_info->nat_mode);
  bd_info = switch_bd_get(intf_info->bd_handle);
  if (!bd_info) {
    status = SWITCH_STATUS_INVALID_HANDLE;
    SWITCH_API_ERROR(
        "interface create failed. "
        "bd allocation failed");
    return status;
  }

  status = switch_pd_port_vlan_mapping_table_add_entry(
      device, vlan_id, 0, intf_info, bd_info->bd_entry, &(intf_info->pv_entry));
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("bd programming failed for l3 intf %lx", intf_handle);
    return status;
  }

  if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_L3_PORT_VLAN) {
    status = switch_pd_egress_vlan_xlate_table_add_entry(
        device,
        intf_info->ifindex,
        handle_to_id(intf_info->bd_handle),
        vlan_id,
        &intf_info->xlate_entry);

    if (status != SWITCH_STATUS_SUCCESS) {
      SWITCH_API_ERROR("xlate programming failed for l3 vlan intf %lx",
                       intf_handle);
      return status;
    }
  }

  status = switch_interface_array_insert(port_lag_handle, intf_handle);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("interface array insert failed");
    return status;
  }

  bd_info->l3_intf_handle = intf_handle;

  return status;
}

switch_status_t switch_api_interface_create_vlan_interface(
    switch_device_t device,
    switch_handle_t intf_handle,
    switch_interface_info_t *intf_info) {
  switch_api_interface_info_t *api_intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_vlan_t vlan_id = 0;
  switch_bd_info_t *bd_info = NULL;
  switch_logical_network_t *ln_info = NULL;
  switch_handle_t bd_handle = 0;

  vlan_id = SWITCH_INTF_VLAN_ID(intf_info);
  status = switch_api_vlan_id_to_handle_get(vlan_id, &bd_handle);
  // Assumption here is vlan is already created
  bd_info = switch_bd_get(bd_handle);
  if (!bd_info) {
    return SWITCH_STATUS_INVALID_VLAN_ID;
  }
  api_intf_info = &intf_info->api_intf_info;
  ln_info = &bd_info->ln_info;
  ln_info->vrf_handle = api_intf_info->vrf_handle;
  ln_info->flags.ipv4_unicast_enabled = api_intf_info->ipv4_unicast_enabled;
  ln_info->flags.ipv6_unicast_enabled = api_intf_info->ipv6_unicast_enabled;
  ln_info->flags.ipv4_multicast_enabled = api_intf_info->ipv4_multicast_enabled;
  ln_info->flags.ipv6_multicast_enabled = api_intf_info->ipv6_multicast_enabled;
  if (!api_intf_info->rmac_handle) {
    if (api_intf_info->mac_valid) {
      api_intf_info->rmac_handle = switch_api_router_mac_group_create(device);
      status = switch_api_router_mac_add(
          device, api_intf_info->rmac_handle, &api_intf_info->mac);
    } else {
      api_intf_info->rmac_handle = switch_api_capability_rmac_handle_get();
    }
  }
  ln_info->rmac_handle = api_intf_info->rmac_handle;
  intf_info->bd_handle = bd_handle;
  intf_info->ifindex = SWITCH_VLAN_INTERFACE_COMPUTE_IFINDEX(intf_handle);
  switch_api_logical_network_update(device, bd_handle, ln_info);

  bd_info->l3_intf_handle = intf_handle;

  return status;
}

switch_handle_t switch_api_interface_create(
    switch_device_t device, switch_api_interface_info_t *api_intf_info) {
  switch_handle_t intf_handle;
  switch_handle_t encap_if_handle;
  switch_interface_info_t *intf_info = NULL;
  switch_interface_info_t *encap_if = NULL;

  intf_handle = switch_interface_handle_create();
  intf_info = switch_api_interface_get(intf_handle);

  if (!intf_info) {
    return SWITCH_STATUS_NO_MEMORY;
  }

  memset(intf_info, 0, sizeof(switch_interface_info_t));
  memcpy(&intf_info->api_intf_info,
         api_intf_info,
         sizeof(switch_api_interface_info_t));

  switch (SWITCH_INTF_TYPE(intf_info)) {
    case SWITCH_API_INTERFACE_L2_VLAN_ACCESS:
    case SWITCH_API_INTERFACE_L2_VLAN_TRUNK:
    case SWITCH_API_INTERFACE_L2_PORT_VLAN:
      switch_api_interface_create_l2(device, intf_handle, intf_info);
      break;
    case SWITCH_API_INTERFACE_L3:            // Pure L3 Port
    case SWITCH_API_INTERFACE_L3_PORT_VLAN:  // L3 Sub-Intf
      switch_api_interface_create_l3(device, intf_handle, intf_info);
      break;

    case SWITCH_API_INTERFACE_L3_VLAN:
      switch_api_interface_create_vlan_interface(
          device, intf_handle, intf_info);
      break;

    case SWITCH_API_INTERFACE_TUNNEL:  // L3 tunnel
      // TODO: Derive a new BD and return
      encap_if_handle = SWITCH_INTF_TUNNEL_ENCAP_OUT_IF(intf_info);
      encap_if = switch_api_interface_get(encap_if_handle);
      if (!encap_if) {
        SWITCH_API_TRACE(
            "%s:%d: invalid encap interface handle", __FUNCTION__, __LINE__);
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      intf_info->ifindex = SWITCH_INTF_COMPUTE_TUNNEL_IFINDEX(intf_handle);
      break;

      break;
    default:
      intf_info->bd_handle = 0;
  }

  return intf_handle;
}

switch_status_t switch_api_interface_handle_reset(switch_device_t device,
                                                  switch_handle_t intf_handle) {
  switch_handle_t port_lag_handle = 0;
  switch_interface_info_t *intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  port_lag_handle = SWITCH_INTF_PORT_HANDLE(intf_info);
  if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_L3_PORT_VLAN) {
    port_lag_handle = SWITCH_INTF_PV_PORT_HANDLE(intf_info);
  }

  if (!(SWITCH_HANDLE_IS_LAG(port_lag_handle))) {
    port_lag_handle = id_to_handle(SWITCH_HANDLE_TYPE_PORT, port_lag_handle);
  }

  status = switch_interface_array_delete(port_lag_handle, intf_handle);
  return status;
}

switch_status_t switch_api_interface_delete_l2(switch_device_t device,
                                               switch_handle_t intf_handle) {
  return switch_api_interface_handle_reset(device, intf_handle);
}

switch_status_t switch_api_interface_delete_vlan_interface(
    switch_device_t device, switch_handle_t intf_handle) {
  switch_interface_info_t *intf_info = NULL;
  switch_bd_info_t *bd_info = NULL;
  switch_logical_network_t *ln_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }
  bd_info = switch_bd_get(intf_info->bd_handle);
  if (!bd_info) {
    return SWITCH_STATUS_INVALID_VLAN_ID;
  }
  // Disable L3 on BD
  ln_info = &bd_info->ln_info;
  ln_info->vrf_handle = 0;
  ln_info->flags.ipv4_unicast_enabled = FALSE;
  ln_info->flags.ipv6_unicast_enabled = FALSE;
  ln_info->rmac_handle = 0;
  status = switch_pd_bd_table_update_entry(
      device, handle_to_id(intf_info->bd_handle), bd_info);
  bd_info->l3_intf_handle = 0;

  return status;
}

switch_status_t switch_api_interface_delete_l3_interface(
    switch_device_t device, switch_handle_t intf_handle) {
  switch_interface_info_t *intf_info = NULL;
  switch_bd_info_t *bd_info = NULL;
  switch_api_interface_info_t *api_intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }
  bd_info = switch_bd_get(intf_info->bd_handle);
  if (!bd_info) {
    return SWITCH_STATUS_INVALID_VLAN_ID;
  }

  switch_pd_port_vlan_mapping_table_delete_entry(device, intf_info->pv_entry);

  if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_L3_PORT_VLAN) {
    status = switch_pd_egress_vlan_xlate_table_delete_entry(
        device, intf_info->xlate_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
      SWITCH_API_ERROR("xlate entry delete failed for l3 intf %lx",
                       intf_handle);
    }
  }

  switch_api_logical_network_delete(device, intf_info->bd_handle);
  intf_info->bd_handle = 0;
  api_intf_info = &intf_info->api_intf_info;
  if (api_intf_info->mac_valid) {
    status = switch_api_router_mac_delete(
        device, api_intf_info->rmac_handle, &api_intf_info->mac);
    status =
        switch_api_router_mac_group_delete(device, api_intf_info->rmac_handle);
  }

  switch_api_interface_handle_reset(device, intf_handle);

  bd_info->l3_intf_handle = 0;

  return status;
}

switch_status_t switch_api_interface_delete(switch_device_t device,
                                            switch_handle_t handle) {
  switch_interface_info_t *intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!SWITCH_INTERFACE_HANDLE_VALID(handle)) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  intf_info = switch_api_interface_get(handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  switch (SWITCH_INTF_TYPE(intf_info)) {
    case SWITCH_API_INTERFACE_L2_VLAN_ACCESS:
    case SWITCH_API_INTERFACE_L2_VLAN_TRUNK:
    case SWITCH_API_INTERFACE_L2_PORT_VLAN:
      switch_api_interface_delete_l2(device, handle);

    case SWITCH_API_INTERFACE_L3:
    case SWITCH_API_INTERFACE_L3_PORT_VLAN:
      switch_api_interface_delete_l3_interface(device, handle);
      break;
    case SWITCH_API_INTERFACE_L3_VLAN:
      switch_api_interface_delete_vlan_interface(device, handle);
      break;
    default:
      break;
  }

  _switch_handle_delete(
      switch_interface_info_t, switch_interface_array, handle);
  return status;
}

switch_status_t switch_api_interface_attribute_set(switch_handle_t intf_handle,
                                                   switch_intf_attr_t attr_type,
                                                   uint64_t value) {
  switch_interface_info_t *intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  switch (attr_type) {
    case SWITCH_INTF_ATTR_V4_UNICAST:
      status =
          switch_api_interface_ipv4_unicast_enabled_set(intf_handle, value);
      break;
    case SWITCH_INTF_ATTR_V6_UNICAST:
      status =
          switch_api_interface_ipv6_unicast_enabled_set(intf_handle, value);
      break;
    case SWITCH_INTF_ATTR_NATIVE_VLAN:
      status = switch_api_interface_native_vlan_set(intf_handle, value);
      break;
    default:
      status = SWITCH_STATUS_INVALID_ATTRIBUTE;
      break;
  }
  return status;
}

switch_status_t switch_api_interface_attribute_get(switch_handle_t intf_handle,
                                                   switch_intf_attr_t attr_type,
                                                   uint64_t *value) {
  switch_interface_info_t *intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  switch (attr_type) {
    case SWITCH_INTF_ATTR_V4_UNICAST:
      status =
          switch_api_interface_ipv4_unicast_enabled_get(intf_handle, value);
      break;
    case SWITCH_INTF_ATTR_V6_UNICAST:
      status =
          switch_api_interface_ipv6_unicast_enabled_get(intf_handle, value);
      break;
    case SWITCH_INTF_ATTR_NATIVE_VLAN:
      status = switch_api_interface_native_vlan_get(intf_handle, value);
      break;
    case SWITCH_INTF_ATTR_VRF:
      switch_api_interface_vrf_get(intf_handle, value);
      break;
    case SWITCH_INTF_ATTR_TYPE:
      // not sure yet
      break;
    case SWITCH_INTF_ATTR_PORT_ID:
      switch_api_interface_port_id_get(intf_handle, value);
      break;
    case SWITCH_INTF_ATTR_VLAN_ID:
      switch_api_interface_vlan_id_get(intf_handle, value);
      break;
    case SWITCH_INTF_ATTR_RMAC_ADDR:
      status = switch_api_interface_rmac_addr_get(intf_handle, value);
      break;
    default:
      status = SWITCH_STATUS_INVALID_ATTRIBUTE;
      break;
  }
  return status;
}

switch_status_t switch_api_interface_ipv4_unicast_enabled_set(
    switch_handle_t intf_handle, uint64_t value) {
  switch_interface_info_t *intf_info = NULL;
  switch_api_interface_info_t *api_intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info = &intf_info->api_intf_info;
  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info->ipv4_unicast_enabled = value;
  status = switch_bd_ipv4_unicast_enabled_set(intf_info->bd_handle, value);
  return status;
}

switch_status_t switch_api_interface_ipv4_unicast_enabled_get(
    switch_handle_t intf_handle, uint64_t *value) {
  switch_interface_info_t *intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  status = switch_bd_ipv4_unicast_enabled_get(intf_info->bd_handle, value);
  return status;
}

switch_status_t switch_api_interface_ipv6_unicast_enabled_set(
    switch_handle_t intf_handle, uint64_t value) {
  switch_interface_info_t *intf_info = NULL;
  switch_api_interface_info_t *api_intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info = &intf_info->api_intf_info;
  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info->ipv6_unicast_enabled = value;
  status = switch_bd_ipv6_unicast_enabled_set(intf_info->bd_handle, value);
  return status;
}

switch_status_t switch_api_interface_ipv6_unicast_enabled_get(
    switch_handle_t intf_handle, uint64_t *value) {
  switch_interface_info_t *intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  status = switch_bd_ipv6_unicast_enabled_get(intf_info->bd_handle, value);
  return status;
}

switch_status_t switch_api_interface_ipv4_multicast_enabled_set(
    switch_handle_t intf_handle, uint64_t value) {
  switch_interface_info_t *intf_info = NULL;
  switch_api_interface_info_t *api_intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info = &intf_info->api_intf_info;
  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info->ipv4_multicast_enabled = value;
  status = switch_bd_ipv4_multicast_enabled_set(intf_info->bd_handle, value);
  return status;
}

switch_status_t switch_api_interface_ipv4_multicast_enabled_get(
    switch_handle_t intf_handle, uint64_t *value) {
  switch_interface_info_t *intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  status = switch_bd_ipv4_multicast_enabled_get(intf_info->bd_handle, value);
  return status;
}

switch_status_t switch_api_interface_ipv6_multicast_enabled_set(
    switch_handle_t intf_handle, uint64_t value) {
  switch_interface_info_t *intf_info = NULL;
  switch_api_interface_info_t *api_intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info = &intf_info->api_intf_info;
  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info->ipv6_multicast_enabled = value;
  status = switch_bd_ipv6_multicast_enabled_set(intf_info->bd_handle, value);
  return status;
}

switch_status_t switch_api_interface_ipv6_multicast_enabled_get(
    switch_handle_t intf_handle, uint64_t *value) {
  switch_interface_info_t *intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  status = switch_bd_ipv6_multicast_enabled_get(intf_info->bd_handle, value);
  return status;
}

switch_status_t switch_api_interface_ipv4_urpf_mode_set(
    switch_handle_t intf_handle, uint64_t value) {
  switch_interface_info_t *intf_info = NULL;
  switch_api_interface_info_t *api_intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info = &intf_info->api_intf_info;
  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info->ipv4_urpf_mode = value;
  status = switch_bd_ipv4_urpf_mode_set(intf_info->bd_handle, value);
  return status;
}

switch_status_t switch_api_interface_ipv4_urpf_mode_get(
    switch_handle_t intf_handle, uint64_t *value) {
  switch_interface_info_t *intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  status = switch_bd_ipv4_urpf_mode_get(intf_info->bd_handle, value);
  return status;
}

switch_status_t switch_api_interface_ipv6_urpf_mode_set(
    switch_handle_t intf_handle, uint64_t value) {
  switch_interface_info_t *intf_info = NULL;
  switch_api_interface_info_t *api_intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info = &intf_info->api_intf_info;
  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info->ipv6_urpf_mode = value;
  status = switch_bd_ipv6_urpf_mode_set(intf_info->bd_handle, value);
  return status;
}

switch_status_t switch_api_interface_ipv6_urpf_mode_get(
    switch_handle_t intf_handle, uint64_t *value) {
  switch_interface_info_t *intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  status = switch_bd_ipv6_urpf_mode_get(intf_info->bd_handle, value);
  return status;
}

switch_status_t switch_api_interface_nat_mode_set(switch_handle_t intf_handle,
                                                  uint8_t value) {
  switch_interface_info_t *intf_info = NULL;
  switch_api_interface_info_t *api_intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info = &intf_info->api_intf_info;
  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info->nat_mode = value;
  status = switch_bd_nat_mode_set(intf_info->bd_handle, value);
  return status;
}

switch_status_t switch_api_interface_nat_mode_get(switch_handle_t intf_handle,
                                                  uint8_t *value) {
  switch_interface_info_t *intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  status = switch_bd_nat_mode_get(intf_info->bd_handle, value);
  return status;
}

switch_status_t switch_api_interface_native_vlan_set(
    switch_handle_t intf_handle, uint64_t value) {
  switch_interface_info_t *intf_info = NULL;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  if (SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  SWITCH_INTF_NATIVE_VLAN_HANDLE(intf_info) = (switch_handle_t)value;
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_interface_native_vlan_get(
    switch_handle_t intf_handle, uint64_t *value) {
  switch_interface_info_t *intf_info = NULL;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  *value = (uint64_t)SWITCH_INTF_NATIVE_VLAN_HANDLE(intf_info);
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_interface_vrf_get(switch_handle_t intf_handle,
                                             uint64_t *value) {
  switch_interface_info_t *intf_info = NULL;
  switch_api_interface_info_t *api_intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info = &intf_info->api_intf_info;

  *value = api_intf_info->vrf_handle;

  return status;
}

switch_status_t switch_api_interface_port_id_get(switch_handle_t intf_handle,
                                                 uint64_t *value) {
  switch_interface_info_t *intf_info = NULL;
  switch_api_interface_info_t *api_intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info = &intf_info->api_intf_info;
  if ((!SWITCH_INTF_IS_PORT_L3(intf_info)) &&
      (!SWITCH_INTF_IS_PORT_L2(intf_info))) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }
  *value = api_intf_info->u.port_lag_handle;

  return status;
}

switch_status_t switch_api_interface_vlan_id_get(switch_handle_t intf_handle,
                                                 uint64_t *value) {
  switch_interface_info_t *intf_info = NULL;
  switch_api_interface_info_t *api_intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info = &intf_info->api_intf_info;
  if (SWITCH_INTF_IS_PORT_L3(intf_info) || SWITCH_INTF_IS_PORT_L2(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }
  *value = api_intf_info->u.vlan_id;

  return status;
}

switch_status_t switch_api_interface_rmac_addr_get(switch_handle_t intf_handle,
                                                   uint64_t *value) {
  switch_interface_info_t *intf_info = NULL;
  switch_api_interface_info_t *api_intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  api_intf_info = &intf_info->api_intf_info;

  memcpy((uint8_t *)value, api_intf_info->mac.mac_addr, 6);

  return status;
}

switch_status_t switch_interface_array_insert(switch_handle_t port_lag_handle,
                                              switch_handle_t intf_handle) {
  switch_handle_type_t handle_type = 0;
  switch_port_info_t *port_info = NULL;
  switch_lag_info_t *lag_info = NULL;
  void **array = NULL;
  void *temp = NULL;
  switch_interface_info_t *intf_info = NULL;

  handle_type = switch_handle_get_type(port_lag_handle);

  switch (handle_type) {
    case SWITCH_HANDLE_TYPE_PORT:
      port_info = switch_api_port_get_internal(port_lag_handle);
      if (!port_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      array = &port_info->intf_array;
      break;

    case SWITCH_HANDLE_TYPE_LAG:
      lag_info = switch_api_lag_get_internal(port_lag_handle);
      if (!lag_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      array = &lag_info->intf_array;
      break;

    default:
      return SWITCH_STATUS_INVALID_HANDLE;
  }

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    SWITCH_API_ERROR("intf array insert failed. invalid interface handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  JLI(temp, *array, intf_handle);
  *(unsigned long *)temp = (unsigned long)intf_handle;
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_interface_array_delete(switch_handle_t port_lag_handle,
                                              switch_handle_t intf_handle) {
  switch_handle_type_t handle_type = 0;
  switch_port_info_t *port_info = NULL;
  switch_lag_info_t *lag_info = NULL;
  void **array = NULL;
  switch_interface_info_t *intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  handle_type = switch_handle_get_type(port_lag_handle);

  switch (handle_type) {
    case SWITCH_HANDLE_TYPE_PORT:
      port_info = switch_api_port_get_internal(port_lag_handle);
      if (!port_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      array = &port_info->intf_array;
      break;

    case SWITCH_HANDLE_TYPE_LAG:
      lag_info = switch_api_lag_get_internal(port_lag_handle);
      if (!lag_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      array = &lag_info->intf_array;
      break;

    default:
      return SWITCH_STATUS_INVALID_HANDLE;
  }

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    SWITCH_API_ERROR("intf array insert failed. invalid interface handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  JLD(status, *array, intf_handle);
  return status;
}

switch_status_t switch_interface_handle_get(switch_handle_t port_lag_handle,
                                            switch_handle_t bd_handle,
                                            switch_handle_t *intf_handle) {
  switch_handle_type_t handle_type = 0;
  switch_port_info_t *port_info = NULL;
  switch_lag_info_t *lag_info = NULL;
  void **array = NULL;
  void *temp = NULL;
  switch_handle_t tmp_intf_handle = 0;
  switch_interface_info_t *intf_info = NULL;

  *intf_handle = 0;

  handle_type = switch_handle_get_type(port_lag_handle);

  switch (handle_type) {
    case SWITCH_HANDLE_TYPE_PORT:
      port_info = switch_api_port_get_internal(port_lag_handle);
      if (!port_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      array = &port_info->intf_array;
      break;

    case SWITCH_HANDLE_TYPE_LAG:
      lag_info = switch_api_lag_get_internal(port_lag_handle);
      if (!lag_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
      }
      array = &lag_info->intf_array;
      break;

    default:
      return SWITCH_STATUS_INVALID_HANDLE;
  }

  JLF(temp, *array, tmp_intf_handle);
  while (temp) {
    intf_info = switch_api_interface_get(tmp_intf_handle);
    if (intf_info) {
      switch (SWITCH_INTF_TYPE(intf_info)) {
        case SWITCH_API_INTERFACE_L2_VLAN_ACCESS:
        case SWITCH_API_INTERFACE_L2_VLAN_TRUNK:
        case SWITCH_API_INTERFACE_L2_PORT_VLAN:
          *intf_handle = tmp_intf_handle;
          return SWITCH_STATUS_SUCCESS;
        case SWITCH_API_INTERFACE_L3:
          *intf_handle = tmp_intf_handle;
          return SWITCH_STATUS_SUCCESS;
        case SWITCH_API_INTERFACE_L3_PORT_VLAN:
          if (bd_handle == intf_info->bd_handle) {
            *intf_handle = tmp_intf_handle;
            return SWITCH_STATUS_SUCCESS;
          }
          break;
        default:
          break;
      }
    }
    JLN(temp, *array, tmp_intf_handle);
  }

  return SWITCH_STATUS_ITEM_NOT_FOUND;
}

switch_status_t switch_api_interface_l3_ifs_get(
    switch_l3_interfaces_iterator_fn iterator_fn) {
  switch_interface_info_t *intf_info = NULL;
  void *temp = NULL;
  switch_handle_t intf_handle = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  JLF(temp, switch_interface_array, intf_handle);
  while (temp) {
    if (SWITCH_INTF_IS_PORT_L3(intf_info)) {
      intf_info = switch_api_interface_get(intf_handle);
      if (intf_info) {
        iterator_fn(intf_info->api_intf_info);
      }
    }
    JLN(temp, switch_interface_array, intf_handle);
  }
  return status;
}

switch_status_t switch_api_interface_get_entry(switch_handle_t intf_handle,
                                               char *entry,
                                               int entry_length) {
  switch_interface_info_t *intf_info = NULL;
  int bytes_output = 0;

  UNUSED(entry_length);
  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }
  bytes_output += sprintf(
      entry + bytes_output, "\nintf_handle: %x", (unsigned int)intf_handle);
  bytes_output +=
      sprintf(entry + bytes_output, "\nifindex: %x", intf_info->ifindex);
  bytes_output += sprintf(
      entry + bytes_output, "intf_type: %x", SWITCH_INTF_TYPE(intf_info));
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_interface_print_entry(switch_handle_t intf_handle) {
  switch_interface_info_t *intf_info = NULL;
  switch_api_interface_info_t *api_intf_info = NULL;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }
  api_intf_info = &intf_info->api_intf_info;
  printf("\n\n intf_handle: %x", (unsigned int)intf_handle);
  printf("\n ifindex %x intf type %x",
         intf_info->ifindex,
         SWITCH_INTF_TYPE(intf_info));
  printf("\n v4 %d v6 %d",
         api_intf_info->ipv4_unicast_enabled,
         api_intf_info->ipv6_unicast_enabled);
  printf("\n v4 urpf %d v6 urpf %d",
         api_intf_info->ipv4_urpf_mode,
         api_intf_info->ipv6_urpf_mode);
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_interface_print_all(void) {
  switch_handle_t intf_handle = 0;
  switch_handle_t next_intf_handle = 0;

  switch_handle_get_first(switch_interface_array, intf_handle);
  while (intf_handle) {
    switch_api_interface_print_entry(intf_handle);
    switch_handle_get_next(
        switch_interface_array, intf_handle, next_intf_handle);
    intf_handle = next_intf_handle;
  }
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_l3_interface_bd_stats_enable(
    switch_device_t device, switch_handle_t intf_handle) {
  switch_interface_info_t *intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  status = switch_api_bd_stats_enable(device, intf_info->bd_handle);
  return status;
}

switch_status_t switch_api_l3_interface_bd_stats_disable(
    switch_device_t device, switch_handle_t intf_handle) {
  switch_interface_info_t *intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  status = switch_api_bd_stats_disable(device, intf_info->bd_handle);
  return status;
}

switch_status_t switch_api_l3_interface_stats_get(
    switch_device_t device,
    switch_handle_t intf_handle,
    uint8_t count,
    switch_bd_stats_id_t *counter_ids,
    switch_counter_t *counters) {
  switch_interface_info_t *intf_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  intf_info = switch_api_interface_get(intf_handle);
  if (!intf_info) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
    return SWITCH_STATUS_INVALID_INTERFACE;
  }

  status = switch_api_bd_stats_get(
      device, intf_info->bd_handle, count, counter_ids, counters);
  return status;
}

#ifdef SWITCH_INTERFACE_TEST
int _switch_interface_main(int argc, char **argv) {
  switch_interface_info_t info;

  switch_interface_init();

  info.type = SWITCH_API_INTERFACE_L3;

  info.u.port = 0;
  switch_handle_t id1 = switch_interface_create(0, &info);

  info.u.port = 0;
  switch_handle_t id2 = switch_interface_create(0, &info);

  printf("id1 = 0x%lx id2 0x%lx\n", id1, id2);

  switch_api_interface_delete(id1);
  switch_api_interface_delete(id2);

  switch_interface_free();
  return 0;
}
#endif

#ifdef __cplusplus
}
#endif
