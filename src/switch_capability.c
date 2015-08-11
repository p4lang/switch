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
#include "switchapi/switch_handle.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_vlan.h"
#include "switchapi/switch_vrf.h"
#include "switchapi/switch_capability.h"
#include "switchapi/switch_rmac.h"
#include "switch_pd.h"
#include "switch_capability_int.h"
#include "switch_rmac_int.h"

unsigned int switch_max_configured_ports = 256;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static switch_capability_info_t *switch_info = NULL;

switch_status_t
switch_capability_init(switch_device_t device)
{
    switch_api_capability_t *api_switch_info = NULL;
    switch_port_info_t *port_info = NULL;
    int index = 0;

    switch_info = switch_malloc(sizeof(switch_capability_info_t), 1);
    if (!switch_info) {
        return SWITCH_STATUS_NO_MEMORY;
    }
    api_switch_info = &switch_info->api_switch_info;
    memset(switch_info, 0, sizeof(switch_capability_info_t));
    memset(api_switch_info, 0, sizeof(switch_api_capability_t));

    // Create Default VLAN
    api_switch_info->default_vlan = SWITCH_API_DEFAULT_VLAN;
    switch_info->default_vlan_handle = switch_api_vlan_create(device, SWITCH_API_DEFAULT_VLAN);

    // Create Default Vrf
    api_switch_info->default_vrf = SWITCH_API_DEFAULT_VRF;
    switch_info->default_vrf_handle = switch_api_vrf_create(device, SWITCH_API_DEFAULT_VRF);

    api_switch_info->max_ports = switch_max_configured_ports;
    for (index = 0; index < SWITCH_API_MAX_PORTS; index++) {
        port_info = switch_api_port_get_internal((switch_port_t)index);
        api_switch_info->port_list[index] = port_info->port_handle;
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_api_default_vlan_internal()
{
    return switch_info->default_vlan_handle;
}

switch_handle_t
switch_api_default_vrf_internal()
{
    return switch_info->default_vrf_handle;
}

switch_handle_t
switch_api_capability_rmac_handle_get()
{
    return switch_info->rmac_handle;
}

uint16_t
switch_api_capability_smac_index_get()
{
    return switch_info->smac_index;
}

switch_status_t
switch_api_capability_set(switch_device_t device, switch_api_capability_t *api_switch_info) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_mac_addr_t mac;

    memset(&mac, 0, sizeof(switch_mac_addr_t));
    if (memcmp(&api_switch_info->switch_mac, &mac, ETH_LEN) != 0) {
        memcpy(&switch_info->api_switch_info.switch_mac, &api_switch_info->switch_mac, ETH_LEN);
        switch_info->rmac_handle = switch_api_router_mac_group_create(device);
        status = switch_api_router_mac_add(device, switch_info->rmac_handle, &api_switch_info->switch_mac);
        switch_info->smac_index = switch_smac_rewrite_index_from_rmac(switch_info->rmac_handle);
    }
    return status;
}

switch_status_t
switch_api_capability_get(switch_device_t device, switch_api_capability_t *api_switch_info) {
    memcpy(api_switch_info, &switch_info->api_switch_info, sizeof(switch_api_capability_t));
    return SWITCH_STATUS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
