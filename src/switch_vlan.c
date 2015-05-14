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

#include "switchapi/switch_id.h"
#include "switchapi/switch_vlan.h"
#include "switchapi/switch_interface.h"
#include "switchapi/switch_port.h"
#include "switchapi/switch_mcast.h"
#include "switch_pd.h"
#include "switch_lag_int.h"
#include "switch_log.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
static void *switch_bd_array = NULL;

switch_status_t switch_bd_init(void)
{
    switch_handle_type_init(SWITCH_HANDLE_TYPE_BD, (16*1024));
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_bd_free(void)
{
    switch_handle_type_free(SWITCH_HANDLE_TYPE_BD);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t switch_bd_create()
{
    switch_handle_t handle;
    _switch_handle_create(SWITCH_HANDLE_TYPE_BD,
                      switch_bd_info_t,
                      switch_bd_array, NULL, handle);
    return handle;
}

switch_bd_info_t *switch_bd_get(switch_handle_t handle)
{
    switch_bd_info_t *bd_info = NULL;
    _switch_handle_get(switch_bd_info_t,
                   switch_bd_array,
                   handle, bd_info);
    return bd_info;
}

void switch_bd_delete(switch_handle_t handle)
{
    _switch_handle_delete(switch_bd_info_t, switch_bd_array, handle);
}


void switch_logical_network_mc_index_allocate(switch_bd_info_t *bd_info)
{
    switch_logical_network_t *ln_info = NULL;

    ln_info = &bd_info->ln_info;
    //if ((ln_info->flood_type & SWITCH_VLAN_FLOOD_UUC) &&
    //    (bd_info->uuc_mc_index == 0)) {
        bd_info->uuc_mc_index = switch_api_mcast_index_allocate();
    //}
    if ((ln_info->flood_type & SWITCH_VLAN_FLOOD_UMC) && 
        (bd_info->umc_mc_index == 0)) {
        bd_info->umc_mc_index = switch_api_mcast_index_allocate();
    }
    if ((ln_info->flood_type & SWITCH_VLAN_FLOOD_BCAST) &&
        (bd_info->bcast_mc_index == 0)) {
        bd_info->bcast_mc_index = switch_api_mcast_index_allocate();
    }
}

void switch_logical_network_mc_index_free(switch_bd_info_t *bd_info)
{
    switch_logical_network_t *ln_info = NULL;

    ln_info = &bd_info->ln_info;
    //if (ln_info->flood_type & SWITCH_VLAN_FLOOD_UUC) {
        switch_api_mcast_index_delete(bd_info->uuc_mc_index);
        bd_info->uuc_mc_index = 0;
    //}
    if (ln_info->flood_type & SWITCH_VLAN_FLOOD_UMC) {
        switch_api_mcast_index_delete(bd_info->umc_mc_index);
        bd_info->umc_mc_index = 0;
    }
    if (ln_info->flood_type & SWITCH_VLAN_FLOOD_BCAST) {
        switch_api_mcast_index_delete(bd_info->bcast_mc_index);
        bd_info->bcast_mc_index = 0;
    }
}

void switch_logical_network_init_default(switch_bd_info_t *bd_info)
{
    switch_logical_network_t *ln_info = NULL;

    ln_info = &bd_info->ln_info;
    ln_info->age_interval = SWITCH_API_VLAN_DEFAULT_AGE_INTERVAL;
    ln_info->flood_type = SWITCH_VLAN_FLOOD_NONE;
    SWITCH_LN_FLOOD_ENABLED(bd_info) = TRUE;
    SWITCH_LN_LEARN_ENABLED(bd_info) = TRUE;
    return;
}

switch_handle_t
switch_api_logical_network_create(switch_device_t device, switch_logical_network_t *ln_info)
{
    switch_bd_info_t                  *bd_info = NULL;
    switch_handle_t                    handle;

    handle = switch_bd_create();
    bd_info = switch_bd_get(handle);
    memset(bd_info, 0, sizeof(switch_bd_info_t));
    memcpy(&bd_info->ln_info, ln_info, sizeof(switch_logical_network_t));
    tommy_list_init(&(bd_info->members));
    switch_logical_network_mc_index_allocate(bd_info);

#ifdef SWITCH_PD
    switch_pd_bd_table_add_entry(device,
                            handle_to_id(handle),
                            bd_info,
                            &bd_info->bd_entry);
#endif
    return handle;
}

switch_status_t switch_api_logical_network_delete(switch_device_t device, switch_handle_t network_handle)
{
    switch_bd_info_t *bd_info = NULL;

    bd_info = switch_bd_get(network_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    switch_logical_network_mc_index_free(bd_info);
#ifdef SWITCH_PD
    switch_pd_bd_table_delete_entry(device, bd_info->bd_entry);
#endif
    switch_bd_delete(network_handle);
    return SWITCH_STATUS_SUCCESS;;
}

switch_handle_t switch_api_vlan_create(switch_device_t device, switch_vlan_t vlan_id)
{
    switch_bd_info_t                  *bd_info = NULL;
    switch_bd_info_t                   info;
    switch_handle_t                    handle;

    bd_info = &info;
    memset(&info, 0, sizeof(switch_bd_info_t));
    SWITCH_LN_VLAN_ID(bd_info) = vlan_id;
    SWITCH_LN_NETWORK_TYPE(bd_info) = SWITCH_LOGICAL_NETWORK_TYPE_VLAN;
    switch_logical_network_init_default(bd_info);
    handle = switch_api_logical_network_create(device, &bd_info->ln_info);
    return handle;
}

switch_status_t switch_api_vlan_delete(switch_handle_t vlan_handle)
{
    switch_bd_info_t *bd_info = switch_bd_get(vlan_handle);
    switch_device_t device = SWITCH_DEV_ID;

    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    switch_api_logical_network_delete(device, vlan_handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_vlan_attribute_set(switch_handle_t vlan_handle,
                          switch_vlan_attr_t attr_type,
                          uint64_t value)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    switch(attr_type) {
        case SWITCH_VLAN_ATTR_FLOOD_TYPE:
            status = switch_api_vlan_flood_type_set(vlan_handle, value);
        break;

        case SWITCH_VLAN_ATTR_VRF_ID:
            status = switch_api_vlan_vrf_handle_set(vlan_handle, value);
        break;

        case SWITCH_VLAN_ATTR_MAC_LEARNING:
            status = switch_api_vlan_learning_enabled_set(vlan_handle, value);
        break;

        case SWITCH_VLAN_ATTR_AGE_INTERVAL:
            status = switch_api_vlan_aging_interval_set(vlan_handle, value);
        break;

        default:
            status = SWITCH_STATUS_INVALID_ATTRIBUTE;
    }
    return status;
}

switch_status_t
switch_api_vlan_attribute_get(switch_handle_t vlan_handle,
                          switch_vlan_attr_t attr_type,
                          uint64_t *value)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    switch(attr_type) {
        case SWITCH_VLAN_ATTR_FLOOD_TYPE:
            status = switch_api_vlan_flood_type_get(vlan_handle, value);
        break;

        case SWITCH_VLAN_ATTR_VRF_ID:
            status = switch_api_vlan_vrf_handle_get(vlan_handle, value);
        break;

        case SWITCH_VLAN_ATTR_MAC_LEARNING:
            status = switch_api_vlan_learning_enabled_get(vlan_handle, value);
        break;

        case SWITCH_VLAN_ATTR_AGE_INTERVAL:
            status = switch_api_vlan_aging_interval_get(vlan_handle, value);
        break;

        default:
            status = SWITCH_STATUS_INVALID_ATTRIBUTE;
    }

    return status;
}

switch_status_t
switch_api_ln_attribute_set(switch_handle_t ln_handle,
                        switch_ln_attr_t attr_type,
                        uint64_t value)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    switch (attr_type) {
        case SWITCH_LN_ATTR_NETWORK_TYPE:
            status = switch_api_ln_network_type_set(ln_handle, value);
        break;
        case SWITCH_LN_ATTR_IPV4_UNICAST:
            status = switch_api_ln_ipv4_unicast_enabled_set(ln_handle, value);
        break;
        case SWITCH_LN_ATTR_IPV6_UNICAST:
            status = switch_api_ln_ipv6_unicast_enabled_set(ln_handle, value);
        break;
        default:
            status = SWITCH_STATUS_INVALID_ATTRIBUTE;
    }
    return status;
}

switch_status_t
switch_api_ln_attribute_get(switch_handle_t ln_handle,
                          switch_ln_attr_t attr_type,
                          uint64_t *value)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    switch(attr_type) {
        case SWITCH_LN_ATTR_NETWORK_TYPE:
            status = switch_api_ln_network_type_get(ln_handle, value);
        break;
        case SWITCH_LN_ATTR_IPV4_UNICAST:
            status = switch_api_ln_ipv4_unicast_enabled_get(ln_handle, value);
        break;
        case SWITCH_LN_ATTR_IPV6_UNICAST:
            status = switch_api_ln_ipv6_unicast_enabled_get(ln_handle, value);
        break;
        default:
            status = SWITCH_STATUS_INVALID_ATTRIBUTE;
    }
    return status;
}

switch_status_t
switch_api_vlan_flood_type_set(switch_handle_t vlan_handle, uint64_t value)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_logical_network_t          *ln_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    ln_info = &bd_info->ln_info;
    ln_info->flood_type = (switch_vlan_flood_type_t) value;
    switch_logical_network_mc_index_allocate(bd_info);
    status = switch_pd_bd_table_update_entry(device,
                                        handle_to_id(vlan_handle),
                                        bd_info,
                                        bd_info->bd_entry);
    return status;
}

switch_status_t
switch_api_vlan_flood_type_get(switch_handle_t vlan_handle, uint64_t *value)
{
    switch_bd_info_t                   *bd_info  = NULL;
    switch_logical_network_t           *ln_info = NULL;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    ln_info = &bd_info->ln_info;
    *value = (uint64_t) (ln_info->flood_type);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_vlan_aging_interval_set(switch_handle_t vlan_handle, uint64_t value)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_logical_network_t          *ln_info = NULL;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    ln_info = &bd_info->ln_info;
    ln_info->age_interval = (uint32_t) value;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_vlan_aging_interval_get(switch_handle_t vlan_handle, uint64_t *value)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_logical_network_t          *ln_info = NULL;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    ln_info = &bd_info->ln_info;
    *value = (uint64_t) ln_info->age_interval;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_vlan_vrf_handle_set(switch_handle_t vlan_handle, uint64_t value)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_logical_network_t          *ln_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    ln_info = &bd_info->ln_info;
    ln_info->vrf_handle = (switch_handle_t) value; 
    status = switch_pd_bd_table_update_entry(device,
                                        handle_to_id(vlan_handle),
                                        bd_info,
                                        bd_info->bd_entry);
    return status;
}

switch_status_t
switch_api_vlan_vrf_handle_get(switch_handle_t vlan_handle, uint64_t *value)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_logical_network_t          *ln_info = NULL;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    ln_info = &bd_info->ln_info;
    *value = (uint64_t) ln_info->vrf_handle;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_ln_network_type_set(switch_handle_t ln_handle, uint64_t value)
{
    switch_bd_info_t      *bd_info  = NULL;
    switch_status_t                status = SWITCH_STATUS_SUCCESS;
    switch_device_t                device = SWITCH_DEV_ID;

    bd_info = switch_bd_get(ln_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    SWITCH_LN_NETWORK_TYPE(bd_info) = (switch_handle_t) value; 
    status = switch_pd_bd_table_update_entry(device,
                                        handle_to_id(ln_handle),
                                        bd_info,
                                        bd_info->bd_entry);
    return status;
}

switch_status_t
switch_api_ln_network_type_get(switch_handle_t ln_handle, uint64_t *value)
{
    switch_bd_info_t *bd_info  = NULL;

    bd_info = switch_bd_get(ln_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    *value = (uint64_t) SWITCH_LN_NETWORK_TYPE(bd_info);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_bd_ipv4_unicast_enabled_set(switch_handle_t bd_handle, uint64_t value)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    SWITCH_LN_IPV4_UNICAST_ENABLED(bd_info) = (uint8_t) value; 
    status = switch_pd_bd_table_update_entry(device,
                                        handle_to_id(bd_handle),
                                        bd_info,
                                        bd_info->bd_entry);
    return status;
}

switch_status_t switch_api_ln_ipv4_unicast_enabled_set(switch_handle_t ln_handle, uint64_t value)
{
    return switch_bd_ipv4_unicast_enabled_set(ln_handle, value);
}

switch_status_t
switch_bd_ipv4_unicast_enabled_get(switch_handle_t bd_handle, uint64_t *value)
{
    switch_bd_info_t *bd_info  = NULL;

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    *value = (uint64_t) SWITCH_LN_IPV4_UNICAST_ENABLED(bd_info);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_ln_ipv4_unicast_enabled_get(switch_handle_t ln_handle, uint64_t *value)
{
    return switch_bd_ipv4_unicast_enabled_get(ln_handle, value);
}

switch_status_t
switch_bd_ipv6_unicast_enabled_set(switch_handle_t bd_handle, uint64_t value)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    SWITCH_LN_IPV6_UNICAST_ENABLED(bd_info) = (uint8_t) value; 
    status = switch_pd_bd_table_update_entry(device,
                                        handle_to_id(bd_handle),
                                        bd_info,
                                        bd_info->bd_entry);
    return status;
}

switch_status_t
switch_api_ln_ipv6_unicast_enabled_set(switch_handle_t ln_handle, uint64_t value)
{
    return switch_bd_ipv6_unicast_enabled_set(ln_handle, value);
}

switch_status_t
switch_bd_ipv6_unicast_enabled_get(switch_handle_t bd_handle, uint64_t *value)
{
    switch_bd_info_t *bd_info = NULL;

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    *value = (uint64_t) SWITCH_LN_IPV6_UNICAST_ENABLED(bd_info);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_ln_ipv6_unicast_enabled_get(switch_handle_t ln_handle, uint64_t *value)
{
    return switch_bd_ipv6_unicast_enabled_get(ln_handle, value);
}

switch_status_t
switch_bd_ipv4_urpf_mode_set(switch_handle_t bd_handle, uint64_t value)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    bd_info->ipv4_urpf_mode = (uint8_t) value; 
    status = switch_pd_bd_table_update_entry(device,
                                        handle_to_id(bd_handle),
                                        bd_info,
                                        bd_info->bd_entry);
    return status;
}

switch_status_t
switch_bd_ipv4_urpf_mode_get(switch_handle_t bd_handle, uint64_t *value)
{
    switch_bd_info_t *bd_info  = NULL;

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    *value = (uint64_t) bd_info->ipv4_urpf_mode;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_bd_ipv6_urpf_mode_set(switch_handle_t bd_handle, uint64_t value)
{
    switch_bd_info_t                   *bd_info  = NULL;
    switch_status_t                     status = SWITCH_STATUS_SUCCESS;
    switch_device_t                     device = SWITCH_DEV_ID;

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    bd_info->ipv6_urpf_mode = (uint8_t) value; 
    status = switch_pd_bd_table_update_entry(device,
                                        handle_to_id(bd_handle),
                                        bd_info,
                                        bd_info->bd_entry);
    return status;
}

switch_status_t
switch_bd_ipv6_urpf_mode_get(switch_handle_t bd_handle, uint64_t *value)
{
    switch_bd_info_t *bd_info  = NULL;

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    *value = (uint64_t) bd_info->ipv6_urpf_mode;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_vlan_learning_enabled_set(switch_handle_t vlan_handle, uint64_t value)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    SWITCH_LN_LEARN_ENABLED(bd_info) = (uint8_t) value; 
    status = switch_pd_bd_table_update_entry(device,
                                        handle_to_id(vlan_handle),
                                        bd_info,
                                        bd_info->bd_entry);
    return status;
}

switch_status_t
switch_api_vlan_learning_enabled_get(switch_handle_t vlan_handle, uint64_t *value)
{
    switch_bd_info_t *bd_info  = NULL;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    *value = (uint64_t) SWITCH_LN_LEARN_ENABLED(bd_info);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_vlan_ports_add(switch_handle_t vlan_handle,
                          uint8_t port_count,
                          switch_handle_t *interface_handle)
{
    switch_bd_info_t                  *info = NULL;
    switch_ln_member_t                *vlan_member = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;
    switch_vlan_t                      vlan_id = 0;
    int                                count = 0;

    info = switch_bd_get(vlan_handle);
    if (!info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    while (count < port_count) {
        vlan_member = switch_malloc(sizeof(switch_ln_member_t), 1);
        if (!vlan_member) {
            return SWITCH_STATUS_NO_MEMORY;
        }

        memset(vlan_member, 0, sizeof(switch_ln_member_t));
        intf_info = switch_api_interface_get(interface_handle[count]);
        if (!intf_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
        }

        if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
            if (SWITCH_INTF_IS_PORT_L2_ACCESS(intf_info)) {
                vlan_id = 0;
            } else if ((SWITCH_INTF_IS_PORT_L2_TRUNK(intf_info)) && 
                (SWITCH_INTF_NATIVE_VLAN_HANDLE(intf_info) == vlan_handle) &&
                (SWITCH_INTF_NATIVE_VLAN_HANDLE(intf_info) != 0)) {
                vlan_id = 0;
            } else {
                vlan_id = SWITCH_LN_VLAN_ID(info);
            }
        }
        vlan_member->member = interface_handle[count];
        tommy_list_insert_tail(&(info->members), &(vlan_member->node), vlan_member);
#ifdef SWITCH_PD
        status = switch_pd_port_vlan_mapping_table_add_entry(device,
                                                         vlan_id, 0,
                                                         intf_info,
                                                         info->bd_entry,
                                                         &(vlan_member->pv_hw_entry));
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d: unable to add to port vlan entry for vlan %d",
                         __FUNCTION__, __LINE__, vlan_id);
            return SWITCH_STATUS_PD_FAILURE;
        }
        status = switch_api_vlan_xlate_add(vlan_handle, interface_handle[count], vlan_id);
        if (status != SWITCH_STATUS_SUCCESS) {
            return status;
        }

        status = switch_api_multicast_member_add(device, info->uuc_mc_index,
                                             vlan_handle,
                                             port_count, interface_handle);

#endif
        count++;
    }

    return status;
}

switch_status_t
switch_api_vlan_ports_remove(switch_handle_t vlan_handle,
                             uint8_t port_count,
                             switch_handle_t *interface_handle)
{
    switch_bd_info_t                  *info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_ln_member_t                *vlan_member = NULL;
    tommy_node                        *node = NULL;
    switch_device_t                    device = SWITCH_DEV_ID;
    int                                count = 0;
    int                                i = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_vlan_t                      vlan_id = 0;

    info = switch_bd_get(vlan_handle);
    if (!info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    node = tommy_list_head(&(info->members));
    while (node) {
        vlan_member = (switch_ln_member_t *) node->data;
        node = node->next;

        for(i = 0; i < port_count; i++) {
            intf_info = switch_api_interface_get(interface_handle[i]);
            if (!intf_info) {
                return SWITCH_STATUS_INVALID_INTERFACE;
            }
            if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
                if (SWITCH_INTF_IS_PORT_L2_ACCESS(intf_info)) {
                    vlan_id = 0;
                } else if ((SWITCH_INTF_IS_PORT_L2_TRUNK(intf_info)) && 
                    (SWITCH_INTF_NATIVE_VLAN_HANDLE(intf_info) == vlan_handle) &&
                    (SWITCH_INTF_NATIVE_VLAN_HANDLE(intf_info) != 0)) {
                    vlan_id = 0;
                } else {
                    vlan_id = SWITCH_LN_VLAN_ID(info);
                }
            }
            vlan_member->member = interface_handle[count];
            if (vlan_member->member == interface_handle[i]) {
#ifdef SWITCH_PD
                status = switch_api_vlan_xlate_remove(vlan_handle, interface_handle[count], vlan_id);
                if (status != SWITCH_STATUS_SUCCESS) {
                    return status;
                }
                status = switch_pd_port_vlan_mapping_table_delete_entry(device,
                                                  vlan_member->pv_hw_entry);
                if (status != SWITCH_STATUS_SUCCESS) {
                    SWITCH_API_ERROR("%s:%d: unable to remove port vlan entry for vlan %d!",
                                 __FUNCTION__, __LINE__, vlan_id);
                    return SWITCH_STATUS_PD_FAILURE;
                }
                
                status = switch_api_multicast_member_delete(device,
                                             info->uuc_mc_index,
                                             vlan_handle,
                                             port_count, interface_handle);
#endif
                tommy_list_remove_existing(&(info->members), &(vlan_member->node));
                switch_free(vlan_member);
                count++;
            }
        }
        if (count == port_count) {
            break;
        }
    }

    if (count != port_count) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }
    return status;
}

switch_status_t
switch_bd_router_mac_handle_set(switch_handle_t bd_handle, switch_handle_t rmac_handle)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_logical_network_t          *ln_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    ln_info = &bd_info->ln_info;
    ln_info->rmac_handle = rmac_handle;
    status = switch_pd_bd_table_update_entry(device,
                                        handle_to_id(bd_handle),
                                        bd_info,
                                        bd_info->bd_entry);
    return status;
}

switch_status_t
switch_api_vlan_xlate_add(switch_handle_t bd_handle, switch_handle_t intf_handle, switch_vlan_t vlan_id)
{
    switch_interface_info_t           *intf_info = NULL;
    tommy_node                        *node = NULL;
    switch_lag_info_t                 *lag_info = NULL;
    switch_lag_member_t               *lag_member = NULL;
    switch_ln_member_t                *bd_member = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;
    switch_handle_t                    port_handle = 0;

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        SWITCH_API_ERROR("%s:%d: invalid interface!", __FUNCTION__, __LINE__);
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_L2_PORT_VLAN) {
        port_handle = SWITCH_INTF_PV_PORT_HANDLE(intf_info);
    } else {
        port_handle = SWITCH_INTF_PORT_HANDLE(intf_info);
    }
    if (SWITCH_HANDLE_IS_LAG(port_handle)) {
        lag_info = switch_api_lag_get_internal(port_handle);
        if (!lag_info) {
            SWITCH_API_ERROR("%s:%d: Invalid lag handle!", __FUNCTION__, __LINE__);
            return SWITCH_STATUS_INVALID_HANDLE;
        }
        node = tommy_list_head(&(lag_info->egress));
        while(node) {
            lag_member = node->data;
            status = switch_pd_egress_vlan_xlate_table_add_entry(device, lag_member->port,
                                                     handle_to_id(bd_handle),
                                                     vlan_id, &lag_member->xlate_entry);
            if (status != SWITCH_STATUS_SUCCESS) {
                SWITCH_API_ERROR("%s:%d unable to add xlate entry for vlan %d", 
                             __FUNCTION__, __LINE__, vlan_id);
                return SWITCH_STATUS_PD_FAILURE;
            }
            
            node = node->next;
        }
    } else {
        bd_member = switch_api_logical_network_search_member(bd_handle, intf_handle);
        if (!bd_member) {
            SWITCH_API_ERROR("%s:%d interface is not port of vlan!", __FUNCTION__, __LINE__);
            return SWITCH_STATUS_INVALID_INTERFACE;
        }
        status = switch_pd_egress_vlan_xlate_table_add_entry(device, port_handle,
                                                 handle_to_id(bd_handle),
                                                 vlan_id, &bd_member->xlate_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d unable to add xlate entry for vlan %d", 
                         __FUNCTION__, __LINE__, vlan_id);
            return SWITCH_STATUS_PD_FAILURE;
        }
    }
    return status;
}

switch_status_t
switch_api_vlan_xlate_remove(switch_handle_t bd_handle, switch_handle_t intf_handle, switch_vlan_t vlan_id)
{
    switch_interface_info_t           *intf_info = NULL;
    tommy_node                        *node = NULL;
    switch_lag_info_t                 *lag_info = NULL;
    switch_lag_member_t               *lag_member = NULL;
    switch_ln_member_t                *bd_member = NULL;
    switch_handle_t                    port_handle = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        SWITCH_API_ERROR("%s:%d: invalid interface!", __FUNCTION__, __LINE__);
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_L2_PORT_VLAN) {
        port_handle = SWITCH_INTF_PV_PORT_HANDLE(intf_info);
    } else {
        port_handle = SWITCH_INTF_PORT_HANDLE(intf_info);
    }
    if (SWITCH_HANDLE_IS_LAG(port_handle)) {
        lag_info = switch_api_lag_get_internal(port_handle);
        if (!lag_info) {
            SWITCH_API_ERROR("%s:%d: Invalid lag handle!", __FUNCTION__, __LINE__);
            return SWITCH_STATUS_INVALID_HANDLE;
        }
        node = tommy_list_head(&(lag_info->egress));
        while(node) {
            lag_member = node->data;
            status = switch_pd_egress_vlan_xlate_table_delete_entry(device, lag_member->xlate_entry);
            if (status != SWITCH_STATUS_SUCCESS) {
                SWITCH_API_ERROR("%s:%d: unable to remove vlan xlate entry",__FUNCTION__, __LINE__);
                return SWITCH_STATUS_PD_FAILURE;
            }
            node = node->next;
        }
    } else {
        bd_member = switch_api_logical_network_search_member(bd_handle, intf_handle);
        if (!bd_member) {
            SWITCH_API_ERROR("%s:%d interface is not port of vlan!", __FUNCTION__, __LINE__);
            return SWITCH_STATUS_INVALID_INTERFACE;
        }
        status = switch_pd_egress_vlan_xlate_table_delete_entry(device, bd_member->xlate_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d unable to remove xlate entry", __FUNCTION__, __LINE__);
            return SWITCH_STATUS_PD_FAILURE;
        }
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_ln_member_t *
switch_api_logical_network_search_member(switch_handle_t bd_handle, switch_handle_t intf_handle)
{
    switch_ln_member_t                *ln_member = NULL;
    tommy_node                        *node = NULL;
    switch_bd_info_t                  *bd_info = NULL;

    bd_info = switch_bd_get(bd_handle);
    node = tommy_list_head(&bd_info->members);
    while (node) {
        ln_member = node->data;
        if (ln_member->member == intf_handle) {
            return ln_member;
        }
        node = node->next;
    }
    return NULL;
}

switch_status_t
switch_bd_get_entry(switch_handle_t bd_handle, char *entry, int entry_length)
{
    switch_bd_info_t                  *bd_info = NULL;
    switch_logical_network_t          *ln_info = NULL;
    int                                bytes_output = 0;

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }
    ln_info = &bd_info->ln_info;
    bytes_output += sprintf(entry + bytes_output, "\nvlan_handle: %x", (unsigned int) bd_handle);
    bytes_output += sprintf(entry + bytes_output, "\nvrf_handle: %x", (unsigned int) ln_info->vrf_handle);
    bytes_output += sprintf(entry + bytes_output, "rmac_handle: %x", (unsigned int) ln_info->rmac_handle);
    bytes_output += sprintf(entry + bytes_output, "type: %d", SWITCH_LN_NETWORK_TYPE(bd_info));
    bytes_output += sprintf(entry + bytes_output, "\nucast mc %x", bd_info->uuc_mc_index);
    bytes_output += sprintf(entry + bytes_output, "mcast mc %x", bd_info->umc_mc_index);
    bytes_output += sprintf(entry + bytes_output, "bcast mc %x", bd_info->bcast_mc_index);
    bytes_output += sprintf(entry + bytes_output, "\nv4_urpf %d", bd_info->ipv4_urpf_mode);
    bytes_output += sprintf(entry + bytes_output, "v6_urpf %d", bd_info->ipv6_urpf_mode);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_vlan_get_entry(switch_handle_t vlan_handle, char *entry, int entry_length)
{
    return switch_bd_get_entry(vlan_handle, entry, entry_length);
}

switch_status_t
switch_api_vlan_print_entry(switch_handle_t vlan_handle)
{
    switch_bd_info_t                  *bd_info = NULL;
    switch_logical_network_t          *ln_info = NULL;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }
    ln_info = &bd_info->ln_info;
    printf("\n\n vlan handle %x", (unsigned int) vlan_handle);
    printf("\n vrf_handle %x rmac_handle %x",
           (unsigned int) ln_info->vrf_handle,
           (unsigned int) ln_info->rmac_handle);
    printf("\n bd type %d", SWITCH_LN_NETWORK_TYPE(bd_info));
    printf("\n flood uuc %x umc %x bcast %x",
           bd_info->uuc_mc_index, bd_info->umc_mc_index, bd_info->bcast_mc_index);
    printf("\n v4 urpf %d v6 urpf %d", bd_info->ipv4_urpf_mode, bd_info->ipv6_urpf_mode);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_vlan_print_all(void)
{
    switch_handle_t                    vlan_handle;
    switch_handle_t                    next_vlan_handle;

    switch_handle_get_first(switch_bd_array, vlan_handle);
    while (vlan_handle) {
        switch_api_vlan_print_entry(vlan_handle);
        switch_handle_get_next(switch_bd_array, vlan_handle, next_vlan_handle);
        vlan_handle = next_vlan_handle;
    }
    return SWITCH_STATUS_SUCCESS;
}

#ifdef SWITCH_VLAN_tEST
int _switch_vlan_main (int argc, char **argv)
{
    return 0;
}
#endif

#ifdef __cplusplus
}
#endif
