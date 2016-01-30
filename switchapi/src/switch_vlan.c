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
#include "switchapi/switch_utils.h"
#include "switch_pd.h"
#include "switch_lag_int.h"
#include "switch_log.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

switch_api_id_allocator *bd_stats_index=NULL;
static void *switch_bd_array = NULL;
switch_handle_t vlan_handle_list[SWITCH_API_MAX_VLANS];
static tommy_hashtable switch_vlan_port_hash_table;

switch_status_t switch_bd_init(switch_device_t device)
{
    bd_stats_index = switch_api_id_allocator_new(16 * 1024, FALSE);
    switch_handle_type_init(SWITCH_HANDLE_TYPE_BD, (16 * 1024));
    tommy_hashtable_init(&switch_vlan_port_hash_table, SWITCH_VLAN_PORT_HASH_TABLE_SIZE);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_bd_free(switch_device_t device)
{
    switch_handle_type_free(SWITCH_HANDLE_TYPE_BD);
    switch_api_id_allocator_destroy(bd_stats_index);
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


void switch_logical_network_mc_index_allocate(switch_device_t device, switch_bd_info_t *bd_info)
{
    switch_logical_network_t *ln_info = NULL;

    ln_info = &bd_info->ln_info;
    //if ((ln_info->flood_type & SWITCH_VLAN_FLOOD_UUC) &&
    //    (bd_info->uuc_mc_index == 0)) {
        bd_info->uuc_mc_index = switch_api_mcast_index_allocate(device);
    //}
    if ((ln_info->flood_type & SWITCH_VLAN_FLOOD_UMC) && 
        (bd_info->umc_mc_index == 0)) {
        bd_info->umc_mc_index = switch_api_mcast_index_allocate(device);
    } else {
        bd_info->umc_mc_index = bd_info->uuc_mc_index;
    }
    if ((ln_info->flood_type & SWITCH_VLAN_FLOOD_BCAST) &&
        (bd_info->bcast_mc_index == 0)) {
        bd_info->bcast_mc_index = switch_api_mcast_index_allocate(device);
    } else {
        bd_info->bcast_mc_index = bd_info->uuc_mc_index;
    }
}

void switch_logical_network_mc_index_free(switch_device_t device, switch_bd_info_t *bd_info)
{
    switch_logical_network_t *ln_info = NULL;

    ln_info = &bd_info->ln_info;
    //if (ln_info->flood_type & SWITCH_VLAN_FLOOD_UUC) {
        switch_api_mcast_index_delete(device, bd_info->uuc_mc_index);
        bd_info->uuc_mc_index = 0;
    //}
    if (ln_info->flood_type & SWITCH_VLAN_FLOOD_UMC) {
        switch_api_mcast_index_delete(device, bd_info->umc_mc_index);
    }
    bd_info->umc_mc_index = 0;
    if (ln_info->flood_type & SWITCH_VLAN_FLOOD_BCAST) {
        switch_api_mcast_index_delete(device, bd_info->bcast_mc_index);
    }
    bd_info->bcast_mc_index = 0;
}

void switch_logical_network_init_default(switch_bd_info_t *bd_info)
{
    switch_logical_network_t *ln_info = NULL;

    ln_info = &bd_info->ln_info;
    ln_info->age_interval = SWITCH_API_VLAN_DEFAULT_AGE_INTERVAL;
    ln_info->flood_type = SWITCH_VLAN_FLOOD_NONE;
    SWITCH_LN_FLOOD_ENABLED(bd_info) = TRUE;
    SWITCH_LN_LEARN_ENABLED(bd_info) = TRUE;
    bd_info->bd_entry = SWITCH_HW_INVALID_HANDLE;
    return;
}

switch_handle_t
switch_api_logical_network_create(switch_device_t device, switch_logical_network_t *ln_info)
{
    switch_bd_info_t                  *bd_info = NULL;
    switch_handle_t                    handle;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    handle = switch_bd_create();
    bd_info = switch_bd_get(handle);
    if (!bd_info) {
        status = SWITCH_STATUS_NO_MEMORY;
        SWITCH_API_ERROR("%s:%d unable to create logical network. %s",
                         __FUNCTION__, __LINE__,
                         switch_print_error(status));
        return SWITCH_API_INVALID_HANDLE;
    }
    memset(bd_info, 0, sizeof(switch_bd_info_t));
    memcpy(&bd_info->ln_info, ln_info, sizeof(switch_logical_network_t));
    tommy_list_init(&(bd_info->members));
    switch_logical_network_mc_index_allocate(device, bd_info);
    bd_info->rid = switch_mcast_rid_allocate();
    if (ln_info->rmac_handle) {
        bd_info->smac_index =
            switch_smac_rewrite_index_from_rmac(ln_info->rmac_handle);
    }
    bd_info->ln_info.mrpf_group = handle;

#ifdef SWITCH_PD
    status = switch_pd_bd_table_add_entry(device, handle_to_id(handle),
                                          bd_info, &bd_info->bd_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_API_INVALID_HANDLE;
    }

    status = switch_pd_egress_bd_map_table_add_entry(device, handle, bd_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_API_INVALID_HANDLE;
    }
#endif
    return handle;
}

switch_status_t switch_api_logical_network_delete(switch_device_t device, switch_handle_t network_handle)
{
    switch_bd_info_t                  *bd_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    if (!SWITCH_BD_HANDLE_VALID(network_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    bd_info = switch_bd_get(network_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

#ifdef SWITCH_PD
    status = switch_pd_bd_table_delete_entry(device, bd_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }
    status = switch_pd_egress_bd_map_table_delete_entry(device, bd_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }
#endif

    switch_mcast_rid_free(bd_info->rid);
    switch_logical_network_mc_index_free(device, bd_info);
    switch_bd_delete(network_handle);
    return status;
}

switch_status_t
switch_api_logical_network_update(switch_device_t device,
                                  switch_handle_t network_handle,
                                  switch_logical_network_t *ln_info)
{
    switch_bd_info_t                  *bd_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    if (!SWITCH_BD_HANDLE_VALID(network_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    bd_info = switch_bd_get(network_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    memcpy(&bd_info->ln_info, ln_info, sizeof(switch_logical_network_t));

    if (ln_info->rmac_handle) {
        bd_info->smac_index =
            switch_smac_rewrite_index_from_rmac(ln_info->rmac_handle);
    }

#ifdef SWITCH_PD
    status = switch_pd_bd_table_update_entry(device,
                                             handle_to_id(network_handle),
                                             bd_info,
                                             bd_info->bd_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }
    if (bd_info->egress_bd_entry) {
        status = switch_pd_egress_bd_map_table_update_entry(device,
                                                            network_handle,
                                                            bd_info);
    } else {
        status = switch_pd_egress_bd_map_table_add_entry(device,
                                                         network_handle,
                                                         bd_info);
    }
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }
#endif

    return status;
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
    if (handle != SWITCH_API_INVALID_HANDLE) {
        switch_api_vlan_id_to_handle_set(vlan_id, handle);
        switch_api_vlan_stats_enable(device, handle);
    }
    return handle;
}

switch_status_t switch_api_vlan_delete(switch_device_t device, switch_handle_t vlan_handle)
{
    switch_bd_info_t                  *bd_info = NULL;
    switch_vlan_t                      vlan_id = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    if (!SWITCH_BD_HANDLE_VALID(vlan_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    vlan_id = SWITCH_LN_VLAN_ID(bd_info);
    switch_api_vlan_stats_disable(device, vlan_handle);
    status = switch_api_logical_network_delete(device, vlan_handle);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }
    switch_api_vlan_id_to_handle_set(vlan_id, 0);
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
    switch_logical_network_mc_index_allocate(device, bd_info);
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

switch_status_t
switch_bd_ipv4_unicast_enabled_set(switch_handle_t bd_handle, uint64_t value)
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

switch_status_t
switch_api_ln_ipv4_unicast_enabled_set(switch_handle_t ln_handle, uint64_t value)
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
switch_bd_ipv4_multicast_enabled_set(switch_handle_t bd_handle, uint64_t value)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    SWITCH_LN_IPV4_MULTICAST_ENABLED(bd_info) = (uint8_t) value;
    status = switch_pd_bd_table_update_entry(device,
                                        handle_to_id(bd_handle),
                                        bd_info,
                                        bd_info->bd_entry);
    return status;
}

switch_status_t
switch_api_ln_ipv4_multicast_enabled_set(switch_handle_t ln_handle,
                                         uint64_t value)
{
    return switch_bd_ipv4_multicast_enabled_set(ln_handle, value);
}

switch_status_t
switch_bd_ipv4_multicast_enabled_get(switch_handle_t bd_handle,
                                     uint64_t *value)
{
    switch_bd_info_t *bd_info  = NULL;

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    *value = (uint64_t) SWITCH_LN_IPV4_MULTICAST_ENABLED(bd_info);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_ln_ipv4_multicast_enabled_get(switch_handle_t ln_handle,
                                         uint64_t *value)
{
    return switch_bd_ipv4_multicast_enabled_get(ln_handle, value);
}

switch_status_t
switch_bd_ipv6_multicast_enabled_set(switch_handle_t bd_handle, uint64_t value)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    SWITCH_LN_IPV6_MULTICAST_ENABLED(bd_info) = (uint8_t) value;
    status = switch_pd_bd_table_update_entry(device,
                                        handle_to_id(bd_handle),
                                        bd_info,
                                        bd_info->bd_entry);
    return status;
}

switch_status_t
switch_api_ln_ipv6_multicast_enabled_set(switch_handle_t ln_handle,
                                         uint64_t value)
{
    return switch_bd_ipv6_multicast_enabled_set(ln_handle, value);
}

switch_status_t
switch_bd_ipv6_multicast_enabled_get(switch_handle_t bd_handle,
                                     uint64_t *value)
{
    switch_bd_info_t *bd_info  = NULL;

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    *value = (uint64_t) SWITCH_LN_IPV6_MULTICAST_ENABLED(bd_info);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_ln_ipv6_multicast_enabled_get(switch_handle_t ln_handle,
                                         uint64_t *value)
{
    return switch_bd_ipv6_multicast_enabled_get(ln_handle, value);
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
switch_api_vlan_igmp_snooping_enabled_set(switch_handle_t vlan_handle,
                                          uint64_t value)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    SWITCH_LN_IGMP_SNOOPING_ENABLED(bd_info) = (uint8_t) value;
    status = switch_pd_bd_table_update_entry(device,
                                        handle_to_id(vlan_handle),
                                        bd_info,
                                        bd_info->bd_entry);
    return status;
}

switch_status_t
switch_api_vlan_igmp_snooping_enabled_get(switch_handle_t vlan_handle,
                                          uint64_t *value)
{
    switch_bd_info_t *bd_info  = NULL;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    *value = (uint64_t) SWITCH_LN_IGMP_SNOOPING_ENABLED(bd_info);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_vlan_mld_snooping_enabled_set(switch_handle_t vlan_handle,
                                         uint64_t value)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    SWITCH_LN_MLD_SNOOPING_ENABLED(bd_info) = (uint8_t) value;
    status = switch_pd_bd_table_update_entry(device,
                                        handle_to_id(vlan_handle),
                                        bd_info,
                                        bd_info->bd_entry);
    return status;
}

switch_status_t
switch_api_vlan_mld_snooping_enabled_get(switch_handle_t vlan_handle,
                                         uint64_t *value)
{
    switch_bd_info_t *bd_info  = NULL;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    *value = (uint64_t) SWITCH_LN_MLD_SNOOPING_ENABLED(bd_info);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_vlan_mrpf_group_set(switch_handle_t vlan_handle, uint64_t value)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    bd_info->ln_info.mrpf_group = value;
    status = switch_pd_bd_table_update_entry(device, handle_to_id(vlan_handle),
                                             bd_info, bd_info->bd_entry);
    return status;
}

switch_status_t switch_api_vlan_id_to_handle_set(switch_vlan_t vlan_id,
                                                 switch_handle_t vlan_handle)
{
    if (vlan_id > SWITCH_API_MAX_VLANS) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    vlan_handle_list[vlan_id] = vlan_handle;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_vlan_id_to_handle_get(switch_vlan_t vlan_id,
                                                 switch_handle_t *vlan_handle)
{
    if (vlan_id > SWITCH_API_MAX_VLANS) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    *vlan_handle = vlan_handle_list[vlan_id];
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_vlan_handle_to_id_get(switch_handle_t vlan_handle,
                                                 switch_vlan_t *vlan_id) {
    if (!SWITCH_BD_HANDLE_VALID(vlan_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    switch_bd_info_t *info = NULL;
    info = switch_bd_get(vlan_handle);
    if (!info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    *vlan_id = SWITCH_LN_VLAN_ID(info);
    return SWITCH_STATUS_SUCCESS;
}

static inline void
switch_vlan_port_hash_key_init(uchar *key, switch_vlan_port_key_t *vlan_port_key,
                               uint32_t *len, uint32_t *hash)
{
    *len = 0;
    memset(key, 0, SWITCH_VLAN_PORT_HASH_KEY_SIZE);

    memcpy(key, &(vlan_port_key->vlan_handle), sizeof(switch_handle_t));
    *len += sizeof(switch_handle_t);

    memcpy((key + *len), &(vlan_port_key->port_lag_handle), sizeof(switch_handle_t));
    *len += sizeof(switch_handle_t);

    *hash = MurmurHash2(key, *len, 0x98761234);
}

static inline int
switch_vlan_port_hash_cmp(const void *key1, const void *key2)
{
    return memcmp(key1, key2, SWITCH_VLAN_PORT_HASH_KEY_SIZE);
}

static switch_status_t
switch_vlan_port_key_insert_hash(switch_vlan_port_key_t *vlan_port_key, switch_handle_t intf_handle)
{
    switch_vlan_port_info_t           *vlan_port_info = NULL;
    unsigned char                      key[SWITCH_VLAN_PORT_HASH_KEY_SIZE];
    uint32_t                           len = 0;
    uint32_t                           hash = 0;

    switch_vlan_port_hash_key_init(key, vlan_port_key, &len, &hash);
    vlan_port_info = switch_malloc(sizeof(switch_vlan_port_info_t), 1);
    if (!vlan_port_info) { 
        return SWITCH_STATUS_NO_MEMORY;
    }
    memcpy(&vlan_port_info->vlan_port_key, vlan_port_key, sizeof(switch_vlan_port_key_t));
    vlan_port_info->intf_handle = intf_handle;
    tommy_hashtable_insert(&switch_vlan_port_hash_table,
                           &(vlan_port_info->node),
                           vlan_port_info, hash);
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
switch_vlan_port_key_delete_hash(switch_vlan_port_key_t *vlan_port_key)
{
    switch_vlan_port_info_t           *vlan_port_info = NULL;
    unsigned char                      key[SWITCH_VLAN_PORT_HASH_KEY_SIZE];
    uint32_t                           len = 0;
    uint32_t                           hash = 0;

    switch_vlan_port_hash_key_init(key, vlan_port_key, &len, &hash);
    vlan_port_info= tommy_hashtable_remove(&switch_vlan_port_hash_table,
                                           switch_vlan_port_hash_cmp,
                                           key, hash);
    if (!vlan_port_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    switch_free(vlan_port_info);
    return SWITCH_STATUS_SUCCESS;
}

static switch_vlan_port_info_t *
switch_vlan_port_key_search_hash(switch_vlan_port_key_t *vlan_port_key)
{
    switch_vlan_port_info_t           *vlan_port_info = NULL;
    unsigned char                      key[SWITCH_VLAN_PORT_HASH_KEY_SIZE];
    uint32_t                           len = 0;
    uint32_t                           hash = 0;

    switch_vlan_port_hash_key_init(key, vlan_port_key, &len, &hash);
    vlan_port_info = tommy_hashtable_search(&switch_vlan_port_hash_table,
                                           switch_vlan_port_hash_cmp,
                                           key, hash);
    return vlan_port_info;
}

switch_status_t switch_intf_handle_get(switch_handle_t vlan_handle,
                                       switch_handle_t port_lag_handle,
                                       switch_handle_t *intf_handle)
{
    switch_vlan_port_info_t           *vlan_port_info = NULL;
    switch_vlan_port_key_t             vlan_port_key;

    vlan_port_key.vlan_handle = vlan_handle;
    vlan_port_key.port_lag_handle = port_lag_handle;
    vlan_port_info = switch_vlan_port_key_search_hash(&vlan_port_key);
    if (!vlan_port_info) {
        *intf_handle = 0;
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    *intf_handle = vlan_port_info->intf_handle;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_vlan_ports_add(switch_device_t device,
                          switch_handle_t vlan_handle,
                          uint16_t port_count,
                          switch_vlan_port_t *vlan_port)
{
    switch_bd_info_t                  *info = NULL;
    switch_ln_member_t                *vlan_member = NULL;
    switch_handle_t                    intf_handle = 0;
    switch_interface_info_t           *intf_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_vlan_t                      vlan_id = 0;
    switch_handle_type_t               handle_type = 0;
    switch_api_interface_info_t        api_intf_info;
    switch_vlan_port_key_t             vlan_port_key;
    int                                count = 0;

    if (!SWITCH_BD_HANDLE_VALID(vlan_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    info = switch_bd_get(vlan_handle);
    if (!info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    while (count < port_count) {
        intf_handle = vlan_port[count].handle;
        if ((!SWITCH_PORT_HANDLE_VALID(intf_handle)) &&
            (!SWITCH_LAG_HANDLE_VALID(intf_handle)) &&
            (!SWITCH_INTERFACE_HANDLE_VALID(intf_handle))) {
            return SWITCH_STATUS_INVALID_HANDLE;
        }

        intf_handle = vlan_port[count].handle;
        handle_type = switch_handle_get_type(vlan_port[count].handle);
        if (handle_type == SWITCH_HANDLE_TYPE_PORT ||
            handle_type == SWITCH_HANDLE_TYPE_LAG) {
            if (vlan_port[count].tagging_mode == SWITCH_VLAN_PORT_UNTAGGED) {
                api_intf_info.type = SWITCH_API_INTERFACE_L2_VLAN_ACCESS;
            } else if (vlan_port[count].tagging_mode == SWITCH_VLAN_PORT_TAGGED) {
                api_intf_info.type = SWITCH_API_INTERFACE_L2_VLAN_TRUNK;
            }
            api_intf_info.u.port_lag_handle = vlan_port[count].handle;
            intf_handle = switch_api_interface_create(device, &api_intf_info);
            if (intf_handle == SWITCH_API_INVALID_HANDLE) {
                SWITCH_API_ERROR("%s:%d: unable to create interface for vlan %d",
                                 __FUNCTION__, __LINE__, vlan_id);
                return SWITCH_STATUS_FAILURE;
            }
            vlan_port_key.vlan_handle = vlan_handle;
            vlan_port_key.port_lag_handle = vlan_port[count].handle;
            switch_vlan_port_key_insert_hash(&vlan_port_key, intf_handle);
        }
        intf_info = switch_api_interface_get(intf_handle);
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
        vlan_member = switch_malloc(sizeof(switch_ln_member_t), 1);
        if (!vlan_member) {
            return SWITCH_STATUS_NO_MEMORY;
        }

        memset(vlan_member, 0, sizeof(switch_ln_member_t));
        vlan_member->member = intf_handle;
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
        status = switch_api_vlan_xlate_add(device, vlan_handle, intf_handle, vlan_id);
        if (status != SWITCH_STATUS_SUCCESS) {
            return status;
        }

        switch_vlan_interface_t vlan_intf;
        memset(&vlan_intf, 0, sizeof(vlan_intf));
        vlan_intf.vlan_handle = vlan_handle;
        vlan_intf.intf_handle = intf_handle;
        status = switch_api_multicast_member_add(device, info->uuc_mc_index,
                                                 1, &vlan_intf);
        if (status != SWITCH_STATUS_SUCCESS) {
            return status;
        }
#endif
        count++;
    }

    return status;
}

switch_status_t
switch_api_vlan_ports_remove(switch_device_t device,
                             switch_handle_t vlan_handle,
                             uint16_t port_count,
                             switch_vlan_port_t *vlan_port)
{
    switch_bd_info_t                  *info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_ln_member_t                *vlan_member = NULL;
    tommy_node                        *node = NULL;
    switch_handle_t                    intf_handle = 0;
    int                                count = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_vlan_t                      vlan_id = 0;
    switch_handle_type_t               handle_type = 0;
    switch_vlan_port_key_t             vlan_port_key;

    if (!SWITCH_BD_HANDLE_VALID(vlan_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    info = switch_bd_get(vlan_handle);
    if (!info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    for(count = 0; count < port_count; count++) {
        intf_handle = vlan_port[count].handle;
        if ((!SWITCH_PORT_HANDLE_VALID(intf_handle)) &&
            (!SWITCH_LAG_HANDLE_VALID(intf_handle)) &&
            (!SWITCH_INTERFACE_HANDLE_VALID(intf_handle))) {
            return SWITCH_STATUS_INVALID_HANDLE;
        }
        handle_type = switch_handle_get_type(vlan_port[count].handle);
        if (handle_type == SWITCH_HANDLE_TYPE_PORT ||
            handle_type == SWITCH_HANDLE_TYPE_LAG) {
            status = switch_intf_handle_get(vlan_handle, vlan_port[count].handle, &intf_handle);
            if (status != SWITCH_STATUS_SUCCESS) {
                SWITCH_API_ERROR("%s:%d unable to get interface!\n", __FUNCTION__, __LINE__);
                return SWITCH_STATUS_INVALID_INTERFACE;
            }
        }

        intf_info = switch_api_interface_get(intf_handle);
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
        node = tommy_list_head(&(info->members));
        while (node) {
            vlan_member = (switch_ln_member_t *) node->data;
            node = node->next;
            if (vlan_member->member == intf_handle) {
#ifdef SWITCH_PD
                status = switch_api_vlan_xlate_remove(device, vlan_handle, intf_handle, vlan_id);
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

                switch_vlan_interface_t vlan_intf;
                memset(&vlan_intf, 0, sizeof(vlan_intf));
                vlan_intf.vlan_handle = vlan_handle;
                vlan_intf.intf_handle = intf_handle;
                status = switch_api_multicast_member_delete(device,
                                                            info->uuc_mc_index,
                                                            1, &vlan_intf);
                // item not found is ok since stp removes the
                // member when clearing the stp state
                if (status != SWITCH_STATUS_ITEM_NOT_FOUND &&
                    status != SWITCH_STATUS_SUCCESS) {
                    return status;
                }
#endif
                status = SWITCH_STATUS_SUCCESS;
                tommy_list_remove_existing(&(info->members), &(vlan_member->node));
                switch_free(vlan_member);

                if (handle_type == SWITCH_HANDLE_TYPE_PORT||
                    handle_type == SWITCH_HANDLE_TYPE_LAG) {
                    status = switch_api_interface_delete(device, intf_handle);
                    if (status != SWITCH_STATUS_SUCCESS) {
                        return status;
                    }
                    vlan_port_key.vlan_handle = vlan_handle;
                    vlan_port_key.port_lag_handle = vlan_port[count].handle;
                    switch_vlan_port_key_delete_hash(&vlan_port_key);
                }
            }
        }
    }
    return status;
}

switch_status_t
switch_api_vlan_interfaces_get(switch_device_t device,
                               switch_handle_t vlan_handle,
                               uint16_t *mbr_count,
                               switch_vlan_interface_t **mbrs)
{
    switch_bd_info_t *info = NULL;
    tommy_node *node = NULL;
    uint16_t mbr_count_max = 0;

    if (!SWITCH_BD_HANDLE_VALID(vlan_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    info = switch_bd_get(vlan_handle);
    if (!info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    *mbrs = NULL;
    *mbr_count = 0;

    node = tommy_list_head(&(info->members));
    while (node) {
        switch_ln_member_t *vlan_member = NULL;
        vlan_member = (switch_ln_member_t *) node->data;
        node = node->next;

        if (mbr_count_max == *mbr_count) {
            mbr_count_max += 16;
            *mbrs = switch_realloc(*mbrs, (sizeof(switch_vlan_interface_t) *
                                           mbr_count_max));
        }
        (*mbrs)[*mbr_count].vlan_handle = vlan_handle;
        (*mbrs)[*mbr_count].intf_handle = vlan_member->member;
        (*mbr_count)++;
    }

    return SWITCH_STATUS_SUCCESS;
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
switch_api_vlan_xlate_add(switch_device_t device, switch_handle_t bd_handle,
                          switch_handle_t intf_handle, switch_vlan_t vlan_id)
{
    switch_interface_info_t           *intf_info = NULL;
    tommy_node                        *node = NULL;
    switch_lag_info_t                 *lag_info = NULL;
    switch_lag_member_t               *lag_member = NULL;
    switch_ln_member_t                *bd_member = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_handle_t                    port_handle = 0;

    if (!SWITCH_INTERFACE_HANDLE_VALID(intf_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

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
switch_api_vlan_xlate_remove(switch_device_t device, switch_handle_t bd_handle,
                             switch_handle_t intf_handle, switch_vlan_t vlan_id)
{
    switch_interface_info_t           *intf_info = NULL;
    tommy_node                        *node = NULL;
    switch_lag_info_t                 *lag_info = NULL;
    switch_lag_member_t               *lag_member = NULL;
    switch_ln_member_t                *bd_member = NULL;
    switch_handle_t                    port_handle = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    if (!SWITCH_INTERFACE_HANDLE_VALID(intf_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

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

switch_status_t
switch_api_vlan_stats_enable(switch_device_t device, switch_handle_t vlan_handle)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_logical_network_t          *ln_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_bd_stats_t                 *ingress_bd_stats = NULL;
    switch_bd_stats_t                 *egress_bd_stats = NULL;
    int                                index = 0;
    uint16_t                           bd_stats_start_idx = 0;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    ln_info = &bd_info->ln_info;
    if (!ln_info->flags.stats_enabled) {
        ln_info->flags.stats_enabled = TRUE;
        bd_info->ingress_bd_stats = (switch_bd_stats_t *) switch_malloc(sizeof(switch_bd_stats_t), 1);
        if (!bd_info->ingress_bd_stats) {
            return SWITCH_STATUS_NO_MEMORY;
        }
        memset(bd_info->ingress_bd_stats, 0, sizeof(switch_bd_stats_t));
        bd_info->egress_bd_stats = (switch_bd_stats_t *) switch_malloc(sizeof(switch_bd_stats_t), 1);
        if (!bd_info->egress_bd_stats) {
            return SWITCH_STATUS_NO_MEMORY;
        }
        memset(bd_info->egress_bd_stats, 0, sizeof(switch_bd_stats_t));
        ingress_bd_stats = bd_info->ingress_bd_stats;
        bd_stats_start_idx = switch_api_id_allocator_allocate_contiguous(bd_stats_index, SWITCH_VLAN_STATS_MAX);
        for (index = 0; index < SWITCH_VLAN_STATS_MAX; index++) {
            ingress_bd_stats->stats_idx[index] = bd_stats_start_idx;
            bd_stats_start_idx++;
        }
        if (bd_info->bd_entry != SWITCH_HW_INVALID_HANDLE) {
            status = switch_pd_bd_table_update_entry(device,
                                        handle_to_id(vlan_handle),
                                        bd_info,
                                        bd_info->bd_entry);
        }
        egress_bd_stats = bd_info->egress_bd_stats;
        status = switch_pd_egress_bd_stats_table_add_entry(
                             device,
                             handle_to_id(vlan_handle),
                             egress_bd_stats->stats_hw_entry);
    }
    return status;
}

switch_status_t
switch_api_vlan_stats_disable(switch_device_t device, switch_handle_t vlan_handle)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_logical_network_t          *ln_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_bd_stats_t                 *ingress_bd_stats = NULL;
    switch_bd_stats_t                 *egress_bd_stats = NULL;
    int                                index = 0;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    ln_info = &bd_info->ln_info;
    if (ln_info->flags.stats_enabled) {
        ln_info->flags.stats_enabled = FALSE;
        ingress_bd_stats = bd_info->ingress_bd_stats;
        for (index = 0; index < SWITCH_VLAN_STATS_MAX; index++) {
            switch_api_id_allocator_release(bd_stats_index, ingress_bd_stats->stats_idx[index]);
            ingress_bd_stats->stats_idx[index] = 0;
        }
        if (bd_info->bd_entry != SWITCH_HW_INVALID_HANDLE) {
            status = switch_pd_bd_table_update_entry(device,
                                        handle_to_id(vlan_handle),
                                        bd_info,
                                        bd_info->bd_entry);
        }
        switch_free(bd_info->ingress_bd_stats);
        egress_bd_stats = bd_info->egress_bd_stats;
        status = switch_pd_egress_bd_stats_table_delete_entry(
                             device,
                             egress_bd_stats->stats_hw_entry);
        switch_free(bd_info->egress_bd_stats);
    }
    return status;
}

switch_status_t
switch_api_vlan_stats_get(
        switch_device_t device,
        switch_handle_t vlan_handle,
        uint8_t count,
        switch_vlan_stats_t *counter_ids,
        switch_counter_t *counters)
{
    switch_bd_info_t                  *bd_info  = NULL;
    switch_logical_network_t          *ln_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_bd_stats_t                 *ingress_bd_stats = NULL;
    switch_bd_stats_t                 *egress_bd_stats = NULL;
    int                                index = 0;
    switch_vlan_stats_t                counter_id = 0;

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    ln_info = &bd_info->ln_info;
    if (ln_info->flags.stats_enabled) {
        ingress_bd_stats = bd_info->ingress_bd_stats;
        egress_bd_stats = bd_info->egress_bd_stats;
        status = switch_pd_vlan_ingress_stats_get(device, ingress_bd_stats);
        status = switch_pd_vlan_egress_stats_get(device, egress_bd_stats);
        for (index = 0; index < count; index++) {
            counter_id = counter_ids[index];
            switch (counter_id) {
                case SWITCH_VLAN_STATS_IN_UCAST:
                case SWITCH_VLAN_STATS_IN_MCAST:
                case SWITCH_VLAN_STATS_IN_BCAST:
                    counters[index] = ingress_bd_stats->counters[counter_id];
                    break;
                case SWITCH_VLAN_STATS_OUT_UCAST:
                case SWITCH_VLAN_STATS_OUT_MCAST:
                case SWITCH_VLAN_STATS_OUT_BCAST:
                    counters[index] = egress_bd_stats->counters[counter_id];
                    break;
                default:
                    break;
            }
        }
    }
    return status;
}

#ifdef __cplusplus
}
#endif
