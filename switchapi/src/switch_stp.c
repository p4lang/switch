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
#include "switchapi/switch_stp.h"
#include "switchapi/switch_port.h"
#include "switchapi/switch_interface.h"
#include "switch_stp_int.h"
#include "switch_pd.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif /* cplusplus */

static void *switch_stp_instance_array;

switch_status_t
switch_stp_init(switch_device_t device)
{
    switch_stp_instance_array = NULL;
    switch_handle_type_init(SWITCH_HANDLE_TYPE_STP, SWITCH_MAX_STP_INSTANCES);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_stp_free(switch_device_t device)
{
    switch_handle_type_free(SWITCH_HANDLE_TYPE_STP);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_stg_handle_create()
{
    switch_handle_t stg_handle;
    _switch_handle_create(SWITCH_HANDLE_TYPE_STP, switch_stp_info_t,
                      switch_stp_instance_array, NULL,
                      stg_handle);
    return stg_handle;
}

void
switch_stg_handle_delete(switch_handle_t stg_handle)
{
    _switch_handle_delete(switch_stp_info_t, switch_stp_instance_array, stg_handle);
}

switch_stp_info_t *
switch_api_stp_get_internal(switch_handle_t stg_handle)
{
    switch_stp_info_t *stp_info = NULL;
    _switch_handle_get(switch_stp_info_t, switch_stp_instance_array,
                   stg_handle, stp_info);
    return stp_info;
}

switch_handle_t
switch_api_stp_group_create(switch_device_t device,
                            switch_stp_mode_t stp_mode)
{
    switch_handle_t                    stg_handle;
    switch_stp_info_t                 *stp_info = NULL;

    stg_handle = switch_stg_handle_create();
    stp_info = switch_api_stp_get_internal(stg_handle);
    if (!stp_info) {
        // No memory
        return 0;
    }

    tommy_list_init(&(stp_info->vlan_list));
    tommy_list_init(&(stp_info->port_list));
    return stg_handle;
}

switch_status_t
switch_api_stp_group_delete(switch_device_t device, switch_handle_t stg_handle)
{
    switch_stp_info_t                 *stp_info = NULL;
    tommy_node                        *node = NULL;
    switch_stp_port_entry_t           *port_entry = NULL;
    switch_stp_vlan_entry_t           *vlan_entry = NULL;

    if (!SWITCH_STP_HANDLE_VALID(stg_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    stp_info = switch_api_stp_get_internal(stg_handle);
    if (!stp_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    node = tommy_list_head(&(stp_info->port_list));
    while (node) {
        port_entry = node->data;
        node = node->next;
        switch_api_stp_port_state_set(device, stg_handle,
                          port_entry->intf_handle,
                          SWITCH_PORT_STP_STATE_NONE);
    }
    node = tommy_list_head(&(stp_info->vlan_list));
    while (node) {
        vlan_entry = node->data;
        node = node->next;
        switch_api_stp_group_vlans_remove(device, 
                                          stg_handle, 1,
                                          &vlan_entry->bd_handle);
    }
    switch_stg_handle_delete(stg_handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_stp_group_vlans_add(switch_device_t device,
                              switch_handle_t stg_handle,
                              uint16_t vlan_count,
                              switch_handle_t *vlan_handle)
{
    switch_stp_info_t                 *stp_info = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_stp_vlan_entry_t           *vlan_entry = NULL;
    switch_handle_t                    bd_handle;
    int                                count = 0;

    if (!SWITCH_STP_HANDLE_VALID(stg_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    stp_info = switch_api_stp_get_internal(stg_handle);
    if (!stp_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    for (count = 0; count < vlan_count; count++) {
        bd_handle = vlan_handle[count];
        bd_info = switch_bd_get(bd_handle);
        if (!bd_info) {
            return SWITCH_STATUS_INVALID_VLAN_ID;
        }

        vlan_entry = switch_malloc(sizeof(switch_stp_vlan_entry_t), 1);
        if (!vlan_entry) {
            return SWITCH_STATUS_NO_MEMORY;
        }
        memset(vlan_entry, 0 , sizeof(switch_stp_vlan_entry_t));

        vlan_entry->bd_handle = bd_handle;
        bd_info->stp_handle = stg_handle;

        switch_pd_bd_table_update_entry(device,
                                   handle_to_id(bd_handle),
                                   bd_info,
                                   bd_info->bd_entry);

        tommy_list_insert_head(&(stp_info->vlan_list),
                        &(vlan_entry->node), vlan_entry);
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_stp_group_vlans_remove(switch_device_t device,
                                 switch_handle_t stg_handle,
                                 uint16_t vlan_count,
                                 switch_handle_t *vlan_handle)
{
    switch_stp_info_t                 *stp_info = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_stp_vlan_entry_t           *vlan_entry = NULL;
    tommy_node                        *node = NULL;
    switch_handle_t                    bd_handle;
    int                                count = 0;

    if (!SWITCH_STP_HANDLE_VALID(stg_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    stp_info = switch_api_stp_get_internal(stg_handle);
    if (!stp_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    for (count = 0; count < vlan_count; count++) {
        bd_handle = vlan_handle[count];
        bd_info = switch_bd_get(bd_handle);
        if (!bd_info) {
            return SWITCH_STATUS_INVALID_VLAN_ID;
        }

        node = tommy_list_head(&(stp_info->vlan_list));
        while (node) {
            vlan_entry = node->data;
            if (vlan_entry->bd_handle == bd_handle) {
                break;
            }
            node = node->next;
        }

        if (!node) {
            return SWITCH_STATUS_ITEM_NOT_FOUND;
        }

        bd_info->stp_handle = 0;
        switch_pd_bd_table_update_entry(device,
                               handle_to_id(bd_handle),
                               bd_info,
                               bd_info->bd_entry);

        vlan_entry = tommy_list_remove_existing(&(stp_info->vlan_list), node);
        switch_free(vlan_entry);
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_stp_port_state_set(switch_device_t device, switch_handle_t stg_handle,
                              switch_handle_t handle, switch_stp_state_t state)
{
    switch_stp_info_t                 *stp_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_stp_port_entry_t           *port_entry = NULL;
    tommy_node                        *node = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_port_info_t                *port_info = NULL;
    switch_lag_info_t                 *lag_info = NULL;
    switch_handle_t                    intf_handle; 
    switch_handle_type_t               handle_type = 0;
    bool                               new_entry = FALSE;

    if (!SWITCH_STP_HANDLE_VALID(stg_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    if ((!SWITCH_PORT_HANDLE_VALID(handle)) &&
        (!SWITCH_LAG_HANDLE_VALID(handle)) &&
        (!SWITCH_INTERFACE_HANDLE_VALID(handle))) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    stp_info = switch_api_stp_get_internal(stg_handle);
    if (!stp_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    handle_type = switch_handle_get_type(handle);
    intf_handle = handle;
    if (handle_type == SWITCH_HANDLE_TYPE_PORT) {
       port_info = switch_api_port_get_internal((switch_port_t)handle); 
       if (!port_info) {
           return SWITCH_STATUS_INVALID_PORT_NUMBER;
       }
       intf_handle = port_info->intf_handle;
    }
    if (handle_type == SWITCH_HANDLE_TYPE_LAG) {
        lag_info = switch_api_lag_get_internal(handle);
        if (!lag_info) {
            return SWITCH_STATUS_INVALID_HANDLE;
        }
        intf_handle = lag_info->intf_handle;
    }

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    if (SWITCH_INTF_IS_PORT_L3(intf_info)) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    node = tommy_list_head(&stp_info->port_list);
    while (node) {
        port_entry = node->data;
        if (port_entry->intf_handle == intf_handle) {
            port_entry->intf_state = state;
            break;
        }
        node = node->next;
    }

    if (state == SWITCH_PORT_STP_STATE_NONE) {
        if (!node) {
            return SWITCH_STATUS_ITEM_NOT_FOUND;
        }
        status = switch_stp_update_flood_list(device, stg_handle, intf_handle, state);
        status = switch_pd_spanning_tree_table_delete_entry(device, port_entry->hw_entry);
        tommy_list_remove_existing(&(stp_info->port_list), &(port_entry->node));
        switch_free(port_entry);
    } else {
        if (!node) {
            new_entry = TRUE;
            port_entry = switch_malloc(sizeof(switch_stp_port_entry_t), 1);
            if (!port_entry) {
                return SWITCH_STATUS_NO_MEMORY;
            }
            memset(port_entry, 0, sizeof(switch_stp_port_entry_t));
            port_entry->intf_handle = intf_handle;
            port_entry->intf_state = state;
            tommy_list_insert_head(&(stp_info->port_list),
                                   &(port_entry->node), port_entry);
        }

        status = switch_stp_update_flood_list(device, stg_handle, intf_handle, state);

        if (new_entry) {
            status = switch_pd_spanning_tree_table_add_entry(device,
                                        handle_to_id(stg_handle),
                                        intf_info->ifindex,
                                        port_entry->intf_state,
                                        &port_entry->hw_entry);
        } else {
            status = switch_pd_spanning_tree_table_update_entry(device,
                                        handle_to_id(stg_handle),
                                        intf_info->ifindex,
                                        port_entry->intf_state,
                                        port_entry->hw_entry);
        }
    }
    return status;
}

switch_status_t
switch_api_stp_port_state_get(switch_device_t device, switch_handle_t stg_handle,
                              switch_handle_t handle, switch_stp_state_t *state)
{
    switch_stp_info_t                 *stp_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_stp_port_entry_t           *port_entry = NULL;
    tommy_node                        *node = NULL;
    switch_port_info_t                *port_info = NULL;
    switch_lag_info_t                 *lag_info = NULL;
    switch_handle_t                    intf_handle = 0; 
    switch_handle_type_t               handle_type = 0;

    if (!SWITCH_STP_HANDLE_VALID(stg_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    if ((!SWITCH_PORT_HANDLE_VALID(handle)) &&
        (!SWITCH_LAG_HANDLE_VALID(handle)) &&
        (!SWITCH_INTERFACE_HANDLE_VALID(handle))) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    stp_info = switch_api_stp_get_internal(stg_handle);
    if (!stp_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    handle_type = switch_handle_get_type(handle);
    intf_handle = handle;
    if (handle_type == SWITCH_HANDLE_TYPE_PORT) {
       port_info = switch_api_port_get_internal((switch_port_t)handle); 
       if (!port_info) {
           return SWITCH_STATUS_INVALID_PORT_NUMBER;
       }
       intf_handle = port_info->intf_handle;
    }
    if (handle_type == SWITCH_HANDLE_TYPE_LAG) {
        lag_info = switch_api_lag_get_internal(handle);
        if (!lag_info) {
            return SWITCH_STATUS_INVALID_HANDLE;
        }
        intf_handle = lag_info->intf_handle;
    }

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    if (SWITCH_INTF_IS_PORT_L3(intf_info)) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    *state = SWITCH_PORT_STP_STATE_NONE;
    node = tommy_list_head(&(stp_info->port_list));
    while (node) {
        port_entry = node->data;
        if (port_entry->intf_handle == intf_handle) {
            *state = port_entry->intf_state;
            break;
        }
        node = node->next;
    }

    if (!node) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_stp_port_state_clear(switch_device_t device, switch_handle_t stg_handle,
                                switch_handle_t handle)
{
    switch_stp_info_t                 *stp_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_stp_port_entry_t           *port_entry = NULL;
    tommy_node                        *node = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_port_info_t                *port_info = NULL;
    switch_lag_info_t                 *lag_info = NULL;
    switch_handle_t                    intf_handle = 0; 
    switch_handle_type_t               handle_type = 0;

    if (!SWITCH_STP_HANDLE_VALID(stg_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    if ((!SWITCH_PORT_HANDLE_VALID(handle)) &&
        (!SWITCH_LAG_HANDLE_VALID(handle)) &&
        (!SWITCH_INTERFACE_HANDLE_VALID(handle))) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    stp_info = switch_api_stp_get_internal(stg_handle);
    if (!stp_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    handle_type = switch_handle_get_type(handle);
    intf_handle = handle;
    if (handle_type == SWITCH_HANDLE_TYPE_PORT) {
       port_info = switch_api_port_get_internal((switch_port_t)handle); 
       if (!port_info) {
           return SWITCH_STATUS_INVALID_PORT_NUMBER;
       }
       intf_handle = port_info->intf_handle;
    }
    if (handle_type == SWITCH_HANDLE_TYPE_LAG) {
        lag_info = switch_api_lag_get_internal(handle);
        if (!lag_info) {
            return SWITCH_STATUS_INVALID_HANDLE;
        }
        intf_handle = lag_info->intf_handle;
    }

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    if (SWITCH_INTF_IS_PORT_L3(intf_info)) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    node = tommy_list_head(&(stp_info->port_list));
    while (node) {
        port_entry = node->data;
        if (port_entry->intf_handle == intf_handle) {
            break;
        }
        node = node->next;
    }
    if (!node) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    tommy_list_remove_existing(&(stp_info->port_list), &(port_entry->node));
    switch_free(port_entry);
    return status;
}

switch_status_t
switch_stp_update_flood_list(switch_device_t device, switch_handle_t stg_handle,
                             switch_handle_t intf_handle, switch_stp_state_t state)
{
    switch_stp_info_t                 *stp_info = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_stp_vlan_entry_t           *vlan_entry = NULL;
    tommy_node                        *node = NULL;
    switch_handle_t                    bd_handle = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_vlan_interface_t            vlan_intf;

    if (!SWITCH_STP_HANDLE_VALID(stg_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    stp_info = switch_api_stp_get_internal(stg_handle);
    if (!stp_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    node = tommy_list_head(&(stp_info->vlan_list));
    while (node) {
        vlan_entry = node->data;
        bd_handle = vlan_entry->bd_handle;
        bd_info = switch_bd_get(bd_handle);
        if (!bd_info) {
            return SWITCH_STATUS_INVALID_VLAN_ID;
        }

        memset(&vlan_intf, 0, sizeof(vlan_intf));
        vlan_intf.vlan_handle = bd_handle;
        vlan_intf.intf_handle = intf_handle;
        switch (state) {
            case SWITCH_PORT_STP_STATE_FORWARDING:
                status = switch_api_multicast_member_add(
                    device, bd_info->uuc_mc_index, 1, &vlan_intf);
                break;
            case SWITCH_PORT_STP_STATE_BLOCKING:
            case SWITCH_PORT_STP_STATE_NONE:
                status = switch_api_multicast_member_delete(
                    device, bd_info->uuc_mc_index, 1, &vlan_intf);
                break;

            default:
                break;
        }
        node = node->next;
    }
    return status;
}

switch_status_t
switch_api_stp_group_print_entry(switch_handle_t stg_handle)
{
    switch_stp_info_t                 *stp_info = NULL;
    switch_stp_vlan_entry_t           *vlan_entry = NULL;
    switch_stp_port_entry_t           *port_entry = NULL;
    tommy_node                        *node = NULL;
    switch_handle_t                    bd_handle = 0;
    switch_handle_t                    intf_handle = 0;

    if (!SWITCH_STP_HANDLE_VALID(stg_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    stp_info = switch_api_stp_get_internal(stg_handle);
    if (!stp_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    printf("\n\nstp_group_handle: %x", (unsigned int) stg_handle);
    node = tommy_list_head(&(stp_info->vlan_list));
    printf("\nlist of vlan handles:");
    while (node) {
        vlan_entry = node->data;
        bd_handle = vlan_entry->bd_handle;
        printf("\n\tvlan_handle: %x", (unsigned int) bd_handle);
        node = node->next;
    }
    printf("\nlist of interface handles:");
    node = tommy_list_head(&(stp_info->port_list));
    while (node) {
        port_entry = node->data;
        intf_handle = port_entry->intf_handle;
        printf("\n\tintf_handle: %x stp_state %x",
                (unsigned int) intf_handle,
                port_entry->intf_state);
        node = node->next;
    }
    printf("\n");
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_stp_group_print_all(void)
{
    switch_handle_t                    stp_handle = 0;
    switch_handle_t                    next_stp_handle = 0;

    switch_handle_get_first(switch_stp_instance_array, stp_handle);
    while (stp_handle) {
        switch_api_stp_group_print_entry(stp_handle);
        switch_handle_get_next(switch_stp_instance_array, stp_handle, next_stp_handle);
        stp_handle = next_stp_handle;
    }
    return SWITCH_STATUS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
