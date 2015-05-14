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

#include "switchapi/switch_handle.h"
#include "switchapi/switch_l3.h"
#include "switchapi/switch_neighbor.h"
#include "switchapi/switch_rmac.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_nhop.h"
#include "switch_nhop_int.h"
#include "switch_pd.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// Next hop related BEGIN
static void *switch_nhop_array;
static switch_api_id_allocator *ecmp_select;

switch_status_t
switch_nhop_init()
{
    switch_nhop_array = NULL;
    ecmp_select = switch_api_id_allocator_new(64 * 1024/ 32);
    switch_handle_type_init(SWITCH_HANDLE_TYPE_NHOP, (16*1024));
    switch_nhop_create();
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_nhop_free(void)
{
    switch_handle_type_free(SWITCH_HANDLE_TYPE_NHOP);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_nhop_create()
{
    switch_handle_t nhop_handle;
    _switch_handle_create(SWITCH_HANDLE_TYPE_NHOP, switch_nhop_info_t, switch_nhop_array, NULL, nhop_handle);
    return nhop_handle;
}

switch_nhop_info_t *
switch_nhop_get(switch_handle_t nhop_handle)
{
    switch_nhop_info_t *nhop_info = NULL;
    _switch_handle_get(switch_nhop_info_t, switch_nhop_array, nhop_handle, nhop_info);
    return nhop_info;
}

switch_status_t
switch_nhop_delete(switch_handle_t handle)
{
    _switch_handle_delete(switch_nhop_info_t, switch_nhop_array, handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_api_nhop_create(switch_device_t device, switch_handle_t intf_handle)
{
    switch_handle_t                    nhop_handle;
    switch_nhop_info_t                *nhop_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_spath_info_t               *spath_info = NULL;

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    nhop_handle = switch_nhop_create();
    nhop_info = switch_nhop_get(nhop_handle);
    nhop_info->type = SWITCH_NHOP_INDEX_TYPE_ONE_PATH;
    spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));
    spath_info->interface_handle = intf_handle;
    intf_info->nhop_handle = nhop_handle;

#ifdef SWITCH_PD
    switch_pd_nexthop_table_add_entry(device,
                                  handle_to_id(nhop_handle),
                                  intf_info,
                                  &spath_info->hw_entry);

    if (SWITCH_INTF_IS_PORT_L3(intf_info) && intf_info->bd_handle) {
        switch_pd_urpf_bd_table_add_entry(device, handle_to_id(nhop_handle),
                                     handle_to_id(intf_info->bd_handle),
                                     &spath_info->urpf_hw_entry);
    }
#endif
    return nhop_handle;
}

switch_status_t
switch_api_nhop_delete(switch_device_t device, switch_handle_t nhop_handle)
{
    switch_nhop_info_t                *nhop_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_spath_info_t               *spath_info = NULL;

    nhop_info = switch_nhop_get(nhop_handle);
    if (!nhop_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));
    intf_info = switch_api_interface_get(spath_info->interface_handle);
    if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }
#ifdef SWITCH_PD
    switch_pd_nexthop_table_delete_entry(device, spath_info->hw_entry);
    if (SWITCH_INTF_IS_PORT_L3(intf_info) && intf_info->bd_handle) {
        switch_pd_urpf_bd_table_delete_entry(device, spath_info->urpf_hw_entry);
    }
#endif
    switch_nhop_delete(nhop_handle);
    UNUSED(nhop_info);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_api_ecmp_create(switch_device_t device)
{
    switch_handle_t                    nhop_handle;
    switch_nhop_info_t                *nhop_info = NULL;
    switch_ecmp_info_t                *ecmp_info = NULL;

    nhop_handle = switch_nhop_create();
    nhop_info = switch_nhop_get(nhop_handle);
    if (!nhop_info) {
        return 0;
    }
    nhop_info->type = SWITCH_NHOP_INDEX_TYPE_ECMP;
    ecmp_info = &(SWITCH_NHOP_ECMP_INFO(nhop_info));
    memset(ecmp_info, 0, sizeof(switch_ecmp_info_t));
    ecmp_info->hw_entry = SWITCH_HW_INVALID_HANDLE;
    ecmp_info->count = 0;
    tommy_list_init(&(ecmp_info->members));

#ifdef SWITCH_PD
    switch_pd_ecmp_group_create(device, &(ecmp_info->pd_group_hdl));
#endif

    return nhop_handle;
}

switch_handle_t
switch_api_ecmp_create_with_members(switch_device_t device,
                                    uint32_t member_count,
                                    switch_handle_t *nhop_handle)
{
    switch_nhop_info_t                *nhop_info = NULL;
    switch_spath_info_t               *spath_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_ecmp_info_t                *ecmp_info = NULL;
    switch_ecmp_member_t              *ecmp_member = NULL;
    switch_handle_t                    ecmp_handle;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    int                                index = 0;

    ecmp_handle = switch_api_ecmp_create(device);
    nhop_info = switch_nhop_get(ecmp_handle);
    if (!nhop_info) {
        return 0;
    }

    ecmp_info = &(SWITCH_NHOP_ECMP_INFO(nhop_info));
    tommy_list_init(&ecmp_info->members);

#ifdef SWITCH_PD
    status = switch_pd_ecmp_group_create(device, &(ecmp_info->pd_group_hdl));
#endif

    for (index = 0; index < member_count; index++) {
        ecmp_member = switch_malloc(sizeof(switch_ecmp_member_t), 1);
        if (!ecmp_member) {
            // TODO: Cleanup memory
            return 0;
        }

        ecmp_member->nhop_handle = nhop_handle[index];
        ecmp_member->mbr_hdl = 0;

        nhop_info = switch_nhop_get(ecmp_member->nhop_handle);
        if (!nhop_info) {
            return SWITCH_STATUS_INVALID_NHOP;
        }

        spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));
        intf_info = switch_api_interface_get(spath_info->interface_handle);
        if (!intf_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
        }

#ifdef SWITCH_PD
        status = switch_pd_ecmp_member_add(device, ecmp_info->pd_group_hdl, 
                    handle_to_id(ecmp_member->nhop_handle), intf_info,
                    &(ecmp_member->mbr_hdl));

        if (SWITCH_INTF_IS_PORT_L3(intf_info) && intf_info->bd_handle) {
            status = switch_pd_urpf_bd_table_add_entry(device, handle_to_id(ecmp_handle),
                                                  handle_to_id(intf_info->bd_handle),
                                                  &(ecmp_member->urpf_hw_entry));
    }

#endif
        tommy_list_insert_head(&ecmp_info->members, &(ecmp_member->node), ecmp_member);
    }

#ifdef SWITCH_PD
    status = switch_pd_ecmp_group_table_add_entry_with_selector(device, handle_to_id(ecmp_handle), 
                    ecmp_info->pd_group_hdl, &(ecmp_info->hw_entry));
#endif
    ecmp_info->count = member_count;
    if (status != SWITCH_STATUS_SUCCESS) {
        return 0;
    }
    return ecmp_handle;
}

switch_status_t
switch_api_ecmp_delete(switch_device_t device, switch_handle_t handle)
{
    switch_nhop_info_t                *nhop_info = NULL;
    switch_ecmp_info_t                *ecmp_info = NULL;

    nhop_info = switch_nhop_get(handle);
    if (!nhop_info) {
        return SWITCH_STATUS_INVALID_NHOP;
    }
    ecmp_info = &(SWITCH_NHOP_ECMP_INFO(nhop_info));
#ifdef SWITCH_PD
    switch_pd_ecmp_group_delete(device, ecmp_info->pd_group_hdl);
#endif
    return switch_api_nhop_delete(device, handle);
}

switch_status_t
switch_api_ecmp_member_add(switch_device_t device, switch_handle_t ecmp_handle, switch_handle_t nhop_handle)
{
    switch_nhop_info_t                *e_nhop_info = NULL;
    switch_nhop_info_t                *nhop_info = NULL;
    switch_ecmp_info_t                *ecmp_info = NULL;
    switch_ecmp_member_t              *ecmp_member = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_spath_info_t               *spath_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    nhop_info = switch_nhop_get(nhop_handle);
    if (!nhop_info) {
        return SWITCH_STATUS_INVALID_NHOP;
    }
    spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));

    e_nhop_info = switch_nhop_get(ecmp_handle);
    if (!e_nhop_info) {
        return SWITCH_STATUS_INVALID_NHOP;
    }
    ecmp_info = &(SWITCH_NHOP_ECMP_INFO(e_nhop_info));

    ecmp_member = switch_malloc(sizeof(switch_ecmp_member_t), 1);
    if (!ecmp_member) {
        return SWITCH_STATUS_NO_MEMORY;
    }
    ecmp_member->nhop_handle = nhop_handle;
    intf_info = switch_api_interface_get(spath_info->interface_handle);
    if (!intf_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
    }

#ifdef SWITCH_PD
    status = switch_pd_ecmp_member_add(device, ecmp_info->pd_group_hdl, 
                    handle_to_id(ecmp_member->nhop_handle), intf_info,
                    &(ecmp_member->mbr_hdl));
    if(ecmp_info->count == 0) {
            switch_pd_ecmp_group_table_add_entry_with_selector(device, 
                    handle_to_id(ecmp_handle),
                    ecmp_info->pd_group_hdl, 
                    &(ecmp_info->hw_entry)); 
    }
    if (SWITCH_INTF_IS_PORT_L3(intf_info) && intf_info->bd_handle) {
        switch_pd_urpf_bd_table_add_entry(device, handle_to_id(ecmp_handle),
                                     handle_to_id(intf_info->bd_handle),
                                     &(ecmp_member->urpf_hw_entry));
    }
#endif
    ecmp_info->count++;
    tommy_list_insert_head(&ecmp_info->members, &(ecmp_member->node), ecmp_member);
    return status;
}

switch_status_t
switch_api_ecmp_member_delete(switch_device_t device, switch_handle_t ecmp_handle, switch_handle_t nhop_handle)
{
    switch_nhop_info_t                *nhop_info = NULL;
    switch_nhop_info_t                *e_nhop_info = NULL;
    switch_spath_info_t               *spath_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_ecmp_info_t                *ecmp_info = NULL;
    switch_ecmp_member_t              *ecmp_member = NULL;
    tommy_node                        *node = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    nhop_info = switch_nhop_get(nhop_handle);
    if (!nhop_info) {
        return SWITCH_STATUS_INVALID_NHOP;
    }
    spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));

    e_nhop_info = switch_nhop_get(ecmp_handle);
    if (!e_nhop_info) {
        return SWITCH_STATUS_INVALID_NHOP;
    }
    ecmp_info = &(SWITCH_NHOP_ECMP_INFO(e_nhop_info));
    node = tommy_list_head(&(ecmp_info->members));
    while (node) {
        ecmp_member = (switch_ecmp_member_t *) node->data;
        if (ecmp_member->nhop_handle == nhop_handle) {
            break;
        }
        node = node->next;
    }

    if (!node) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    intf_info = switch_api_interface_get(spath_info->interface_handle);
    if (!intf_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
    }

#if SWITCH_PD
    if(ecmp_info->count == 1) {
        status = switch_pd_ecmp_group_table_delete_entry(device, ecmp_info->hw_entry);
    }
    status = switch_pd_ecmp_member_delete(device, ecmp_info->pd_group_hdl, 
            ecmp_member->mbr_hdl);
    if (SWITCH_INTF_IS_PORT_L3(intf_info) && intf_info->bd_handle) {
        status = switch_pd_urpf_bd_table_delete_entry(device, ecmp_member->urpf_hw_entry);
    }
#endif
    ecmp_info->count--;
    ecmp_member = tommy_list_remove_existing(&(ecmp_info->members), node);
    switch_free(ecmp_member);
    return status;
}

switch_status_t
switch_api_nhop_print_entry(switch_handle_t nhop_handle)
{
    switch_nhop_info_t                *nhop_info = NULL;
    switch_spath_info_t               *spath_info = NULL;
    switch_ecmp_info_t                *ecmp_info = NULL;
    switch_ecmp_member_t              *ecmp_member = NULL;
    tommy_node                        *node = NULL;

    nhop_info = switch_nhop_get(nhop_handle);
    if (!nhop_info) {
        return SWITCH_STATUS_INVALID_NHOP;
    }

    printf("\n\nnhop_handle %x", (unsigned int) nhop_handle);
    if (nhop_info->type == SWITCH_NHOP_INDEX_TYPE_ONE_PATH) {
        spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));
        printf("\ntype : single path");
        printf("\nintf_handle %x", (unsigned int) spath_info->interface_handle);
    } else {
        ecmp_info = &(SWITCH_NHOP_ECMP_INFO(nhop_info));
        printf("\ntype : ecmp path");
        printf("\nnumber of ecmp path %d", ecmp_info->count);
        node = tommy_list_head(&(ecmp_info->members));
        while (node) {
            ecmp_member = node->data;
            printf("\n\tecmp_member_nhop %x", (unsigned int) ecmp_member->nhop_handle);
            node = node->next;
        }
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_nhop_print_all(void)
{
    switch_handle_t                    nhop_handle = 0;
    switch_handle_t                    next_nhop_handle = 0;

    switch_handle_get_first(switch_nhop_array, nhop_handle);
    while (nhop_handle) {
        switch_api_nhop_print_entry(nhop_handle);
        switch_handle_get_next(switch_nhop_array, nhop_handle, next_nhop_handle);
        nhop_handle = next_nhop_handle;
    }
    return SWITCH_STATUS_SUCCESS;
}
