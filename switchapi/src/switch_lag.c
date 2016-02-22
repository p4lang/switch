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

#include "switchapi/switch_lag.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_port.h"
#include "switch_lag_int.h"
#include "switch_pd.h"
#include "switch_log.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static void *switch_lag_array;
static void *switch_lag_member_array;
static switch_api_id_allocator *lag_select;

#define SWITCH_INITIAL_LAG_SIZE 16

switch_status_t
switch_lag_init(switch_device_t device)
{
    UNUSED(device);
    switch_lag_array = NULL;
    lag_select = switch_api_id_allocator_new(64 * 1024/ 32, FALSE);
    switch_handle_type_init(SWITCH_HANDLE_TYPE_LAG, (1*1024));
    switch_handle_type_init(SWITCH_HANDLE_TYPE_LAG_MEMBER, (1*1024));
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_lag_free(switch_device_t device)
{
    UNUSED(device);
    switch_handle_type_free(SWITCH_HANDLE_TYPE_LAG);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_lag_handle_create()
{
    switch_handle_t lag_handle;
    _switch_handle_create(SWITCH_HANDLE_TYPE_LAG, switch_lag_info_t,
                      switch_lag_array, &info, lag_handle);
    return lag_handle;
}

switch_status_t
switch_lag_handle_delete(switch_handle_t lag_handle)
{
    _switch_handle_delete(switch_lag_info_t, switch_lag_array, lag_handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_lag_info_t *
switch_api_lag_get_internal(switch_handle_t lag_handle)
{
    switch_lag_info_t *lag_info = NULL;
    _switch_handle_get(switch_lag_info_t, switch_lag_array, lag_handle, lag_info);
    return lag_info;
}

switch_handle_t
switch_lag_member_handle_create()
{
    switch_handle_t lag_member_handle;
    _switch_handle_create(SWITCH_HANDLE_TYPE_LAG_MEMBER,
                          switch_lag_member_t,
                          switch_lag_member_array,
                          &info,
                          lag_member_handle);
    return lag_member_handle;
}

switch_status_t
switch_lag_member_handle_delete(switch_handle_t lag_member_handle)
{
    _switch_handle_delete(switch_lag_member_t,
                          switch_lag_member_array,
                          lag_member_handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_lag_member_t *
switch_api_lag_member_get_internal(switch_handle_t lag_member_handle)
{
    switch_lag_member_t *lag_member = NULL;
    _switch_handle_get(switch_lag_member_t,
                       switch_lag_member_array,
                       lag_member_handle,
                       lag_member);
    return lag_member;
}

switch_handle_t
switch_api_lag_create(switch_device_t device)
{
    switch_handle_t                    lag_handle;
    switch_lag_info_t                 *lag_info = NULL;

    lag_handle = switch_lag_handle_create();
    lag_info = switch_api_lag_get_internal(lag_handle);
    if (!lag_info) {
        return SWITCH_API_INVALID_HANDLE;
    }

    memset(lag_info, 0, sizeof(switch_lag_info_t));
    lag_info->lacp = FALSE;
    lag_info->type = SWITCH_API_LAG_SIMPLE;
    lag_info->ifindex = SWITCH_LAG_COMPUTE_IFINDEX(lag_handle);
    tommy_list_init(&(lag_info->ingress));
    tommy_list_init(&(lag_info->egress));
#ifdef SWITCH_PD
    if(switch_pd_lag_group_create(device, &(lag_info->pd_group_hdl)) != 0) {
        // Need to check for error
        return SWITCH_API_INVALID_HANDLE;
    }
    lag_info->device = device;
#endif
    return lag_handle;
}

switch_status_t
switch_api_lag_delete(switch_device_t device, switch_handle_t lag_handle)
{
    switch_lag_info_t                 *lag_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    if (!SWITCH_LAG_HANDLE_VALID(lag_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    lag_info = switch_api_lag_get_internal(lag_handle);
    if (!lag_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }
#ifdef SWITCH_PD
    status = switch_pd_lag_group_delete(lag_info->device, lag_info->pd_group_hdl);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }
#endif
    if (lag_info->egr_bmap) {
        switch_api_id_allocator_destroy(lag_info->egr_bmap);
    }
    switch_lag_handle_delete(lag_handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_lag_member_add(switch_device_t device, switch_handle_t lag_handle,
                          switch_direction_t direction, switch_port_t port)
{
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_lag_info_t                 *lag_info = NULL;
    switch_lag_member_t               *lag_member = NULL;
    switch_handle_t                    lag_member_handle = 0;
    switch_port_info_t                *port_info = NULL;

    if (!SWITCH_LAG_HANDLE_VALID(lag_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    lag_info = switch_api_lag_get_internal(lag_handle);
    if (!lag_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    if (!lag_info->egr_bmap) {
        lag_info->egr_bmap = switch_api_id_allocator_new(SWITCH_INITIAL_LAG_SIZE, FALSE);
        if (!lag_info->egr_bmap) {
            return SWITCH_STATUS_NO_MEMORY;
        }
    }

    lag_member_handle = switch_lag_member_handle_create();
    lag_member = switch_api_lag_member_get_internal(lag_member_handle);
    if (!lag_member) {
        return SWITCH_STATUS_NO_MEMORY;
    }

    lag_member->index = switch_api_id_allocator_allocate(lag_info->egr_bmap);
    lag_member->port = port;
    lag_member->lag_member_handle = lag_member_handle;
    lag_member->lag_handle = lag_handle;
    lag_member->direction = direction;

    switch (direction) {
        case SWITCH_API_DIRECTION_BOTH:
        case SWITCH_API_DIRECTION_EGRESS:
            tommy_list_insert_head(&lag_info->egress,
                    &(lag_member->egress_node),
                    lag_member);
            port_info = switch_api_port_get_internal(port);
            if (!port_info) {
                return SWITCH_STATUS_INVALID_PORT_NUMBER;
            }
            status = switch_pd_lag_member_add(device, lag_info->pd_group_hdl,
                                              SWITCH_PORT_ID(port_info),
                                              &(lag_member->mbr_hdl));
            if (status != SWITCH_STATUS_SUCCESS) {
                return status;
            }
            if (lag_info->count == 0) {
                status = switch_pd_lag_group_table_add_entry_with_selector(device,
                                                lag_info->ifindex,
                                                lag_info->pd_group_hdl,
                                                &lag_info->hw_entry);
                if (status != SWITCH_STATUS_SUCCESS) {
                    return status;
                }
            }
            lag_info->count++;
            // Update lag table in pre
            status = switch_multicast_update_lag_port_map(device, lag_handle);
            if (status != SWITCH_STATUS_SUCCESS) {
                return status;
            }

            if (direction == SWITCH_API_DIRECTION_EGRESS)
                break;
        case SWITCH_API_DIRECTION_INGRESS:
            tommy_list_insert_head(&lag_info->ingress,
                    &(lag_member->ingress_node),
                    lag_member);
            // lookup port table
            port_info = switch_api_port_get_internal(port);
            if (!port_info) {
                return SWITCH_STATUS_INVALID_PORT_NUMBER;
            }
            status = switch_pd_port_mapping_table_add_entry(device, port,
                    lag_info->ifindex,
                    port_info->port_type,
                    &port_info->hw_entry);
            if (status != SWITCH_STATUS_SUCCESS) {
                return status;
            }
            status = switch_pd_egress_lag_table_add_entry(device,
                                     SWITCH_PORT_ID(port_info),
                                     lag_info->ifindex,
                                     &(port_info->eg_lag_entry));
            break;
        default:
            break;
    }
    return status;
}

switch_status_t
switch_api_lag_member_delete(switch_device_t device, switch_handle_t lag_handle,
                             switch_direction_t direction, switch_port_t port)
{
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_lag_info_t                 *lag_info = NULL;
    switch_lag_member_t               *lag_member = NULL;
    tommy_node                        *delete_node = NULL;
    switch_port_info_t                *port_info = NULL;

    if (!SWITCH_LAG_HANDLE_VALID(lag_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    lag_info = switch_api_lag_get_internal(lag_handle);
    if (!lag_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    switch (direction) {
        case SWITCH_API_DIRECTION_BOTH:
        case SWITCH_API_DIRECTION_EGRESS:
            delete_node = tommy_list_head(&(lag_info->egress));
            while (delete_node) {
                lag_member = delete_node->data;
                if (lag_member->port == port) {
                    break;
                }
                delete_node = delete_node->next;
            }
            if (!delete_node) {
                return SWITCH_STATUS_ITEM_NOT_FOUND;
            }
            if(lag_info->count == 1) {
                status = switch_pd_lag_group_table_delete_entry(device, lag_info->hw_entry);
                if (status != SWITCH_STATUS_SUCCESS) {
                    return status;
                }
            }
            status = switch_pd_lag_member_delete(device, lag_info->pd_group_hdl, lag_member->mbr_hdl);
            if (status != SWITCH_STATUS_SUCCESS) {
                return status;
            }
            lag_member = tommy_list_remove_existing(&(lag_info->egress), delete_node);

            //Update the lag table in pre
            status = switch_multicast_update_lag_port_map(device, lag_handle);
            if (status != SWITCH_STATUS_SUCCESS) {
                return status;
            }
            lag_info->count--;

            if (direction == SWITCH_API_DIRECTION_EGRESS)
                break;
            // else fall through
        case SWITCH_API_DIRECTION_INGRESS:
            delete_node = tommy_list_head(&(lag_info->ingress));
            while (delete_node) {
                lag_member = delete_node->data;
                if (lag_member->port == port) {
                    break;
                }
                delete_node = delete_node->next;
            }
            if (!delete_node) {
                return SWITCH_STATUS_ITEM_NOT_FOUND;
            }
            lag_member = tommy_list_remove_existing(&(lag_info->ingress), delete_node);
            port_info = switch_api_port_get_internal(port);
            if (!port_info) {
                return SWITCH_STATUS_INVALID_PORT_NUMBER;
            }
            //part of lag
            status = switch_pd_port_mapping_table_add_entry(device, port,
                                     port_info->ifindex,
                                     port_info->port_type,
                                     &port_info->hw_entry);
            if (status != SWITCH_STATUS_SUCCESS) {
                return status;
            }
            status = switch_pd_egress_lag_table_add_entry(device,
                                     SWITCH_PORT_ID(port_info),
                                     port_info->ifindex,
                                     &(port_info->eg_lag_entry));
            if (status != SWITCH_STATUS_SUCCESS) {
                return status;
            }
            switch_free(lag_member);
            break;
        default:
            break;
    }
    return status;
}

switch_handle_t
switch_api_lag_member_create(
        switch_device_t device,
        switch_handle_t lag_handle,
        switch_direction_t direction,
        switch_port_t port)
{
    switch_lag_info_t                 *lag_info = NULL;
    tommy_node                        *node = NULL;
    switch_handle_t                    lag_member_handle = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_lag_member_t               *lag_member = NULL;

    if (!SWITCH_LAG_HANDLE_VALID(lag_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    lag_info = switch_api_lag_get_internal(lag_handle);
    if (!lag_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    status = switch_api_lag_member_add(
                             device,
                             lag_handle,
                             direction,
                             port);

    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_API_INVALID_HANDLE;
    }

    if (direction == SWITCH_API_DIRECTION_BOTH ||
        direction == SWITCH_API_DIRECTION_INGRESS) {
        node = tommy_list_head(&(lag_info->ingress));
    } else {
        node = tommy_list_head(&(lag_info->egress));
    }

    while (node) {
        lag_member = node->data;
        if (lag_member->port == port) {
            break;
        }
        node = node->next;
    }

    if (lag_member) {
        lag_member_handle = lag_member->lag_member_handle;
    }

    return lag_member_handle;
}

switch_status_t
switch_api_lag_member_remove(
        switch_device_t device,
        switch_handle_t lag_member_handle)
{
    switch_lag_member_t               *lag_member = NULL;
    switch_lag_info_t                 *lag_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    lag_member = switch_api_lag_member_get_internal(lag_member_handle);
    if (!lag_member) {
        return SWITCH_STATUS_INVALID_PARAMETER;
    }

    lag_info = switch_api_lag_get_internal(lag_member->lag_handle);
    if (!lag_info) {
        return SWITCH_STATUS_INVALID_PARAMETER;
    }

    status = switch_api_lag_member_delete(
                             device,
                             lag_member->lag_handle,
                             lag_member->direction,
                             lag_member->port);
    return status;
}

unsigned int
switch_lag_get_count(switch_handle_t lag_handle)
{
    switch_lag_info_t *info = NULL;
    _switch_handle_get(switch_lag_info_t, switch_lag_array, lag_handle, info);
    return info->count;
}

switch_status_t
switch_api_lag_print_entry(switch_handle_t lag_handle)
{
    switch_lag_info_t                 *lag_info = NULL;
    switch_lag_member_t               *lag_member = NULL;
    tommy_node                        *node = NULL;

    lag_info = switch_api_lag_get_internal(lag_handle);
    if (!lag_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    printf("\n\nlag_handle: %x", (unsigned int) lag_handle);
    printf("\ningress port list:");
    node = tommy_list_head(&(lag_info->ingress));
    while (node) {
        lag_member = node->data;
        printf("\n\tport : %d", (int)lag_member->port);
        node = node->next;
    }
    printf("\negress port list:");
    node = tommy_list_head(&(lag_info->egress));
    while (node) {
        lag_member = node->data;
        printf("\n\tport : %d", (int)lag_member->port);
        node = node->next;
    }
    printf("\n");
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_lag_print_all(void)
{
    switch_handle_t                    lag_handle = 0;
    switch_handle_t                    next_lag_handle = 0;

    switch_handle_get_first(switch_lag_array, lag_handle);
    while (lag_handle) {
        switch_api_lag_print_entry(lag_handle);
        switch_handle_get_next(switch_lag_array, lag_handle, next_lag_handle);
        lag_handle = next_lag_handle;
    }
    return SWITCH_STATUS_SUCCESS;
}

#ifdef SWITCH_LAG_TEST
int lag_main (int argc, char **argv)
{
    return 0;
}
#endif

#ifdef __cplusplus
}
#endif
