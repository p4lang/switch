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

#include <Judy.h>
#include "switchapi/switch_mirror.h"
#include "switchapi/switch_status.h"
#include "switch_mirror_int.h"
#include "switch_nhop_int.h"
#include "switch_pd.h"
#include "switch_log.h"
#include "switch_capability_int.h"

static void *switch_mirror_array = NULL;
static switch_api_id_allocator *session_id_allocator;

switch_handle_t switch_mirror_set_and_create(unsigned int id);

switch_status_t
switch_mirror_init(switch_device_t device)
{
    switch_mirror_array = NULL;
    switch_handle_type_init(SWITCH_HANDLE_TYPE_MIRROR,
                                        SWITCH_MAX_MIRROR_SESSIONS);
    session_id_allocator = switch_api_id_allocator_new(
                                        SWITCH_MAX_MIRROR_SESSIONS/32,
                                        FALSE);

    // negative mirroring action
    switch_pd_neg_mirror_add_entry(device);
    // keep this id allocated so it is not given to anyone else
    switch_mirror_set_and_create(SWITCH_NEGATIVE_MIRROR_SESSION_ID);
    switch_api_id_allocator_set(session_id_allocator,
                                SWITCH_NEGATIVE_MIRROR_SESSION_ID);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_mirror_create()
{
    switch_handle_t mirror_handle;
    _switch_handle_create(SWITCH_HANDLE_TYPE_MIRROR,
                          switch_mirror_info_t,
                          switch_mirror_array,
                          NULL, mirror_handle);
    return mirror_handle;
}

switch_handle_t
switch_mirror_set_and_create(unsigned int id)
{
    switch_handle_t mirror_handle;
    _switch_handle_set_and_create(SWITCH_HANDLE_TYPE_MIRROR,
                          switch_mirror_info_t,
                          switch_mirror_array,
                          NULL, id, mirror_handle);
    return mirror_handle;
}

switch_mirror_info_t *
switch_mirror_info_get(switch_handle_t mirror_handle)
{
    switch_mirror_info_t *mirror_info = NULL;
    _switch_handle_get(switch_mirror_info_t, switch_mirror_array, mirror_handle, mirror_info);
    return mirror_info;
}

switch_status_t
switch_mirror_delete(switch_handle_t mirror_handle)
{
    _switch_handle_delete(switch_mirror_info_t,
                          switch_mirror_array,
                          mirror_handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_api_mirror_session_create(switch_device_t device,
                                 switch_api_mirror_info_t *api_mirror_info)
{
    switch_mirror_info_t              *mirror_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_handle_t                    mirror_handle = 0;
    switch_handle_t                    intf_handle = 0;
    switch_api_interface_info_t        api_intf_info;
    switch_handle_t                    tunnel_intf_handle = 0;
    switch_tunnel_info_t              *tunnel_info = NULL;
    switch_handle_t                    inner_neigh_handle = 0;
    switch_handle_t                    outer_neigh_handle = 0;
    switch_api_neighbor_t              api_neighbor;
    switch_nhop_key_t                  nhop_key;
    switch_handle_t                    nhop_handle = 0;
    switch_handle_t                    vlan_handle = 0;
    switch_vlan_port_t                 vlan_port;
    switch_ip_encap_t                 *ip_encap = NULL;

    if (api_mirror_info->session_id) {
        mirror_handle = switch_mirror_set_and_create(api_mirror_info->session_id);
    } else {
        mirror_handle = switch_mirror_create();
        api_mirror_info->session_id = handle_to_id(mirror_handle);
    }
    mirror_info = switch_mirror_info_get(mirror_handle);
    if (!mirror_info) {
        return SWITCH_API_INVALID_HANDLE;
    }

    memset(mirror_info, 0, sizeof(switch_mirror_info_t));

    api_mirror_info->enable = TRUE;
    memcpy(&mirror_info->api_mirror_info, api_mirror_info, sizeof(switch_api_mirror_info_t));
    switch_api_id_allocator_set(session_id_allocator,
                                api_mirror_info->session_id);

    switch (api_mirror_info->session_type) {
        case SWITCH_MIRROR_SESSION_TYPE_SIMPLE:
            status = switch_pd_mirror_session_update(device, mirror_handle, mirror_info);
            break;
        case SWITCH_MIRROR_SESSION_TYPE_TRUNCATE:
        case SWITCH_MIRROR_SESSION_TYPE_COALESCE:
            break;
        default:
            break;
    }

    if (SWITCH_NHOP_HANDLE_VALID(api_mirror_info->nhop_handle)) {
        status = switch_pd_mirror_table_entry_add(device,
                                        mirror_handle,
                                        mirror_info);
    } else if (api_mirror_info->tunnel_create || api_mirror_info->vlan_create) {
        switch (api_mirror_info->mirror_type) {
            case SWITCH_MIRROR_TYPE_LOCAL:
                break;
            case SWITCH_MIRROR_TYPE_REMOTE:
                vlan_handle = switch_api_vlan_create(device,
                                                     api_mirror_info->vlan_id);
                memset(&api_intf_info, 0, sizeof(switch_api_interface_info_t));
                api_intf_info.type = SWITCH_API_INTERFACE_L2_VLAN_TRUNK;
                api_intf_info.u.port_lag_handle = api_mirror_info->egress_port;
                intf_handle = switch_api_interface_create(device, &api_intf_info);
                if (intf_handle == SWITCH_API_INVALID_HANDLE) {
                    SWITCH_API_TRACE("%s:%d: failed to create encap interface\n",
                                     __FUNCTION__, __LINE__);
                    return SWITCH_API_INVALID_HANDLE;
                }
                vlan_port.tagging_mode = 0;
                vlan_port.handle = intf_handle;
                status = switch_api_vlan_ports_add(device, vlan_handle,
                                                   1, &vlan_port);
                mirror_info->vlan_handle = vlan_handle;
                mirror_info->intf_handle = intf_handle;
                break;
            case SWITCH_MIRROR_TYPE_ENHANCED_REMOTE:
                //Create the encap interface
                memset(&api_intf_info, 0, sizeof(switch_api_interface_info_t));
                api_intf_info.type = SWITCH_API_INTERFACE_L2_VLAN_ACCESS;
                api_intf_info.u.port_lag_handle = api_mirror_info->egress_port;
                intf_handle = switch_api_interface_create(device, &api_intf_info);
                if (intf_handle == SWITCH_API_INVALID_HANDLE) {
                    SWITCH_API_TRACE("%s:%d: failed to create encap interface\n",
                                     __FUNCTION__, __LINE__);
                    return SWITCH_API_INVALID_HANDLE;
                }

                tunnel_info = &api_mirror_info->tunnel_info;
                tunnel_info->u.ip_encap.vrf_handle = switch_api_default_vrf_internal();
                tunnel_info->encap_mode = SWITCH_API_TUNNEL_ENCAP_MODE_IP;
                tunnel_info->out_if = intf_handle;
                tunnel_intf_handle = switch_api_tunnel_interface_create(device, 0,
                                                                        tunnel_info);
                if (intf_handle == SWITCH_API_INVALID_HANDLE) {
                    SWITCH_API_TRACE("failed to create tunnel interface %s:%d\n",
                                     __FUNCTION__, __LINE__);
                    return SWITCH_API_INVALID_HANDLE;
                }

                memset(&nhop_key, 0, sizeof(switch_nhop_key_t));
                nhop_key.intf_handle = tunnel_intf_handle;
                nhop_handle = switch_api_nhop_create(device, &nhop_key);
                if (nhop_handle == SWITCH_API_INVALID_HANDLE) {
                    SWITCH_API_TRACE("%s:%d: failed to create nhop for tunnel interface\n",
                                     __FUNCTION__, __LINE__);
                    return SWITCH_API_INVALID_HANDLE;
                }

                ip_encap = &tunnel_info->u.ip_encap;
                memset(&api_neighbor, 0, sizeof(switch_api_neighbor_t));
                api_neighbor.vrf_handle = switch_api_default_vrf_internal();
                api_neighbor.interface = tunnel_intf_handle;
                api_neighbor.nhop_handle = nhop_handle;
                api_neighbor.rw_type = SWITCH_API_NEIGHBOR_RW_TYPE_L2;
                if (SWITCH_IP_ENCAP_SRC_IP_TYPE(ip_encap) == SWITCH_API_IP_ADDR_V4) {
                    api_neighbor.neigh_type = SWITCH_API_NEIGHBOR_IPV4_TUNNEL;
                } else {
                    api_neighbor.neigh_type = SWITCH_API_NEIGHBOR_IPV4_TUNNEL;
                }
                inner_neigh_handle = switch_api_neighbor_entry_add(device, &api_neighbor);
                if (inner_neigh_handle == SWITCH_API_INVALID_HANDLE) {
                    SWITCH_API_TRACE("%s:%d: failed to create inner neighbor for tunnel interface\n",
                                     __FUNCTION__, __LINE__);
                    return SWITCH_API_INVALID_HANDLE;
                }

                memset(&api_neighbor, 0, sizeof(switch_api_neighbor_t));
                api_neighbor.vrf_handle = switch_api_default_vrf_internal();
                api_neighbor.interface = tunnel_intf_handle;
                memcpy(&api_neighbor.mac_addr, &api_mirror_info->dst_mac,
                       sizeof(switch_mac_addr_t));
                outer_neigh_handle = switch_api_neighbor_entry_add(device, &api_neighbor);
                if (outer_neigh_handle == SWITCH_API_INVALID_HANDLE) {
                    SWITCH_API_TRACE("%s:%d failed to create inner neighbor for tunnel interface\n",
                                     __FUNCTION__, __LINE__);
                    return SWITCH_API_INVALID_HANDLE;
                }

                mirror_info->intf_handle = intf_handle;
                mirror_info->tunnel_intf_handle = tunnel_intf_handle;
                mirror_info->inner_neigh_handle = inner_neigh_handle;
                mirror_info->outer_neigh_handle = outer_neigh_handle;
                mirror_info->api_mirror_info.nhop_handle = nhop_handle;

                status = switch_pd_mirror_table_entry_add(device,
                                                mirror_handle,
                                                mirror_info);
                break;
            default:
                return SWITCH_API_INVALID_HANDLE;
            }
    }

    if (status != SWITCH_STATUS_SUCCESS) {
        switch_api_id_allocator_release(session_id_allocator,
                                        api_mirror_info->session_id);
        switch_mirror_delete(mirror_handle);
        return SWITCH_API_INVALID_HANDLE;
    }
    return mirror_handle;
}

switch_status_t
switch_api_mirror_session_update(switch_device_t device,
                                 switch_handle_t mirror_handle,
                                 switch_api_mirror_info_t *api_mirror_info)
{
    switch_status_t                   status = SWITCH_STATUS_SUCCESS;
    switch_mirror_info_t             *mirror_info = NULL;
    switch_api_mirror_info_t         *tmp_api_mirror_info = NULL;

    mirror_info = switch_mirror_info_get(mirror_handle);
    if (!mirror_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    tmp_api_mirror_info = &mirror_info->api_mirror_info;
    memcpy(&mirror_info->api_mirror_info, api_mirror_info, sizeof(switch_api_mirror_info_t));
    switch (api_mirror_info->session_type) {
        case SWITCH_MIRROR_SESSION_TYPE_SIMPLE:
            status = switch_pd_mirror_session_update(device, mirror_handle, mirror_info);
            break;
        case SWITCH_MIRROR_SESSION_TYPE_TRUNCATE:
        case SWITCH_MIRROR_SESSION_TYPE_COALESCE:
            break;
        default:
            break;
    }
    if (!SWITCH_NHOP_HANDLE_VALID(tmp_api_mirror_info->nhop_handle) &&
         SWITCH_NHOP_HANDLE_VALID(api_mirror_info->nhop_handle)) {
        status = switch_pd_mirror_table_entry_add(device,
                                        mirror_handle,
                                        mirror_info);
    }
    return status;
}

switch_status_t
switch_api_mirror_session_delete(switch_device_t device, switch_handle_t mirror_handle)
{
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_mirror_info_t              *mirror_info = NULL;
    switch_api_mirror_info_t          *api_mirror_info = NULL;
    switch_vlan_port_t                 vlan_port;

    mirror_info = switch_mirror_info_get(mirror_handle);
    if (!mirror_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    api_mirror_info = &mirror_info->api_mirror_info;
    switch (api_mirror_info->session_type) {
        case SWITCH_MIRROR_SESSION_TYPE_SIMPLE:
            status = switch_pd_mirror_session_delete(device, mirror_handle);
            break;
        case SWITCH_MIRROR_SESSION_TYPE_TRUNCATE:
        case SWITCH_MIRROR_SESSION_TYPE_COALESCE:
            break;
        default:
            break;
    }

    if (api_mirror_info->tunnel_create || api_mirror_info->vlan_create) {
        switch (api_mirror_info->mirror_type) {
            case SWITCH_MIRROR_TYPE_LOCAL:
                break;
            case SWITCH_MIRROR_TYPE_REMOTE:
                vlan_port.tagging_mode = 0;
                vlan_port.handle = mirror_info->intf_handle;
                status = switch_api_vlan_ports_remove(device,
                                                      mirror_info->vlan_handle,
                                                      1, &vlan_port);
                status = switch_api_interface_delete(device, mirror_info->intf_handle);
                status = switch_api_vlan_delete(device, mirror_info->vlan_handle);
                break;
            case SWITCH_MIRROR_TYPE_ENHANCED_REMOTE:
                status = switch_api_neighbor_entry_remove(device, mirror_info->outer_neigh_handle);
                status = switch_api_neighbor_entry_remove(device, mirror_info->inner_neigh_handle);
                status = switch_api_nhop_delete(device, mirror_info->api_mirror_info.nhop_handle);
                status = switch_api_tunnel_interface_delete(device, mirror_info->tunnel_intf_handle);
                status = switch_api_interface_delete(device, mirror_info->intf_handle);
                status = switch_pd_mirror_table_entry_delete(device, mirror_info);
                break;
            default:
                return SWITCH_STATUS_FAILURE;
        }
    } else if (SWITCH_NHOP_HANDLE_VALID(api_mirror_info->nhop_handle)) {
        status = switch_pd_mirror_table_entry_delete(device, mirror_info);
    }

    switch_api_id_allocator_release(session_id_allocator,
                                    api_mirror_info->session_id);
    switch_mirror_delete(mirror_handle);
    return status;
}
