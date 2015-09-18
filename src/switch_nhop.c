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
#include "switchapi/switch_utils.h"
#include "switch_nhop_int.h"
#include "switch_neighbor_int.h"
#include "switch_hostif_int.h"
#include "switch_pd.h"
#include "switch_log.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// Next hop related BEGIN
static void *switch_nhop_array;
static switch_api_id_allocator *ecmp_select;
static tommy_hashtable switch_nhop_hash_table;

switch_status_t
switch_nhop_init(switch_device_t device)
{
    switch_nhop_array = NULL;
    ecmp_select = switch_api_id_allocator_new(64 * 1024/ 32, FALSE);
    switch_handle_type_init(SWITCH_HANDLE_TYPE_NHOP, (16*1024));
    tommy_hashtable_init(&switch_nhop_hash_table, SWITCH_NHOP_HASH_TABLE_SIZE);
    switch_nhop_create();
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_nhop_free(switch_device_t device)
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

static inline void
switch_nhop_hash_key_init(uchar *key, switch_nhop_key_t *nhop_key,
                             uint32_t *len, uint32_t *hash)
{
    *len=0;
    memset(key, 0, SWITCH_NHOP_HASH_KEY_SIZE);
    memcpy(key, (uchar *) &nhop_key->intf_handle, sizeof(switch_handle_t));
    *len += sizeof(switch_handle_t);
    key[*len] = nhop_key->ip_addr.type;
    *len += 4;
    if(nhop_key->ip_addr.type == SWITCH_API_IP_ADDR_V4) {
        *(unsigned int *)(&key[*len]) = nhop_key->ip_addr.ip.v4addr;
        *len += 16;
    }
    else {
        memcpy(&key[*len], nhop_key->ip_addr.ip.v6addr, 16);
        *len += 16;
    }
    key[*len] = nhop_key->ip_addr.prefix_len;
    *len += 4;
    *hash = MurmurHash2(key, *len, 0x98761234);
}

static inline int
switch_nhop_hash_cmp(const void *key1, const void *key2)
{
    return memcmp(key1, key2, SWITCH_NHOP_HASH_KEY_SIZE);
}

static switch_status_t
switch_nhop_insert_hash(switch_spath_info_t *spath_info,
                        switch_nhop_key_t *nhop_key,
                        switch_handle_t nhop_handle)
{
    switch_nhop_key_t                 *temp_nhop_key = NULL;
    unsigned char                      key[SWITCH_NHOP_HASH_KEY_SIZE];
    uint32_t                           len = 0;
    uint32_t                           hash = 0;

    temp_nhop_key = &spath_info->nhop_key;
    memset(temp_nhop_key, 0, sizeof(switch_nhop_key_t));
    memcpy(temp_nhop_key, nhop_key, sizeof(switch_nhop_key_t));
    spath_info->nhop_handle = nhop_handle;
    switch_nhop_hash_key_init(key, temp_nhop_key, &len, &hash);
    tommy_hashtable_insert(&switch_nhop_hash_table,
                           &(spath_info->node),
                           spath_info, hash);
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
switch_nhop_delete_hash(switch_spath_info_t *spath_info)
{
    switch_nhop_key_t                 *temp_nhop_key = NULL;
    unsigned char                      key[SWITCH_NHOP_HASH_KEY_SIZE];
    uint32_t                           len = 0;
    uint32_t                           hash = 0;

    temp_nhop_key = &spath_info->nhop_key;
    if (!temp_nhop_key->ip_addr_valid) {
        return SWITCH_STATUS_SUCCESS;
    }
    switch_nhop_hash_key_init(key, temp_nhop_key, &len, &hash);
    spath_info = tommy_hashtable_remove(&switch_nhop_hash_table,
                                        switch_nhop_hash_cmp,
                                        key, hash);
    if (!spath_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_api_nhop_handle_get(switch_nhop_key_t *nhop_key)
{
    switch_spath_info_t               *spath_info = NULL;
    unsigned char                      key[SWITCH_NHOP_HASH_KEY_SIZE];
    uint32_t                           len = 0;
    uint32_t                           hash = 0;

    switch_nhop_hash_key_init(key, nhop_key, &len, &hash);
    spath_info = tommy_hashtable_search(&switch_nhop_hash_table,
                                      switch_nhop_hash_cmp,
                                      key, hash);
    if (!spath_info) {
        return SWITCH_API_INVALID_HANDLE;
    }
    return spath_info->nhop_handle;
}

switch_handle_t
switch_api_neighbor_handle_get(switch_handle_t nhop_handle)
{
    switch_nhop_info_t                *nhop_info = NULL;
    switch_spath_info_t               *spath_info = NULL;

    if (!SWITCH_NHOP_HANDLE_VALID(nhop_handle)) {
        return SWITCH_API_INVALID_HANDLE;
    }

    nhop_info = switch_nhop_get(nhop_handle);
    if (!nhop_info) {
        return SWITCH_API_INVALID_HANDLE;
    }
    spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));
    return spath_info->neighbor_handle;
}

switch_status_t
switch_nhop_ifindex_get(switch_handle_t nhop_handle,
                        switch_ifindex_t *ifindex,
                        bool *flood,
                        uint32_t *mc_index)
{
    switch_nhop_info_t                *nhop_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_neighbor_info_t            *neighbor_info = NULL;
    switch_api_neighbor_t             *neighbor = NULL;
    switch_api_mac_entry_t             mac_entry;
    switch_mac_info_t                 *mac_info = NULL;
    switch_handle_t                    neighbor_handle;
    switch_bd_info_t                  *bd_info = NULL;
    switch_port_info_t                *tmp_port_info = NULL;
    switch_lag_info_t                 *tmp_lag_info = NULL;
    switch_interface_info_t           *tmp_intf_info = NULL;
    switch_api_mac_entry_t            *tmp_mac_entry = NULL;
    switch_handle_type_t               handle_type = 0;
    switch_handle_t                    encap_if;
    switch_spath_info_t               *spath_info = NULL;

    nhop_info = switch_nhop_get(nhop_handle);
    if (!nhop_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));
    intf_info = switch_api_interface_get(spath_info->nhop_key.intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    *ifindex = intf_info->ifindex;
    *flood = FALSE;
    *mc_index = 0;

    if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_TUNNEL) {
        encap_if = SWITCH_INTF_TUNNEL_ENCAP_OUT_IF(intf_info);
        intf_info = switch_api_interface_get(encap_if);
        if (!intf_info) {
            return SWITCH_STATUS_INVALID_HANDLE;
        }
        *ifindex = intf_info->ifindex;
        SWITCH_API_TRACE("%s:%d ifindex for tunnel interface: %x",
                         __FUNCTION__, __LINE__, *ifindex);
    }

    if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_L3_VLAN) {
        neighbor_handle = spath_info->neighbor_handle;
        if (neighbor_handle == SWITCH_API_INVALID_HANDLE ||
            neighbor_handle == 0) {
            *ifindex = switch_api_cpu_glean_ifindex();
        } else {
            neighbor_info = switch_neighbor_info_get(neighbor_handle);
            if (!neighbor_info) {
                return SWITCH_STATUS_INVALID_HANDLE;
            }
            neighbor = &neighbor_info->neighbor;
            memset(&mac_entry, 0, sizeof(switch_api_mac_entry_t));
            mac_entry.vlan_handle = intf_info->bd_handle;
            memcpy(&mac_entry.mac, &neighbor->mac_addr, ETH_LEN);
            mac_info = switch_mac_table_entry_find(&mac_entry);
            if (!mac_info) {
                bd_info = switch_bd_get(intf_info->bd_handle);
                if (!bd_info) {
                    return SWITCH_STATUS_INVALID_HANDLE;
                }
                *mc_index = handle_to_id(bd_info->uuc_mc_index);
                *flood = TRUE;
            } else {
                tmp_mac_entry = &mac_info->mac_entry;
                handle_type = switch_handle_get_type(tmp_mac_entry->handle);
                switch (handle_type) {
                    case SWITCH_HANDLE_TYPE_PORT:
                        tmp_port_info = switch_api_port_get_internal(tmp_mac_entry->handle);
                        if (!tmp_port_info) {
                            return SWITCH_STATUS_INVALID_HANDLE;
                        }
                        *ifindex = tmp_port_info->ifindex;
                        break;
                    case SWITCH_HANDLE_TYPE_LAG:
                        tmp_lag_info = switch_api_lag_get_internal(tmp_mac_entry->handle);
                        if (!tmp_lag_info) {
                            return SWITCH_STATUS_INVALID_HANDLE;
                        }
                        *ifindex = tmp_lag_info->ifindex;
                        break;
                    case SWITCH_HANDLE_TYPE_INTERFACE:
                        tmp_intf_info = switch_api_interface_get(tmp_mac_entry->handle);
                        if (!tmp_intf_info) {
                            return SWITCH_STATUS_INVALID_HANDLE;
                        }
                        *ifindex = tmp_intf_info->ifindex;
                        break;
                    default:
                        return SWITCH_STATUS_INVALID_HANDLE;
                }
            }
        }
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_api_nhop_create(switch_device_t device, switch_nhop_key_t *nhop_key)
{
    switch_handle_t                    nhop_handle;
    switch_nhop_info_t                *nhop_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_spath_info_t               *spath_info = NULL;
    switch_ifindex_t                   ifindex = 0;
    bool                               flood = FALSE;
    uint32_t                           mc_index = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    if (!SWITCH_INTERFACE_HANDLE_VALID(nhop_key->intf_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    intf_info = switch_api_interface_get(nhop_key->intf_handle);
    if (!intf_info) {
        return SWITCH_API_INVALID_HANDLE;
    }

    if((nhop_handle = switch_api_nhop_handle_get(nhop_key)) == SWITCH_API_INVALID_HANDLE) {
        nhop_handle = switch_nhop_create();
    } else {
        nhop_info = switch_nhop_get(nhop_handle);
        if (!nhop_info) {
            return SWITCH_API_INVALID_HANDLE;
        }
        return nhop_handle;
    }
    nhop_info = switch_nhop_get(nhop_handle);
    if (!nhop_info) {
        return SWITCH_API_INVALID_HANDLE;
    }
    nhop_info->type = SWITCH_NHOP_INDEX_TYPE_ONE_PATH;
    spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));
    spath_info->nhop_key.intf_handle = nhop_key->intf_handle;
    intf_info->nhop_handle = nhop_handle;
    nhop_info->valid = 1;

    status = switch_nhop_ifindex_get(nhop_handle, &ifindex, &flood, &mc_index);
    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_API_INVALID_HANDLE;
    }

#ifdef SWITCH_PD
    bool tunnel = (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_TUNNEL);
    status = switch_pd_nexthop_table_add_entry(device,
                                  handle_to_id(nhop_handle),
                                  handle_to_id(intf_info->bd_handle),
                                  ifindex, flood, mc_index, tunnel,
                                  &spath_info->hw_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_API_INVALID_HANDLE;
    }

    if (SWITCH_INTF_IS_PORT_L3(intf_info) && intf_info->bd_handle) {
        status = switch_pd_urpf_bd_table_add_entry(device, handle_to_id(nhop_handle),
                                     handle_to_id(intf_info->bd_handle),
                                     &spath_info->urpf_hw_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            return SWITCH_API_INVALID_HANDLE;
        }
    }
#endif
    if (nhop_key->ip_addr_valid) {
        switch_nhop_insert_hash(spath_info, nhop_key, nhop_handle);
    }
    return nhop_handle;
}

switch_status_t
switch_api_nhop_update(switch_device_t device, switch_handle_t nhop_handle)
{
    switch_nhop_info_t                *nhop_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_spath_info_t               *spath_info = NULL;
    switch_ifindex_t                   ifindex = 0;
    bool                               flood = FALSE;
    uint32_t                           mc_index = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    if (!SWITCH_NHOP_HANDLE_VALID(nhop_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    nhop_info = switch_nhop_get(nhop_handle);
    if (!nhop_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    status = switch_nhop_ifindex_get(nhop_handle, &ifindex, &flood, &mc_index);
    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));
    intf_info = switch_api_interface_get(spath_info->nhop_key.intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

#ifdef SWITCH_PD
    bool tunnel = (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_TUNNEL);
    status = switch_pd_nexthop_table_update_entry(device,
                                  handle_to_id(nhop_handle),
                                  handle_to_id(intf_info->bd_handle),
                                  ifindex, flood, mc_index, tunnel,
                                  &spath_info->hw_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_API_INVALID_HANDLE;
    }

#endif
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_nhop_delete(switch_device_t device, switch_handle_t nhop_handle)
{
    switch_nhop_info_t                *nhop_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_spath_info_t               *spath_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    if (!SWITCH_NHOP_HANDLE_VALID(nhop_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    nhop_info = switch_nhop_get(nhop_handle);
    if (!nhop_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    if (nhop_info->type != SWITCH_NHOP_INDEX_TYPE_ONE_PATH) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    if (nhop_info->ref_count) {
        return SWITCH_STATUS_RESOURCE_IN_USE;
    }

    spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));
    intf_info = switch_api_interface_get(spath_info->nhop_key.intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }
    nhop_info->valid = 0;
    if(nhop_info->u.spath.neighbor_handle == 0) {
#ifdef SWITCH_PD
        status = switch_pd_nexthop_table_delete_entry(device, spath_info->hw_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            return status;
        }
        if (SWITCH_INTF_IS_PORT_L3(intf_info) && intf_info->bd_handle) {
            status = switch_pd_urpf_bd_table_delete_entry(device, spath_info->urpf_hw_entry);
            if (status != SWITCH_STATUS_SUCCESS) {
                return status;
            }
        }
#endif
        switch_nhop_delete_hash(spath_info);
        switch_nhop_delete(nhop_handle);
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_api_ecmp_create(switch_device_t device)
{
    switch_handle_t                    nhop_handle;
    switch_nhop_info_t                *nhop_info = NULL;
    switch_ecmp_info_t                *ecmp_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    nhop_handle = switch_nhop_create();
    nhop_info = switch_nhop_get(nhop_handle);
    if (!nhop_info) {
        return SWITCH_API_INVALID_HANDLE;
    }
    nhop_info->type = SWITCH_NHOP_INDEX_TYPE_ECMP;
    ecmp_info = &(SWITCH_NHOP_ECMP_INFO(nhop_info));
    memset(ecmp_info, 0, sizeof(switch_ecmp_info_t));
    ecmp_info->hw_entry = SWITCH_HW_INVALID_HANDLE;
    ecmp_info->count = 0;
    tommy_list_init(&(ecmp_info->members));

#ifdef SWITCH_PD
    status = switch_pd_ecmp_group_create(device, &(ecmp_info->pd_group_hdl));
    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_API_INVALID_HANDLE;
    }
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
    uint32_t                           index = 0;

    ecmp_handle = switch_api_ecmp_create(device);
    nhop_info = switch_nhop_get(ecmp_handle);
    if (!nhop_info) {
        return SWITCH_API_INVALID_HANDLE;
    }

    ecmp_info = &(SWITCH_NHOP_ECMP_INFO(nhop_info));
    tommy_list_init(&ecmp_info->members);

#ifdef SWITCH_PD
    status = switch_pd_ecmp_group_create(device, &(ecmp_info->pd_group_hdl));
    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_API_INVALID_HANDLE;
    }
#endif

    for (index = 0; index < member_count; index++) {
        if (!SWITCH_NHOP_HANDLE_VALID(nhop_handle[index])) {
            return SWITCH_STATUS_INVALID_HANDLE;
        }

        ecmp_member = switch_malloc(sizeof(switch_ecmp_member_t), 1);
        if (!ecmp_member) {
            // TODO: Cleanup memory
            return SWITCH_API_INVALID_HANDLE;
        }
        ecmp_member->nhop_handle = nhop_handle[index];
        ecmp_member->mbr_hdl = 0;

        nhop_info = switch_nhop_get(ecmp_member->nhop_handle);
        if (!nhop_info) {
            return SWITCH_API_INVALID_HANDLE;
        }

        spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));
        intf_info = switch_api_interface_get(spath_info->nhop_key.intf_handle);
        if (!intf_info) {
            return SWITCH_API_INVALID_HANDLE;
        }
        nhop_info->ref_count++;

#ifdef SWITCH_PD
        status = switch_pd_ecmp_member_add(device, ecmp_info->pd_group_hdl, 
                    handle_to_id(ecmp_member->nhop_handle), intf_info,
                    &(ecmp_member->mbr_hdl));
        if (status != SWITCH_STATUS_SUCCESS) {
            return SWITCH_API_INVALID_HANDLE;
        }

        if (SWITCH_INTF_IS_PORT_L3(intf_info) && intf_info->bd_handle) {
            status = switch_pd_urpf_bd_table_add_entry(device, handle_to_id(ecmp_handle),
                                                  handle_to_id(intf_info->bd_handle),
                                                  &(ecmp_member->urpf_hw_entry));
            if (status != SWITCH_STATUS_SUCCESS) {
                return SWITCH_API_INVALID_HANDLE;
            }
        }
#endif
        tommy_list_insert_head(&ecmp_info->members, &(ecmp_member->node), ecmp_member);
    }

#ifdef SWITCH_PD
    status = switch_pd_ecmp_group_table_add_entry_with_selector(device, handle_to_id(ecmp_handle), 
                    ecmp_info->pd_group_hdl, &(ecmp_info->hw_entry));
    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_API_INVALID_HANDLE;
    }
#endif
    ecmp_info->count = member_count;
    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_API_INVALID_HANDLE;
    }
    return ecmp_handle;
}

switch_status_t
switch_api_ecmp_delete(switch_device_t device, switch_handle_t handle)
{
    switch_nhop_info_t                *nhop_info = NULL;
    switch_ecmp_info_t                *ecmp_info = NULL;
    tommy_node                        *node = NULL;
    switch_ecmp_member_t              *ecmp_member = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    if (!SWITCH_NHOP_HANDLE_VALID(handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    nhop_info = switch_nhop_get(handle);
    if (!nhop_info) {
        return SWITCH_STATUS_INVALID_NHOP;
    }
    if (nhop_info->type != SWITCH_NHOP_INDEX_TYPE_ONE_PATH) {
        ecmp_info = &(SWITCH_NHOP_ECMP_INFO(nhop_info));
        if (ecmp_info->count > 0) {
            node = tommy_list_head(&(ecmp_info->members));
            while (node) {
                ecmp_member = (switch_ecmp_member_t *) node->data;
                nhop_info = switch_nhop_get(ecmp_member->nhop_handle);
                if (!nhop_info) {
                    return SWITCH_STATUS_INVALID_NHOP;
                }
                nhop_info->ref_count--;
                node = node->next;
            }
        }
#ifdef SWITCH_PD
        status = switch_pd_ecmp_group_delete(device, ecmp_info->pd_group_hdl);
        if (status != SWITCH_STATUS_SUCCESS) {
            return status;
        }
#endif
    }
    return switch_nhop_delete(handle);
}

switch_status_t
switch_api_ecmp_member_add(switch_device_t device, switch_handle_t ecmp_handle,
                           uint16_t nhop_count, switch_handle_t *nhop_handle_list)
{
    switch_nhop_info_t                *e_nhop_info = NULL;
    switch_nhop_info_t                *nhop_info = NULL;
    switch_ecmp_info_t                *ecmp_info = NULL;
    switch_ecmp_member_t              *ecmp_member = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_spath_info_t               *spath_info = NULL;
    switch_handle_t                    nhop_handle;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    int                                count = 0;

    if (!SWITCH_NHOP_HANDLE_VALID(ecmp_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    e_nhop_info = switch_nhop_get(ecmp_handle);
    if (!e_nhop_info) {
        return SWITCH_STATUS_INVALID_NHOP;
    }
    ecmp_info = &(SWITCH_NHOP_ECMP_INFO(e_nhop_info));

    for (count = 0; count < nhop_count; count++) {
        nhop_handle = nhop_handle_list[count];
        if (!SWITCH_NHOP_HANDLE_VALID(nhop_handle)) {
            return SWITCH_STATUS_INVALID_HANDLE;
        }
        nhop_info = switch_nhop_get(nhop_handle);
        if (!nhop_info) {
            return SWITCH_STATUS_INVALID_NHOP;
        }
        spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));

        ecmp_member = switch_malloc(sizeof(switch_ecmp_member_t), 1);
        if (!ecmp_member) {
            return SWITCH_STATUS_NO_MEMORY;
        }
        ecmp_member->nhop_handle = nhop_handle;
        intf_info = switch_api_interface_get(spath_info->nhop_key.intf_handle);
        if (!intf_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
        }

        nhop_info->ref_count++;
#ifdef SWITCH_PD
        status = switch_pd_ecmp_member_add(device, ecmp_info->pd_group_hdl, 
                    handle_to_id(ecmp_member->nhop_handle), intf_info,
                    &(ecmp_member->mbr_hdl));
        if (status != SWITCH_STATUS_SUCCESS) {
            return status;
        }
        if (ecmp_info->count == 0) {
            status = switch_pd_ecmp_group_table_add_entry_with_selector(device, 
                    handle_to_id(ecmp_handle),
                    ecmp_info->pd_group_hdl, 
                    &(ecmp_info->hw_entry)); 
            if (status != SWITCH_STATUS_SUCCESS) {
                return status;
            }
        }
        if (SWITCH_INTF_IS_PORT_L3(intf_info) && intf_info->bd_handle) {
            status = switch_pd_urpf_bd_table_add_entry(device, handle_to_id(ecmp_handle),
                                     handle_to_id(intf_info->bd_handle),
                                     &(ecmp_member->urpf_hw_entry));
            if (status != SWITCH_STATUS_SUCCESS) {
                return status;
            }
        }
#endif
        ecmp_info->count++;
        tommy_list_insert_head(&ecmp_info->members, &(ecmp_member->node), ecmp_member);
    }
    return status;
}

switch_status_t
switch_api_ecmp_member_delete(switch_device_t device, switch_handle_t ecmp_handle,
                              uint16_t nhop_count, switch_handle_t *nhop_handle_list)
{
    switch_nhop_info_t                *nhop_info = NULL;
    switch_nhop_info_t                *e_nhop_info = NULL;
    switch_spath_info_t               *spath_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_ecmp_info_t                *ecmp_info = NULL;
    switch_ecmp_member_t              *ecmp_member = NULL;
    tommy_node                        *node = NULL;
    switch_handle_t                    nhop_handle;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    int                                count = 0;

    if (!SWITCH_NHOP_HANDLE_VALID(ecmp_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    e_nhop_info = switch_nhop_get(ecmp_handle);
    if (!e_nhop_info) {
        return SWITCH_STATUS_INVALID_NHOP;
    }
    for (count = 0; count < nhop_count; count++) {
        nhop_handle = nhop_handle_list[count];
        if (!SWITCH_NHOP_HANDLE_VALID(nhop_handle)) {
            return SWITCH_STATUS_INVALID_HANDLE;
        }
        nhop_info = switch_nhop_get(nhop_handle);
        if (!nhop_info) {
            return SWITCH_STATUS_INVALID_NHOP;
        }
        spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));
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
        intf_info = switch_api_interface_get(spath_info->nhop_key.intf_handle);
        if (!intf_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
        }

        nhop_info->ref_count--;
#if SWITCH_PD
        if (ecmp_info->count == 1) {
            status = switch_pd_ecmp_group_table_delete_entry(device, ecmp_info->hw_entry);
            if (status != SWITCH_STATUS_SUCCESS) {
                return status;
            }
        }
        status = switch_pd_ecmp_member_delete(device, ecmp_info->pd_group_hdl, 
                                              ecmp_member->mbr_hdl);
        if (status != SWITCH_STATUS_SUCCESS) {
            return status;
        }
        if (SWITCH_INTF_IS_PORT_L3(intf_info) && intf_info->bd_handle) {
            status = switch_pd_urpf_bd_table_delete_entry(device, ecmp_member->urpf_hw_entry);
            if (status != SWITCH_STATUS_SUCCESS) {
                return status;
            }
        }
#endif
        ecmp_info->count--;
        ecmp_member = tommy_list_remove_existing(&(ecmp_info->members), node);
        switch_free(ecmp_member);
    }
    return status;
}

switch_nhop_index_type_t
switch_api_nhop_type_get(switch_handle_t nhop_handle)
{
    switch_nhop_info_t                *nhop_info = NULL;

    if (!SWITCH_NHOP_HANDLE_VALID(nhop_handle)) {
        return SWITCH_NHOP_INDEX_TYPE_NONE;
    }

    nhop_info = switch_nhop_get(nhop_handle);
    if (!nhop_info) {
        return SWITCH_NHOP_INDEX_TYPE_NONE;
    }
    return nhop_info->type;
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
        printf("\nintf_handle %x", (unsigned int) spath_info->nhop_key.intf_handle);
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
