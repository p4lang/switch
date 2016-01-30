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
#include "switchapi/switch_interface.h"
#include "switchapi/switch_mcast.h"
#include "switchapi/switch_utils.h"
#include "switchapi/switch_vrf.h"
#include "switch_vrf_int.h"
#include "switch_lag_int.h"
#include "switch_tunnel_int.h"
#include "switch_pd.h"
#include "switch_log.h"
#include <string.h>

#define SWITCH_MGID_TABLE_SIZE 16 * 1024
#define SWITCH_RID_HASH_TABLE_SIZE 16 * 1024
#define SWTICH_MCAST_GROUP_HASH_TABLE_SIZE 16 * 1024
#define SWITCH_RID_ALLOCATOR_SIZE 16 * 1024

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static void *switch_mcast_array;
static tommy_hashtable switch_rid_hash_table;
static tommy_hashtable switch_mcast_group_hash_table;
static switch_api_id_allocator *switch_rid_allocator;

switch_status_t
switch_mcast_init(switch_device_t device)
{
    switch_mcast_array = NULL;
    switch_handle_type_init(SWITCH_HANDLE_TYPE_MGID, SWITCH_MGID_TABLE_SIZE);
    tommy_hashtable_init(&switch_rid_hash_table, SWITCH_RID_HASH_TABLE_SIZE);
    tommy_hashtable_init(&switch_mcast_group_hash_table, SWTICH_MCAST_GROUP_HASH_TABLE_SIZE);
    switch_rid_allocator = switch_api_id_allocator_new(SWITCH_RID_ALLOCATOR_SIZE, FALSE);
    //Reserve the RID 0.
    //switch_api_id_allocator_allocate(switch_rid_allocator);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_mcast_free(switch_device_t device)
{
    switch_handle_type_free(SWITCH_HANDLE_TYPE_MGID);
    tommy_hashtable_done(&switch_rid_hash_table);
    tommy_hashtable_done(&switch_mcast_group_hash_table);
    switch_api_id_allocator_destroy(switch_rid_allocator);
    return SWITCH_STATUS_SUCCESS;
}

uint16_t
switch_mcast_rid_allocate()
{
    uint16_t rid = 0;
    rid = switch_api_id_allocator_allocate(switch_rid_allocator);
    return rid;
}

void
switch_mcast_rid_free(uint16_t rid)
{
    switch_api_id_allocator_release(switch_rid_allocator, rid);
    return;
}

static inline void
switch_mcast_rid_hash_key_init(uchar *key, switch_mcast_rid_key_t *rid_key,
                               uint32_t *len, uint32_t *hash)
{
    *len = 0;
    memset(key, 0, SWITCH_MCAST_RID_HASH_KEY_SIZE);

    memcpy(key, &(rid_key->mgid_handle), sizeof(switch_handle_t));
    *len += sizeof(switch_handle_t);

    memcpy((key + *len), &(rid_key->bd_handle), sizeof(switch_handle_t));
    *len += sizeof(switch_handle_t);

    memcpy((key + *len), &(rid_key->intf_handle), sizeof(switch_handle_t));
    *len += sizeof(switch_handle_t);

    *hash = MurmurHash2(key, *len, 0x98761234);
}

static inline int
switch_mcast_rid_hash_cmp(const void *key1, const void *key2)
{
    return memcmp(key1, key2, SWITCH_MCAST_RID_HASH_KEY_SIZE);
}

static switch_mcast_rid_t *
switch_mcast_rid_insert_hash(switch_mcast_rid_key_t *rid_key)
{
    switch_mcast_rid_t                *rid_info = NULL;
    unsigned char                      key[SWITCH_MCAST_RID_HASH_KEY_SIZE];
    uint32_t                           len = 0;
    uint32_t                           hash = 0;

    switch_mcast_rid_hash_key_init(key, rid_key, &len, &hash);
    rid_info = switch_malloc(sizeof(switch_mcast_rid_t), 1);
    if (!rid_info) {
        return NULL;
    }
    memcpy(&rid_info->rid_key, rid_key, sizeof(switch_mcast_rid_key_t));
    tommy_hashtable_insert(&switch_rid_hash_table,
                            &(rid_info->node),
                            rid_info, hash);
    return rid_info;
}

static switch_status_t
switch_mcast_rid_delete_hash(switch_mcast_rid_key_t *rid_key)
{
    switch_mcast_rid_t                *rid_info = NULL;
    unsigned char                      key[SWITCH_MCAST_RID_HASH_KEY_SIZE];
    uint32_t                           len = 0;
    uint32_t                           hash = 0;

    switch_mcast_rid_hash_key_init(key, rid_key, &len, &hash);
    rid_info = tommy_hashtable_remove(&switch_rid_hash_table,
                                      switch_mcast_rid_hash_cmp,
                                      key, hash);
    if (!rid_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    switch_free(rid_info);
    return SWITCH_STATUS_SUCCESS;
}

static switch_mcast_rid_t *
switch_mcast_rid_search_hash(switch_mcast_rid_key_t *rid_key, bool *inner_replica)
{
    switch_mcast_rid_t                *rid_info = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    unsigned char                      key[SWITCH_MCAST_RID_HASH_KEY_SIZE];
    uint32_t                           len = 0;
    uint32_t                           hash = 0;

    //TODO: Return appropriate error code during failure
    intf_info = switch_api_interface_get(rid_key->intf_handle);
    if (!intf_info) {
        return NULL;
    }
    bd_info = switch_bd_get(rid_key->bd_handle);
    if (!bd_info) {
        return NULL;
    }

    *inner_replica = TRUE;
    if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_TUNNEL) {
        *inner_replica = FALSE;
    }

    if (SWITCH_LN_NETWORK_TYPE(bd_info) == SWITCH_LOGICAL_NETWORK_TYPE_ENCAP_BASIC ||
        SWITCH_LN_NETWORK_TYPE(bd_info) == SWITCH_LOGICAL_NETWORK_TYPE_ENCAP_ENHANCED) {
        if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_L2_VLAN_ACCESS) {
            rid_key->intf_handle = 0;
        }
    } else if (SWITCH_LN_NETWORK_TYPE(bd_info) == SWITCH_LOGICAL_NETWORK_TYPE_VLAN) {
        rid_key->intf_handle = 0;
    }
    switch_mcast_rid_hash_key_init(key, rid_key, &len, &hash);
    rid_info = tommy_hashtable_search(&switch_rid_hash_table,
                                      switch_mcast_rid_hash_cmp,
                                      key, hash);
    return rid_info;
}

static inline void
switch_mcast_group_hash_key_init(uchar *key, switch_mcast_group_key_t *group_key,
                                 uint32_t *len, uint32_t *hash)
{
    switch_ip_addr_type_t addr_type = 0;
    uchar *key_start = key;

    *len = 0;
    memset(key, 0, SWITCH_MCAST_GROUP_HASH_KEY_SIZE);

    addr_type = SWITCH_MCAST_GROUP_IP_TYPE(group_key);
    memcpy(key, &addr_type, sizeof(switch_ip_addr_type_t));
    key += 1;
    *len += 1;

    memcpy(key, &(group_key->sg_entry), 1);
    key += 1;
    *len += 1;

    if (addr_type == SWITCH_API_IP_ADDR_V4) {
        memcpy(key, &(SWITCH_MCAST_GROUP_IPV4_SRC_IP(group_key)), 4);
        key += 4;
        *len += 4;
        memcpy(key, &(SWITCH_MCAST_GROUP_IPV4_GRP_IP(group_key)), 4);
        key += 4;
        *len += 4;
    } else {
        memcpy(key, (SWITCH_MCAST_GROUP_IPV6_SRC_IP(group_key)), 16);
        key += 16;
        *len += 16;
        memcpy(key, (SWITCH_MCAST_GROUP_IPV6_GRP_IP(group_key)), 16);
        key += 16;
        *len += 16;
    }

    memcpy(key, &(group_key->bd_vrf_handle), sizeof(switch_handle_t));
    key += sizeof(switch_handle_t);
    *len += sizeof(switch_handle_t);

    *hash = MurmurHash2(key_start, *len, 0x98761234);
}

static inline int
switch_mcast_group_hash_cmp(const void *key1, const void *arg)
{
    unsigned char                      key2[SWITCH_MCAST_GROUP_HASH_KEY_SIZE];
    uint32_t                           len = 0;
    uint32_t                           hash = 0;
    switch_mcast_group_info_t         *group_info = (void *)arg;

    switch_mcast_group_hash_key_init(key2, &group_info->group_key, &len, &hash);
    return memcmp(key1, key2, SWITCH_MCAST_GROUP_HASH_KEY_SIZE);
}

static switch_mcast_group_info_t *
switch_mcast_group_insert_hash(switch_mcast_group_key_t *group_key)
{
    switch_mcast_group_info_t         *group_info = NULL;
    unsigned char                      key[SWITCH_MCAST_GROUP_HASH_KEY_SIZE];
    uint32_t                           len = 0;
    uint32_t                           hash = 0;

    switch_mcast_group_hash_key_init(key, group_key, &len, &hash);
    group_info = switch_malloc(sizeof(switch_mcast_group_info_t), 1);
    if (!group_info) {
        return NULL;
    }
    memcpy(&group_info->group_key, group_key, sizeof(switch_mcast_group_key_t));
    tommy_hashtable_insert(&switch_mcast_group_hash_table,
                            &(group_info->node), group_info, hash);
    return group_info;
}

static switch_status_t
switch_mcast_group_delete_hash(switch_mcast_group_key_t *group_key)
{
    switch_mcast_rid_t                *group_info = NULL;
    unsigned char                      key[SWITCH_MCAST_GROUP_HASH_KEY_SIZE];
    uint32_t                           len = 0;
    uint32_t                           hash = 0;

    switch_mcast_group_hash_key_init(key, group_key, &len, &hash);
    group_info = tommy_hashtable_remove(&switch_mcast_group_hash_table,
                                      switch_mcast_group_hash_cmp,
                                      key, hash);
    if (!group_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    switch_free(group_info);
    return SWITCH_STATUS_SUCCESS;
}

static switch_mcast_group_info_t *
switch_mcast_group_search_hash(switch_mcast_group_key_t *group_key)
{
    switch_mcast_group_info_t         *group_info = NULL;
    unsigned char                      key[SWITCH_MCAST_GROUP_HASH_KEY_SIZE];
    uint32_t                           len = 0;
    uint32_t                           hash = 0;

    switch_mcast_group_hash_key_init(key, group_key, &len, &hash);
    group_info = tommy_hashtable_search(&switch_mcast_group_hash_table,
                                      switch_mcast_group_hash_cmp,
                                      key, hash);
    return group_info;
}

switch_handle_t
switch_api_mcast_index_allocate(switch_device_t device)
{
    switch_mcast_info_t               *mcast_info = NULL;
    switch_handle_t                    mgid_handle;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;


    _switch_handle_create(SWITCH_HANDLE_TYPE_MGID, switch_mcast_info_t,
                          switch_mcast_array, NULL, mgid_handle);
    mcast_info = switch_mcast_tree_get(mgid_handle);
    if (!mcast_info) {
        return 0;
    }
    status = switch_pd_mcast_mgrp_tree_create(device,
                                              handle_to_id(mgid_handle),
                                              mcast_info);
    if (status) {
        return 0;
    }
    tommy_list_init(&mcast_info->node_list);
    return mgid_handle;
}

switch_mcast_info_t *
switch_mcast_tree_get(switch_handle_t mgid_handle)
{
    switch_mcast_info_t *mcast_info = NULL;
    _switch_handle_get(switch_mcast_info_t, switch_mcast_array,
                       mgid_handle, mcast_info);
    return mcast_info;
}

switch_status_t
switch_api_mcast_index_delete(switch_device_t device, switch_handle_t mgid_handle)
{
    switch_mcast_info_t               *mcast_info = NULL;

    mcast_info = switch_mcast_tree_get(mgid_handle);
    if (!mcast_info) {
        return 0;
    }

    switch_pd_mcast_mgrp_tree_delete(device, mcast_info);
    _switch_handle_delete(switch_mcast_info_t, switch_mcast_array, mgid_handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_api_multicast_tree_create(switch_device_t device)
{
    return switch_api_mcast_index_allocate(device);
}

switch_status_t
switch_api_multicast_tree_delete(switch_device_t device,
                                 switch_handle_t mgid_handle)
{
    switch_mcast_info_t               *mcast_info = NULL;
    switch_mcast_node_t               *mcast_node = NULL;
    tommy_node                        *node = NULL;

    mcast_info = switch_mcast_tree_get(mgid_handle);
    if (!mcast_info) {
        SWITCH_API_ERROR("%s:%d: invalid multicast handle %lx",
                     __FUNCTION__, __LINE__, mgid_handle);
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    node = tommy_list_head(&mcast_info->node_list);
    while (node) {
        mcast_node = node->data;
        node = node->next;
        switch_pd_mcast_mgid_table_delete_entry(device,
                                                mcast_info->mgrp_hdl,
                                                mcast_node);
        switch_pd_mcast_delete_entry(device, mcast_node);
        switch_pd_rid_table_delete_entry(
            device, SWITCH_MCAST_NODE_RID_HW_ENTRY(mcast_node));
        mcast_node = tommy_list_remove_existing(&mcast_info->node_list,
                                                &(mcast_node->node));
        switch_free(mcast_node);
    }

    return switch_api_mcast_index_delete(device, mgid_handle);
}

switch_mcast_node_t *
switch_mcast_find_node(switch_mcast_info_t *mcast_info,
                       switch_mcast_node_type_t node_type,
                       switch_handle_t rid)
{
    switch_mcast_node_t               *mcast_node = NULL;
    tommy_node                        *node = NULL;

    node = tommy_list_head(&mcast_info->node_list);
    while(node) {
        mcast_node = node->data;
        if (node_type == SWITCH_NODE_TYPE_SINGLE) {
            if (SWITCH_MCAST_NODE_RID(mcast_node) == rid) {
                break;
            }
        }
        node = node->next;
    }

    if (!node) {
        mcast_node = NULL;
    }

    return mcast_node;
}

bool
switch_mcast_node_empty(switch_mcast_node_t *node)
{
    switch_mc_lag_map_t               *lag_map = NULL;
    switch_mc_port_map_t              *port_map = NULL;
    int                                i = 0;

    lag_map = &(SWITCH_MCAST_NODE_INFO_LAG_MAP(node));
    port_map = &(SWITCH_MCAST_NODE_INFO_PORT_MAP(node));

    for (i = 0; i < SWITCH_PORT_ARRAY_SIZE; i++) {
        if ((*port_map)[i]) {
            return FALSE;
        }
    }
    for (i = 0; i < SWITCH_LAG_ARRAY_SIZE; i++) {
        if ((*lag_map)[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

switch_status_t
switch_mcast_update_port_map(switch_mcast_node_t *node,
                             switch_handle_t intf_handle,
                             bool set)
{
    switch_interface_info_t           *intf_info = NULL;
    switch_interface_info_t           *out_intf_info = NULL;
    switch_handle_t                    port_handle;
    switch_handle_t                    out_intf_handle;
    switch_port_t                      port_id = 0;
    uint16_t                           lag_index = 0;

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    port_handle = SWITCH_INTF_PORT_HANDLE(intf_info);
    switch(SWITCH_INTF_TYPE(intf_info)) {
        case SWITCH_API_INTERFACE_L2_VLAN_ACCESS:
        case SWITCH_API_INTERFACE_L2_VLAN_TRUNK:
        case SWITCH_API_INTERFACE_L2_PORT_VLAN:
            if (SWITCH_HANDLE_IS_LAG(port_handle)) {
                lag_index = SWITCH_INTF_L2_LAG_INDEX(intf_info);
            } else {
                port_id = SWITCH_INTF_L2_PORT(intf_info);
            }
            break;
        case SWITCH_API_INTERFACE_L3:
        case SWITCH_API_INTERFACE_L3_VLAN:
        case SWITCH_API_INTERFACE_L3_PORT_VLAN:
            if (SWITCH_HANDLE_IS_LAG(port_handle)) {
                lag_index = SWITCH_INTF_L3_LAG_INDEX(intf_info);
            } else {
                port_id = SWITCH_INTF_L3_PORT(intf_info);
            }
            break;
        case SWITCH_API_INTERFACE_TUNNEL:
            out_intf_handle = SWITCH_INTF_TUNNEL_ENCAP_OUT_IF(intf_info);
            out_intf_info = switch_api_interface_get(out_intf_handle);
            if (!out_intf_info) {
                return SWITCH_STATUS_INVALID_INTERFACE;
            }
            if (SWITCH_HANDLE_IS_LAG(out_intf_handle)) {
                lag_index = SWITCH_INTF_L3_LAG_INDEX(out_intf_info);
            } else {
                port_id = SWITCH_INTF_L3_PORT(out_intf_info);
            }
            break;
        default:
            return SWITCH_STATUS_FAILURE;
    }
    if (set) {
        if (lag_index) {
            SWITCH_MC_LAG_MAP_SET_(SWITCH_MCAST_NODE_INFO_LAG_MAP(node),
                                   lag_index);
        } else {
            SWITCH_MC_PORT_MAP_SET_(SWITCH_MCAST_NODE_INFO_PORT_MAP(node),
                                    port_id);
        }
    } else {
        if (lag_index) {
            SWITCH_MC_LAG_MAP_CLEAR_(SWITCH_MCAST_NODE_INFO_LAG_MAP(node),
                                     lag_index);
        } else {
            SWITCH_MC_PORT_MAP_CLEAR_(SWITCH_MCAST_NODE_INFO_PORT_MAP(node),
                                      port_id);
        }
    }
    return SWITCH_STATUS_SUCCESS;
}

static void
switch_mcast_update_mcast_info(switch_mcast_info_t *mcast_info,
                               uint16_t mbr_count,
                               switch_vlan_interface_t *mbrs, bool add)
{
    for (int i = 0; i < mbr_count; i++) {
        switch_vlan_interface_t *mbr = &mbrs[i];
        int found = -1;
        for (int i = 0; i < mcast_info->mbr_count; i++) {
            if (memcmp(&(mcast_info->mbrs[i]), mbr,
                       sizeof(switch_vlan_interface_t)) == 0) {
                found = i;
                break;
            }
        }

        // (add and entry is already present) or (delete and entry is not found)
        if ((add && (found != -1)) || (!add && (found == -1))) {
            continue;
        }

        if (add) {
            if (mcast_info->mbr_count_max == mcast_info->mbr_count) {
                mcast_info->mbrs = switch_realloc(mcast_info->mbrs,
                    (sizeof(switch_vlan_interface_t) *
                    (mcast_info->mbr_count_max + 16)));
                if (!mcast_info->mbrs) {
                    return;
                }
                mcast_info->mbr_count_max += 16;
            }
            mcast_info->mbrs[mcast_info->mbr_count] = *mbr;
            mcast_info->mbr_count++;
        } else {
            mcast_info->mbrs[found] = mcast_info->mbrs[mcast_info->mbr_count-1];
            mcast_info->mbr_count--;
        }
    }
}

switch_status_t
switch_mcast_rid_get(switch_handle_t bd_handle,
                     switch_handle_t intf_handle,
                     switch_rid_t *rid)
{
    switch_bd_info_t                  *bd_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_ln_member_t                *ln_member = NULL;

    *rid = 0;

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_TUNNEL ||
        SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_L2_PORT_VLAN) {
        ln_member = switch_api_logical_network_search_member(bd_handle, intf_handle);
        if (!ln_member) {
            return SWITCH_STATUS_FAILURE;
        }
        *rid = ln_member->rid;
    } else {
        *rid = bd_info->rid;
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_multicast_member_add(switch_device_t device,
                                switch_handle_t mgid_handle,
                                uint16_t mbr_count,
                                switch_vlan_interface_t *mbrs)
{
    switch_mcast_info_t               *mcast_info = NULL;
    switch_mcast_node_t               *mcast_node = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_interface_info_t           *intf_info = NULL;
    switch_handle_t                    bd_handle = 0;
    switch_handle_t                    intf_handle = 0;
    switch_handle_type_t               handle_type;
    uint16_t                           rid = 0;
    bool                               inner_replica = TRUE;
    bool                               new_rid_node = FALSE;
    int                                index = 0;

    mcast_info = switch_mcast_tree_get(mgid_handle);
    if (!mcast_info) {
        SWITCH_API_ERROR("%s:%d: invalid multicast handle %lx",
                     __FUNCTION__, __LINE__, mgid_handle);
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    for (index = 0; index < mbr_count; index++) {

        bd_handle = mbrs[index].vlan_handle;
        if (bd_handle) {
            bd_info = switch_bd_get(bd_handle);
            if (!bd_info) {
                SWITCH_API_ERROR("%s:%d: invalid bd handle %lx",
                                 __FUNCTION__, __LINE__, bd_handle);
                continue;
            }
        }

        intf_handle = mbrs[index].intf_handle;
        handle_type = switch_handle_get_type(intf_handle);
        if ((handle_type == SWITCH_HANDLE_TYPE_PORT) ||
            (handle_type == SWITCH_HANDLE_TYPE_LAG)) {
            status = switch_intf_handle_get(bd_handle, intf_handle,
                                            &intf_handle);
            if (status != SWITCH_STATUS_SUCCESS) {
                SWITCH_API_ERROR("%s:%d: invalid interface %lx",
                                 __FUNCTION__, __LINE__,
                                 mbrs[index].intf_handle);
                continue;
            }
        }

        intf_info = switch_api_interface_get(intf_handle);
        if (!intf_info ||
            (SWITCH_INTF_TYPE(intf_info)== SWITCH_API_INTERFACE_L3_VLAN)) {
            SWITCH_API_ERROR("%s:%d: invalid interface %lx",
                         __FUNCTION__, __LINE__, bd_handle);
            continue;
        }
        if (!bd_handle) {
            bd_handle = intf_info->bd_handle;
            bd_info = switch_bd_get(bd_handle);
            if (!bd_info) {
                return SWITCH_STATUS_INVALID_VLAN_ID;
            }
        }

        status = switch_mcast_rid_get(bd_handle, intf_handle, &rid);
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d: cannot find valid rid for bd %lx",
                             __FUNCTION__, __LINE__, bd_handle);
            continue;
        }

        new_rid_node = FALSE;
        mcast_node = switch_mcast_find_node(mcast_info,
                                            SWITCH_NODE_TYPE_SINGLE,
                                            rid);
        if (!mcast_node) {
            mcast_node = switch_malloc(sizeof(switch_mcast_node_t), 1);
            if (!mcast_node) {
                return SWITCH_STATUS_NO_MEMORY;
            }
            memset(mcast_node, 0, sizeof(switch_mcast_node_t));
            SWITCH_MCAST_NODE_RID(mcast_node) = rid;
            new_rid_node = TRUE;
            tommy_list_insert_head(&mcast_info->node_list,
                               &(mcast_node->node), mcast_node);
        }

        status = switch_mcast_update_port_map(mcast_node, intf_handle, TRUE);

        // Create a L1 Node
        if (new_rid_node) {
            switch_ip_encap_t *ip_encap = NULL;
            switch_encap_type_t encap_type = SWITCH_API_ENCAP_TYPE_NONE;
            uint8_t tunnel_type = 0;
            uint16_t tunnel_index = 0;

            status = switch_pd_mcast_add_entry(device, mcast_node);
            //Associate L1 Node to multicast tree
            status = switch_pd_mcast_mgid_table_add_entry(device,
                                              mcast_info->mgrp_hdl, mcast_node);
            if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_TUNNEL) {
                encap_type = SWITCH_INTF_TUNNEL_ENCAP_TYPE(intf_info);
                ip_encap = &(SWITCH_INTF_TUNNEL_IP_ENCAP(intf_info));
                tunnel_type = switch_tunnel_get_egress_tunnel_type(encap_type,
                                                                   ip_encap);
                tunnel_index = handle_to_id(intf_handle);
            }
            status = switch_pd_rid_table_add_entry(device, rid,
                         handle_to_id(bd_handle),
                         inner_replica, tunnel_type, tunnel_index,
                         &(SWITCH_MCAST_NODE_RID_HW_ENTRY(mcast_node)));
            SWITCH_API_TRACE("%s:%d: new l1 node allocated with rid %x", 
                         __FUNCTION__, __LINE__, rid);
        } else {
            status = switch_pd_mcast_update_entry(device, mcast_node);
        }
    }

    switch_mcast_update_mcast_info(mcast_info, mbr_count, mbrs, true);
    return status;
}

switch_status_t
switch_api_multicast_member_delete(switch_device_t device,
                                   switch_handle_t mgid_handle,
                                   uint16_t mbr_count,
                                   switch_vlan_interface_t *mbrs)
{
    switch_mcast_info_t               *mcast_info = NULL;
    switch_mcast_node_t               *mcast_node = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_handle_t                    bd_handle = 0;
    switch_handle_t                    intf_handle = 0;
    switch_interface_info_t           *intf_info = NULL;
    switch_handle_type_t               handle_type;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    uint16_t                           rid = 0;
    int                                index = 0;
    bool                               delete_mcast_node = FALSE;

    mcast_info = switch_mcast_tree_get(mgid_handle);
    if (!mcast_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    for (index = 0; index < mbr_count; index++) {

        bd_handle = mbrs[index].vlan_handle;
        if (bd_handle) {
            bd_info = switch_bd_get(bd_handle);
            if (!bd_info) {
                SWITCH_API_ERROR("%s:%d: invalid bd handle %lx",
                                 __FUNCTION__, __LINE__, bd_handle);
                return SWITCH_STATUS_INVALID_VLAN_ID;
            }
        }

        intf_handle = mbrs[index].intf_handle;
        handle_type = switch_handle_get_type(intf_handle);
        if ((handle_type == SWITCH_HANDLE_TYPE_PORT) ||
            (handle_type == SWITCH_HANDLE_TYPE_LAG)) {
            status = switch_intf_handle_get(bd_handle, intf_handle,
                                            &intf_handle);
            if (status != SWITCH_STATUS_SUCCESS) {
                SWITCH_API_ERROR("%s:%d: invalid interface %lx",
                                 __FUNCTION__, __LINE__,
                                 mbrs[index].intf_handle);
                return SWITCH_STATUS_INVALID_INTERFACE;
            }
        }
        intf_info = switch_api_interface_get(intf_handle);
        if (!intf_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
        }

        if (!bd_handle) {
            bd_handle = intf_info->bd_handle;
            bd_info = switch_bd_get(bd_handle);
            if (!bd_info) {
                return SWITCH_STATUS_INVALID_VLAN_ID;
            }
        }

        status = switch_mcast_rid_get(bd_handle, intf_handle, &rid);
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d: cannot find valid rid for bd %lx",
                             __FUNCTION__, __LINE__, bd_handle);
            return SWITCH_STATUS_INVALID_INTERFACE;
        }


        mcast_node = switch_mcast_find_node(mcast_info,
                                            SWITCH_NODE_TYPE_SINGLE,
                                            rid);
        if (!mcast_node) {
            // Found rid but not l1 node.
            // This should never happen.
            return SWITCH_STATUS_ITEM_NOT_FOUND;
        }

        status = switch_mcast_update_port_map(mcast_node,
                                             intf_handle, FALSE);
        delete_mcast_node = switch_mcast_node_empty(mcast_node);
        if (delete_mcast_node) {
            status = switch_pd_mcast_mgid_table_delete_entry(
                device, mcast_info->mgrp_hdl, mcast_node);
            status = switch_pd_mcast_delete_entry(device, mcast_node);
            status = switch_pd_rid_table_delete_entry(device,
                         SWITCH_MCAST_NODE_RID_HW_ENTRY(mcast_node));
            mcast_node = tommy_list_remove_existing(&mcast_info->node_list,
                                                    &(mcast_node->node));
            switch_free(mcast_node);
        }
    }

    switch_mcast_update_mcast_info(mcast_info, mbr_count, mbrs, false);
    return status;
}

switch_status_t
switch_api_multicast_member_get(switch_device_t device,
                                switch_handle_t mgid_handle,
                                uint16_t *mbr_count,
                                switch_vlan_interface_t **mbrs)
{
    switch_mcast_info_t               *mcast_info = NULL;

    mcast_info = switch_mcast_tree_get(mgid_handle);
    if (!mcast_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    *mbr_count = mcast_info->mbr_count;
    *mbrs = NULL;
    if (*mbr_count) {
        *mbrs = switch_malloc(sizeof(switch_vlan_interface_t), *mbr_count);
        memcpy(*mbrs, mcast_info->mbrs,
               sizeof(switch_vlan_interface_t) * (*mbr_count));
    }
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
switch_mcast_get_rpf_group(switch_mcast_mode_t mc_mode,
                           switch_handle_t *rpf_bd_list, uint16_t rpf_bd_count,
                           uint16_t *rpf_group)
{
    if ((mc_mode == SWITCH_API_MCAST_IPMC_NONE) ||
        ((mc_mode == SWITCH_API_MCAST_IPMC_PIM_SM) && (rpf_bd_count != 1)) ||
        ((mc_mode == SWITCH_API_MCAST_IPMC_PIM_BIDIR) && (!rpf_bd_count))) {
        return SWITCH_STATUS_INVALID_PARAMETER;
    }

    if (mc_mode == SWITCH_API_MCAST_IPMC_PIM_BIDIR) {
        if (rpf_bd_count != 1) {
            return SWITCH_STATUS_INVALID_PARAMETER;
        }
        *rpf_group = rpf_bd_list[0];
        return SWITCH_STATUS_SUCCESS;
    }

    switch_handle_t rpf_handle = 0;
    switch_handle_type_t rpf_handle_type = 0;

    rpf_handle = rpf_bd_list[0];
    rpf_handle_type = switch_handle_get_type(rpf_handle);
    if ((rpf_handle_type != SWITCH_HANDLE_TYPE_BD) &&
        (rpf_handle_type != SWITCH_HANDLE_TYPE_INTERFACE)) {
        return SWITCH_STATUS_INVALID_PARAMETER;
    }

    if (rpf_handle_type == SWITCH_HANDLE_TYPE_INTERFACE) {
        switch_interface_info_t *intf_info = NULL;
        intf_info = switch_api_interface_get(rpf_handle);
        if (!intf_info) {
            SWITCH_API_ERROR("%s:%d: invalid interface handle %lx",
                         __FUNCTION__, __LINE__, rpf_handle);
            return SWITCH_STATUS_INVALID_INTERFACE;
        }
        rpf_handle = intf_info->bd_handle;
    }

    switch_bd_info_t *bd_info = NULL;
    bd_info = switch_bd_get(rpf_handle);
    if (!bd_info) {
        SWITCH_API_ERROR("%s:%d: invalid rpf handle %lx",
                         __FUNCTION__, __LINE__, rpf_bd_list[0]);
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    *rpf_group = handle_to_id(rpf_handle);

    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_multicast_mroute_add(switch_device_t device,
                                switch_handle_t mgid_handle,
                                switch_handle_t vrf_handle,
                                const switch_ip_addr_t *src_ip,
                                const switch_ip_addr_t *grp_ip,
                                switch_mcast_mode_t mc_mode,
                                switch_handle_t *rpf_bd_list,
                                uint16_t rpf_bd_count)
{
    switch_mcast_group_info_t         *group_info = NULL;
    switch_mcast_group_key_t          *group_key = NULL;
    switch_vrf_info_t                 *vrf_info = NULL;
    switch_mcast_group_key_t           group_key_temp;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    bool                               core_entry = false;
    uint16_t                           rpf_group = 0;

    status = switch_mcast_get_rpf_group(mc_mode, rpf_bd_list, rpf_bd_count,
                                        &rpf_group);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }

    group_key = &group_key_temp;
    memset(group_key, 0, sizeof(switch_mcast_group_key_t));
    memcpy(&group_key->src_ip, src_ip, sizeof(switch_ip_addr_t));
    memcpy(&group_key->grp_ip, grp_ip, sizeof(switch_ip_addr_t));
    group_key->bd_vrf_handle = vrf_handle;
    group_key->sg_entry = (group_key->src_ip.prefix_len == 0) ? false : true;

    group_info = switch_mcast_group_search_hash(group_key);
    if (!group_info) {
        group_info = switch_mcast_group_insert_hash(group_key);
        if (!group_info) {
            return SWITCH_STATUS_NO_MEMORY;
        }
    }

    vrf_info = switch_vrf_get(vrf_handle);
    if (!vrf_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }
    if (SWITCH_VRF_IS_CORE(vrf_info)) {
        core_entry = TRUE;
    }

    group_info->mgid_handle = mgid_handle;
    status = switch_pd_mcast_table_add_entry(device,
                                             handle_to_id(mgid_handle),
                                             mc_mode, group_info,
                                             core_entry, TRUE, rpf_group);
    return status;
}

switch_status_t
switch_api_multicast_mroute_delete(switch_device_t device,
                                   switch_handle_t vrf_handle,
                                   const switch_ip_addr_t *src_ip,
                                   const switch_ip_addr_t *grp_ip)
{
    switch_mcast_group_info_t         *group_info = NULL;
    switch_mcast_group_key_t          *group_key = NULL;
    switch_vrf_info_t                 *vrf_info = NULL;
    switch_mcast_group_key_t           group_key_temp;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    bool                               core_entry = FALSE;

    group_key = &group_key_temp;
    memset(group_key, 0, sizeof(switch_mcast_group_key_t));
    memcpy(&group_key->src_ip, src_ip, sizeof(switch_ip_addr_t));
    memcpy(&group_key->grp_ip, grp_ip, sizeof(switch_ip_addr_t));
    group_key->bd_vrf_handle = vrf_handle;
    group_key->sg_entry = (group_key->src_ip.prefix_len == 0) ? false : true;

    group_info = switch_mcast_group_search_hash(group_key);
    if (!group_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    vrf_info = switch_vrf_get(vrf_handle);
    if (!vrf_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }
    if (SWITCH_VRF_IS_CORE(vrf_info)) {
        core_entry = TRUE;
    }

    status = switch_pd_mcast_table_delete_entry(device, group_info,
                                                core_entry, TRUE);

    switch_mcast_group_delete_hash(group_key);
    return status;
}

switch_status_t
switch_api_multicast_mroute_tree_get(switch_device_t device,
                                     switch_handle_t vrf_handle,
                                     const switch_ip_addr_t *src_ip,
                                     const switch_ip_addr_t *grp_ip,
                                     switch_handle_t *mgid_handle)
{
    switch_mcast_group_info_t         *group_info = NULL;
    switch_mcast_group_key_t          *group_key = NULL;
    switch_mcast_group_key_t           group_key_temp;

    group_key = &group_key_temp;
    memset(group_key, 0, sizeof(switch_mcast_group_key_t));
    memcpy(&group_key->src_ip, src_ip, sizeof(switch_ip_addr_t));
    memcpy(&group_key->grp_ip, grp_ip, sizeof(switch_ip_addr_t));
    group_key->bd_vrf_handle = vrf_handle;
    group_key->sg_entry = (group_key->src_ip.prefix_len == 0) ? false : true;

    group_info = switch_mcast_group_search_hash(group_key);
    if (!group_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    *mgid_handle = group_info->mgid_handle;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_multicast_l2route_add(switch_device_t device,
                                 switch_handle_t mgid_handle,
                                 switch_handle_t bd_handle,
                                 const switch_ip_addr_t *src_ip,
                                 const switch_ip_addr_t *grp_ip)
{
    switch_mcast_group_info_t         *group_info = NULL;
    switch_mcast_group_key_t          *group_key = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_mcast_group_key_t           group_key_temp;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    bool                               core_entry = FALSE;
    switch_mcast_mode_t                mc_mode = SWITCH_API_MCAST_IPMC_NONE;

    group_key = &group_key_temp;
    memset(group_key, 0, sizeof(switch_mcast_group_key_t));
    memcpy(&group_key->src_ip, src_ip, sizeof(switch_ip_addr_t));
    memcpy(&group_key->grp_ip, grp_ip, sizeof(switch_ip_addr_t));
    group_key->bd_vrf_handle = bd_handle;
    group_key->sg_entry = (group_key->src_ip.prefix_len == 0) ? false : true;

    group_info = switch_mcast_group_search_hash(group_key);
    if (!group_info) {
        group_info = switch_mcast_group_insert_hash(group_key);
        if (!group_info) {
            return SWITCH_STATUS_NO_MEMORY;
        }
    }

    if (SWITCH_HANDLE_IS_BD(bd_handle)) {
        bd_info = switch_bd_get(bd_handle);
        if (!bd_info) {
            return SWITCH_STATUS_INVALID_HANDLE;
        }
        if (SWITCH_BD_IS_CORE(bd_info)) {
            core_entry = TRUE;
        }
    }

    group_info->mgid_handle = mgid_handle;
    status = switch_pd_mcast_table_add_entry(device,
                                             handle_to_id(mgid_handle),
                                             mc_mode, group_info,
                                             core_entry, FALSE, 0);
    return status;
}

switch_status_t
switch_api_multicast_l2route_delete(switch_device_t device,
                                    switch_handle_t bd_handle,
                                    const switch_ip_addr_t *src_ip,
                                    const switch_ip_addr_t *grp_ip)
{
    switch_mcast_group_info_t         *group_info = NULL;
    switch_mcast_group_key_t          *group_key = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_mcast_group_key_t           group_key_temp;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    bool                               core_entry = FALSE;

    group_key = &group_key_temp;
    memset(group_key, 0, sizeof(switch_mcast_group_key_t));
    memcpy(&group_key->src_ip, src_ip, sizeof(switch_ip_addr_t));
    memcpy(&group_key->grp_ip, grp_ip, sizeof(switch_ip_addr_t));
    group_key->bd_vrf_handle = bd_handle;
    group_key->sg_entry = (group_key->src_ip.prefix_len == 0) ? false : true;

    group_info = switch_mcast_group_search_hash(group_key);
    if (!group_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    if (SWITCH_HANDLE_IS_BD(bd_handle)) {
        bd_info = switch_bd_get(bd_handle);
        if (!bd_info) {
            return SWITCH_STATUS_INVALID_HANDLE;
        }
        if (SWITCH_BD_IS_CORE(bd_info)) {
            core_entry = TRUE;
        }
    }

    status = switch_pd_mcast_table_delete_entry(device,
                                                group_info,
                                                core_entry, FALSE);

    switch_mcast_group_delete_hash(group_key);
    return status;
}

switch_status_t
switch_api_multicast_l2route_tree_get(switch_device_t device,
                                      switch_handle_t bd_handle,
                                      const switch_ip_addr_t *src_ip,
                                      const switch_ip_addr_t *grp_ip,
                                      switch_handle_t *mgid_handle)
{
    switch_mcast_group_info_t         *group_info = NULL;
    switch_mcast_group_key_t          *group_key = NULL;
    switch_mcast_group_key_t           group_key_temp;

    group_key = &group_key_temp;
    memset(group_key, 0, sizeof(switch_mcast_group_key_t));
    memcpy(&group_key->src_ip, src_ip, sizeof(switch_ip_addr_t));
    memcpy(&group_key->grp_ip, grp_ip, sizeof(switch_ip_addr_t));
    group_key->bd_vrf_handle = bd_handle;
    group_key->sg_entry = (group_key->src_ip.prefix_len == 0) ? false : true;

    group_info = switch_mcast_group_search_hash(group_key);
    if (!group_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    *mgid_handle = group_info->mgid_handle;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_multicast_update_lag_port_map(switch_device_t device, switch_handle_t lag_handle)
{
    switch_lag_info_t                 *lag_info = NULL;
    switch_lag_member_t               *lag_member = NULL;
    tommy_node                        *node = NULL;
    switch_mc_port_map_t               port_map;
    switch_port_t                      port_id = 0;
    uint16_t                           lag_index = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    lag_info = switch_api_lag_get_internal(lag_handle);
    if (!lag_info) {
        SWITCH_API_ERROR("%s:%d: invalid lag handle", __FUNCTION__, __LINE__);
        return SWITCH_STATUS_INVALID_HANDLE;
    }
    memset(port_map, 0, sizeof(switch_mc_port_map_t));
    lag_index = handle_to_id(lag_handle);
    node = tommy_list_head(&(lag_info->egress));
    while (node) {
        lag_member = node->data;
        port_id = lag_member->port;
        SWITCH_MC_PORT_MAP_SET_(port_map, port_id);
        node = node->next;
    }
    status = switch_pd_mcast_lag_port_map_update(device, lag_index, port_map);
    return status;
}

#ifdef __cplusplus
}
#endif
