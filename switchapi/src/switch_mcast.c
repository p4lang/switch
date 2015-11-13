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
#include "switchapi/switch_mcast.h"
#include "switchapi/switch_interface.h"
#include "switchapi/switch_utils.h"
#include "switchapi/switch_vrf.h"
#include "switch_vrf_int.h"
#include "switch_lag_int.h"
#include "switch_nhop_int.h"
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
static switch_api_id_allocator *switch_rid_allocator;

switch_status_t
switch_mcast_init(switch_device_t device)
{
    switch_mcast_array = NULL;
    switch_handle_type_init(SWITCH_HANDLE_TYPE_MGID, SWITCH_MGID_TABLE_SIZE);
    tommy_hashtable_init(&switch_rid_hash_table, SWITCH_RID_HASH_TABLE_SIZE);
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
switch_mcast_rid_switch_free(uint16_t rid)
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

switch_handle_t
switch_api_mcast_index_allocate(switch_device_t device)
{
    switch_mcast_info_t               *mcast_info = NULL;
    switch_handle_t                    mgid_handle;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;


    _switch_handle_create(SWITCH_HANDLE_TYPE_MGID, switch_mcast_info_t, switch_mcast_array, NULL, mgid_handle);
    mcast_info = switch_mcast_tree_get(mgid_handle);
    if (!mcast_info) {
        return 0;
    }
    status = switch_pd_mcast_mgrp_tree_create(device, handle_to_id(mgid_handle), mcast_info);
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
    _switch_handle_get(switch_mcast_info_t, switch_mcast_array, mgid_handle, mcast_info);
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
switch_api_multicast_tree_delete(switch_device_t device, switch_handle_t mgid_handle)
{
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

switch_status_t
switch_api_multicast_member_add(switch_device_t device,
                                switch_handle_t mgid_handle,
                                switch_handle_t bd_handle,
                                uint16_t intf_handle_count,
                                switch_handle_t *interface_handle)
{
    switch_mcast_info_t               *mcast_info = NULL;
    switch_mcast_rid_t                *rid_info = NULL;
    switch_mcast_node_t               *mcast_node = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_mcast_rid_key_t             rid_key;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_interface_info_t           *intf_info = NULL;
    switch_handle_t                    intf_handle = 0;
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

    if (bd_handle) {
        bd_info = switch_bd_get(bd_handle);
        if (!bd_info) {
            SWITCH_API_ERROR("%s:%d: invalid bd handle %lx",
                         __FUNCTION__, __LINE__, bd_handle);
            return SWITCH_STATUS_INVALID_VLAN_ID;
        }
    }

    for (index = 0; index < intf_handle_count; index++) {
        new_rid_node = FALSE;
        intf_handle = interface_handle[index];
        intf_info = switch_api_interface_get(intf_handle);
        if (!intf_info) {
            SWITCH_API_ERROR("%s:%d: invalid interface %lx",
                         __FUNCTION__, __LINE__, bd_handle);
            return SWITCH_STATUS_INVALID_INTERFACE;
        }
        if (!bd_handle) {
            bd_handle = intf_info->bd_handle;
            bd_info = switch_bd_get(bd_handle);
            if (!bd_info) {
                return SWITCH_STATUS_INVALID_VLAN_ID;
            }
        }

        memset(&rid_key, 0, sizeof(switch_mcast_rid_key_t));
        rid_key.mgid_handle = mgid_handle;
        rid_key.bd_handle = bd_handle;
        rid_key.intf_handle = intf_handle;
        rid_info = switch_mcast_rid_search_hash(&rid_key, &inner_replica);
        if (!rid_info) {
            rid_info = switch_mcast_rid_insert_hash(&rid_key);
            rid = rid_info->rid;
            intf_info->rid = switch_mcast_rid_allocate();
            rid = intf_info->rid;

            mcast_node = switch_malloc(sizeof(switch_mcast_node_t), 1);
            if (!mcast_node) {
                return SWITCH_STATUS_NO_MEMORY;
            }
            memset(mcast_node, 0, sizeof(switch_mcast_node_t));
            SWITCH_MCAST_NODE_RID(mcast_node) = rid;
            new_rid_node = TRUE;
            tommy_list_insert_head(&mcast_info->node_list,
                               &(mcast_node->node), mcast_node);
        } else {
            rid = rid_info->rid;
            mcast_node = switch_mcast_find_node(mcast_info,
                                                SWITCH_NODE_TYPE_SINGLE,
                                                rid);
            if (!mcast_node) {
                // Found rid but not l1 node.
                // This should never happen. 
                return SWITCH_STATUS_ITEM_NOT_FOUND;
            }
        }

        status = switch_mcast_update_port_map(mcast_node, intf_handle, TRUE);

        // Create a L1 Node
        if (new_rid_node) {
            status = switch_pd_mcast_add_entry(device, mcast_node);
            //Associate L1 Node to multicast tree
            status = switch_pd_mcast_mgid_table_add_entry(device,
                                              mcast_info->mgrp_hdl, mcast_node);
            status = switch_pd_rid_table_add_entry(device, rid,
                         handle_to_id(bd_handle),
                         inner_replica,
                         handle_to_id(intf_info->nhop_handle),
                         &(SWITCH_MCAST_NODE_RID_HW_ENTRY(mcast_node)));
            SWITCH_API_TRACE("%s:%d: new l1 node allocated with rid %x", 
                         __FUNCTION__, __LINE__, rid);
        } else {
            status = switch_pd_mcast_update_entry(device, mcast_node);
        }
    }
    return status;
}

switch_status_t
switch_api_multicast_member_delete(switch_device_t device,
                                   switch_handle_t mgid_handle,
                                   switch_handle_t bd_handle,
                                   uint16_t intf_handle_count,
                                   switch_handle_t *interface_handle)
{
    switch_mcast_info_t               *mcast_info = NULL;
    switch_mcast_rid_t                *rid_info = NULL;
    switch_mcast_node_t               *mcast_node = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_handle_t                    intf_handle = 0;
    switch_interface_info_t           *intf_info = NULL;
    switch_mcast_rid_key_t             rid_key;
    bool                               inner_replica = FALSE;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    uint16_t                           rid = 0;
    int                                index = 0;
    bool                               delete_mcast_node = FALSE;

    mcast_info = switch_mcast_tree_get(mgid_handle);
    if (!mcast_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    for (index = 0; index < intf_handle_count; index++) {
        intf_handle = interface_handle[index];
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

        memset(&rid_key, 0, sizeof(switch_mcast_rid_key_t));
        rid_key.mgid_handle = mgid_handle;
        rid_key.bd_handle = bd_handle;
        rid_key.intf_handle = intf_handle;

        rid_info = switch_mcast_rid_search_hash(&rid_key, &inner_replica);
        if (!rid_info) {
            return SWITCH_STATUS_ITEM_NOT_FOUND;
        }
        rid = rid_info->rid;
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
            status = switch_pd_mcast_mgid_table_delete_entry(device,
                                                             mcast_info->mgrp_hdl,
                                                             mcast_node);
            status = switch_pd_mcast_delete_entry(device, mcast_node);
            status = switch_pd_rid_table_delete_entry(device,
                         SWITCH_MCAST_NODE_RID_HW_ENTRY(mcast_node));
            mcast_node = tommy_list_remove_existing(&mcast_info->node_list,
                                                    &(mcast_node->node));
            switch_free(mcast_node);
            switch_mcast_rid_delete_hash(&rid_key);
            switch_mcast_rid_switch_free(rid);
        }
    }
    return status;
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
