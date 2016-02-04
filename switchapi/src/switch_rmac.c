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
#include "switchapi/switch_rmac.h"
#include "switchapi/switch_utils.h"
#include "switch_pd.h"
#include "switch_rmac_int.h"
#include "switch_log.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
static void *switch_rmac_array;
static tommy_hashtable smac_rewrite_table;
switch_api_id_allocator *smac_rewrite_index_allocator = NULL;

// Router MAC API's

/*
 * @function: switch_api_router_mac_group_create
 * Creates a RMAC Group
 * @return: Returns rmac group id if success
 */
switch_handle_t
switch_api_router_mac_group_create(switch_device_t device)
{
    switch_rmac_info_t                *rmac_info = NULL;
    switch_handle_t                    rmac_handle;

    _switch_handle_create(SWITCH_HANDLE_TYPE_MY_MAC, switch_rmac_info_t, switch_rmac_array, NULL, rmac_handle);
    rmac_info = switch_api_rmac_info_get_internal(rmac_handle);
    tommy_list_init(&(rmac_info->rmac_list));
    return rmac_handle;
}

/*
 * @function: - switch_api_router_mac_group_delete
 * Destroy a RMAC Group
 * @param - RMAC id that has to be deleted
 * @return - Returns rmac group id if success
 */
switch_status_t
switch_api_router_mac_group_delete(switch_device_t device, switch_handle_t rmac_handle)
{
    switch_rmac_info_t                *rmac_info = NULL;

    if (!SWITCH_RMAC_HANDLE_VALID(rmac_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    rmac_info = switch_api_rmac_info_get_internal(rmac_handle);
    if (!rmac_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    //TODO: cleanup all the router macs
    _switch_handle_delete(switch_rmac_info_t, switch_rmac_array, rmac_handle);
    return SWITCH_STATUS_SUCCESS;
}

/*
 * @function: switch_api_router_mac_add
 * Add Router mac to rmac group
 * @param device - Device to be programmed
 * @param rmac_handle - ID of the RMAC group
 * @param mac - Router mac address to be added to the group
 * @return: Returns success if mac is added successfully
 */
switch_status_t
switch_api_router_mac_add(switch_device_t device, switch_handle_t rmac_handle, switch_mac_addr_t *mac)
{
    switch_rmac_info_t                *rmac_info = NULL;
    switch_rmac_entry_t               *rmac_entry = NULL;
    tommy_node                        *node = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    if (!SWITCH_RMAC_HANDLE_VALID(rmac_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    rmac_info = switch_api_rmac_info_get_internal(rmac_handle);
    if (!rmac_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }
    node = tommy_list_head(&(rmac_info->rmac_list));
    while (node) {
        rmac_entry = node->data;
        if (memcmp(&(rmac_entry->mac), mac, sizeof(switch_mac_addr_t)) == 0) {
            return SWITCH_STATUS_SUCCESS;
        }
        node = node->next;
    }
    rmac_entry = switch_malloc(sizeof(switch_rmac_entry_t), 1);
    if (!rmac_entry) {
        return SWITCH_STATUS_NO_MEMORY;
    }
    memcpy(&rmac_entry->mac, mac, sizeof(switch_mac_addr_t));
    tommy_list_insert_head(&(rmac_info->rmac_list), &(rmac_entry->node), rmac_entry);
    status = switch_smac_rewrite_add_entry(mac);
    if (status != SWITCH_STATUS_SUCCESS) {
        printf("MAC rewrite table add failed with error code %d\n", status);
        return status;
    }
#ifdef SWITCH_PD
    
    status = switch_pd_inner_rmac_table_add_entry(device,
                                              handle_to_id(rmac_handle), mac,
                                              &rmac_entry->inner_rmac_entry);
    if(status != SWITCH_STATUS_SUCCESS) {
        printf("Inner RMAC table add failed with error code %d\n", status);
        return status;
    }

    status = switch_pd_outer_rmac_table_add_entry(device,
                                              handle_to_id(rmac_handle), mac,
                                              &rmac_entry->outer_rmac_entry);
    if(status != SWITCH_STATUS_SUCCESS) {
        printf("Outer RMAC table add failed with error code %d\n", status);
    }
#endif
    return status; 
}
    
/*
 * @function: switch_api_router_mac_delete
 * Add Router mac to rmac group
 * @param device - Device to be programmed
 * @param rmac_handle - ID of the RMAC group
 * @param mac - Router mac address to be removed from the group
 * @return: Returns success if mac is deleted successfully
 */
switch_status_t
switch_api_router_mac_delete(switch_device_t device, switch_handle_t rmac_handle, switch_mac_addr_t *mac)
{
    switch_rmac_info_t                *rmac_info = NULL;
    switch_rmac_entry_t               *rmac_entry = NULL;
    tommy_node                        *node = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    if (!SWITCH_RMAC_HANDLE_VALID(rmac_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    rmac_info = switch_api_rmac_info_get_internal(rmac_handle);
    if (!rmac_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    node = tommy_list_head(&(rmac_info->rmac_list));
    while (node) {
        rmac_entry = node->data;
        if (memcmp(&(rmac_entry->mac), mac, sizeof(switch_mac_addr_t)) == 0) {
            break;
        }
        node = node->next;
    }
    if (!node) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    switch_smac_rewrite_delete_entry(mac);
    rmac_entry = tommy_list_remove_existing(&(rmac_info->rmac_list), node);
#ifdef SWITCH_PD
    status = switch_pd_outer_rmac_table_delete_entry(device, rmac_entry->outer_rmac_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }
    status = switch_pd_inner_rmac_table_delete_entry(device, rmac_entry->inner_rmac_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }
#endif
    free(rmac_entry);
    return status;
}

switch_status_t
switch_api_interface_router_mac_handle_set(switch_handle_t intf_handle, uint64_t value)
{

    switch_interface_info_t           *intf_info = NULL;
    switch_api_interface_info_t       *api_intf_info = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_rmac_info_t                *rmac_info = NULL;
    switch_handle_t                    rmac_handle = 0;
    switch_handle_t                    bd_handle = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    api_intf_info = &intf_info->api_intf_info;
    if (!SWITCH_INTF_IS_PORT_L3(intf_info)) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    rmac_handle = (switch_handle_t) value;
    rmac_info = switch_api_rmac_info_get_internal(rmac_handle);
    if (!rmac_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    bd_handle = intf_info->bd_handle;
    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    api_intf_info->rmac_handle = rmac_handle;
    status = switch_bd_router_mac_handle_set(bd_handle, rmac_handle);
    return status;
}

switch_status_t
switch_api_interface_router_mac_handle_get(switch_handle_t intf_handle, uint64_t *value)
{
    switch_interface_info_t           *intf_info = NULL;
    switch_api_interface_info_t       *api_intf_info = NULL;

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }
    api_intf_info = &intf_info->api_intf_info;
    *value = (uint64_t)(api_intf_info->rmac_handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_router_mac_group_print_entry(switch_handle_t rmac_handle)
{
    switch_rmac_info_t                *rmac_info = NULL;
    switch_rmac_entry_t               *rmac_entry = NULL;
    tommy_node                        *node = NULL;
    switch_mac_addr_t                 *mac = NULL;

    rmac_info = switch_api_rmac_info_get_internal(rmac_handle);
    if (!rmac_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }
    printf("\n\nrmac_handle %x", (unsigned int) rmac_handle);
    node = tommy_list_head(&(rmac_info->rmac_list));
    while (node) {
        rmac_entry = node->data;
        mac = &rmac_entry->mac;
        printf("\n\t mac %02x:%02x:%02x:%02x:%02x:%02x",
                mac->mac_addr[0], mac->mac_addr[1], mac->mac_addr[2],
                mac->mac_addr[3], mac->mac_addr[4], mac->mac_addr[5]);
        node = node->next;
    }
    printf("\n");
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_router_mac_group_print_all(void)
{
    switch_handle_t                    rmac_handle = 0;
    switch_handle_t                    next_rmac_handle = 0;

    switch_handle_get_first(switch_rmac_array, rmac_handle);
    while (rmac_handle) {
        switch_api_router_mac_group_print_entry(rmac_handle);
        switch_handle_get_next(switch_rmac_array, rmac_handle, next_rmac_handle);
        rmac_handle = next_rmac_handle;
    }
    return SWITCH_STATUS_SUCCESS;
}

// End of Router MAC API's

/*
 * Internal Router MAC API's
 * These API's will be used intenrally in SDK to manage
 * the rmac groups
 */
switch_status_t
switch_router_mac_init(switch_device_t device)
{
    p4_pd_entry_hdl_t                  smac_hdl = 0;
    switch_mac_addr_t                  temp_mac;

    unsigned char mac[ETH_LEN] = {0x00, 0x77, 0x66, 0x55, 0x44, 0x33};

    switch_rmac_array = NULL;
    //switch_pd_mac_rewrite_table_add_entry(device, smac_idx, mac);
    tommy_hashtable_init(&smac_rewrite_table, SWITCH_SMAC_REWRITE_HASH_TABLE_SIZE);
    smac_rewrite_index_allocator = switch_api_id_allocator_new(SWITCH_SMAC_REWRITE_HASH_TABLE_SIZE, TRUE);
    switch_handle_type_init(SWITCH_HANDLE_TYPE_MY_MAC, (512));
    memcpy(&temp_mac.mac_addr, &mac, ETH_LEN);
    switch_pd_tunnel_smac_rewrite_table_add_entry(0, 1, &temp_mac, &smac_hdl); 
    return SWITCH_STATUS_SUCCESS;
}
    
switch_status_t
switch_router_mac_free(switch_device_t device)
{
    tommy_hashtable_done(&smac_rewrite_table);
    switch_handle_type_free(SWITCH_HANDLE_TYPE_MY_MAC);
    return SWITCH_STATUS_SUCCESS;
}

switch_rmac_info_t *
switch_api_rmac_info_get_internal(switch_handle_t rmac_handle)
{
    switch_rmac_info_t *rmac_info = NULL;
    _switch_handle_get(switch_rmac_info_t, switch_rmac_array, rmac_handle, rmac_info);
    return rmac_info;
}

static void
switch_smac_rewrite_hash_key_init(uchar *key, switch_mac_addr_t *mac,
                                  uint32_t *len, uint32_t *hash)
{
    *len=0;
    memset(key, 0, ETH_LEN);
    memcpy(key, mac, ETH_LEN);
    *len = ETH_LEN;
    *hash = MurmurHash2(key, *len, 0x98761234);
}

static inline int
switch_smac_rewrite_hash_cmp(const void *key1, const void *key2)
{
    return memcmp(key1, key2, ETH_LEN);
}

static void
switch_smac_rewrite_hash_insert(switch_smac_entry_t *smac_entry)
{
    unsigned char                      key[ETH_LEN];
    unsigned int                       len = 0;
    uint32_t                           hash;

    switch_smac_rewrite_hash_key_init(key, &smac_entry->mac, &len, &hash);
    tommy_hashtable_insert(&smac_rewrite_table, &(smac_entry->node), smac_entry, hash);
}

static void
switch_smac_rewrite_hash_delete(switch_smac_entry_t *smac_entry)
{
    unsigned char                      key[ETH_LEN];
    uint32_t                           hash = 0;
    unsigned int                       len = 0;

    switch_smac_rewrite_hash_key_init(key, &smac_entry->mac, &len, &hash);
    tommy_hashtable_remove(&smac_rewrite_table, switch_smac_rewrite_hash_cmp, key, hash);
}


static switch_smac_entry_t *
switch_smac_rewrite_search_entry(switch_mac_addr_t *mac)
{
    switch_smac_entry_t              *smac_entry = NULL;
    unsigned char                     key[ETH_LEN];
    unsigned int                      len = 0;
    uint32_t                          hash;

    switch_smac_rewrite_hash_key_init(key, mac, &len, &hash);
    smac_entry = tommy_hashtable_search(&smac_rewrite_table, switch_smac_rewrite_hash_cmp, key, hash);
    return smac_entry;
}

uint16_t
switch_smac_rewrite_index_from_rmac(switch_handle_t rmac_handle)
{
    switch_rmac_info_t                *rmac_info = NULL;
    switch_rmac_entry_t               *rmac_entry = NULL;
    tommy_node                        *node = NULL;
    switch_mac_addr_t                 *mac = NULL;
    uint16_t                           smac_index = 0;
    switch_smac_entry_t               *smac_entry = NULL;

    rmac_info = switch_api_rmac_info_get_internal(rmac_handle);
    if (!rmac_info) {
        return smac_index;
    }

    node = tommy_list_head(&(rmac_info->rmac_list));
    while (node) {
        rmac_entry = node->data;
        mac = &rmac_entry->mac;
        smac_entry = switch_smac_rewrite_search_entry(mac);
        if (smac_entry) {
            smac_index = smac_entry->smac_index;
            break;
        }
        node = node->next;
    }
    return smac_index;
}

switch_status_t
switch_smac_rewrite_add_entry(switch_mac_addr_t *mac)
{
    switch_smac_entry_t               *smac_entry = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    uint16_t                           smac_index = 0;
    switch_device_t                    device = SWITCH_DEV_ID;

    smac_entry = switch_smac_rewrite_search_entry(mac);
    if (smac_entry) {
        smac_entry->ref_count++;
        return SWITCH_STATUS_SUCCESS;
    }
    smac_entry = switch_malloc(sizeof(switch_smac_entry_t), 1);
    if (!smac_entry) {
        return SWITCH_STATUS_NO_MEMORY;
    }
    memset(smac_entry, 0, sizeof(switch_smac_entry_t));
    smac_index = switch_api_id_allocator_allocate(smac_rewrite_index_allocator);
    memcpy(&smac_entry->mac, mac, ETH_LEN);
    smac_entry->smac_index = smac_index;
    smac_entry->ref_count = 1;
    switch_smac_rewrite_hash_insert(smac_entry);
    status = switch_pd_smac_rewrite_table_add_entry(device, smac_entry);
    return status;
}

switch_status_t
switch_smac_rewrite_delete_entry(switch_mac_addr_t *mac)
{
    switch_smac_entry_t               *smac_entry = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;

    smac_entry = switch_smac_rewrite_search_entry(mac);
    if (!smac_entry) {
        SWITCH_API_ERROR("%s:%d: unable to find mac!", __FUNCTION__, __LINE__);
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    smac_entry->ref_count--;
    if (smac_entry->ref_count == 0) {
        switch_pd_smac_rewrite_table_delete_entry(device, smac_entry);
        switch_smac_rewrite_hash_delete(smac_entry);
        switch_api_id_allocator_release(smac_rewrite_index_allocator, smac_entry->smac_index);
        free(smac_entry);
    }
    return status;
}

#ifdef __cplusplus
}
#endif
