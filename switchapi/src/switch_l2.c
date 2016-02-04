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

#include <assert.h>
#include "switchapi/switch_vlan.h"
#include "switchapi/switch_l2.h"
#include "switchapi/switch_l3.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_utils.h"
#include "switch_nhop_int.h"
#include "switch_neighbor_int.h"
#include "switch_pd.h"
#include "switch_log.h"

#include <string.h>

#define SWITCH_L2_HASH_TABLE_SIZE (128 * 1024)

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static tommy_hashtable switch_mac_hash_table;
static void *dmac_entry_hdl_array = NULL;
static void *vlan_mac_hdl_array = NULL;
static void *intf_mac_hdl_array = NULL;
static switch_mac_cb_fn_t switch_mac_cb_fn;
static switch_mac_global_params_t mac_params;

static inline
void switch_mac_table_entry_key_init(uchar *key, switch_handle_t vlan,
                                switch_mac_addr_t *mac, uint32_t *len,
                                uint32_t *hash)
{
    *len=0;
    memset(key, 0, 10);
    *(unsigned int *)(&key[0]) = (unsigned int)handle_to_id(vlan);
    *len += sizeof(unsigned int);
    memcpy(&key[4], mac->mac_addr, ETH_LEN);
    *len += ETH_LEN;
    *hash = MurmurHash2(key, *len, 0x98761234);
}

static inline
int switch_mac_entry_hash_cmp(const void *key1,
                         const void *key2)
{
    return memcmp(key1, key2, 10);
}

static inline void switch_print_mac_table_entry(switch_api_mac_entry_t *mac_entry,
                                                char *buffer, int buffer_size)
{
    switch_mac_addr_t                 *mac = NULL;

    mac = &mac_entry->mac;
    snprintf(buffer, buffer_size,
             "type: %s vlan handle: %lx mac: %02x:%02x:%02x:%02x:%02x:%02x -> handle: %lx",
             mac_entry->entry_type == SWITCH_MAC_ENTRY_STATIC ? "static" : "dynamic",
             mac_entry->vlan_handle,
             mac->mac_addr[0], mac->mac_addr[1], mac->mac_addr[2],
             mac->mac_addr[3], mac->mac_addr[4], mac->mac_addr[5],
             mac_entry->handle);
}

static switch_status_t
switch_mac_insert_into_vlan_list(switch_mac_info_t *mac_info)
{
    switch_mac_vlan_list_t            *mac_vlan_list = NULL;
    switch_api_mac_entry_t            *mac_entry = NULL;
    void                              *temp = NULL;

    mac_entry = &mac_info->mac_entry;
    JLG(temp, vlan_mac_hdl_array, mac_entry->vlan_handle);
    if (!temp) {
        mac_vlan_list = switch_malloc(sizeof(switch_mac_vlan_list_t), 1);
        if (!mac_vlan_list) {
            SWITCH_API_ERROR("%s:%d: No memory!", __FUNCTION__, __LINE__);
            return SWITCH_STATUS_NO_MEMORY;
        }
        tommy_list_init(&(mac_vlan_list->mac_entries));
        mac_vlan_list->num_entries = 0;
        JLI(temp, vlan_mac_hdl_array, mac_entry->vlan_handle);
        *(unsigned long *)temp = (unsigned long) (mac_vlan_list);
    }
    mac_vlan_list = (switch_mac_vlan_list_t *) (*(unsigned long *)temp);
    tommy_list_insert_tail(&(mac_vlan_list->mac_entries), &(mac_info->vlan_node), mac_info);
    mac_vlan_list->num_entries++;
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
switch_mac_insert_into_interface_list(switch_mac_info_t *mac_info)
{
    switch_mac_intf_list_t            *mac_intf_list = NULL;
    switch_api_mac_entry_t            *mac_entry = NULL;
    void                              *temp = NULL;

    mac_entry = &mac_info->mac_entry;
    JLG(temp, intf_mac_hdl_array, mac_entry->handle);
    if (!temp) {
        mac_intf_list = switch_malloc(sizeof(switch_mac_intf_list_t), 1);
        if (!mac_intf_list) {
            SWITCH_API_ERROR("%s:%d: No memory!", __FUNCTION__, __LINE__);
            return SWITCH_STATUS_NO_MEMORY;
        }
        tommy_list_init(&(mac_intf_list->mac_entries));
        mac_intf_list->num_entries = 0;
        JLI(temp, intf_mac_hdl_array, mac_entry->handle);
        *(unsigned long *)temp = (unsigned long) mac_intf_list;
    }
    mac_intf_list = (switch_mac_intf_list_t *) (*(unsigned long *)temp);
    tommy_list_insert_tail(&(mac_intf_list->mac_entries), &(mac_info->interface_node), mac_info);
    mac_intf_list->num_entries++;
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
switch_mac_remove_from_vlan_list(switch_mac_info_t *mac_info)
{
    switch_mac_vlan_list_t            *mac_vlan_list = NULL;
    switch_api_mac_entry_t            *mac_entry = NULL;
    void                              *temp = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    mac_entry = &mac_info->mac_entry;
    JLG(temp, vlan_mac_hdl_array, mac_entry->vlan_handle);
    if (!temp) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    mac_vlan_list = (switch_mac_vlan_list_t *) (*(unsigned long *)temp);
    tommy_list_remove_existing(&(mac_vlan_list->mac_entries), &(mac_info->vlan_node));
    mac_vlan_list->num_entries--;
    if (mac_vlan_list->num_entries == 0) {
        JLD(status, vlan_mac_hdl_array, mac_entry->vlan_handle);
    }
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
switch_mac_remove_from_interface_list(switch_mac_info_t *mac_info)
{
    switch_mac_intf_list_t            *mac_intf_list = NULL;
    switch_api_mac_entry_t            *mac_entry = NULL;
    void                              *temp = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    mac_entry = &mac_info->mac_entry;
    JLG(temp, intf_mac_hdl_array, mac_entry->handle);
    if (!temp) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    mac_intf_list = (switch_mac_intf_list_t *) (*(unsigned long *)temp);
    tommy_list_remove_existing(&(mac_intf_list->mac_entries), &(mac_info->interface_node));
    mac_intf_list->num_entries--;
    if (mac_intf_list->num_entries == 0) {
        JLD(status, intf_mac_hdl_array, mac_entry->handle);
    }
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
switch_mac_table_entry_insert(switch_api_mac_entry_t *mac_entry, switch_mac_info_t **mac_info)
{
    switch_api_mac_entry_t            *tmp_mac_entry = NULL;
    unsigned char                      key[10];
    unsigned int                       len = 0;
    uint32_t                           hash = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    switch_mac_table_entry_key_init(key,
                                mac_entry->vlan_handle,
                                &(mac_entry->mac),
                                &len, &hash);
    *mac_info = switch_malloc(sizeof(switch_mac_info_t), 1);
    if (!(*mac_info)) {
        status = SWITCH_STATUS_NO_MEMORY;
        goto cleanup;
    }

    memset(*mac_info, 0, sizeof(switch_mac_info_t));
    tmp_mac_entry = &(*mac_info)->mac_entry;
    tmp_mac_entry->vlan_handle = mac_entry->vlan_handle;
    tmp_mac_entry->handle = mac_entry->handle;
    tmp_mac_entry->entry_type = mac_entry->entry_type;
    memcpy(&(tmp_mac_entry->mac), &(mac_entry->mac), ETH_LEN);
#ifdef SWITCH_PD
    (*mac_info)->smac_entry = 0;
    (*mac_info)->dmac_entry = 0;
#endif
    memcpy((*mac_info)->key, key, 10);
    tommy_hashtable_insert(&switch_mac_hash_table, &((*mac_info)->node), *mac_info, hash);
    status = switch_mac_insert_into_vlan_list(*mac_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        goto cleanup;
    }
    status = switch_mac_insert_into_interface_list(*mac_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        goto cleanup;
    }
    return status;
cleanup:
    SWITCH_API_ERROR("%s:%d: unable to insert mac hash\n",
                     __FUNCTION__, __LINE__);
    return status;
}

static switch_status_t
switch_mac_table_entry_delete(switch_api_mac_entry_t *mac_entry)
{
    switch_mac_info_t                 *mac_info = NULL;
    unsigned char                      key[10];
    unsigned int                       len = 0;
    uint32_t                           hash = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    switch_mac_table_entry_key_init(key,
                                mac_entry->vlan_handle,
                                &(mac_entry->mac),
                                &len, &hash);
    mac_info = tommy_hashtable_remove(&switch_mac_hash_table,
                                   switch_mac_entry_hash_cmp,
                                   key, hash);
    status = switch_mac_remove_from_vlan_list(mac_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        goto cleanup;
    }
    status = switch_mac_remove_from_interface_list(mac_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        goto cleanup;
    }
    switch_free(mac_info);
    return status;
cleanup:
    SWITCH_API_ERROR("%s:%d: failed to delete mac hash\n",
                     __FUNCTION__, __LINE__);
    return status;
}

switch_mac_info_t *
switch_mac_table_entry_find(switch_api_mac_entry_t *mac_entry)
{
    switch_mac_info_t                 *mac_info = NULL;
    unsigned char                      key[10];
    unsigned int                       len = 0;
    uint32_t                           hash = 0;

    switch_mac_table_entry_key_init(key,
                                mac_entry->vlan_handle,
                                &(mac_entry->mac),
                                &len, &hash);
    mac_info = tommy_hashtable_search(&switch_mac_hash_table,
                                       switch_mac_entry_hash_cmp,
                                       key, hash);
    return mac_info;
}

#ifndef P4_L2_DISABLE
p4_pd_status_t
switch_mac_learn_notify_cb(p4_pd_sess_hdl_t sess_hdl,
                           p4_pd_dc_mac_learn_digest_digest_msg_t *msg,
                           void *client_data)
{
    p4_pd_dc_mac_learn_digest_digest_entry_t    *learn_entry = NULL;
    switch_mac_info_t                           *mac_info = NULL;
    switch_bd_info_t                            *bd_info = NULL;
    switch_interface_info_t                     *intf_info = NULL;
    switch_api_mac_entry_t                       mac_entry;
    switch_status_t                              status = SWITCH_STATUS_SUCCESS;
    switch_device_t                              device = SWITCH_DEV_ID;
    switch_handle_t                              intf_handle = 0;
    int                                          index = 0;

    SWITCH_API_TRACE("%s:%d: Received %d learn notifications!",
                 __FUNCTION__, __LINE__, msg->num_entries);

    for (index = 0; index < msg->num_entries; index++) {
        learn_entry = &(msg->entries[index]);
        SWITCH_API_TRACE("%s:%d:MAC learn BD: 0x%d, MAC: 0x%02x:%02x:%02x:%02x:%02x:%02x => If: %d\n",
                     __FUNCTION__, __LINE__,
                     learn_entry->ingress_metadata_bd,
                     learn_entry->l2_metadata_lkp_mac_sa[0],
                     learn_entry->l2_metadata_lkp_mac_sa[1],
                     learn_entry->l2_metadata_lkp_mac_sa[2],
                     learn_entry->l2_metadata_lkp_mac_sa[3],
                     learn_entry->l2_metadata_lkp_mac_sa[4],
                     learn_entry->l2_metadata_lkp_mac_sa[5],
                     learn_entry->ingress_metadata_ifindex);
        memset(&mac_entry, 0, sizeof(switch_api_mac_entry_t));
        mac_entry.vlan_handle = id_to_handle(SWITCH_HANDLE_TYPE_BD, learn_entry->ingress_metadata_bd);
        bd_info = switch_bd_get(mac_entry.vlan_handle);
        if (!bd_info) {
            SWITCH_API_TRACE("%s:%d: Ignoring the mac. vlan not found!", __FUNCTION__, __LINE__);
            continue;
        }

        if (!SWITCH_LN_LEARN_ENABLED(bd_info)) {
            SWITCH_API_TRACE("%s:%d: Ignoring the mac. learning disabled on vlan!", __FUNCTION__, __LINE__);
            continue;
        }

        intf_handle = switch_api_interface_get_from_ifindex(learn_entry->ingress_metadata_ifindex);
        if (!intf_handle) {
            SWITCH_API_TRACE("%s:%d: Ignoring the mac. invalid ifindex!", __FUNCTION__, __LINE__);
            continue;
        }

        intf_info = switch_api_interface_get(intf_handle);
        if (!intf_info) {
            SWITCH_API_TRACE("%s:%d: Ignoring the mac. invalid interface!", __FUNCTION__, __LINE__);
            continue;
        }

        memcpy(&mac_entry.mac, learn_entry->l2_metadata_lkp_mac_sa, ETH_LEN);
        mac_entry.handle = intf_handle;
        mac_entry.entry_type = SWITCH_MAC_ENTRY_DYNAMIC;
        mac_info = switch_mac_table_entry_find(&mac_entry);
        if (!mac_info) {
            status = switch_api_mac_table_entry_add(device, &mac_entry);
        } else {
            status = switch_api_mac_table_entry_update(device, &mac_entry);
        }
        if (switch_mac_cb_fn.mac_learn_notify_cb) {
            switch_mac_cb_fn.mac_learn_notify_cb(&mac_entry);
        }
    }

    // ack the entries
    p4_pd_dc_mac_learn_digest_notify_ack(sess_hdl, msg);
    return status;
}
#endif

void
switch_mac_aging_notify_cb(p4_pd_entry_hdl_t entry_hdl, void *client_data)
{
    switch_mac_info_t                 *mac_info = NULL;
    void                              *temp = NULL;
    switch_api_mac_entry_t            *mac_entry = NULL;
    switch_device_t                    device = SWITCH_DEV_ID;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    JLG(temp, dmac_entry_hdl_array, entry_hdl);
    if (!temp) {
        SWITCH_API_ERROR("%s%d: Invalid dmac entry handle", __FUNCTION__, __LINE__);
        return;
    }

    mac_info = (switch_mac_info_t *) (*(unsigned long *)temp);
    mac_entry = &(mac_info->mac_entry);
    SWITCH_API_TRACE("%s:%d: Received aging notification %x - (%lx, 0x%02x:%02x:%02x:%02x:%02x:%02x) -> %lx)",
                 __FUNCTION__, __LINE__, entry_hdl,
                 mac_entry->vlan_handle,
                 mac_entry->mac.mac_addr[0],
                 mac_entry->mac.mac_addr[1],
                 mac_entry->mac.mac_addr[2],
                 mac_entry->mac.mac_addr[3],
                 mac_entry->mac.mac_addr[4],
                 mac_entry->mac.mac_addr[5],
                 mac_entry->handle);

    if (switch_mac_cb_fn.mac_aging_notify_cb) {
        switch_mac_cb_fn.mac_aging_notify_cb(mac_entry);
    }
    status = switch_api_mac_table_entry_delete(device, &(mac_info->mac_entry));
    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d: failed to delete mac!", __FUNCTION__, __LINE__);
    }
    return;
}

switch_api_mac_entry_t *
switch_mac_aging_poll_entries(switch_device_t device)
{
    switch_mac_info_t                 *mac_info = NULL;
    void                              *temp = NULL;
    p4_pd_entry_hdl_t                  entry_hdl = 0;
#ifndef P4_L2_DISABLE
    p4_pd_sess_hdl_t                   sess_hdl = 0;
    p4_pd_hit_state_t                  hit_state = ENTRY_IDLE;
#endif
    p4_pd_status_t                     status = 0;

    JLF(temp, dmac_entry_hdl_array, *((Word_t *)&entry_hdl));
    while (temp) {
#ifndef P4_L2_DISABLE
        status = p4_pd_dc_dmac_get_hit_state(sess_hdl, entry_hdl, &hit_state);
#endif /* P4_L2_DISABLE */
        if (!status) {
            SWITCH_API_ERROR("%s:%d: failed to get hit state for entry %x",
                         __FUNCTION__, __LINE__, entry_hdl);
        }
        JLN(temp, dmac_entry_hdl_array, *((Word_t *)&entry_hdl));
        mac_info = (switch_mac_info_t *) (*(unsigned long *) temp);
    }
    return &(mac_info->mac_entry);
}

uint32_t
switch_api_mac_get_default_aging_time_internal()
{
    return mac_params.aging_time;
}

switch_status_t
switch_mac_table_init(switch_device_t device)
{
#ifndef P4_L2_DISABLE
    p4_pd_sess_hdl_t sess_hdl = 0;
#endif

    switch_mac_cb_fn.mac_learn_notify_cb = NULL;
    switch_mac_cb_fn.mac_aging_notify_cb = NULL;
    switch_api_mac_table_aging_time_set(SWITCH_MAC_TABLE_DEFAULT_AGING_TIME);
    tommy_hashtable_init(&switch_mac_hash_table, SWITCH_L2_HASH_TABLE_SIZE);
#ifdef SWITCH_PD 
#ifndef P4_L2_DISABLE
    p4_pd_dc_mac_learn_digest_register(sess_hdl, (uint8_t)device, switch_mac_learn_notify_cb, NULL); 
    p4_pd_dc_dmac_enable_entry_timeout(sess_hdl, switch_mac_aging_notify_cb, mac_params.aging_time, NULL);
#endif /* P4_L2_DISABLE */
#endif 
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_mac_table_free(void)
{
    tommy_hashtable_done(&switch_mac_hash_table);
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
switch_mac_update_nhop(switch_device_t device,
                       switch_handle_t intf_handle,
                       switch_api_mac_entry_t *mac_entry)
{
    switch_interface_info_t           *intf_info = NULL;
    switch_neighbor_dmac_t            *neighbor_dmac = NULL;
    switch_neighbor_info_t            *neighbor_info = NULL;
    switch_handle_t                    nhop_handle = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    if (!SWITCH_INTERFACE_HANDLE_VALID(intf_handle)) {
        return SWITCH_STATUS_SUCCESS;
    }

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_SUCCESS;
    }

    neighbor_dmac = switch_neighbor_dmac_search_hash(mac_entry->vlan_handle, &mac_entry->mac);
    if (!neighbor_dmac) {
        return SWITCH_STATUS_SUCCESS;
    }

    neighbor_info = switch_neighbor_info_get(neighbor_dmac->neighbor_handle);
    if (!neighbor_info) {
        return SWITCH_STATUS_FAILURE;
    }

    nhop_handle = neighbor_info->neighbor.nhop_handle;
    if (SWITCH_NHOP_HANDLE_VALID(nhop_handle)) {
        status = switch_api_nhop_update(device, nhop_handle);
    }
    return status;
}

/*
 * Routine Description:
 * Add an entry to Dmac table and smac table
 * For access ports and lag, ifindex is used.
 * For tunnel ports, nhop is used.
 *
 @param device - device id
 @param mac_entry - Mac Entry
 */
switch_status_t
switch_api_mac_table_entry_add(switch_device_t device,
                               switch_api_mac_entry_t *mac_entry)
{
    switch_interface_info_t           *intf_info = NULL;
    switch_mac_info_t                 *mac_info = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_logical_network_t          *ln_info = NULL;
    switch_nhop_info_t                *nhop_info = NULL;
    switch_spath_info_t               *spath_info = NULL;
    void                              *temp = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_handle_type_t               handle_type = 0;
    uint16_t                           nhop_index = 0;
    uint16_t                           mgid_index = 0;
    uint32_t                           aging_time = 0;
    switch_handle_t                    intf_handle = 0;
    char                               buffer[200];

    if ((!SWITCH_PORT_HANDLE_VALID(mac_entry->handle)) &&
        (!SWITCH_LAG_HANDLE_VALID(mac_entry->handle)) &&
        (!SWITCH_INTERFACE_HANDLE_VALID(mac_entry->handle)) &&
        (!SWITCH_MGID_HANDLE_VALID(mac_entry->handle)) &&
        (!SWITCH_NHOP_HANDLE_VALID(mac_entry->handle))) {
        status = SWITCH_STATUS_INVALID_HANDLE;
        goto cleanup;
    }

    mac_info = switch_mac_table_entry_find(mac_entry);
    if (mac_info) {
        status = SWITCH_STATUS_ITEM_ALREADY_EXISTS;
        goto cleanup;
    }

    handle_type = switch_handle_get_type(mac_entry->handle);
    switch(handle_type) {
        case SWITCH_HANDLE_TYPE_PORT:
        case SWITCH_HANDLE_TYPE_LAG:
            status = switch_intf_handle_get(mac_entry->vlan_handle, mac_entry->handle, &intf_handle);
            if (status != SWITCH_STATUS_SUCCESS) {
                goto cleanup;
            }
            intf_info = switch_api_interface_get(intf_handle);
            if (!intf_info) {
                status = SWITCH_STATUS_INVALID_INTERFACE;
                goto cleanup;
            }
            break;
        case SWITCH_HANDLE_TYPE_INTERFACE:
            mac_entry->mac_action = TRUE;
            intf_handle = mac_entry->handle;
            intf_info = switch_api_interface_get(intf_handle);
            if (!intf_info) {
                status = SWITCH_STATUS_INVALID_INTERFACE;
                goto cleanup;
            }
            if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_TUNNEL) {
                nhop_info = switch_nhop_get(intf_info->nhop_handle);
                if (!nhop_info) {
                    return SWITCH_STATUS_INVALID_NHOP;
                }
                nhop_index = handle_to_id(intf_info->nhop_handle);
            }
        break;

        case SWITCH_HANDLE_TYPE_NHOP:
            mac_entry->mac_action = TRUE;
            nhop_info = switch_nhop_get(mac_entry->handle);
            if (!nhop_info) {
                status = SWITCH_STATUS_INVALID_NHOP;
                goto cleanup;
            }
            spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));
            intf_info = switch_api_interface_get(spath_info->nhop_key.intf_handle);
            if (!intf_info) {
                status = SWITCH_STATUS_INVALID_INTERFACE;
                goto cleanup;
            }
            nhop_index = handle_to_id(mac_entry->handle);
        break;

        case SWITCH_HANDLE_TYPE_MGID:
            mac_entry->mac_action = TRUE;
            mgid_index = handle_to_id(mac_entry->handle);
        break;
        default:
            status = SWITCH_STATUS_INVALID_HANDLE;
            goto cleanup;
    }

    bd_info = switch_bd_get(mac_entry->vlan_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    ln_info = &bd_info->ln_info;

    status = switch_mac_table_entry_insert(mac_entry, &mac_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        goto cleanup;
    }

    switch_mac_update_nhop(device, intf_handle, mac_entry);

    if (mac_entry->entry_type == SWITCH_MAC_ENTRY_DYNAMIC) {
        aging_time = switch_api_mac_get_default_aging_time_internal();
        if (ln_info->age_interval) {
            aging_time = ln_info->age_interval;
        }
    }

#ifdef SWITCH_PD
    mac_info->smac_entry = SWITCH_HW_INVALID_HANDLE;
    mac_info->dmac_entry = SWITCH_HW_INVALID_HANDLE;
    status = switch_pd_dmac_table_add_entry(device, mac_entry,
                                        nhop_index, mgid_index,
                                        aging_time, intf_info,
                                        &mac_info->dmac_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        goto cleanup;
    }

    // Do not learn multicast macs on smac table
    if (!mgid_index && SWITCH_LN_LEARN_ENABLED(bd_info)) {
        status = switch_pd_smac_table_add_entry(device, mac_entry,
                                           intf_info,
                                           &mac_info->smac_entry);
    }
    if (status != SWITCH_STATUS_SUCCESS) {
        goto cleanup;
    }
#endif

    switch_print_mac_table_entry(mac_entry, buffer, 200);
    SWITCH_API_TRACE("%s:%d Adding entry %s\n",
                     __FUNCTION__, __LINE__,
                     buffer);

    JLI(temp, dmac_entry_hdl_array, mac_info->dmac_entry);
    *(unsigned long *)temp = (unsigned long) mac_info;
    return status;

cleanup:
    switch_print_mac_table_entry(mac_entry, buffer, 200);
    SWITCH_API_ERROR("%s:%d: unable to add mac entry %s. %s\n",
                     __FUNCTION__, __LINE__,
                     buffer,
                     switch_print_error(status));
    return status;

}

switch_status_t
switch_api_mac_table_entries_add(switch_device_t device,
                                 uint16_t mac_entry_count,
                                 switch_api_mac_entry_t *mac_entries)
{
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    int                                count = 0;

    SWITCH_API_TRACE("%s:%d: Adding %d mac table entries\n",
                     __FUNCTION__, __LINE__, mac_entry_count);

    for (count = 0; count < mac_entry_count; count++) {
        status = switch_api_mac_table_entry_add(device, &mac_entries[count]);
        if (status != SWITCH_STATUS_SUCCESS) {
            return status;
        }
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_mac_table_entry_update(switch_device_t device,
                                  switch_api_mac_entry_t *mac_entry)
{
    switch_interface_info_t           *intf_info = NULL;
    switch_mac_info_t                 *mac_info = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_nhop_info_t                *nhop_info = NULL;
    switch_spath_info_t               *spath_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_handle_type_t               handle_type = 0;
    uint16_t                           nhop_index = 0;
    uint16_t                           mgid_index = 0;
    switch_handle_t                    intf_handle = 0;
    char                               buffer[200];
    switch_handle_t                    mac_entry_handle;

    mac_entry_handle = mac_entry->handle;
    mac_info = switch_mac_table_entry_find(mac_entry);
    if (!mac_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    if (!SWITCH_PORT_HANDLE_VALID(mac_entry->handle) &&
        !SWITCH_LAG_HANDLE_VALID(mac_entry->handle) &&
        !SWITCH_INTERFACE_HANDLE_VALID(mac_entry->handle) &&
        !SWITCH_MGID_HANDLE_VALID(mac_entry->handle) &&
        !SWITCH_NHOP_HANDLE_VALID(mac_entry->handle)) {
        status = SWITCH_STATUS_INVALID_HANDLE;
        goto cleanup;
    }

    handle_type = switch_handle_get_type(mac_entry->handle);
    switch(handle_type) {
        case SWITCH_HANDLE_TYPE_PORT:
        case SWITCH_HANDLE_TYPE_LAG:
            status = switch_intf_handle_get(mac_entry->vlan_handle, mac_entry->handle, &intf_handle);
            if (status != SWITCH_STATUS_SUCCESS) {
                goto cleanup;
            }
            intf_info = switch_api_interface_get(intf_handle);
            if (!intf_info) {
                status = SWITCH_STATUS_INVALID_INTERFACE;
                goto cleanup;
            }
            mac_entry_handle = intf_handle;
            break;

        case SWITCH_HANDLE_TYPE_INTERFACE:
            intf_handle = mac_entry->handle;
            intf_info = switch_api_interface_get(intf_handle);
            if (!intf_info) {
                status = SWITCH_STATUS_INVALID_INTERFACE;
                goto cleanup;
            }
            if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_TUNNEL) {
                nhop_info = switch_nhop_get(intf_info->nhop_handle);
                if (!nhop_info) {
                    return SWITCH_STATUS_INVALID_NHOP;
                }
                nhop_index = handle_to_id(intf_info->nhop_handle);
            }
            break;

        case SWITCH_HANDLE_TYPE_NHOP:
            nhop_info = switch_nhop_get(mac_entry->handle);
            if (!nhop_info) {
                status = SWITCH_STATUS_INVALID_NHOP;
                goto cleanup;
            }
            spath_info = &(SWITCH_NHOP_SPATH_INFO(nhop_info));
            intf_info = switch_api_interface_get(spath_info->nhop_key.intf_handle);
            if (!intf_info) {
                status = SWITCH_STATUS_INVALID_INTERFACE;
                goto cleanup;
            }
            nhop_index = handle_to_id(mac_entry->handle);
            break;

        case SWITCH_HANDLE_TYPE_MGID:
            mgid_index = handle_to_id(mac_entry->handle);
            break;

        default:
            return SWITCH_STATUS_INVALID_HANDLE;
    }

    bd_info = switch_bd_get(mac_entry->vlan_handle);
    if (!bd_info) {
        status = SWITCH_STATUS_INVALID_VLAN_ID;
        goto cleanup;
    }

    status = switch_mac_remove_from_interface_list(mac_info);
    assert(status == SWITCH_STATUS_SUCCESS);
    mac_info->mac_entry.handle = mac_entry_handle;
    status = switch_mac_insert_into_interface_list(mac_info);
    assert(status == SWITCH_STATUS_SUCCESS);
    switch_mac_update_nhop(device, intf_handle, &(mac_info->mac_entry));

#ifdef SWITCH_PD
    status = switch_pd_dmac_table_update_entry(device, &(mac_info->mac_entry),
                                        nhop_index, mgid_index,
                                        intf_info,
                                        mac_info->dmac_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        goto cleanup;
    }
    // Do not learn multicast macs on smac table
    if (!mgid_index && SWITCH_LN_LEARN_ENABLED(bd_info)) {
        status = switch_pd_smac_table_update_entry(device,
                                        &(mac_info->mac_entry), intf_info,
                                        mac_info->smac_entry);
    }
    if (status != SWITCH_STATUS_SUCCESS) {
        goto cleanup;
    }
#endif
    switch_print_mac_table_entry(&(mac_info->mac_entry), buffer, 200);
    SWITCH_API_TRACE("%s:%d Updating entry %s\n",
                     __FUNCTION__, __LINE__,
                     buffer);
    return status;

cleanup:
    switch_print_mac_table_entry(&(mac_info->mac_entry), buffer, 200);
    SWITCH_API_ERROR("%s:%d: unable to update mac entry %s. %s\n",
                     __FUNCTION__, __LINE__,
                     buffer,
                     switch_print_error(status));
    return status;
}

switch_status_t
switch_api_mac_table_entries_update(switch_device_t device,
                                    uint16_t mac_entry_count,
                                    switch_api_mac_entry_t *mac_entries)
{
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    int                                count = 0;

    SWITCH_API_TRACE("%s:%d: Updating %d mac table entries\n",
                     __FUNCTION__, __LINE__, mac_entry_count);

    for (count = 0; count < mac_entry_count; count++) {
        status = switch_api_mac_table_entry_update(device, &mac_entries[count]);
        if (status != SWITCH_STATUS_SUCCESS) {
            return status;
        }
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_mac_table_entry_delete(switch_device_t device,
                                  switch_api_mac_entry_t *mac_entry)
{
    switch_mac_info_t                 *mac_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_interface_info_t           *intf_info = NULL;
    switch_handle_t                    intf_handle = 0;
    switch_handle_t                    handle = 0;
    switch_handle_type_t               handle_type = 0;
    char                               buffer[200];

    mac_info = switch_mac_table_entry_find(mac_entry);
    if (!mac_info) {
        status = SWITCH_STATUS_ITEM_NOT_FOUND;
        goto cleanup;
    }

    handle = mac_info->mac_entry.handle;
    handle_type = switch_handle_get_type(handle);
    switch(handle_type) {
        case SWITCH_HANDLE_TYPE_PORT:
        case SWITCH_HANDLE_TYPE_LAG:
            status = switch_intf_handle_get(mac_entry->vlan_handle, handle,
                                            &intf_handle);
            if (status != SWITCH_STATUS_SUCCESS) {
                goto cleanup;
            }
            intf_info = switch_api_interface_get(intf_handle);
            if (!intf_info) {
                status = SWITCH_STATUS_INVALID_INTERFACE;
                goto cleanup;
            }
            break;
        case SWITCH_HANDLE_TYPE_INTERFACE:
            intf_handle = handle;
            intf_info = switch_api_interface_get(intf_handle);
            if (!intf_info) {
                status = SWITCH_STATUS_INVALID_INTERFACE;
                goto cleanup;
            }
        break;
        default:
            intf_handle = 0;
    }

#ifdef SWITCH_PD
    if (mac_info->smac_entry != SWITCH_HW_INVALID_HANDLE) {
        status = switch_pd_smac_table_delete_entry(device, mac_info->smac_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            status = SWITCH_STATUS_FAILURE;
            goto cleanup;
        }
    }
    if (mac_info->dmac_entry != SWITCH_HW_INVALID_HANDLE) {
        status = switch_pd_dmac_table_delete_entry(device, mac_info->dmac_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            status = SWITCH_STATUS_FAILURE;
            goto cleanup;
        }
    }
#endif

    JLD(status, dmac_entry_hdl_array, mac_info->dmac_entry);
    switch_print_mac_table_entry(&mac_info->mac_entry, buffer, 200);
    SWITCH_API_TRACE("%s:%d Deleting entry %s\n",
                     __FUNCTION__, __LINE__,
                     buffer);
    status = switch_mac_table_entry_delete(&mac_info->mac_entry);
    switch_mac_update_nhop(device, intf_handle, mac_entry);
    return status;

cleanup:
    switch_print_mac_table_entry(mac_entry, buffer, 200);
    SWITCH_API_ERROR("%s:%d: unable to delete mac entry for handle %s. %s\n",
                     __FUNCTION__, __LINE__,
                     buffer,
                     switch_print_error(status));
    return status;
}

switch_status_t
switch_api_multicast_l2mac_add(switch_device_t device,
                               switch_api_mac_entry_t *mac_entry)
{
    return switch_api_mac_table_entry_add(device, mac_entry);
}

switch_status_t
switch_api_multicast_l2mac_delete(switch_device_t device,
                                  switch_api_mac_entry_t *mac_entry)
{
    return switch_api_mac_table_entry_delete(device, mac_entry);
}

switch_status_t
switch_api_mac_entries_delete(switch_device_t device,
                              uint16_t mac_entry_count,
                              switch_api_mac_entry_t *mac_entries)
{
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    int                                count = 0;

    SWITCH_API_TRACE("%s:%d: Deleting %d mac table entries\n",
                     __FUNCTION__, __LINE__, mac_entry_count);

    for (count = 0; count < mac_entry_count; count++) {
        status = switch_api_mac_table_entry_delete(device, &mac_entries[count]);
        if (status != SWITCH_STATUS_SUCCESS) {
            return status;
        }
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_mac_table_entries_delete_all(switch_device_t device)
{
    switch_status_t                   status = SWITCH_STATUS_SUCCESS;
    switch_handle_t                   vlan_handle = 0;
    void                             *temp = NULL;

    SWITCH_API_TRACE("%s:%d: Deleting all mac table entries\n",
                     __FUNCTION__, __LINE__);

    JLF(temp, vlan_mac_hdl_array, vlan_handle);
    while (temp) {
        status = switch_api_mac_table_entries_delete_by_vlan(device,
                                                             vlan_handle);
        JLN(temp, vlan_mac_hdl_array, vlan_handle);
    }
    return status;
}

switch_status_t
switch_api_mac_table_entries_delete_by_vlan(switch_device_t device,
                                            switch_handle_t vlan_handle)
{
    switch_mac_vlan_list_t            *mac_vlan_list = NULL;
    switch_mac_info_t                 *mac_info = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    tommy_node                        *node = NULL;
    void                              *temp = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    if (!SWITCH_BD_HANDLE_VALID(vlan_handle)) {
        status = SWITCH_STATUS_INVALID_HANDLE;
        goto cleanup;
    }

    bd_info = switch_bd_get(vlan_handle);
    if (!bd_info) {
        status = SWITCH_STATUS_INVALID_HANDLE;
        goto cleanup;
    }

    SWITCH_API_TRACE("%s:%d: Deleting mac table entries by vlan %lx",
                     __FUNCTION__, __LINE__, vlan_handle);

    JLG(temp, vlan_mac_hdl_array, vlan_handle);
    if (!temp) {
        SWITCH_API_TRACE("%s:%d: No macs to delete!", __FUNCTION__, __LINE__);
        return SWITCH_STATUS_SUCCESS;
    }

    mac_vlan_list = (switch_mac_vlan_list_t *) (*(unsigned long *)temp);
    node = tommy_list_head(&(mac_vlan_list->mac_entries));
    while (node) {
        mac_info = node->data;
        node = node->next;
        status = switch_api_mac_table_entry_delete(device, &mac_info->mac_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            goto cleanup;
        }
    }
    return status;
cleanup:
    SWITCH_API_ERROR("%s:%d: unable to delete macs for vlan %lx. %s",
                     __FUNCTION__, __LINE__,
                     vlan_handle,
                     switch_print_error(status));
    return status;
}

switch_status_t
switch_api_mac_table_entries_delete_by_interface(switch_device_t device,
                                                 switch_handle_t handle)
{
    switch_mac_intf_list_t            *mac_intf_list = NULL;
    switch_mac_info_t                 *mac_info = NULL;
    tommy_node                        *node = NULL;
    void                              *temp = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_handle_t                    intf_handle = 0;
    switch_port_info_t                *port_info = NULL;
    switch_lag_info_t                 *lag_info = NULL;
    switch_handle_type_t               handle_type = 0;

    if (!SWITCH_PORT_HANDLE_VALID(handle) && 
        !SWITCH_LAG_HANDLE_VALID(handle) &&
        !SWITCH_INTERFACE_HANDLE_VALID(handle)) {
        status = SWITCH_STATUS_INVALID_HANDLE;
        goto cleanup;
    }

    handle_type = switch_handle_get_type(handle);
    intf_handle = handle;
    if (handle_type == SWITCH_HANDLE_TYPE_PORT) {
       port_info = switch_api_port_get_internal((switch_port_t)handle); 
       if (!port_info) {
           status = SWITCH_STATUS_INVALID_PORT_NUMBER;
           goto cleanup;
       }
       intf_handle = port_info->intf_handle;
    }
    if (handle_type == SWITCH_HANDLE_TYPE_LAG) {
        lag_info = switch_api_lag_get_internal(handle);
        if (!lag_info) {
            status = SWITCH_STATUS_INVALID_HANDLE;
            goto cleanup;
        }
        intf_handle = lag_info->intf_handle;
    }

    JLG(temp, intf_mac_hdl_array, intf_handle);
    if (!temp) {
        SWITCH_API_TRACE("%s:%d: no macs to delete!", __FUNCTION__, __LINE__);
        return SWITCH_STATUS_SUCCESS;
    }

    mac_intf_list = (switch_mac_intf_list_t *) (*(unsigned long *)temp);
    node = tommy_list_head(&(mac_intf_list->mac_entries));
    while (node) {
        mac_info = node->data;
        node = node->next;
        status = switch_api_mac_table_entry_delete(device, &mac_info->mac_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            goto cleanup;
        }
    }
    return status;
cleanup:
    SWITCH_API_ERROR("%s:%d: unable to delete macs for handle %lx. %s",
                     __FUNCTION__, __LINE__,
                     handle,
                     switch_print_error(status));
    return status;
}

switch_status_t
switch_api_mac_table_entries_delete_by_interface_vlan(switch_device_t device,
                                                      switch_handle_t handle,
                                                      switch_handle_t vlan_handle)
{
    switch_mac_vlan_list_t            *mac_vlan_list = NULL;
    switch_mac_info_t                 *mac_info = NULL;
    tommy_node                        *node = NULL;
    void                              *temp = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_handle_t                    intf_handle = 0;
    switch_port_info_t                *port_info = NULL;
    switch_lag_info_t                 *lag_info = NULL;
    switch_handle_type_t               handle_type = 0;

    if (!SWITCH_PORT_HANDLE_VALID(handle) && 
        !SWITCH_LAG_HANDLE_VALID(handle) &&
        !SWITCH_INTERFACE_HANDLE_VALID(handle)) {
        status = SWITCH_STATUS_INVALID_HANDLE;
        goto cleanup;
    }

    if (!SWITCH_BD_HANDLE_VALID(vlan_handle)) {
        status = SWITCH_STATUS_INVALID_HANDLE;
        goto cleanup;
    }

    JLG(temp, vlan_mac_hdl_array, vlan_handle);
    if (!temp) {
        SWITCH_API_TRACE("%s:%d: no macs to delete!", __FUNCTION__, __LINE__);
        return SWITCH_STATUS_SUCCESS;
    }

    handle_type = switch_handle_get_type(handle);
    intf_handle = handle;
    if (handle_type == SWITCH_HANDLE_TYPE_PORT) {
       port_info = switch_api_port_get_internal((switch_port_t)handle); 
       if (!port_info) {
           status = SWITCH_STATUS_INVALID_PORT_NUMBER;
           goto cleanup;
       }
       intf_handle = port_info->intf_handle;
    }
    if (handle_type == SWITCH_HANDLE_TYPE_LAG) {
        lag_info = switch_api_lag_get_internal(handle);
        if (!lag_info) {
            status = SWITCH_STATUS_INVALID_HANDLE;
            goto cleanup;
        }
        intf_handle = lag_info->intf_handle;
    }

    mac_vlan_list = (switch_mac_vlan_list_t *) (*(unsigned long *)temp);
    node = tommy_list_head(&(mac_vlan_list->mac_entries));
    while (node) {
        mac_info = node->data;
        node = node->next;
        if (intf_handle != mac_info->mac_entry.handle) {
            continue;
        }
        status = switch_api_mac_table_entry_delete(device, &mac_info->mac_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            return status;
        }
    }
    return status;
cleanup:
    SWITCH_API_ERROR("%s:%d: unable to delete macs for handle %lx. %s",
                     __FUNCTION__, __LINE__,
                     handle,
                     switch_print_error(status));
    return status;
}

switch_status_t
switch_api_mac_table_aging_time_set(uint64_t value)
{
    mac_params.aging_time = value;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_mac_table_aging_time_get(uint64_t *value)
{
    *value = mac_params.aging_time;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_mac_register_learning_callback(switch_mac_learn_entry_notify_cb cb_fn)
{
    switch_mac_cb_fn.mac_learn_notify_cb = cb_fn;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_mac_register_aging_callback(switch_mac_aging_entry_notify_cb cb_fn)
{
    switch_mac_cb_fn.mac_aging_notify_cb = cb_fn;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_mac_table_entries_get(switch_mac_table_iterator_fn iterator_fn)
{
    switch_mac_info_t                 *mac_info = NULL;
    switch_mac_vlan_list_t            *mac_vlan_list = NULL;
    tommy_node                        *node = NULL;
    void                              *temp = NULL;
    switch_handle_t                    vlan_handle = 0;

    JLF(temp, vlan_mac_hdl_array, vlan_handle);
    while (temp) {
        mac_vlan_list = (switch_mac_vlan_list_t *) (*(unsigned long *)temp);
        node = tommy_list_head(&(mac_vlan_list->mac_entries));
        while (node) {
            mac_info = node->data;
            iterator_fn(&mac_info->mac_entry);
            node = node->next;
        }
        JLN(temp, vlan_mac_hdl_array, vlan_handle);
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_mac_table_entries_get_by_vlan(switch_handle_t vlan_handle, switch_mac_table_iterator_fn iterator_fn)
{
    switch_mac_info_t                 *mac_info = NULL;
    switch_mac_vlan_list_t            *mac_vlan_list = NULL;
    tommy_node                        *node = NULL;
    void                              *temp = NULL;

    JLG(temp, vlan_mac_hdl_array, vlan_handle);
    if (!temp) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    mac_vlan_list = (switch_mac_vlan_list_t *) (*(unsigned long *)temp);
    node = tommy_list_head(&(mac_vlan_list->mac_entries));
    while (node) {
        mac_info = node->data;
        iterator_fn(&mac_info->mac_entry);
        node = node->next;
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_mac_table_entries_get_by_interface(switch_handle_t intf_handle, switch_mac_table_iterator_fn iterator_fn)
{
    switch_mac_info_t                 *mac_info = NULL;
    switch_mac_intf_list_t            *mac_intf_list = NULL;
    tommy_node                        *node = NULL;
    void                              *temp = NULL;

    JLG(temp, intf_mac_hdl_array, intf_handle);
    if (!temp) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }
    mac_intf_list = (switch_mac_intf_list_t *) (*(unsigned long *)temp);
    node = tommy_list_head(&(mac_intf_list->mac_entries));
    while (node) {
        mac_info = node->data;
        iterator_fn(&mac_info->mac_entry);
        node = node->next;
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_mac_table_set_learning_timeout(switch_device_t device, uint32_t timeout)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    mac_params.learn_timeout = timeout;
    status = switch_pd_mac_table_set_learning_timeout(device, timeout);
    return status;
}

switch_status_t
switch_api_mac_table_print_all()
{
    switch_mac_info_t                 *mac_info = NULL;
    switch_api_mac_entry_t            *mac_entry = NULL;
    switch_mac_vlan_list_t            *mac_vlan_list = NULL;
    tommy_node                        *node = NULL;
    void                              *temp = NULL;
    switch_handle_t                    vlan_handle = 0;
    char                               buffer[200];

    JLF(temp, vlan_mac_hdl_array, vlan_handle);
    while (temp) {
        mac_vlan_list = (switch_mac_vlan_list_t *) (*(unsigned long *)temp);
        node = tommy_list_head(&(mac_vlan_list->mac_entries));
        while (node) {
            mac_info = node->data;
            mac_entry = &mac_info->mac_entry;
            switch_print_mac_table_entry(mac_entry, buffer, 200);
            node = node->next;
        }
        JLN(temp, vlan_mac_hdl_array, vlan_handle);
    }
    return SWITCH_STATUS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
