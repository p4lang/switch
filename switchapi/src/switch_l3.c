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
#include "switchapi/switch_lag.h"
#include "switchapi/switch_l3.h"
#include "switchapi/switch_neighbor.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_utils.h"
#include "switch_pd.h"
#include "switch_nhop_int.h"
#include "switch_l3_int.h"
#include "switch_hostif_int.h"
#include "switch_log.h"
#include "arpa/inet.h"
#include <string.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static tommy_hashtable switch_l3_hash_table;
static void *switch_vrf_v4_routes = NULL;
static void *switch_vrf_v6_routes = NULL;

static inline unsigned int
prefix_to_v4_mask(unsigned int prefix)
{
    return (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;
}

static void
prefix_to_v6_mask(unsigned int prefix, uint8_t *mask)
{
    unsigned int i = 0;
    memset(mask, 0, 16);
    for (i = 0; i < prefix/16; i++) {
        mask[i] = 0xFF;
    }
    if (i != 8) {
        mask[i] = (0xFF << (128 - prefix)) & 0xFF;
    }
}

switch_status_t
switch_l3_init(switch_device_t device)
{
    UNUSED(device);
    // IP + VRF Hash table init (V4 only for now!)
    tommy_hashtable_init(&switch_l3_hash_table, SWITCH_L3_HASH_TABLE_SIZE);
    switch_handle_type_init(SWITCH_HANDLE_TYPE_URPF, (4096));
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_l3_free(switch_device_t device)
{
    UNUSED(device);
    tommy_hashtable_done(&switch_l3_hash_table);
    switch_handle_type_free(SWITCH_HANDLE_TYPE_URPF);
    return SWITCH_STATUS_SUCCESS;
}

void
switch_l3_hash_key_init(uchar *key, switch_handle_t vrf,
                         switch_ip_addr_t *ip_addr, uint32_t *len,
                         uint32_t *hash)
{
    *len=0;
    memset(key, 0, SWITCH_L3_HASH_KEY_SIZE);
    *(unsigned int *)(&key[0]) = (unsigned int)handle_to_id(vrf);
    key[4] = ip_addr->type;
    if(ip_addr->type == SWITCH_API_IP_ADDR_V4) {
        *(unsigned int *)(&key[5]) = ip_addr->ip.v4addr;
        *len = 9;
    }
    else {
        memcpy(&key[5], ip_addr->ip.v6addr, 4*sizeof(unsigned int));
        *len = 21;
    }
    key[*len] = ip_addr->prefix_len;
    (*len)++;
    *hash = MurmurHash2(key, *len, 0x98761234);
}

static switch_status_t
switch_l3_hash_key_decode(switch_l3_hash_t *hash_entry, switch_handle_t *vrf_handle,
                          switch_ip_addr_t *ip_addr)
{
    uint8_t len = 0;

    memset(ip_addr, 0, sizeof(switch_ip_addr_t));
    *vrf_handle = id_to_handle(SWITCH_HANDLE_TYPE_VRF, *(unsigned int *)(&hash_entry->key[len]));
    len += 4;

    ip_addr->type = hash_entry->key[len];
    len += 1;

    if (ip_addr->type == SWITCH_API_IP_ADDR_V4) {
        ip_addr->ip.v4addr = *(unsigned int *)(&hash_entry->key[len]);
        len += 4;
    } else {
        memcpy(ip_addr->ip.v6addr, &hash_entry->key[len], 16);
        len += 16;
    }
    ip_addr->prefix_len = hash_entry->key[len];
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
switch_l3_insert_into_vrf_list(switch_l3_hash_t *hash_entry)
{
    switch_vrf_route_list_t           *vrf_route_list = NULL;
    void                              *temp = NULL;
    switch_ip_addr_t                   ip_addr;
    switch_handle_t                    vrf_handle = 0;

    memset(&ip_addr, 0, sizeof(switch_ip_addr_t));
    switch_l3_hash_key_decode(hash_entry, &vrf_handle, &ip_addr);
    if (ip_addr.type == SWITCH_API_IP_ADDR_V4) {
        JLG(temp, switch_vrf_v4_routes, vrf_handle);
    } else {
        JLG(temp, switch_vrf_v6_routes, vrf_handle);
    }

    if (!temp) {
        vrf_route_list = switch_malloc(sizeof(switch_vrf_route_list_t), 1);
        if (!vrf_route_list) {
            SWITCH_API_ERROR("%s:%d: No memory!", __FUNCTION__, __LINE__);
            return SWITCH_STATUS_NO_MEMORY;
        }
        tommy_list_init(&(vrf_route_list->routes));
        vrf_route_list->num_entries = 0;
        if (ip_addr.type == SWITCH_API_IP_ADDR_V4) {
            JLI(temp, switch_vrf_v4_routes, vrf_handle);
        } else {
            JLI(temp, switch_vrf_v6_routes, vrf_handle);
        }
        *(unsigned long *)temp = (unsigned long) (vrf_route_list);
    }
    vrf_route_list = (switch_vrf_route_list_t *) (*(unsigned long *)temp);
    tommy_list_insert_tail(&(vrf_route_list->routes), &(hash_entry->vrf_route_node), hash_entry);
    vrf_route_list->num_entries++;
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
switch_l3_remove_from_vrf_list(switch_l3_hash_t *hash_entry)
{
    switch_vrf_route_list_t           *vrf_route_list = NULL;
    void                              *temp = NULL;
    switch_ip_addr_t                   ip_addr;
    switch_handle_t                    vrf_handle = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    memset(&ip_addr, 0, sizeof(switch_ip_addr_t));
    switch_l3_hash_key_decode(hash_entry, &vrf_handle, &ip_addr);
    if (ip_addr.type == SWITCH_API_IP_ADDR_V4) {
        JLG(temp, switch_vrf_v4_routes, vrf_handle);
    } else {
        JLG(temp, switch_vrf_v6_routes, vrf_handle);
    }

    if (!temp) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    vrf_route_list = (switch_vrf_route_list_t *) (*(unsigned long *)temp);
    tommy_list_remove_existing(&(vrf_route_list->routes), &(hash_entry->vrf_route_node));
    vrf_route_list->num_entries--;
    if (vrf_route_list->num_entries == 0) {
        if (ip_addr.type == SWITCH_API_IP_ADDR_V4) {
            JLD(status, switch_vrf_v4_routes, vrf_handle);
        } else {
            JLD(status, switch_vrf_v6_routes, vrf_handle);
        }
    }
    return status;
}

static switch_l3_hash_t *
switch_l3_insert_hash(switch_handle_t vrf, switch_ip_addr_t *ip_addr,
                      switch_handle_t interface)
{
    switch_l3_hash_t                  *hash_entry = NULL;
    unsigned char                      key[SWITCH_L3_HASH_KEY_SIZE];
    unsigned int                       len = 0;
    uint32_t                           hash;

    switch_l3_hash_key_init(key, vrf, ip_addr, &len, &hash);
    hash_entry = switch_malloc(sizeof(switch_l3_hash_t), 1);
    if (!hash_entry) {
        return NULL;
    }
    memcpy(hash_entry->key, key, SWITCH_L3_HASH_KEY_SIZE);
    hash_entry->path_count = 1;
    tommy_hashtable_insert(&switch_l3_hash_table, &(hash_entry->node), hash_entry, hash);
    switch_l3_insert_into_vrf_list(hash_entry);
    return hash_entry;
}

static inline int
switch_l3_hash_cmp(const void *key1, const void *key2)
{
    return memcmp(key1, key2, SWITCH_L3_HASH_KEY_SIZE);
}

static switch_status_t
switch_l3_delete_hash(switch_handle_t vrf, switch_ip_addr_t *ip_addr)
{
    switch_l3_hash_t                  *hash_entry = NULL;
    unsigned char                      key[SWITCH_L3_HASH_KEY_SIZE];
    unsigned int                       len = 0;
    uint32_t                           hash;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    switch_l3_hash_key_init(key, vrf, ip_addr, &len, &hash);
    hash_entry = tommy_hashtable_remove(&switch_l3_hash_table, switch_l3_hash_cmp, key, hash);
    switch_l3_remove_from_vrf_list(hash_entry);
    switch_free(hash_entry);
    return status; 
}

static switch_l3_hash_t *
switch_l3_search_hash(switch_handle_t vrf, switch_ip_addr_t *ip_addr)
{
    unsigned char                      key[SWITCH_L3_HASH_KEY_SIZE];
    unsigned int                       len = 0;
    uint32_t                           hash = 0;

    switch_l3_hash_key_init(key, vrf, ip_addr, &len, &hash);
    switch_l3_hash_t *hash_entry = tommy_hashtable_search(&switch_l3_hash_table, switch_l3_hash_cmp, key, hash);
    return hash_entry;
}

switch_status_t
switch_api_l3_interface_address_add(switch_device_t device,
                                    switch_handle_t interface_handle,
                                    switch_handle_t vrf_handle,
                                    switch_ip_addr_t *ip_addr)
{
    switch_interface_info_t           *info = NULL;
    switch_ip_addr_info_t             *ip_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    UNUSED(device);
    info = switch_api_interface_get(interface_handle);
    if (!info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    ip_info = switch_malloc(sizeof(switch_ip_addr_info_t), 1);
    if (!ip_info) {
        return SWITCH_STATUS_NO_MEMORY;
    }

    ip_info->vrf_handle = vrf_handle;
    ip_info->default_ip = TRUE;
    ip_info->ip = *ip_addr;

    // append to list and increment member count
    tommy_list_insert_head(&(info->ip_addr), &(ip_info->node), ip_info);
    info->ip_addr_count++;

    return status;
}

switch_status_t
switch_api_l3_interface_address_delete(switch_device_t device,
                                       switch_handle_t interface_handle,
                                       switch_handle_t vrf_handle,
                                       switch_ip_addr_t *ip_addr)
{
    switch_interface_info_t           *info = NULL;
    switch_ip_addr_info_t             *ip_info = NULL;
    tommy_node                        *node = NULL;

    UNUSED(device);
    UNUSED(vrf_handle);
    info = switch_api_interface_get(interface_handle);
    if (!info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }
    // delete from list and decrement member count
    node = tommy_list_head(&(info->ip_addr));
    while(node) {
        ip_info = node->data;
        if (SWITCH_L3_IP_TYPE(ip_info) == ip_addr->type &&
            SWITCH_L3_IP_IPV4_ADDRESS(ip_info) == ip_addr->ip.v4addr) {
            break;
        }
        node = node->next;
    }

    if (!node) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    // remove from list
    ip_info = tommy_list_remove_existing(&(info->ip_addr), node);
    info->ip_addr_count--;

    switch_free(ip_info);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_l3_route_add(switch_device_t device, switch_handle_t vrf,
                        switch_ip_addr_t *ip_addr, switch_handle_t nhop_handle)
{
    switch_l3_hash_t                  *hash_entry = NULL;
    switch_nhop_info_t                *nhop_info = NULL;
    uint32_t                           nhop_index = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    unsigned int                       v4_mask = 0;
    uint8_t                            v6_mask[16];
    switch_ip_addr_t                   masked_ip;

    if (!SWITCH_VRF_HANDLE_VALID(vrf)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    if (!SWITCH_NHOP_HANDLE_VALID(nhop_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    nhop_index = handle_to_id(nhop_handle);
    nhop_info = switch_nhop_get(nhop_handle);
    if (!nhop_info) {
        SWITCH_API_ERROR("%s:%d: Invalid nexthop!", __FUNCTION__, __LINE__);
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    hash_entry = switch_l3_search_hash(vrf, ip_addr);
    if (hash_entry) {
#ifdef SWITCH_PD
        status = switch_pd_ip_fib_update_entry(device, handle_to_id(vrf),
                                       ip_addr,
                                       SWITCH_NHOP_TYPE_IS_ECMP(nhop_info),
                                       nhop_index,
                                       hash_entry->hw_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            return status;
        }

        status = switch_pd_urpf_update_entry(device, handle_to_id(vrf),
                                        ip_addr, handle_to_id(nhop_handle),
                                        hash_entry->urpf_entry);
#endif
    } else {
        memcpy(&masked_ip, ip_addr, sizeof(switch_ip_addr_t));
        if (ip_addr->type == SWITCH_API_IP_ADDR_V4) {
            v4_mask = prefix_to_v4_mask(ip_addr->prefix_len);
            masked_ip.ip.v4addr = ip_addr->ip.v4addr & v4_mask;
        } else {
            int i = 0;
            prefix_to_v6_mask(ip_addr->prefix_len, v6_mask);
            for (i = 0; i < 16; i++) {
                masked_ip.ip.v6addr[i] = ip_addr->ip.v6addr[i] & v6_mask[i];
            }
        }
        hash_entry = switch_l3_insert_hash(vrf, ip_addr, nhop_handle);
        if (!hash_entry) {
            return SWITCH_STATUS_NO_MEMORY;
        }
        hash_entry->nhop_handle = nhop_handle;
#ifdef SWITCH_PD
        // set the HW entry
        status = switch_pd_ip_fib_add_entry(device, handle_to_id(vrf),
                                       ip_addr,
                                       SWITCH_NHOP_TYPE_IS_ECMP(nhop_info),
                                       nhop_index,
                                       &hash_entry->hw_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            return status;
        }

        status = switch_pd_urpf_add_entry(device, handle_to_id(vrf),
                                     ip_addr, handle_to_id(nhop_handle),
                                     &hash_entry->urpf_entry);
#endif
    }
    return status;
}

switch_status_t
switch_api_l3_route_delete(switch_device_t device, switch_handle_t vrf,
                           switch_ip_addr_t *ip_addr, switch_handle_t nhop_handle)
{
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_l3_hash_t                  *hash_entry = NULL;
    
    if (!SWITCH_VRF_HANDLE_VALID(vrf)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    UNUSED(nhop_handle);
    hash_entry = switch_l3_search_hash(vrf, ip_addr);
    if (!hash_entry) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
#ifdef SWITCH_PD
    status = switch_pd_ip_fib_delete_entry(device, ip_addr, hash_entry->hw_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }
    status = switch_pd_urpf_delete_entry(device, handle_to_id(vrf),
                                    ip_addr,
                                    hash_entry->urpf_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }
#endif
    status = switch_l3_delete_hash(vrf, ip_addr);
    return status;
}

switch_status_t
switch_api_l3_v4_route_entries_get_by_vrf(switch_handle_t vrf_handle, switch_l3_table_iterator_fn iterator_fn)
{
    switch_l3_hash_t                  *hash_entry = NULL;
    tommy_node                        *node = NULL;
    switch_vrf_route_list_t           *vrf_route_list = NULL;
    void                              *temp = NULL;
    switch_ip_addr_t                  ip_addr;

    JLG(temp, switch_vrf_v4_routes, vrf_handle);
    if (!temp) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    vrf_route_list = (switch_vrf_route_list_t *) (*(unsigned long *)temp);
    node = tommy_list_head(&(vrf_route_list->routes));
    while (node) {
        hash_entry = node->data;
        switch_l3_hash_key_decode(hash_entry, &vrf_handle, &ip_addr);
        iterator_fn(vrf_handle, ip_addr, hash_entry->nhop_handle);
        node = node->next;
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_l3_v6_route_entries_get_by_vrf(switch_handle_t vrf_handle, switch_l3_table_iterator_fn iterator_fn)
{
    switch_l3_hash_t                  *hash_entry = NULL;
    tommy_node                        *node = NULL;
    switch_vrf_route_list_t           *vrf_route_list = NULL;
    void                              *temp = NULL;
    switch_ip_addr_t                   ip_addr;

    JLG(temp, switch_vrf_v6_routes, vrf_handle);
    if (!temp) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    vrf_route_list = (switch_vrf_route_list_t *) (*(unsigned long *)temp);
    node = tommy_list_head(&(vrf_route_list->routes));
    while (node) {
        hash_entry = node->data;
        switch_l3_hash_key_decode(hash_entry, &vrf_handle, &ip_addr);
        iterator_fn(vrf_handle, ip_addr, hash_entry->nhop_handle);
        node = node->next;
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_l3_route_entries_get_by_vrf(switch_handle_t vrf_handle, switch_l3_table_iterator_fn iterator_fn)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    status = switch_api_l3_v4_route_entries_get_by_vrf(vrf_handle, iterator_fn);
    status = switch_api_l3_v6_route_entries_get_by_vrf(vrf_handle, iterator_fn);
    return status;
}

switch_status_t
switch_api_l3_route_entries_get(switch_l3_table_iterator_fn iterator_fn)
{
    void                              *temp = NULL;
    switch_handle_t                    vrf_handle = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    JLF(temp, switch_vrf_v4_routes, vrf_handle);
    while (temp) {
        status = switch_api_l3_v4_route_entries_get_by_vrf(vrf_handle, iterator_fn);
        JLN(temp, switch_vrf_v4_routes, vrf_handle);
    }
    vrf_handle = 0;
    JLF(temp, switch_vrf_v6_routes, vrf_handle);
    while (temp) {
        status = switch_api_l3_v6_route_entries_get_by_vrf(vrf_handle, iterator_fn);
        JLN(temp, switch_vrf_v6_routes, vrf_handle);
    }
    return status;
}

switch_status_t
switch_api_l3_v4_routes_print_by_vrf(switch_handle_t vrf_handle)
{
    switch_l3_hash_t                  *hash_entry = NULL;
    tommy_node                        *node = NULL;
    switch_vrf_route_list_t           *vrf_route_list = NULL;
    void                              *temp = NULL;
    switch_ip_addr_t                  ip_addr;

    JLG(temp, switch_vrf_v4_routes, vrf_handle);
    if (!temp) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    vrf_route_list = (switch_vrf_route_list_t *) (*(unsigned long *)temp);
    node = tommy_list_head(&(vrf_route_list->routes));
    while (node) {
        hash_entry = node->data;
        switch_l3_hash_key_decode(hash_entry, &vrf_handle, &ip_addr);
        printf("\nvrf_handle %x ip %x -> nhop %x",
               (unsigned int) vrf_handle, ip_addr.ip.v4addr,
               (unsigned int) hash_entry->nhop_handle);
        node = node->next;
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_l3_v6_routes_print_by_vrf(switch_handle_t vrf_handle)
{
    switch_l3_hash_t                  *hash_entry = NULL;
    tommy_node                        *node = NULL;
    switch_vrf_route_list_t           *vrf_route_list = NULL;
    void                              *temp = NULL;
    switch_ip_addr_t                   ip_addr;
    char                               v6_addr[INET6_ADDRSTRLEN];

    JLG(temp, switch_vrf_v6_routes, vrf_handle);
    if (!temp) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    vrf_route_list = (switch_vrf_route_list_t *) (*(unsigned long *)temp);
    node = tommy_list_head(&(vrf_route_list->routes));
    while (node) {
        hash_entry = node->data;
        switch_l3_hash_key_decode(hash_entry, &vrf_handle, &ip_addr);
        inet_ntop(AF_INET6, ip_addr.ip.v6addr, v6_addr, INET6_ADDRSTRLEN);
        printf("\nvrf_handle %x ip %s -> nhop %x",
                (unsigned int) vrf_handle, v6_addr,
                (unsigned int) hash_entry->nhop_handle);
        node = node->next;
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_l3_v4_routes_print_all(void)
{
    void                              *temp = NULL;
    switch_handle_t                    vrf_handle = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    JLF(temp, switch_vrf_v4_routes, vrf_handle);
    while (temp) {
        status = switch_api_l3_v4_routes_print_by_vrf(vrf_handle);
        JLN(temp, switch_vrf_v4_routes, vrf_handle);
    }
    return status;
}

switch_status_t
switch_api_l3_v6_routes_print_all(void)
{
    switch_handle_t                    vrf_handle = 0;
    void                              *temp = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    JLF(temp, switch_vrf_v6_routes, vrf_handle);
    while (temp) {
        status = switch_api_l3_v6_routes_print_by_vrf(vrf_handle);
        JLN(temp, switch_vrf_v6_routes, vrf_handle);
    }
    return status;
}

switch_status_t
switch_api_l3_routes_print_all(void)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    status = switch_api_l3_v4_routes_print_all();
    status = switch_api_l3_v6_routes_print_all();
    return status;
}

switch_status_t
switch_api_init_default_route_entries(switch_device_t device,
                                      switch_handle_t vrf_handle)
{
    switch_handle_t drop_nhop_handle;
    switch_ip_addr_t ip_addr;
    switch_status_t ret;

    drop_nhop_handle =
        switch_api_cpu_nhop_get(SWITCH_HOSTIF_REASON_CODE_NULL_DROP);

    // 127/8, drop
    memset(&ip_addr, 0, sizeof(ip_addr));
    ip_addr.type = SWITCH_API_IP_ADDR_V4;
    ip_addr.ip.v4addr = 0x7f000000;
    ip_addr.prefix_len = 8;
    ret = switch_api_l3_route_add(device, vrf_handle, &ip_addr,
                                  drop_nhop_handle);
    assert(ret == SWITCH_STATUS_SUCCESS);

    // ::1/128, drop
    memset(&ip_addr, 0, sizeof(ip_addr));
    ip_addr.type = SWITCH_API_IP_ADDR_V6;
    ip_addr.ip.v6addr[15] = 1;
    ip_addr.prefix_len = 128;
    ret = switch_api_l3_route_add(device, vrf_handle, &ip_addr,
                                  drop_nhop_handle);
    assert(ret == SWITCH_STATUS_SUCCESS);

    return SWITCH_STATUS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
