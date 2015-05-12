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

//
//  switch_neighbor.c
//  switch_api
//
//  Created on 7/28/14.
//  Copyright (c) 2014 bn. All rights reserved.
//

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_neighbor.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_utils.h"
#include "switch_neighbor_int.h"
#include "switch_tunnel_int.h"
#include "switch_interface_int.h"
#include "switch_pd.h"
#include "switch_log.h"
#include "switch_defines.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
static void *switch_neighbor_array=NULL;
static tommy_hashtable switch_dmac_rewrite_table;
switch_api_id_allocator *dmac_rewrite_index_allocator = NULL;
    
switch_status_t
switch_neighbor_init(void)
{
    switch_neighbor_array = NULL;
    tommy_hashtable_init(&switch_dmac_rewrite_table, SWITCH_DMAC_REWRITE_HASH_TABLE_SIZE);
    dmac_rewrite_index_allocator = switch_api_id_allocator_new(SWITCH_DMAC_REWRITE_HASH_TABLE_SIZE);
    return switch_handle_type_init(SWITCH_HANDLE_TYPE_ARP, (64*1024));
}

switch_status_t
switch_neighbor_free(void)
{
    switch_handle_type_free(SWITCH_HANDLE_TYPE_ARP);
    tommy_hashtable_done(&switch_dmac_rewrite_table);
    switch_api_id_allocator_destroy(dmac_rewrite_index_allocator);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_neighbor_info_create()
{
    switch_handle_t handle;
    _switch_handle_create(SWITCH_HANDLE_TYPE_ARP, switch_neighbor_info_t, switch_neighbor_array, NULL, handle);
    return handle;
}

switch_neighbor_info_t *
switch_neighbor_info_get(switch_handle_t handle)
{
    switch_neighbor_info_t *neighbor_info = NULL;
    _switch_handle_get(switch_neighbor_info_t, switch_neighbor_array, handle, neighbor_info);
    return neighbor_info;
}

void
switch_neighbor_info_delete(switch_handle_t handle)
{
    _switch_handle_delete(switch_neighbor_info_t, switch_neighbor_array, handle);
}

static void
switch_dmac_rewrite_hash_key_init(uchar *key, switch_mac_addr_t *mac,
                                  uint32_t *len, uint32_t *hash)
{
    *len=0;
    memset(key, 0, SWITCH_DMAC_REWRITE_HASH_KEY_SIZE);
    memcpy(key, mac, sizeof(switch_mac_addr_t));
    *len = sizeof(switch_mac_addr_t);
    *hash = MurmurHash2(key, *len, 0x98761234);
}

static inline int
switch_dmac_rewrite_hash_cmp(const void *key1, const void *key2)
{
    return memcmp(key1, key2, SWITCH_DMAC_REWRITE_HASH_KEY_SIZE);
}

static switch_dmac_rewrite_t *
switch_dmac_rewrite_search_hash(switch_mac_addr_t *mac)
{
    unsigned char                      key[SWITCH_DMAC_REWRITE_HASH_KEY_SIZE];
    unsigned int                       len = 0;
    uint32_t                           hash = 0;
    switch_dmac_rewrite_t             *dmac_rewrite = NULL;

    switch_dmac_rewrite_hash_key_init(key, mac, &len, &hash);
    dmac_rewrite = tommy_hashtable_search(&switch_dmac_rewrite_table, switch_dmac_rewrite_hash_cmp, key, hash);
    return dmac_rewrite;
}

static uint16_t
switch_dmac_rewrite_insert_hash(switch_mac_addr_t *mac)
{
    unsigned char                      key[SWITCH_DMAC_REWRITE_HASH_KEY_SIZE];
    unsigned int                       len = 0;
    uint32_t                           hash = 0;
    uint16_t                           mac_index = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;
    switch_dmac_rewrite_t             *dmac_rewrite = NULL;

    dmac_rewrite = switch_dmac_rewrite_search_hash(mac);
    if (dmac_rewrite) {
        mac_index = dmac_rewrite->index;
        dmac_rewrite->ref_count++;
    } else {
        switch_dmac_rewrite_hash_key_init(key, mac, &len, &hash);
        dmac_rewrite = switch_malloc(sizeof(switch_dmac_rewrite_t), 1);
        mac_index = switch_api_id_allocator_allocate(dmac_rewrite_index_allocator);
        memcpy(&dmac_rewrite->mac, mac, sizeof(switch_mac_addr_t));
        dmac_rewrite->index = mac_index;
        dmac_rewrite->ref_count = 1;
        status = switch_pd_tunnel_dmac_rewrite_table_add_entry(device, mac_index, mac, &dmac_rewrite->rewrite_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d: unable to add tunnel dmac entry!", __FUNCTION__, __LINE__);
        }
        tommy_hashtable_insert(&switch_dmac_rewrite_table, &(dmac_rewrite->node), dmac_rewrite, hash);
    }
    return mac_index;
}

static switch_status_t
switch_dmac_rewrite_delete_hash(switch_mac_addr_t *mac)
{
    switch_dmac_rewrite_t             *dmac_rewrite = NULL;
    unsigned char                      key[SWITCH_DMAC_REWRITE_HASH_KEY_SIZE];
    unsigned int                       len = 0;
    uint32_t                           hash = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_device_t                    device = SWITCH_DEV_ID;

    dmac_rewrite = switch_dmac_rewrite_search_hash(mac);
    if (!dmac_rewrite) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    dmac_rewrite->ref_count--;
    if (dmac_rewrite->ref_count == 0) {
        switch_dmac_rewrite_hash_key_init(key, mac, &len, &hash);
        dmac_rewrite = tommy_hashtable_remove(&switch_dmac_rewrite_table, switch_dmac_rewrite_hash_cmp, key, hash);
        status = switch_pd_tunnel_dmac_rewrite_table_delete_entry(device, dmac_rewrite->rewrite_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d unabl to delete tunnel dmac entry!", __FUNCTION__, __LINE__);
        }
        switch_api_id_allocator_release(dmac_rewrite_index_allocator, dmac_rewrite->index);
        switch_free(dmac_rewrite);
    }
    return status; 
}

switch_status_t
switch_api_neighbor_entry_add_rewrite(switch_device_t device,
                                      switch_neighbor_info_t *neighbor_info)
{
    switch_ip_addr_type_t              addr_type;
    uint16_t                           smac_index = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    uint16_t                           nhop_index = 0;
    switch_api_neighbor_t             *neighbor = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_tunnel_info_t              *tunnel_info = NULL;
    uint16_t                           tunnel_index = 0;
    switch_encap_type_t                encap_type = 0;
    uint16_t                           outer_bd = 0;

    addr_type = SWITCH_NEIGHBOR_ADDR_TYPE(neighbor_info);
    neighbor = &neighbor_info->neighbor;
    nhop_index = handle_to_id(neighbor->nhop_handle);
    
    intf_info = switch_api_interface_get(neighbor->interface);
    if (!intf_info) {
        SWITCH_API_ERROR("%s:%d invalid interface!", __FUNCTION__, __LINE__);
        return SWITCH_STATUS_INVALID_INTERFACE;
    }
    if (neighbor->neigh_type == SWITCH_API_NEIGHBOR_MPLS_SWAP_L2VPN ||
        neighbor->neigh_type == SWITCH_API_NEIGHBOR_MPLS_SWAP_L3VPN ||
        neighbor->neigh_type == SWITCH_API_NEIGHBOR_MPLS_SWAP_PUSH_L2VPN ||
        neighbor->neigh_type == SWITCH_API_NEIGHBOR_MPLS_SWAP_PUSH_L3VPN ||
        neighbor->neigh_type == SWITCH_API_NEIGHBOR_MPLS_PUSH_L2VPN ||
        neighbor->neigh_type == SWITCH_API_NEIGHBOR_MPLS_PUSH_L3VPN) {
        tunnel_index = handle_to_id(neighbor->interface);
        status = switch_pd_rewrite_table_mpls_rewrite_add_entry(device, nhop_index,
                                                           tunnel_index, neighbor->neigh_type, 
                                                           smac_index, neighbor->mac_addr,
                                                           neighbor->mpls_label, neighbor->header_count,
                                                           &neighbor_info->rewrite_entry);
    } else if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_TUNNEL) {
        tunnel_index = handle_to_id(neighbor->interface);
        tunnel_info = &(SWITCH_INTF_TUNNEL_INFO(intf_info));
        if (tunnel_info->encap_mode == SWITCH_API_TUNNEL_ENCAP_MODE_IP) {
            encap_type = SWITCH_INTF_TUNNEL_ENCAP_TYPE(intf_info);
            status = switch_pd_rewrite_table_tunnel_rewrite_add_entry(device, nhop_index,
                                                          smac_index, outer_bd,
                                                          addr_type, neighbor->mac_addr,
                                                          tunnel_index, encap_type,
                                                          &neighbor_info->rewrite_entry);
        }
    } else {
        status = switch_pd_rewrite_table_unicast_rewrite_add_entry(device, nhop_index, smac_index,
                                                          neighbor->mac_addr, addr_type,
                                                          &neighbor_info->rewrite_entry);
    }

    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d: Unable to add unicast rewrite entry!.", __FUNCTION__, __LINE__);
    }
    return status;
}

switch_status_t
switch_api_neighbor_entry_add_tunnel_rewrite(switch_device_t device,
                                             switch_neighbor_info_t *neighbor_info)
{
    switch_interface_info_t           *intf_info = NULL;
    switch_api_neighbor_t             *neighbor = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_handle_t                    ln_handle = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    uint16_t                           smac_index = 1;
    uint16_t                           dmac_index = 0;
    uint16_t                           sip_index = 0;
    uint16_t                           dip_index = 0;
    switch_handle_t                    vrf_handle = 0;
    switch_ip_encap_t                 *ip_encap = NULL;
    switch_mpls_encap_t               *mpls_encap = NULL;
    switch_tunnel_info_t              *tunnel_info = NULL;
    switch_ip_addr_t                  *src_ip = NULL;
    switch_ip_addr_t                  *dst_ip = NULL;

    neighbor = &neighbor_info->neighbor;
    intf_info = switch_api_interface_get(neighbor->interface);
    if (!intf_info) {
        SWITCH_API_ERROR("%s:%d: invalid interface for tunnel rewrite!", __FUNCTION__, __LINE__);
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    ln_handle = intf_info->ln_bd_handle;
    bd_info = switch_bd_get(ln_handle);
    if (!bd_info) {
        SWITCH_API_ERROR("%s:%d: unable to find ln!.", __FUNCTION__, __LINE__);
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    tunnel_info = &(SWITCH_INTF_TUNNEL_INFO(intf_info));
    dmac_index = switch_dmac_rewrite_insert_hash(&neighbor->mac_addr);

    if (tunnel_info->encap_mode == SWITCH_API_TUNNEL_ENCAP_MODE_IP) {
        ip_encap = &(SWITCH_INTF_TUNNEL_IP_ENCAP(intf_info));
        vrf_handle = ip_encap->vrf_handle;

        src_ip = &ip_encap->src_ip;
        sip_index = switch_tunnel_src_vtep_index_get(vrf_handle, src_ip);

        dst_ip = &ip_encap->dst_ip;
        dip_index = switch_tunnel_dst_vtep_index_get(vrf_handle, dst_ip);

        status = switch_pd_tunnel_rewrite_table_add_entry(device, handle_to_id(neighbor->interface),
                                                     sip_index, dip_index,
                                                     smac_index, dmac_index,
                                                     &neighbor_info->rewrite_entry);
    } else if (tunnel_info->encap_mode == SWITCH_API_TUNNEL_ENCAP_MODE_MPLS) {
        mpls_encap = &(SWITCH_INTF_TUNNEL_MPLS_ENCAP(intf_info));
        status = switch_pd_tunnel_rewrite_table_mpls_add_entry(device, handle_to_id(neighbor->interface),
                                                     smac_index, dmac_index, mpls_encap,
                                                     &neighbor_info->rewrite_entry);
    }

    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d unable to add tunnel rewrite entry", __FUNCTION__, __LINE__);
        return status;
    }

    return status;
}
    
switch_handle_t
switch_api_neighbor_entry_add(switch_device_t device, switch_api_neighbor_t *neighbor)
{
    switch_neighbor_info_t            *neighbor_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    switch_handle_t                    handle;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    intf_info = switch_api_interface_get(neighbor->interface);
    if (!intf_info) {
        SWITCH_API_ERROR("%s:%d: invalid interface for rewrite!", __FUNCTION__, __LINE__);
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    handle = switch_neighbor_info_create();
    neighbor_info = switch_neighbor_info_get(handle);
    memcpy(&neighbor_info->neighbor, neighbor, sizeof(switch_api_neighbor_t));

#ifdef SWITCH_PD
    if (neighbor->nhop_handle) {
        status = switch_api_neighbor_entry_add_rewrite(device, neighbor_info);
    } else {
        status = switch_api_neighbor_entry_add_tunnel_rewrite(device, neighbor_info);
    }
#endif
    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d: failed to create neighbor entry!", __FUNCTION__, __LINE__);
    }
    return handle;
}
    
switch_status_t
switch_api_neighbor_entry_remove(switch_device_t device, switch_handle_t neighbor_handle)
{
    switch_neighbor_info_t *neighbor_info = NULL;

    neighbor_info = switch_neighbor_info_get(neighbor_handle);
    if (!neighbor_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
#ifdef SWITCH_PD
    if (neighbor_info->neighbor.nhop_handle) {
        switch_pd_rewrite_table_delete_entry(device, neighbor_info->rewrite_entry);
    } else {
        switch_dmac_rewrite_delete_hash(&neighbor_info->neighbor.mac_addr);
        switch_pd_tunnel_rewrite_table_delete_entry(device, neighbor_info->rewrite_entry);
    }
#endif
    switch_neighbor_info_delete(neighbor_handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_neighbor_print_entry(switch_handle_t neighbor_handle)
{
    switch_neighbor_info_t            *neighbor_info = NULL;
    switch_api_neighbor_t             *neighbor = NULL;
    switch_mac_addr_t                 *mac = NULL;

    neighbor_info = switch_neighbor_info_get(neighbor_handle);
    if (!neighbor_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    neighbor = &neighbor_info->neighbor;
    printf("\n\nneighbor_handle: %x:", (unsigned int) neighbor_handle);
    printf("\n\ttype: %x", neighbor->neigh_type);
    printf("\n\tvrf_handle :%x nhop_handle %x interface_handle %x",
            (unsigned int) neighbor->vrf_handle,
            (unsigned int) neighbor->nhop_handle,
            (unsigned int) neighbor->interface);
    mac = &neighbor->mac_addr;
    printf("\n\trewrite mac %02x:%02x:%02x:%02x:%02x:%02x", 
            mac->mac_addr[0], mac->mac_addr[1], mac->mac_addr[2],
            mac->mac_addr[3], mac->mac_addr[4], mac->mac_addr[5]);
    printf("\n");
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_neighbor_print_all(void)
{
    switch_handle_t                    neighbor_handle = 0;
    switch_handle_t                    next_neighbor_handle = 0;

    switch_handle_get_first(switch_neighbor_array, neighbor_handle);
    while (neighbor_handle) {
        switch_api_neighbor_print_entry(neighbor_handle);
        switch_handle_get_next(switch_neighbor_array, neighbor_handle, next_neighbor_handle);
        neighbor_handle = next_neighbor_handle;
    }
    return SWITCH_STATUS_SUCCESS;
}
    
#ifdef __cplusplus
}
#endif
