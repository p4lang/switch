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

#include "switchapi/switch_interface.h"
#include "switchapi/switch_tunnel.h"
#include "switchapi/switch_l3.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_nhop.h"
#include "switchapi/switch_utils.h"
#include "switch_pd.h"
#include "switch_interface_int.h"
#include "switch_tunnel_int.h"
#include "switch_log.h"
#include <string.h>
#include <netinet/in.h>

static tommy_hashtable switch_src_vtep_table;
static tommy_hashtable switch_dst_vtep_table;
switch_api_id_allocator *src_vtep_index_allocator = NULL;
switch_api_id_allocator *dst_vtep_index_allocator = NULL;
static void *mpls_transit_array = NULL;

#define UDP_PORT_VXLAN         4789
#define UDP_PORT_GENEVE        6081
#define GRE_PROTO_NVGRE        0x6558

switch_status_t
switch_tunnel_init(switch_device_t device)
{
    UNUSED(device);
    tommy_hashtable_init(&switch_src_vtep_table, SWITCH_SRC_VTEP_HASH_TABLE_SIZE);
    tommy_hashtable_init(&switch_dst_vtep_table, SWITCH_DST_VTEP_HASH_TABLE_SIZE);
    src_vtep_index_allocator = switch_api_id_allocator_new(SWITCH_SRC_VTEP_HASH_TABLE_SIZE, FALSE);
    dst_vtep_index_allocator = switch_api_id_allocator_new(SWITCH_DST_VTEP_HASH_TABLE_SIZE, FALSE);
    switch_api_id_allocator_allocate(src_vtep_index_allocator);
    switch_api_id_allocator_allocate(dst_vtep_index_allocator);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_tunnel_free(switch_device_t device)
{
    UNUSED(device);
    tommy_hashtable_done(&switch_src_vtep_table);
    tommy_hashtable_done(&switch_dst_vtep_table);
    switch_api_id_allocator_destroy(src_vtep_index_allocator);
    switch_api_id_allocator_destroy(dst_vtep_index_allocator);
    return SWITCH_STATUS_SUCCESS;
}

static void
switch_tunnel_vtep_hash_key_init(uchar *key, switch_handle_t vrf,
                                 switch_ip_addr_t *ip_addr, uint32_t *len,
                                 uint32_t *hash)
{
    *len=0;
    memset(key, 0, SWITCH_VTEP_HASH_KEY_SIZE);
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

static inline int
switch_vtep_hash_cmp(const void *key1, const void *key2)
{
    return memcmp(key1, key2, SWITCH_VTEP_HASH_KEY_SIZE);
}

static uint16_t
switch_tunnel_src_vtep_insert_hash(switch_handle_t vrf, switch_ip_addr_t *ip_addr)
{
    switch_vtep_entry_t               *vtep_entry = NULL;
    unsigned char                      key[SWITCH_VTEP_HASH_KEY_SIZE];
    unsigned int                       len = 0;
    uint32_t                           hash = 0;
    uint16_t                           src_vtep_index = 0;

    switch_tunnel_vtep_hash_key_init(key, vrf, ip_addr, &len, &hash);
    vtep_entry = switch_malloc(sizeof(switch_vtep_entry_t), 1);
    if (!vtep_entry) {
        return src_vtep_index;
    }
    src_vtep_index = switch_api_id_allocator_allocate(src_vtep_index_allocator);
    vtep_entry->vrf = vrf;
    memcpy(&vtep_entry->ip_addr, ip_addr, sizeof(switch_ip_addr_t));
    memcpy(vtep_entry->key, key, SWITCH_VTEP_HASH_KEY_SIZE);
    vtep_entry->entry_index = src_vtep_index;
    tommy_hashtable_insert(&switch_src_vtep_table, &(vtep_entry->node), vtep_entry, hash);
    return src_vtep_index;
}

static switch_status_t
switch_tunnel_src_vtep_delete_hash(switch_handle_t vrf, switch_ip_addr_t *ip_addr)
{
    switch_vtep_entry_t               *vtep_entry = NULL;
    unsigned char                      key[SWITCH_VTEP_HASH_KEY_SIZE];
    unsigned int                       len = 0;
    uint32_t                           hash = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    switch_tunnel_vtep_hash_key_init(key, vrf, ip_addr, &len, &hash);
    vtep_entry = tommy_hashtable_remove(&switch_src_vtep_table, switch_vtep_hash_cmp, key, hash);
    if (!vtep_entry) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    switch_api_id_allocator_release(src_vtep_index_allocator, vtep_entry->entry_index);
    free(vtep_entry);
    return status; 
}

static uint16_t
switch_tunnel_src_vtep_search_hash(switch_handle_t vrf, switch_ip_addr_t *ip_addr)
{
    switch_vtep_entry_t               *vtep_entry = NULL;
    unsigned char                      key[SWITCH_VTEP_HASH_KEY_SIZE];
    unsigned int                       len = 0;
    uint32_t                           hash;
    uint16_t                           src_vtep_index = 0;

    switch_tunnel_vtep_hash_key_init(key, vrf, ip_addr, &len, &hash);
    vtep_entry = tommy_hashtable_search(&switch_src_vtep_table, switch_vtep_hash_cmp, key, hash);

    if (vtep_entry) {
        src_vtep_index = vtep_entry->entry_index;
    }
    return src_vtep_index;
}

static uint16_t
switch_tunnel_dst_vtep_insert_hash(switch_handle_t vrf, switch_ip_addr_t *ip_addr)
{
    switch_vtep_entry_t               *vtep_entry = NULL;
    unsigned char                      key[SWITCH_VTEP_HASH_KEY_SIZE];
    unsigned int                       len = 0;
    uint32_t                           hash;
    uint16_t                           dst_vtep_index = 0;

    switch_tunnel_vtep_hash_key_init(key, vrf, ip_addr, &len, &hash);
    vtep_entry = switch_malloc(sizeof(switch_vtep_entry_t), 1);
    if (!vtep_entry) {
        return dst_vtep_index;
    }
    dst_vtep_index = switch_api_id_allocator_allocate(dst_vtep_index_allocator);
    vtep_entry->vrf = vrf;
    memcpy(&vtep_entry->ip_addr, ip_addr, sizeof(switch_ip_addr_t));
    memcpy(vtep_entry->key, key, SWITCH_VTEP_HASH_KEY_SIZE);
    vtep_entry->entry_index = dst_vtep_index;
    tommy_hashtable_insert(&switch_dst_vtep_table, &(vtep_entry->node), vtep_entry, hash);
    return dst_vtep_index;
}

static switch_status_t
switch_tunnel_dst_vtep_delete_hash(switch_handle_t vrf, switch_ip_addr_t *ip_addr)
{
    switch_vtep_entry_t               *vtep_entry = NULL;
    unsigned char                      key[SWITCH_VTEP_HASH_KEY_SIZE];
    unsigned int                       len = 0;
    uint32_t                           hash = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    switch_tunnel_vtep_hash_key_init(key, vrf, ip_addr, &len, &hash);
    vtep_entry = tommy_hashtable_remove(&switch_dst_vtep_table, switch_vtep_hash_cmp, key, hash);
    if (!vtep_entry) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    switch_api_id_allocator_release(dst_vtep_index_allocator, vtep_entry->entry_index);
    free(vtep_entry);
    return status; 
}

static uint16_t
switch_tunnel_dst_vtep_search_hash(switch_handle_t vrf, switch_ip_addr_t *ip_addr)
{
    switch_vtep_entry_t              *vtep_entry = NULL;
    unsigned char                     key[SWITCH_VTEP_HASH_KEY_SIZE];
    unsigned int                      len = 0;
    uint32_t                          hash = 0;
    uint16_t                          dst_vtep_index = 0;

    switch_tunnel_vtep_hash_key_init(key, vrf, ip_addr, &len, &hash);
    vtep_entry = tommy_hashtable_search(&switch_dst_vtep_table, switch_vtep_hash_cmp, key, hash);

    if (vtep_entry) {
        dst_vtep_index = vtep_entry->entry_index;
    }
    return dst_vtep_index;
}

uint16_t
switch_tunnel_src_vtep_index_get(switch_handle_t vrf, switch_ip_addr_t *ip_addr) {
    return switch_tunnel_src_vtep_search_hash(vrf, ip_addr);
}

uint16_t
switch_tunnel_dst_vtep_index_get(switch_handle_t vrf, switch_ip_addr_t *ip_addr) {
    return switch_tunnel_dst_vtep_search_hash(vrf, ip_addr);
}

static switch_status_t
switch_tunnel_ip_encap_table_add_entries(switch_device_t device,
                                         switch_handle_t intf_handle,
                                         switch_interface_info_t *intf_info)
{
    switch_ip_encap_t                 *ip_encap = NULL;
    switch_ip_encap_pd_hdl_t          *ip_encap_hdl = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    uint16_t                           src_vtep_index = 0;
    uint16_t                           dst_vtep_index = 0;

    ip_encap = &(SWITCH_INTF_TUNNEL_IP_ENCAP(intf_info));
    ip_encap_hdl = &intf_info->ip_encap_hdl;
    /*
     * Allocate Src Vtep Rewrite Index
     */
    src_vtep_index = switch_tunnel_src_vtep_search_hash(ip_encap->vrf_handle, &ip_encap->src_ip);
    if (!src_vtep_index) {
        src_vtep_index = switch_tunnel_src_vtep_insert_hash(ip_encap->vrf_handle, &ip_encap->src_ip);
    }
    /*
     * Allocate Dst Vtep Rewrite Index
     */
    dst_vtep_index = switch_tunnel_dst_vtep_search_hash(ip_encap->vrf_handle, &ip_encap->dst_ip);
    if (!dst_vtep_index) {
        dst_vtep_index = switch_tunnel_dst_vtep_insert_hash(ip_encap->vrf_handle, &ip_encap->dst_ip);
    }
#ifdef SWITCH_PD
    status = switch_pd_src_vtep_table_add_entry(device, ip_encap,
                 intf_info->ifindex, &ip_encap_hdl->src_hw_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d: unable to add src vtep entry for interface %lx", 
                     __FUNCTION__, __LINE__, intf_handle);
        goto cleanup;
    }

    status = switch_pd_dest_vtep_table_add_entry(device, ip_encap, &ip_encap_hdl->dst_hw_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d: unable to add dest vtep entry for interface %lx", 
                     __FUNCTION__, __LINE__, intf_handle);
        goto cleanup;
    }

    status = switch_pd_tunnel_src_rewrite_table_add_entry(device,
                                       src_vtep_index, ip_encap,
                                       &ip_encap_hdl->src_rw_hw_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d: unable to add src rewrite entry for interface %lx", 
                     __FUNCTION__, __LINE__, intf_handle);
        goto cleanup;
    }

    status = switch_pd_tunnel_dst_rewrite_table_add_entry(device,
                                       dst_vtep_index, ip_encap,
                                       &ip_encap_hdl->dst_rw_hw_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d: unable to add dst rewrite entry for interface %lx", 
                     __FUNCTION__, __LINE__, intf_handle);
        goto cleanup;
    }
#endif /* SWITCH_PD */
    SWITCH_API_TRACE("%s:%d: Tunnel interface %lx created [%d : %d]", __FUNCTION__, __LINE__,
                 intf_handle, src_vtep_index, dst_vtep_index);
cleanup:
    return status;
}

static switch_status_t
switch_tunnel_ip_encap_table_delete_entries(switch_device_t device,
                                            switch_handle_t intf_handle,
                                            switch_interface_info_t *intf_info)
{
    switch_ip_encap_t                 *ip_encap = NULL;
    switch_ip_encap_pd_hdl_t          *ip_encap_hdl = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    ip_encap = &(SWITCH_INTF_TUNNEL_IP_ENCAP(intf_info));
    ip_encap_hdl = &intf_info->ip_encap_hdl;
    status = switch_tunnel_src_vtep_delete_hash(ip_encap->vrf_handle, &ip_encap->src_ip);
    status = switch_tunnel_dst_vtep_delete_hash(ip_encap->vrf_handle, &ip_encap->dst_ip);
#ifdef SWITCH_PD
    status = switch_pd_src_vtep_table_delete_entry(device, ip_encap, ip_encap_hdl->src_hw_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d: unable to delete src vtep entry for interface %lx",
                     __FUNCTION__, __LINE__, intf_handle);
        goto cleanup;
    }
    status = switch_pd_dest_vtep_table_delete_entry(device, ip_encap, ip_encap_hdl->dst_hw_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d: unable to delete dst vtep entry for interface %lx",
                     __FUNCTION__, __LINE__, intf_handle);
        goto cleanup;
    }
    status = switch_pd_tunnel_src_rewrite_table_delete_entry(device, ip_encap_hdl->src_rw_hw_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d: unable to delete src rewrite entry for interface %lx",
                     __FUNCTION__, __LINE__, intf_handle);
        goto cleanup;
    }
    status = switch_pd_tunnel_dst_rewrite_table_delete_entry(device, ip_encap_hdl->dst_rw_hw_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d: unable to delete dst rewrite entry for interface %lx",
                     __FUNCTION__, __LINE__, intf_handle);
        goto cleanup;
    }
#endif /* SWITCH_PD */
cleanup:
    return status;
}

static uint32_t
switch_tunnel_mpls_get_pop_label(switch_mpls_encap_t *mpls_encap)
{
    switch_mpls_pop_t         *pop_info = NULL;
    pop_info = &mpls_encap->u.pop_info;
    return pop_info->tag[0].label;
}

static switch_status_t
switch_tunnel_mpls_table_add_entries(switch_device_t device,
                                     switch_handle_t bd_handle,
                                     p4_pd_entry_hdl_t *entry_hdl,
                                     switch_mpls_encap_t *mpls_encap)
{
    switch_interface_info_t           *eg_intf_info = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_ifindex_t                   egress_ifindex = 0;
    uint32_t                           label = 0;

    if (bd_handle) {
        bd_info = switch_bd_get(bd_handle);
        if (!bd_info) {
            return SWITCH_STATUS_INVALID_HANDLE;
        }
    }

    switch (mpls_encap->mpls_mode) {
        case SWITCH_API_MPLS_INITIATE:
            break;
        case SWITCH_API_MPLS_TRANSIT:
            switch(mpls_encap->mpls_action) {
                case SWITCH_API_MPLS_ACTION_SWAP:
                    label = SWITCH_MPLS_SWAP_OLD_LABEL(mpls_encap);
                    break;
                case SWITCH_API_MPLS_ACTION_SWAP_PUSH:
                    label = SWITCH_MPLS_SWAP_PUSH_OLD_LABEL(mpls_encap);
                    break;
                default:
                    return SWITCH_STATUS_UNSUPPORTED_TYPE;

            }
            status = switch_pd_mpls_table_add_entry(device, mpls_encap,
                                               handle_to_id(bd_handle),
                                               label, bd_info, egress_ifindex,
                                               entry_hdl);
            break;
        case SWITCH_API_MPLS_TERMINATE:
            if (mpls_encap->mpls_type == SWITCH_API_MPLS_TYPE_PW) {
                eg_intf_info = switch_api_interface_get(mpls_encap->egress_if);
                if (!eg_intf_info) {
                    SWITCH_API_ERROR("%s:%d: invalid egress interface for pw mode!",
                                 __FUNCTION__, __LINE__);
                    return SWITCH_STATUS_INVALID_INTERFACE;
                }
                egress_ifindex = eg_intf_info->ifindex;
            }
            label = switch_tunnel_mpls_get_pop_label(mpls_encap);
            status = switch_pd_mpls_table_add_entry(device, mpls_encap,
                                               handle_to_id(bd_handle),
                                               label, bd_info, egress_ifindex,
                                               entry_hdl);

            break;
        default:
            SWITCH_API_ERROR("%s:%d invalid mpls tunnel mode!", __FUNCTION__,
                         __LINE__);
            status = SWITCH_STATUS_UNSUPPORTED_TYPE;
    }
    return status;
}

static switch_status_t
switch_tunnel_mpls_table_delete_entries(switch_device_t device,
                                        p4_pd_entry_hdl_t entry_hdl,
                                        switch_mpls_encap_t *mpls_encap)
{
    switch_status_t               status = SWITCH_STATUS_SUCCESS;

    switch (mpls_encap->mpls_mode) {
        case SWITCH_API_MPLS_INITIATE:
            break;
        case SWITCH_API_MPLS_TRANSIT:
            status = switch_pd_mpls_table_delete_entry(device, entry_hdl);
            break;
        case SWITCH_API_MPLS_TERMINATE:
            status = switch_pd_mpls_table_delete_entry(device, entry_hdl);
            break;
        default:
            SWITCH_API_ERROR("%s:%d invalid mpls tunnel mode!", __FUNCTION__,
                         __LINE__);
            status = SWITCH_STATUS_UNSUPPORTED_TYPE;
    }
    return status;
}

switch_handle_t
switch_api_tunnel_interface_create(switch_device_t device,
                                   switch_direction_t direction,
                                   switch_tunnel_info_t *tunnel_info)
{
    switch_handle_t                    intf_handle = 0;
    switch_api_interface_info_t        info;
    switch_interface_info_t           *intf_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    UNUSED(device);
    memset(&info, 0, sizeof(switch_api_interface_info_t));
    info.type = SWITCH_API_INTERFACE_TUNNEL;
    info.flags.core_intf = tunnel_info->flags.core_intf;
    info.flags.flood_enabled = tunnel_info->flags.flood_enabled;
    memcpy(&(info.u.tunnel_info), tunnel_info, sizeof(switch_tunnel_info_t));
    intf_handle = switch_api_interface_create(device, &info);
    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        SWITCH_API_ERROR("%s:%d: unable to allocate memory!", __FUNCTION__, __LINE__);
        return SWITCH_STATUS_NO_MEMORY;
    }

    if (tunnel_info->encap_mode == SWITCH_API_TUNNEL_ENCAP_MODE_IP) {
        status = switch_tunnel_ip_encap_table_add_entries(device, intf_handle, intf_info);
    }

    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d: failed to create tunnel interface!", __FUNCTION__, __LINE__);
        return SWITCH_API_INVALID_HANDLE;
    }
    return intf_handle;
}

switch_status_t
switch_api_tunnel_interface_delete(switch_device_t device, switch_handle_t intf_handle)
{
    switch_interface_info_t           *intf_info = NULL;
    switch_tunnel_info_t              *tunnel_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        SWITCH_API_ERROR("%s:%d: invalid interface handle %lx", 
                     __FUNCTION__, __LINE__, intf_handle);
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    tunnel_info = &(SWITCH_INTF_TUNNEL_INFO(intf_info));
    if (tunnel_info->encap_mode == SWITCH_API_TUNNEL_ENCAP_MODE_IP) {
        status = switch_tunnel_ip_encap_table_delete_entries(device, intf_handle, intf_info);
    }

    status = switch_api_interface_delete(device, intf_handle);
    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d: unable to delete interface %lx",
                     __FUNCTION__, __LINE__, intf_handle);
        goto cleanup;
    }
    SWITCH_API_TRACE("%s:%d: Tunnel interface %lx deleted", __FUNCTION__, __LINE__, intf_handle);
cleanup:
    return status;
}

switch_status_t
switch_api_logical_network_member_add(switch_device_t device,
                                      switch_handle_t bd_handle,
                                      switch_handle_t intf_handle)
{
    switch_interface_info_t           *intf_info = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS; 

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        SWITCH_API_ERROR("%s:%d invalid interface handle %lx", 
                     __FUNCTION__, __LINE__, intf_handle);
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        SWITCH_API_ERROR("%s:%d invalid logical network handle %lx", 
                     __FUNCTION__, __LINE__, bd_handle);
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    intf_info->ln_bd_handle = bd_handle;
    switch(SWITCH_LN_NETWORK_TYPE(bd_info)) {
        case SWITCH_LOGICAL_NETWORK_TYPE_ENCAP_BASIC:
            status = switch_api_logical_network_member_add_basic(device, bd_handle, intf_handle);
            break;
        case SWITCH_LOGICAL_NETWORK_TYPE_ENCAP_ENHANCED:
            status = switch_api_logical_network_member_add_enhanced(device, bd_handle, intf_handle);
            break;

        default:
            status = SWITCH_STATUS_INVALID_LN_TYPE;
    }
    return status;
}

switch_status_t
switch_api_logical_network_member_add_basic(switch_device_t device,
                                            switch_handle_t bd_handle,
                                            switch_handle_t intf_handle)
{
    switch_interface_info_t           *intf_info = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_ln_member_t                *ln_member = NULL;
    switch_ip_encap_t                 *ip_encap = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_encap_type_t                encap_type = SWITCH_API_ENCAP_TYPE_NONE;
    uint16_t                           tunnel_vni = 0;
    uint8_t                            tunnel_type = 0;
    switch_vlan_t                      vlan_id = 0;

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        SWITCH_API_ERROR("%s:%d invalid interface handle %lx",
                     __FUNCTION__, __LINE__, intf_handle);
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        SWITCH_API_ERROR("%s:%d invalid logical network handle %lx",
                     __FUNCTION__, __LINE__, bd_handle);
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    intf_info->ln_bd_handle = bd_handle;
    ln_member = switch_api_logical_network_search_member(bd_handle, intf_handle);
    if (!ln_member) {
        ln_member = switch_malloc(sizeof(switch_ln_member_t), 1);
        if (!ln_member) {
            return SWITCH_STATUS_NO_MEMORY;
        }
        ln_member->member = intf_handle;
        ln_member->rid = switch_mcast_rid_allocate();
        tommy_list_insert_head(&(bd_info->members), &(ln_member->node), ln_member);
    }

    if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_TUNNEL) {
        encap_type = SWITCH_INTF_TUNNEL_ENCAP_TYPE(intf_info);
        ip_encap = &(SWITCH_INTF_TUNNEL_IP_ENCAP(intf_info));
        tunnel_vni = SWITCH_LN_TUNNEL_VNI(bd_info);
        tunnel_type = switch_tunnel_get_egress_tunnel_type(encap_type, ip_encap);
#ifdef SWITCH_PD
        status = switch_pd_tunnel_table_add_entry(device, encap_type,
                                           tunnel_vni,
                                           ln_member->rid,
                                           bd_info,
                                           ip_encap,
                                           handle_to_id(bd_handle),
                                           ln_member->tunnel_hw_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d: unable to add tunnel entry for interface %lx ln %lx",
                         __FUNCTION__, __LINE__, intf_handle, bd_handle);
            goto cleanup;
        }
        status = switch_pd_egress_vni_table_add_entry(device,
                                           handle_to_id(bd_handle),
                                           tunnel_vni, tunnel_type,
                                           &ln_member->egress_bd_hw_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d: unable to add egress bd map entry for interface %lx ln %lx",
                         __FUNCTION__, __LINE__, intf_handle, bd_handle);
            goto cleanup;
        }
#endif
    } else {
        switch(SWITCH_INTF_TYPE(intf_info)) {
            case SWITCH_API_INTERFACE_L2_VLAN_ACCESS:
                vlan_id = 0;
                break;
            case SWITCH_API_INTERFACE_L2_PORT_VLAN:
                vlan_id = SWITCH_INTF_PV_VLAN_ID(intf_info);
                break;
            default:
                SWITCH_API_ERROR("%s:%d: trying to add unsupported interface type for ln %lx",
                             __FUNCTION__, __LINE__, bd_handle);
                return SWITCH_STATUS_UNSUPPORTED_TYPE;
        }
        status = switch_pd_port_vlan_mapping_table_add_entry(device, vlan_id, 0,
                                                    intf_info,
                                                    bd_info->bd_entry,
                                                    &(ln_member->pv_hw_entry));
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d: unable to add port-vlan entry for interface %lx ln %lx",
                         __FUNCTION__, __LINE__, intf_handle, bd_handle);
            goto cleanup;
        }
        status = switch_api_vlan_xlate_add(device, bd_handle, intf_handle, vlan_id);
    }

    if (SWITCH_INTF_FLOOD_ENABLED(intf_info)) {
        switch_vlan_interface_t vlan_intf;
        memset(&vlan_intf, 0, sizeof(vlan_intf));
        vlan_intf.vlan_handle = bd_handle;
        vlan_intf.intf_handle = intf_handle;
        status = switch_api_multicast_member_add(device,
                                                 bd_info->uuc_mc_index,
                                                 1, &vlan_intf);
    }
    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d: Unable to add interface %lx to flood list of ln %lx",
                     __FUNCTION__, __LINE__, intf_handle, bd_handle);
    }

cleanup:
    return status;
}

switch_status_t
switch_api_logical_network_member_add_enhanced(switch_device_t device,
                                               switch_handle_t bd_handle,
                                               switch_handle_t intf_handle)
{
    switch_interface_info_t           *intf_info = NULL;
    switch_tunnel_info_t              *tunnel_info = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_encap_info_t               *encap_info = NULL;
    switch_ln_member_t                *ln_member = NULL;
    switch_ip_encap_t                 *ip_encap = NULL;
    switch_mpls_encap_t               *mpls_encap = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_encap_type_t                encap_type = SWITCH_API_ENCAP_TYPE_NONE;
    uint16_t                           tunnel_vni = 0;
    uint8_t                            tunnel_type = 0;
    switch_vlan_t                      vlan_id = 0;

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        SWITCH_API_ERROR("%s:%d invalid interface handle %lx", 
                     __FUNCTION__, __LINE__, intf_handle);
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        SWITCH_API_ERROR("%s:%d invalid logical network handle %lx", 
                     __FUNCTION__, __LINE__, bd_handle);
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    intf_info->ln_bd_handle = bd_handle;
    ln_member = switch_api_logical_network_search_member(bd_handle, intf_handle);
    if (!ln_member) {
        ln_member = switch_malloc(sizeof(switch_ln_member_t), 1);
        if (!ln_member) {
            return SWITCH_STATUS_NO_MEMORY;
        }
        ln_member->member = intf_handle;
        ln_member->rid = switch_mcast_rid_allocate();
        tommy_list_insert_head(&(bd_info->members), &(ln_member->node), ln_member);
    }

    if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_TUNNEL) {
        tunnel_info = &(SWITCH_INTF_TUNNEL_INFO(intf_info));
        if (tunnel_info->encap_mode == SWITCH_API_TUNNEL_ENCAP_MODE_IP) {
            encap_type = SWITCH_INTF_TUNNEL_ENCAP_TYPE(intf_info);
            ip_encap = &(SWITCH_INTF_TUNNEL_IP_ENCAP(intf_info));
            encap_info = &(SWITCH_INTF_TUNNEL_ENCAP_INFO(intf_info));
            tunnel_vni = switch_tunnel_get_tunnel_vni(encap_info);
            tunnel_type = switch_tunnel_get_egress_tunnel_type(encap_info->encap_type, ip_encap);

#ifdef SWITCH_PD
            ip_encap = &(SWITCH_INTF_TUNNEL_IP_ENCAP(intf_info));
            status = switch_pd_tunnel_table_add_entry(device, encap_type,
                                               tunnel_vni,
                                               ln_member->rid,
                                               bd_info,
                                               ip_encap,
                                               handle_to_id(bd_handle),
                                               ln_member->tunnel_hw_entry);
            if (status != SWITCH_STATUS_SUCCESS) {
                SWITCH_API_ERROR("%s:%d: unable to add tunnel entry for interface %lx ln %lx",
                             __FUNCTION__, __LINE__, intf_handle, bd_handle);
                goto cleanup;
            }

            status = switch_pd_egress_vni_table_add_entry(device,
                                               handle_to_id(bd_handle),
                                               tunnel_vni, tunnel_type,
                                               &ln_member->egress_bd_hw_entry);
            if (status != SWITCH_STATUS_SUCCESS) {
                SWITCH_API_ERROR("%s:%d: unable to add egress bd map entry for interface %lx ln %lx",
                             __FUNCTION__, __LINE__, intf_handle, bd_handle);
                goto cleanup;
            }
        } else if (tunnel_info->encap_mode == SWITCH_API_TUNNEL_ENCAP_MODE_MPLS) {
            mpls_encap = &(SWITCH_INTF_TUNNEL_MPLS_ENCAP(intf_info));
            status = switch_tunnel_mpls_table_add_entries(device, bd_handle,
                                               ln_member->tunnel_hw_entry, mpls_encap);
            if (status != SWITCH_STATUS_SUCCESS) {
                SWITCH_API_ERROR("%s:%d unable to add mpls entry!", __FUNCTION__, __LINE__);
                goto cleanup;
            }
        }
#endif
    } else {
        // access port
        switch(SWITCH_INTF_TYPE(intf_info)) {
            case SWITCH_API_INTERFACE_L2_VLAN_ACCESS:
                vlan_id = 0;
                break;
            case SWITCH_API_INTERFACE_L2_PORT_VLAN:
                vlan_id = SWITCH_INTF_PV_VLAN_ID(intf_info);
                break;
            default:
                SWITCH_API_ERROR("%s:%d: trying to add unsupported interface type for ln %lx",
                             __FUNCTION__, __LINE__, bd_handle);
                return SWITCH_STATUS_UNSUPPORTED_TYPE;
        }
#ifdef SWITCH_PD
        status = switch_pd_port_vlan_mapping_table_add_entry(device, vlan_id, 0,
                                                    intf_info,
                                                    bd_info->bd_entry,
                                                    &(ln_member->pv_hw_entry));
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d: unable to add port to vlan!.", __FUNCTION__, __LINE__);
            return status;
        }
        status = switch_api_vlan_xlate_add(device, bd_handle, intf_handle, vlan_id);
#endif
    }
    if (SWITCH_INTF_FLOOD_ENABLED(intf_info)) {
        switch_vlan_interface_t vlan_intf;
        memset(&vlan_intf, 0, sizeof(vlan_intf));
        vlan_intf.vlan_handle = bd_handle;
        vlan_intf.intf_handle = intf_handle;
        status = switch_api_multicast_member_add(device,
                                                 bd_info->uuc_mc_index,
                                                 1, &vlan_intf);
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d: Unable to add interface %lx to flood list of ln %lx",
                             __FUNCTION__, __LINE__, intf_handle, bd_handle);
        }
    }
cleanup:
    return status;
}

switch_status_t
switch_api_logical_network_member_remove_basic(switch_device_t device,
                                               switch_handle_t bd_handle,
                                               switch_handle_t intf_handle)
{
    switch_interface_info_t           *intf_info = NULL;
    switch_ln_member_t                *ln_member = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_vlan_t                      vlan_id = 0;

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    intf_info->ln_bd_handle = 0;
    ln_member = switch_api_logical_network_search_member(bd_handle, intf_handle);
    if (!ln_member) {
        SWITCH_API_ERROR("%s:%d: unable to find member interface %lx for ln %lx",
                     __FUNCTION__, __LINE__, intf_handle, bd_handle);
        goto cleanup;
    }

    if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_TUNNEL) {
#ifdef SWITCH_PD
        status = switch_pd_tunnel_table_delete_entry(device, ln_member->tunnel_hw_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d: unable to delete tunnel entry for interface %lx ln %lx",
                         __FUNCTION__, __LINE__, intf_handle, bd_handle);
            goto cleanup;
        }

        status = switch_pd_egress_vni_table_delete_entry(device, ln_member->egress_bd_hw_entry);
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d: unable to delete egress bd map entry for interface %lx ln %lx",
                         __FUNCTION__, __LINE__, intf_handle, bd_handle);
            goto cleanup;
        }
#endif
    } else {
        switch(SWITCH_INTF_TYPE(intf_info)) {
            case SWITCH_API_INTERFACE_L2_VLAN_ACCESS:
                vlan_id = 0;
                break;
            case SWITCH_API_INTERFACE_L2_PORT_VLAN:
                vlan_id = SWITCH_INTF_PV_VLAN_ID(intf_info);
                break;
            default:
                SWITCH_API_ERROR("%s:%d: trying to add unsupported interface type for ln %lx",
                             __FUNCTION__, __LINE__, bd_handle);
                return SWITCH_STATUS_UNSUPPORTED_TYPE;
        }
        status = switch_pd_port_vlan_mapping_table_delete_entry(device, ln_member->pv_hw_entry);
#ifdef SWITCH_PD
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d: unable to delete port-vlan entry for interface %lx ln %lx",
                         __FUNCTION__, __LINE__, intf_handle, bd_handle);
            goto cleanup;
#endif
        }
        status = switch_api_vlan_xlate_remove(device, bd_handle, intf_handle, vlan_id);
    }
    if (SWITCH_INTF_FLOOD_ENABLED(intf_info)) {
        switch_vlan_interface_t vlan_intf;
        memset(&vlan_intf, 0, sizeof(vlan_intf));
        vlan_intf.vlan_handle = bd_handle;
        vlan_intf.intf_handle = intf_handle;
        status = switch_api_multicast_member_delete(device,
                                                    bd_info->uuc_mc_index,
                                                    1, &vlan_intf);
    }
    if (status != SWITCH_STATUS_SUCCESS) {
        SWITCH_API_ERROR("%s:%d: Unable to add interface %lx to flood list of ln %lx",
                     __FUNCTION__, __LINE__, intf_handle, bd_handle);
    }
    switch_mcast_rid_free(ln_member->rid);
    tommy_list_remove_existing(&(bd_info->members), &(ln_member->node));
    switch_free(ln_member);
cleanup:
    return status;
}

switch_status_t
switch_api_logical_network_member_remove_enhanced(switch_device_t device,
                                                  switch_handle_t bd_handle,
                                                  switch_handle_t intf_handle)
{
    switch_interface_info_t           *intf_info = NULL;
    switch_ln_member_t                *ln_member = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_tunnel_info_t              *tunnel_info = NULL;
    switch_mpls_encap_t               *mpls_encap = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_vlan_t                      vlan_id = 0;

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    intf_info->ln_bd_handle = 0;
    ln_member = switch_api_logical_network_search_member(bd_handle, intf_handle);
    if (!ln_member) {
        SWITCH_API_ERROR("%s:%d: unable to find member interface %lx for ln %lx",
                     __FUNCTION__, __LINE__, intf_handle, bd_handle);
        goto cleanup;
    }

    if (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_TUNNEL) {
        tunnel_info = &(SWITCH_INTF_TUNNEL_INFO(intf_info));
        if (tunnel_info->encap_mode == SWITCH_API_TUNNEL_ENCAP_MODE_IP) {
#ifdef SWITCH_PD
            status = switch_pd_tunnel_table_delete_entry(device, ln_member->tunnel_hw_entry);
            if (status != SWITCH_STATUS_SUCCESS) {
                SWITCH_API_ERROR("%s:%d: unable to delete tunnel entry for interface %lx ln %lx",
                             __FUNCTION__, __LINE__, intf_handle, bd_handle);
                goto cleanup;
            }

            status = switch_pd_egress_vni_table_delete_entry(device, ln_member->egress_bd_hw_entry);
            if (status != SWITCH_STATUS_SUCCESS) {
                SWITCH_API_ERROR("%s:%d: unable to delete egress bd map entry for interface %lx ln %lx",
                             __FUNCTION__, __LINE__, intf_handle, bd_handle);
                goto cleanup;
            }
        } else if (tunnel_info->encap_mode == SWITCH_API_TUNNEL_ENCAP_MODE_MPLS) {
            mpls_encap = &(SWITCH_INTF_TUNNEL_MPLS_ENCAP(intf_info));
            status = switch_tunnel_mpls_table_delete_entries(device, ln_member->tunnel_hw_entry[0], mpls_encap);
        }
#endif
    } else {
        switch(SWITCH_INTF_TYPE(intf_info)) {
            case SWITCH_API_INTERFACE_L2_VLAN_ACCESS:
                vlan_id = 0;
                break;
            case SWITCH_API_INTERFACE_L2_PORT_VLAN:
                vlan_id = SWITCH_INTF_PV_VLAN_ID(intf_info);
                break;
            default:
                SWITCH_API_ERROR("%s:%d: trying to add unsupported interface type for ln %lx",
                             __FUNCTION__, __LINE__, bd_handle);
                return SWITCH_STATUS_UNSUPPORTED_TYPE;
        }
        status = switch_pd_port_vlan_mapping_table_delete_entry(device, ln_member->pv_hw_entry);
#ifdef SWITCH_PD
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d: unable to delete port-vlan entry for interface %lx ln %lx",
                         __FUNCTION__, __LINE__, intf_handle, bd_handle);
            goto cleanup;
#endif
        }
        status = switch_api_vlan_xlate_remove(device, bd_handle, intf_handle, vlan_id);
    }
    if (SWITCH_INTF_FLOOD_ENABLED(intf_info)) {
        switch_vlan_interface_t vlan_intf;
        memset(&vlan_intf, 0, sizeof(vlan_intf));
        vlan_intf.vlan_handle = bd_handle;
        vlan_intf.intf_handle = intf_handle;
        status = switch_api_multicast_member_delete(device,
                                                    bd_info->uuc_mc_index,
                                                    1, &vlan_intf);
        if (status != SWITCH_STATUS_SUCCESS) {
            SWITCH_API_ERROR("%s:%d: Unable to remove interface %lx from flood list of ln %lx",
                         __FUNCTION__, __LINE__, intf_handle, bd_handle);
        }
    }
    switch_mcast_rid_free(ln_member->rid);
    tommy_list_remove_existing(&(bd_info->members), &(ln_member->node));
    switch_free(ln_member);
cleanup:
    return status;
}

switch_status_t
switch_api_logical_network_member_remove(switch_device_t device,
                                         switch_handle_t bd_handle,
                                         switch_handle_t intf_handle)
{
    switch_interface_info_t           *intf_info = NULL;
    switch_bd_info_t                  *bd_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
    }

    bd_info = switch_bd_get(bd_handle);
    if (!bd_info) {
        return SWITCH_STATUS_INVALID_VLAN_ID;
    }

    switch(SWITCH_LN_NETWORK_TYPE(bd_info)) {
        case SWITCH_LOGICAL_NETWORK_TYPE_ENCAP_BASIC:
            status = switch_api_logical_network_member_remove_basic(device, bd_handle, intf_handle);
            break;
        case SWITCH_LOGICAL_NETWORK_TYPE_ENCAP_ENHANCED:
            status = switch_api_logical_network_member_remove_enhanced(device, bd_handle, intf_handle);
            break;
        default:
            status = SWITCH_STATUS_INVALID_LN_TYPE;
    }
    return status;
}

uint16_t
switch_tunnel_get_tunnel_vni(switch_encap_info_t *encap_info) 
{
    uint16_t tunnel_vni = 0;
    switch(encap_info->encap_type)
    {
        case SWITCH_API_ENCAP_TYPE_VXLAN:
            tunnel_vni = SWITCH_ENCAP_VXLAN_VNI(encap_info);
            break;
        case SWITCH_API_ENCAP_TYPE_GENEVE:
            tunnel_vni = SWITCH_ENCAP_GENEVE_VNI(encap_info);
            break;
        case SWITCH_API_ENCAP_TYPE_NVGRE:
            tunnel_vni = SWITCH_ENCAP_NVGRE_VNI(encap_info);
            break;
        default:
            tunnel_vni = 0;
    }
    return tunnel_vni;
}

switch_tunnel_type_ingress_t
switch_tunnel_get_ingress_tunnel_type(switch_ip_encap_t *ip_encap)
{
    switch_tunnel_type_ingress_t tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_NONE;
    switch (ip_encap->proto)
    {
        case IPPROTO_IPIP:
        case IPPROTO_IPV6:
            tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_IP_IN_IP;
            break;
        case IPPROTO_GRE: {
            switch (ip_encap->u.gre.protocol) {
                case GRE_PROTO_NVGRE:
                    tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_NVGRE;
                    break;
                default :
                    tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_GRE;
                    break;
            }
            break;
        }
        case IPPROTO_UDP: {
            switch (SWITCH_IP_ENCAP_UDP_DST_PORT(ip_encap)) {
                case UDP_PORT_VXLAN:
                    tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_VXLAN;
                    break;
                case UDP_PORT_GENEVE:
                    tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_GENEVE;
                    break;
                default :
                    break;
            }
            break;
        }
        default:
            break;
    }

    return tunnel_type;
}

switch_tunnel_type_egress_t
switch_tunnel_get_egress_tunnel_type(switch_encap_type_t encap_type, switch_ip_encap_t *ip_encap)
{
    switch_tunnel_type_egress_t tunnel_type = 0;
    switch(encap_type)
    {
        case SWITCH_API_ENCAP_TYPE_VXLAN:
            if (SWITCH_IP_ENCAP_SRC_IP_TYPE(ip_encap) == SWITCH_API_IP_ADDR_V4) {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_VXLAN;
            } else {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_VXLAN;
            }
            break;
        case SWITCH_API_ENCAP_TYPE_GENEVE:
            if (SWITCH_IP_ENCAP_SRC_IP_TYPE(ip_encap) == SWITCH_API_IP_ADDR_V4) {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_GENEVE;
            } else {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_GENEVE;
            }
            break;
        case SWITCH_API_ENCAP_TYPE_NVGRE:
            if (SWITCH_IP_ENCAP_SRC_IP_TYPE(ip_encap) == SWITCH_API_IP_ADDR_V4) {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_NVGRE;
            } else {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_NVGRE;
            }
            break;
        default:
            tunnel_type = 0; 
    }
    return tunnel_type;
}

switch_status_t
switch_api_mpls_tunnel_transit_create(switch_device_t device, switch_mpls_encap_t *mpls_encap)
{
    switch_mpls_info_t                *mpls_info = NULL;
    void                              *temp = NULL;
    uint32_t                           swap_label = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    switch(mpls_encap->mpls_action) {
        case SWITCH_API_MPLS_ACTION_SWAP:
            swap_label = SWITCH_MPLS_SWAP_OLD_LABEL(mpls_encap);
            break;
        case SWITCH_API_MPLS_ACTION_SWAP_PUSH:
            swap_label = SWITCH_MPLS_SWAP_PUSH_OLD_LABEL(mpls_encap);
            break;
        default:
            return SWITCH_STATUS_UNSUPPORTED_TYPE;
    }
    JLG(temp, mpls_transit_array, swap_label);
    if (!temp) {
        mpls_info = switch_malloc(sizeof(switch_mpls_info_t), 1);
        if (!mpls_info) {
            SWITCH_API_ERROR("%s:%d: No memory!", __FUNCTION__, __LINE__);
            return SWITCH_STATUS_NO_MEMORY;
        }
        memcpy(&mpls_info->mpls_encap, mpls_encap, sizeof(switch_mpls_encap_t));
        JLI(temp, mpls_transit_array, swap_label);
        *(unsigned long *)temp = (unsigned long) mpls_info;
        status = switch_tunnel_mpls_table_add_entries(device, 0, &mpls_info->tunnel_hw_entry, mpls_encap);
    } else {
        //TODO: Update Mpls transit
    }
    return status;
}

switch_status_t
switch_api_mpls_tunnel_transit_delete(switch_device_t device, switch_mpls_encap_t *mpls_encap)
{
    switch_mpls_info_t                *mpls_info = NULL;
    void                              *temp = NULL;
    uint32_t                           swap_label = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    switch(mpls_encap->mpls_action) {
        case SWITCH_API_MPLS_ACTION_SWAP:
            swap_label = SWITCH_MPLS_SWAP_OLD_LABEL(mpls_encap);
            break;
        case SWITCH_API_MPLS_ACTION_SWAP_PUSH:
            swap_label = SWITCH_MPLS_SWAP_PUSH_OLD_LABEL(mpls_encap);
            break;
        default:
            return SWITCH_STATUS_UNSUPPORTED_TYPE;
    }
    JLG(temp, mpls_transit_array, swap_label);
    if (!temp) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    mpls_info = (switch_mpls_info_t *) (*(unsigned long *)temp);
    status = switch_tunnel_mpls_table_delete_entries(device, mpls_info->tunnel_hw_entry, mpls_encap);
    JLD(status, mpls_transit_array, swap_label);
    switch_free(mpls_info);
    return status;
}
