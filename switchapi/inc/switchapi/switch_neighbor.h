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

#ifndef _switch_neighbor_h_
#define _switch_neighbor_h_

#include "switch_base_types.h"
#include "switch_handle.h"
#include "switch_interface.h"
#include "switch_l3.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

    
/** @defgroup ARP ARP/Neighbor API
 *  API functions to add IP-Mac associations
 *  @{
 */ // begin of ARP API

// ARP
/** ARP information */

/** Neighbor type */
typedef enum switch_neighbor_type_ {
    SWITCH_API_NEIGHBOR_NONE = 0,
    SWITCH_API_NEIGHBOR_MPLS_SWAP_L2VPN = 1,
    SWITCH_API_NEIGHBOR_MPLS_SWAP_L3VPN = 2,
    SWITCH_API_NEIGHBOR_MPLS_SWAP_PUSH_L2VPN = 3,
    SWITCH_API_NEIGHBOR_MPLS_SWAP_PUSH_L3VPN = 4,
    SWITCH_API_NEIGHBOR_MPLS_PUSH_L2VPN = 5,
    SWITCH_API_NEIGHBOR_MPLS_PUSH_L3VPN = 6,
    SWITCH_API_NEIGHBOR_IPV4_TUNNEL = 7,
    SWITCH_API_NEIGHBOR_IPV6_TUNNEL = 8,
} switch_neighbor_type_t;

/** Neighbor rewrite type */
typedef enum switch_neighbor_rw_type_ {
    SWITCH_API_NEIGHBOR_RW_TYPE_L2 = 0,
    SWITCH_API_NEIGHBOR_RW_TYPE_L3 = 1,
} switch_neighbor_rw_type_t;

/** Neighbor identifier */
typedef struct switch_api_neighbor_ {
    switch_neighbor_type_t neigh_type;      /**< neighbor type */
    switch_neighbor_rw_type_t rw_type;      /**< rewrite type */
    switch_handle_t vrf_handle;             /**< vrf instance */
    switch_ip_addr_t ip_addr;               /**< IP address */
    switch_handle_t nhop_handle;            /**< Next hop handle for neighbor */
    switch_handle_t interface;              /**< interface on which address is */
    switch_vlan_t vlan;                     /**< Override VLAN */
    switch_mac_addr_t mac_addr;             /**< MAC of destination */
    uint32_t mpls_label;                    /**< Mpls label for swap and swap-push */
    uint8_t header_count;                   /**< Header count for swap-push and push */
} switch_api_neighbor_t;

/**
ARP entry add
@param device device
@param neighbor - ARP information used to set egress table
*/
switch_handle_t switch_api_neighbor_entry_add(switch_device_t device, switch_api_neighbor_t *neighbor);

/**
ARP entry update
@param device device
@param neighbor_handle - Neighbor handle
@param neighbor - ARP information used to set egress table
*/
switch_status_t switch_api_neighbor_entry_update(switch_device_t device, switch_handle_t neighbor_handle,
                                         switch_api_neighbor_t *neighbor);

/**
ARP entry delete
@param device device
@param neighbor_handle - handle of the arp entry
*/
switch_status_t switch_api_neighbor_entry_remove(switch_device_t device, switch_handle_t neighbor_handle);

/**
 Dump neighbor table
 */
switch_status_t switch_api_neighbor_print_all(void);
    
/** @} */ // end of ARP API
    
#ifdef __cplusplus
}
#endif

#endif
