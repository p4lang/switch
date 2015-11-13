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

#ifndef _switch_l3_h_
#define _switch_l3_h_

#include "switch_base_types.h"
#include "switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
/** @defgroup L3 L3 API
 *  API functions create IP interfaces and route
 *  @{
 */ // begin of L3 API
//L3
    
//RPF check
/** Mode for RPF check - Only use src or dest address or qualify in interface */
typedef enum {
    SWITCH_API_RPF_CHECK_DEFAULT,
    SWITCH_API_RPF_CHECK_LOOSE,
    SWITCH_API_RPF_CHECK_STRICT
} switch_urpf_mode_t;

/**
 Configure IP address on L3 interface
 @param device device
 @param interface_handle interface handle returned from interface_create()
 @param vrf virtual domain identifier
 @param ip_addr IP address to be configured(v4 or v6)
*/
switch_status_t switch_api_l3_interface_address_add(switch_device_t device,
                                                    switch_handle_t interface_handle,
                                                    switch_handle_t vrf,
                                                    switch_ip_addr_t *ip_addr);
/**
 Delete a configured IP address on interface
 @param device device
 @param interface_handle interface handle returned from interface_create()
 @param vrf virtual domain identifier
 @param ip_addr IP address to be deleted
*/
switch_status_t switch_api_l3_interface_address_delete(switch_device_t device,
                                                       switch_handle_t interface_handle,
                                                       switch_handle_t vrf,
                                                       switch_ip_addr_t *ip_addr);
/**
 Host address reachability entry - inserted into a Hash table to match a
 /32 IPv4 ot /128 IPv6 address, When there are multiple paths to reach
 the same destiantion ECMP tables is used implicitly
 @param device device
 @param vrf virtual domain identifier
 @param ip_addr IP address
 @param nhop_handle Nexthop Handle
*/
switch_status_t switch_api_l3_route_add(switch_device_t device, switch_handle_t vrf,
                               switch_ip_addr_t *ip_addr, switch_handle_t nhop_handle);
/**
 Host address entry delete
 @param device device
 @param vrf virtual domain identifier
 @param ip_addr IP address
 @param nhop_handle Nexthop Handle
*/
switch_status_t switch_api_l3_route_delete(switch_device_t device, switch_handle_t vrf,
                                   switch_ip_addr_t *ip_addr, switch_handle_t nhop_handle);
    
/**
 Set native vlan on interface
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Value of v4 urpf mode
*/
switch_status_t switch_api_interface_ipv4_urpf_mode_set(switch_handle_t intf_handle, uint64_t value);

/**
 Get native vlan on interface
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Value of v4 urpf mode
*/
switch_status_t switch_api_interface_ipv4_urpf_mode_get(switch_handle_t intf_handle, uint64_t *value);

/**
 Set native vlan on interface
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Value of v6 urpf mode
*/
switch_status_t switch_api_interface_ipv6_urpf_mode_set(switch_handle_t intf_handle, uint64_t value);

/**
 Get native vlan on interface
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Value of v6 urpf mode
*/
switch_status_t switch_api_interface_ipv6_urpf_mode_get(switch_handle_t intf_handle, uint64_t *value);

/**
 Iterator function prototype for L3 routes
 @param vrf_handle Vrf handle
 @param ip_addr IP Address
 @param nhop_handle Nexthop handle
 */
typedef switch_status_t (*switch_l3_table_iterator_fn)(switch_handle_t vrf_handle, switch_ip_addr_t ip_addr, switch_handle_t nhop_handle);

/**
 Get all L3 routes
 @param iterator_fn - Iterator function to be called
*/
switch_status_t switch_api_l3_route_entries_get(switch_l3_table_iterator_fn iterator_fn);

/**
 Get all L3 routes in a vrf
 @param vrf_handle Vrf handle
 @param iterator_fn - Iterator function to be called
 */
switch_status_t switch_api_l3_route_entries_get_by_vrf(switch_handle_t vrf_handle, switch_l3_table_iterator_fn iterator_fn);

/**
 Get all L3 V4 routes in a vrf 
 @param vrf_handle Vrf handle
 @param iterator_fn - Iterator function to be called
 */
switch_status_t switch_api_l3_v4_route_entries_get_by_vrf(switch_handle_t vrf_handle, switch_l3_table_iterator_fn iterator_fn);

/**
 Get all L3 V6 routes in a vrf 
 @param vrf_handle Vrf handle
 @param iterator_fn - Iterator function to be called
 */
switch_status_t switch_api_l3_v6_route_entries_get_by_vrf(switch_handle_t vrf_handle, switch_l3_table_iterator_fn iterator_fn);

/**
  Dump L3 routing table
 */
switch_status_t switch_api_l3_routes_print_all(void);
/** @} */ // end of L3 API

#ifdef __cplusplus
}
#endif

#endif
