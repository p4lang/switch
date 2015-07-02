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

#ifndef _switch_rmac_h_
#define _switch_rmac_h_

#include "switch_status.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup RMAC Router MAC API
 *  API functions define and manipulate router mac groups
 *  @{
 */ // begin of Router MAC API

/**
 Create a router mac group
 Returns rmac id which will be used to identify the group
 uniquely. 0 is invalid.
 @param device Device to be programmed
 */
switch_handle_t switch_api_router_mac_group_create(switch_device_t device);

/**
 Delete a router mac group
 Returns success/failure based on the group ID.
 @param device Device to be programmed
 @param rmac_handle - Rmac group to be deleted.
 */
switch_status_t switch_api_router_mac_group_delete(switch_device_t device, switch_handle_t rmac_handle);

/**
 Add a mac to router mac group
 @param device Device to be programmed
 @param rmac_handle - ID of the RMAC group
 @param mac - Router mac address to be added to the group
 */
switch_status_t switch_api_router_mac_add(switch_device_t device, switch_handle_t rmac_handle, switch_mac_addr_t *mac);

/**
 Delete a mac from router mac group
 @param device- Device to be programmed
 @param rmac_handle - ID of the RMAC group
 @param mac - Router mac address to be removed from the group
 */
switch_status_t switch_api_router_mac_delete(switch_device_t device, switch_handle_t rmac_handle, switch_mac_addr_t *mac);

/**
 Set router mac handle for L3 Interface
 @param intf_handle - Interface handle
 @param value - Value of router mac handle
 */
switch_status_t switch_api_interface_router_mac_handle_set(switch_handle_t intf_handle, uint64_t value);

/**
 Set router mac handle for L3 Interface
 @param intf_handle - Interface handle
 @param value - Value of router mac handle
 */
switch_status_t switch_api_interface_router_mac_handle_get(switch_handle_t intf_handle, uint64_t *value);

/**
 Dump router mac group table
 */
switch_status_t switch_api_router_mac_group_print_all(void);

/** @} */ // end of Router MAC API
#ifdef __cplusplus
}
#endif

#endif
