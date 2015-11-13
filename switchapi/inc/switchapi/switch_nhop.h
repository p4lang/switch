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

#ifndef _switch_nhop_h_
#define _switch_nhop_h_

#include "switch_base_types.h"
#include "switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Nexthop type */
typedef enum switch_nhop_index_type_ {
    SWITCH_NHOP_INDEX_TYPE_NONE,
    SWITCH_NHOP_INDEX_TYPE_ONE_PATH,
    SWITCH_NHOP_INDEX_TYPE_ECMP
} switch_nhop_index_type_t;

/** Nexthop Key */
typedef struct switch_nhop_key_ {
    switch_handle_t intf_handle;          /**< interface handle */
    switch_ip_addr_t ip_addr;             /**< ip address */
    bool ip_addr_valid;                   /**< ip address valid */
} switch_nhop_key_t;

/**
 Create a Nexthop
 @param device - device to program the nexthop
 @param nhop_key- Interface to be associated with the nexthop and nexthop ip
*/
switch_handle_t switch_api_nhop_create(switch_device_t device, switch_nhop_key_t *nhop_key);

/**
 Delete a Nexthop
 @param device device on which to create nhop group
 @param nhop_handle - Handle that identifies nexthop uniquely
*/
switch_status_t switch_api_nhop_delete(switch_device_t device, switch_handle_t nhop_handle);

/**
 Create a ECMP Group
 @param device - device to create the ecmp group
*/
switch_handle_t switch_api_ecmp_create(switch_device_t device);

/**
 Delete a ECMP Group
 @param ecmp_handle - Handle that identifies ECMP group uniquely
*/
switch_status_t switch_api_ecmp_delete(switch_device_t device, switch_handle_t ecmp_handle);

/**
 Add nexthop member to ecmp group
 @param device - device to program the nexthop
 @param ecmp_handle - handle that identifies ECMP group uniquely
 @param nhop_count - number of nexthops
 @param nhop_handle_list - List of nexthops to be added to the ECMP Group
*/
switch_status_t switch_api_ecmp_member_add(switch_device_t device, switch_handle_t ecmp_handle,
                                           uint16_t nhop_count, switch_handle_t *nhop_handle_list);

/**
 Delete nexthop member from ecmp group
 @param device - device to program the nexthop
 @param ecmp_handle - handle that identifies ECMP group uniquely
 @param nhop_count - number of nexthops
 @param nhop_handle_list - List of nexthops to be added to the ECMP Group
*/
switch_status_t switch_api_ecmp_member_delete(switch_device_t device, switch_handle_t ecmp_handle,
                                              uint16_t nhop_count, switch_handle_t *nhop_handle_list);

/*
 Create ECMP Group along with the members.
 @param member_count - Number of nexthops
 @param nhop_handle - List of nexthops to be added to ECMP group
*/
switch_handle_t switch_api_ecmp_create_with_members(switch_device_t device, uint32_t member_count,
                                            switch_handle_t *nhop_handle);

/*
 Return nexthop handle from (intf_handle, ip address)
 @param nhop_key- Interface to be associated with the nexthop and nexthop ip
 */
switch_handle_t switch_api_nhop_handle_get(switch_nhop_key_t *nhop_key);

/*
 Get neighbor handle from nexthop handle
 @param nhop_handle nexthop handle
 */
switch_handle_t switch_api_neighbor_handle_get(switch_handle_t nhop_handle);

/*
 Get to know whether nhop is single path or ecmp
 @param nhop_handle nexthop handle
*/
switch_nhop_index_type_t switch_api_nhop_type_get(switch_handle_t nhop_handle);

/*
 * Dump all nexthops
 */
switch_status_t switch_api_nhop_print_all(void);

#ifdef __cplusplus
}
#endif

#endif
