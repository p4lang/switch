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

#ifndef _switch_lag_h_
#define _switch_lag_h_

#include "switch_id.h"
#include "switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
    
/** @defgroup LAG LAG configuration API
 *  API functions listed to configure the Link Aggregation groups.
 *  Create LAG, Add/Del ports to LAG and set admin states
    Link aggregation allows for one or more ports to be treated as a single entity for reception
    and transmission of packets through the system. All behavior of packets on all the ports that
    belong to a group is identical on the device. The ports that belong to a single group can span
    multiple pipelines. Transmission of packets through particular ports is determined by the hashing
    scheme selectable globally. Typically the L2 fields (DMAC, SMAC, EtherType) are used for this.
    The choice of this is configurable by the APIs.
 *  @{
 */ // begin of LAG


/**< LACP Key */
typedef unsigned int lacp_key_t;
    
/** type of LAG */
typedef enum switch_lag_type_ {
    SWITCH_API_LAG_SIMPLE,          /**< simple hash */
    SWITCH_API_LAG_RESILIENT        /**< weighted/resilient hash */
} switch_lag_type_t;
    

// Simple LAG API
/**
 Link Aggregation Group creation
 @param device device to use
 */
switch_handle_t switch_api_lag_create(switch_device_t device);
    
/**
 Link Aggregation Group deletion
 @param device device to use
 @param lag_handle handle of group returned on creation
 */
switch_status_t switch_api_lag_delete(switch_device_t device, switch_handle_t lag_handle);

/**
 Link Aggregation Group member port add
 @param device device to use
 @param lag_handle handle of group returned on creation
 @param side allow rx and rx member add separately
 @param port port in the same device on which lag_handle was created
 */
switch_status_t switch_api_lag_member_add(switch_device_t device, switch_handle_t lag_handle,
                                  switch_direction_t side, switch_port_t port);

/**
 Link Aggregation Group member port delete
 @param device device to use
 @param lag_handle handle of group returned on creation
 @param side control rx and tx members independently or both
 @param port port in the same device on which lag_handle was created
 */
switch_status_t switch_api_lag_member_delete(switch_device_t device, switch_handle_t lag_handle,
                                     switch_direction_t side, switch_port_t port);
    
/**
 Link Aggregation Group member add by handle
 @param device device to use
 @param lag_handle handle of group returned on creation
 @param side allow rx and rx member add separately
 @param port port in the same device on which lag_handle was created
 */
switch_handle_t
switch_api_lag_member_create(
        switch_device_t device,
        switch_handle_t lag_handle,
        switch_direction_t direction,
        switch_port_t port);

/**
 Link Aggregation Group member deletion by handle
 @param device device to use
 @param lag_member_handle handle of member returned on creation
 */
switch_status_t
switch_api_lag_member_remove(
        switch_device_t device,
        switch_handle_t lag_member_handle);

/**
 Link Aggregation group member count
 @param lag_handle handle of the link aggregation group
 */
unsigned int switch_lag_get_count(switch_handle_t lag_handle);

/**
 Register a iterator function to walk through all the lag
 @param lag_id Lag index
 @param intf_handle List of member interfaces
 @param member_count Number of lag members
 */
typedef switch_status_t (*switch_lag_iterator_fn)(uint8_t lag_id, switch_handle_t *intf_handle, uint8_t member_count);

/**
 Calls the iterator function for every lag
 @param iterator_fn - Iterator function
 */
switch_status_t switch_api_lag_get(switch_lag_iterator_fn iterator_fn);

/**
 Dump lag table
 */
switch_status_t switch_api_lag_print_all();
    
/** @} */ // end of LAG
    
#ifdef __cplusplus
}
#endif

#endif
