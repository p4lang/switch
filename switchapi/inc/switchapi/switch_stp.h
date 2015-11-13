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

#ifndef _switch_stp_h_
#define _switch_stp_h_

#include "switch_base_types.h"
#include "switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup stp Spanning Tree Group API
 *  API functions listed to configure stp
 *  @{
 */
// begin of stp
//
// Spanning Tree Group API

/** Maximum spanning tree instances */
#define SWITCH_MAX_STP_INSTANCES 1024

/** Maximum vlan in stp instance */
#define SWITCH_MAX_VLAN_PER_STP_INSTANCE 16

/** Spanning Tree Group State */
typedef enum {
    SWITCH_PORT_STP_STATE_NONE,
    SWITCH_PORT_STP_STATE_DISABLED,
    SWITCH_PORT_STP_STATE_LEARNING,
    SWITCH_PORT_STP_STATE_FORWARDING,
    SWITCH_PORT_STP_STATE_BLOCKING,
} switch_stp_state_t;

/** Spanning tree mode */
typedef enum switch_stp_mode_ {
    SWITCH_PORT_STP_MODE_DISABLED,
    SWITCH_PORT_STP_MODE_STP,
    SWITCH_PORT_STP_MODE_RSTP,
    SWITCH_PORT_STP_MODE_MSTP
} switch_stp_mode_t;

/**
 Create a spanning Tree group
 @param device device
 @param stp_mode spanning tree mode
*/
switch_handle_t switch_api_stp_group_create(switch_device_t device, switch_stp_mode_t stp_mode);

/**
 Delete a spanning tree group
 @param device device
 @param stg_handle handle of the spanning tree group
*/
switch_status_t switch_api_stp_group_delete(switch_device_t device, switch_handle_t stg_handle);

/**
 Add VLAN to the stp
 @param device device
 @param stg_handle spanning tree group handle
 @param vlan_count count of vlans
 @param vlan_handle list of vlan handles
*/
switch_status_t switch_api_stp_group_vlans_add(switch_device_t device,
                                              switch_handle_t stg_handle,
                                              uint16_t vlan_count,
                                              switch_handle_t *vlan_handle);

/**
 Remove VLAN from the stp
 @param device device
 @param stg_handle spanning tree group handle
 @param vlan_count count of vlans
 @param vlan_handle list of vlan handles
*/
switch_status_t switch_api_stp_group_vlans_remove(switch_device_t device,
                                                 switch_handle_t stg_handle,
                                                 uint16_t vlan_count,
                                                 switch_handle_t *vlan_handle);

/**
 Set the port belonging to a stp in one of discard, learn or forward
 @param device device
 @param stg_handle handle of the Spanning tree group
 @param intf_handle - spanning tree interface
 @param state stp state
*/
switch_status_t switch_api_stp_port_state_set(switch_device_t device, switch_handle_t stg_handle,
                                      switch_handle_t intf_handle, switch_stp_state_t state);

/**
 Get the state of the port belonging to a stp
 @param device device
 @param stg_handle handle of the Spanning tree group
 @param intf_handle - spanning tree interface
 @param state stp state
*/
switch_status_t switch_api_stp_port_state_get(switch_device_t device, switch_handle_t stg_handle,
                                      switch_handle_t intf_handle, switch_stp_state_t *state);

/**
 Set the port belonging to a stp in one of discard, learn or forward
 @param device device
 @param stg_handle handle of the Spanning tree group
 @param intf_handle - spanning tree interface
*/
switch_status_t switch_api_stp_port_state_clear(switch_device_t device, switch_handle_t stg_handle,
                                       switch_handle_t intf_handle);

/**
 Dump spanning tree group table
 */
switch_status_t switch_api_stp_group_print_all(void);

/** @} */
// end of stp
#ifdef __cplusplus
}
#endif

#endif
