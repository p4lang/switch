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

#ifndef _switch_stp_int_h_
#define _switch_stp_int_h_

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SWITCH_STP_INVALID_VLAN_HANDLE 0xFF 

typedef struct {
    tommy_node node;
    switch_handle_t intf_handle;
    switch_stp_state_t intf_state;
    p4_pd_entry_hdl_t hw_entry;
} switch_stp_port_entry_t;

typedef struct {
    tommy_node node;
    switch_handle_t bd_handle;
} switch_stp_vlan_entry_t;

typedef struct switch_stp_info_ {
    tommy_list vlan_list;
    tommy_list port_list;
} switch_stp_info_t;

/* Internal API's */
switch_status_t switch_stp_init(switch_device_t device);
switch_status_t switch_stp_free(switch_device_t device);
switch_stp_info_t *switch_api_stp_get_internal(switch_handle_t stp_handle);
switch_status_t switch_stp_update_flood_list(switch_device_t device, switch_handle_t stg_handle,
                                     switch_handle_t intf_handle, switch_stp_state_t state);

#ifdef __cplusplus
}
#endif

#endif
