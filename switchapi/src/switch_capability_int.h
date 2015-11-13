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

#ifndef _switch_capability_int_h
#define _switch_capability_int_h

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_capability.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
/** Switch information */
typedef struct switch_capability_info_ {
    switch_api_capability_t api_switch_info;
    switch_mac_addr_t router_mac;                    /**< system router mac */
    bool oper_status;                                /**< operational status */
    switch_ecmp_hash_fields_t ecmp_hash;             /**< system hash */
    switch_handle_t default_vrf_handle;              
    switch_handle_t default_vlan_handle;
    switch_handle_t rmac_handle;
    uint16_t smac_index;
} switch_capability_info_t;

switch_status_t switch_capability_init(switch_device_t device);
switch_handle_t switch_api_default_vlan_internal();
switch_handle_t switch_api_default_vrf_internal();
switch_handle_t switch_api_capability_rmac_handle_get();
uint16_t switch_api_capability_smac_index_get();

#ifdef __cplusplus
}
#endif

#endif
