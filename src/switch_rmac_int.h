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

#include <switchapi/switch_rmac.h>

#ifndef _switch_rmac_int_h_
#define _switch_rmac_int_h_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SWITCH_SMAC_REWRITE_HASH_TABLE_SIZE 1024

typedef struct switch_rmac_node_ {
    switch_mac_addr_t mac;
    tommy_node node;
} switch_rmac_entry_t;

typedef struct switch_rmac_info_ {
    tommy_list rmac_list;
#ifdef SWITCH_PD
    p4_pd_entry_hdl_t outer_rmac_entry;
    p4_pd_entry_hdl_t inner_rmac_entry;
#endif
} switch_rmac_info_t;

typedef struct switch_smac_entry_ {
    switch_mac_addr_t mac;
    uint16_t smac_index;
    uint16_t ref_count;
    tommy_hashtable_node node;
#ifdef SWITCH_PD
    p4_pd_entry_hdl_t hw_smac_entry[3];
#endif
} switch_smac_entry_t;

// Internal API Declarations
switch_status_t switch_router_mac_init(switch_device_t device);
switch_status_t switch_router_mac_free(switch_device_t device);
switch_rmac_info_t * switch_api_rmac_info_get_internal(switch_handle_t rmac_handle);

uint16_t switch_smac_rewrite_add_entry(switch_mac_addr_t *mac);
switch_status_t switch_smac_rewrite_delete_entry(switch_mac_addr_t *mac);
uint16_t switch_smac_rewrite_index_from_rmac(switch_handle_t rmac_handle);
#ifdef __cplusplus
}
#endif

#endif /* _switch_rmac_int_h */
