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

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_neighbor.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SWITCH_DMAC_REWRITE_HASH_TABLE_SIZE 4096
#define SWITCH_DMAC_REWRITE_HASH_KEY_SIZE 6

typedef struct switch_neighbor_ {
    switch_api_neighbor_t neighbor;
#ifdef SWITCH_PD
    p4_pd_entry_hdl_t rewrite_entry;       /**< hold the HW Entry */
#endif
} switch_neighbor_info_t;

typedef struct switch_dmac_rewrite_ {
    switch_mac_addr_t mac;
    tommy_hashtable_node node;
    uint16_t index;
    uint16_t ref_count;
#ifdef SWITCH_PD
    p4_pd_entry_hdl_t rewrite_entry;
#endif
} switch_dmac_rewrite_t;

#define SWITCH_NEIGHBOR_DMAC_HASH_KEY_SIZE 14

typedef struct switch_neighbor_dmac_ {
    switch_handle_t handle;
    switch_mac_addr_t mac;
    tommy_hashtable_node node;
    switch_handle_t neighbor_handle;
} switch_neighbor_dmac_t;

switch_status_t switch_neighbor_init(switch_device_t device);
switch_status_t switch_neighbor_free(switch_device_t device);
switch_status_t
switch_api_neighbor_entry_add_unicast_rewrite(switch_device_t device, switch_neighbor_info_t *neighbor_info);
switch_status_t
switch_api_neighbor_entry_add_tunnel_rewrite(switch_device_t device, switch_neighbor_info_t *neighbor_info);
    
switch_neighbor_info_t * switch_neighbor_info_get(switch_handle_t handle);

switch_neighbor_dmac_t *
switch_neighbor_dmac_search_hash(switch_handle_t bd_handle, switch_mac_addr_t *mac);
#ifdef __cplusplus
}
#endif
