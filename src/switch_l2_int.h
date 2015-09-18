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
#include "switchapi/switch_status.h"
#include "switchapi/switch_l2.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SWITCH_MAC_MAXIMUM_BUFFER_SIZE 128

#define SWITCH_MAC_TABLE_DEFAULT_AGING_TIME 10000
#define SWITCH_MAC_TABLE_MAX_AGING_TIME     90000

typedef struct switch_mac_info_ {
    unsigned char key[10];
    switch_api_mac_entry_t mac_entry;
    tommy_hashtable_node node;
    tommy_node interface_node;
    tommy_node vlan_node;
#ifdef SWITCH_PD
    p4_pd_entry_hdl_t dmac_entry;
    p4_pd_entry_hdl_t smac_entry;
#endif
} switch_mac_info_t;

typedef struct switch_mac_global_params_ {
    uint32_t aging_time;
    uint32_t learn_timeout;
} switch_mac_global_params_t;

typedef struct switch_mac_vlan_list_ {
    tommy_list mac_entries;
    uint32_t num_entries;
} switch_mac_vlan_list_t;

typedef struct switch_mac_intf_list_ {
    tommy_list mac_entries;
    uint32_t num_entries;
} switch_mac_intf_list_t;

switch_status_t switch_mac_table_init(switch_device_t device);
switch_status_t switch_mac_table_free(void);
uint32_t switch_api_mac_get_default_aging_time_internal();
switch_mac_info_t * switch_mac_table_entry_find(switch_api_mac_entry_t *mac_entry);
#ifdef __cplusplus
}
#endif
