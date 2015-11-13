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

#ifndef _switch_vlan_int_h_
#define _switch_vlan_int_h_

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_interface.h"
#include "switchapi/switch_status.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SWITCH_API_VLAN_DEFAULT_AGE_INTERVAL (10000)

#define SWITCH_VLAN_PORT_HASH_KEY_SIZE 16
#define SWITCH_VLAN_PORT_HASH_TABLE_SIZE 4096

/** member of logcal network */
typedef struct {
    tommy_node node;                            /**< linked list node */
    switch_handle_t member;                     /**< handle of member that belongs to bd */
    switch_handle_t stp_handle;
#ifdef SWITCH_PD
    p4_pd_entry_hdl_t pv_hw_entry;
    p4_pd_entry_hdl_t xlate_entry;
    p4_pd_entry_hdl_t tunnel_hw_entry[3];
    p4_pd_entry_hdl_t egress_bd_hw_entry;
#endif
}  switch_ln_member_t;

typedef struct switch_bd_stats_ {
    uint16_t stats_idx[SWITCH_VLAN_STAT_MAX];
    switch_counter_t counters[SWITCH_VLAN_STAT_MAX];
#ifdef SWITCH_PD
    p4_pd_entry_hdl_t stats_hw_entry[SWITCH_VLAN_STAT_MAX];
#endif
} switch_bd_stats_t;

/** Logical Network information */
typedef struct switch_bd_info_ {
    switch_logical_network_t ln_info;
    uint32_t uuc_mc_index;
    uint32_t umc_mc_index;
    uint32_t bcast_mc_index;
    switch_handle_t stp_handle;
    tommy_list members;                         /**< members of VLAN */

    switch_urpf_mode_t ipv4_urpf_mode;
    switch_urpf_mode_t ipv6_urpf_mode;
    uint16_t bd_label;
    switch_bd_stats_t *bd_stats;
#ifdef SWITCH_PD
    p4_pd_mbr_hdl_t bd_entry;                   /**< hw bd table entry */
    p4_pd_entry_hdl_t uuc_entry;                /**< hw uuc entry */
    p4_pd_entry_hdl_t umc_entry;                /**< hw umc entry */
    p4_pd_entry_hdl_t bcast_entry;              /**< hw bcast entry */
    switch_ip_encap_pd_hdl_t ip_encap_hdl;
#endif
} switch_bd_info_t;

typedef struct switch_vlan_port_key_ {
    switch_handle_t vlan_handle;
    switch_handle_t port_lag_handle;
} switch_vlan_port_key_t;

typedef struct switch_vlan_port_info_ {
    switch_vlan_port_key_t vlan_port_key;
    tommy_hashtable_node node;
    switch_handle_t intf_handle;
} switch_vlan_port_info_t;

#define SWITCH_LN_IPV4_UNICAST_ENABLED(ln) \
    ln->ln_info.flags.ipv4_unicast_enabled

#define SWITCH_LN_IPV4_MULTICAST_ENABLED(ln) \
    ln->ln_info.flags.ipv4_multicast_enabled

#define SWITCH_LN_IPV6_UNICAST_ENABLED(ln) \
    ln->ln_info.flags.ipv6_unicast_enabled

#define SWITCH_LN_IPV6_MULTICAST_ENABLED(ln) \
    ln->ln_info.flags.ipv6_multicast_enabled

#define SWITCH_LN_IGMP_SNOOPING_ENABLED(ln) \
    ln->ln_info.flags.igmp_snooping_enabled

#define SWITCH_LN_MLD_SNOOPING_ENABLED(ln) \
    ln->ln_info.flags.mld_snooping_enabled

#define SWITCH_LN_VLAN_ID(ln) \
    ln->ln_info.encap_info.u.vlan_id

#define SWITCH_LN_LEARN_ENABLED(ln) \
    ln->ln_info.flags.learn_enabled

#define SWITCH_LN_FLOOD_ENABLED(ln) \
    ln->ln_info.flags.flood_enabled

#define SWITCH_LN_NETWORK_TYPE(ln) \
    ln->ln_info.type

#define SWITCH_BD_IS_CORE(ln) \
    ln->ln_info.flags.core_bd

#define SWITCH_BD_STATS_START_INDEX(ln) \
    (ln->bd_stats != NULL) ? ln->bd_stats->stats_idx[0] : 0

// Internal API Declarations
switch_handle_t switch_bd_create();
switch_bd_info_t *switch_bd_get(switch_handle_t handle);
void switch_bd_delete(switch_handle_t handle);

switch_status_t switch_bd_init(switch_device_t device);
switch_status_t switch_bd_free(switch_device_t device);

switch_status_t switch_bd_ipv4_unicast_enabled_set(switch_handle_t bd_handle, uint64_t value);
switch_status_t switch_bd_ipv4_unicast_enabled_get(switch_handle_t bd_handle, uint64_t *value);
switch_status_t switch_bd_ipv6_unicast_enabled_set(switch_handle_t bd_handle, uint64_t value);
switch_status_t switch_bd_ipv6_unicast_enabled_get(switch_handle_t bd_handle, uint64_t *value);
switch_status_t switch_bd_ipv4_urpf_mode_set(switch_handle_t bd_handle, uint64_t value);
switch_status_t switch_bd_ipv4_urpf_mode_get(switch_handle_t bd_handle, uint64_t *value);
switch_status_t switch_bd_ipv6_urpf_mode_set(switch_handle_t bd_handle, uint64_t value);
switch_status_t switch_bd_ipv6_urpf_mode_get(switch_handle_t bd_handle, uint64_t *value);
switch_status_t switch_bd_router_mac_handle_set(switch_handle_t bd_handle, switch_handle_t rmac_handle);
switch_status_t switch_api_vlan_xlate_add(switch_device_t device, switch_handle_t bd_handle,
                                          switch_handle_t intf_handle, switch_vlan_t vlan_id);
switch_status_t switch_api_vlan_xlate_remove(switch_device_t device, switch_handle_t bd_handle,
                                             switch_handle_t intf_handle, switch_vlan_t vlan_id);
switch_ln_member_t *
switch_api_logical_network_search_member(switch_handle_t bd_handle, switch_handle_t intf_handle);
switch_status_t switch_intf_handle_get(switch_handle_t vlan_handle, switch_handle_t port_lag_handle,
                                       switch_handle_t *intf_handle);

#ifdef __cplusplus
}
#endif

#endif
