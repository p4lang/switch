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

#include "switch_sup_int.h"
#include "switch_capability_int.h"
#include "switch_rmac_int.h"
#include "switch_l3_int.h"
#include "switch_interface_int.h"
#include "switch_vrf_int.h"
#include "switch_nhop_int.h"
#include "switch_mcast_int.h"
#include "switch_pd.h"
#include "switch_neighbor_int.h"
#include "switch_lag_int.h"
#include "switch_stp_int.h"
#include "switch_log.h"
#include "switch_port_int.h"
#include "switch_tunnel_int.h"
#include "switch_acl_int.h"

#include <string.h>

#define CPU_MIRROR_SESSION_ID          250

static int _api_inited = 0;

switch_status_t
switch_api_lib_init(switch_device_t device)
{
    SWITCH_API_TRACE("Initializing switch api!!");
    switch_pd_client_init(device);
    switch_sup_init(device);
    switch_router_mac_init(device);
    switch_port_init(device);
    switch_bd_init(device);
    switch_lag_init(device);
    switch_interface_init(device);
    switch_mac_table_init(device);
    switch_l3_init(device);
    switch_vrf_init(device);
    switch_neighbor_init(device);
    switch_nhop_init(device);
    switch_mcast_init(device);
    switch_capability_init(device);
    switch_acl_init(device);
    switch_stp_init(device);
    switch_tunnel_init(device);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_init_default_entries(switch_device_t device)
{
    // Default Entries
    SWITCH_API_TRACE("Programming default entries!!");
    switch_pd_validate_outer_ethernet_add_default_entry(device);
    switch_pd_validate_outer_ip_add_default_entry(device);
    switch_pd_storm_control_table_add_default_entry(device);
    switch_pd_outer_rmac_table_add_default_entry(device);
    switch_pd_src_vtep_table_add_default_entry(device);
    switch_pd_dest_vtep_table_add_default_entry(device);
    switch_pd_validate_packet_table_add_default_entry(device);
    switch_pd_acl_table_add_default_entry(device);
    switch_pd_inner_rmac_table_add_default_entry(device);
    switch_pd_fwd_result_table_add_default_entry(device);
    switch_pd_nexthop_table_add_default_entry(device);
    switch_pd_lag_table_add_default_entry(device);
    switch_pd_egress_lag_table_add_default_entry(device);
    switch_pd_rid_table_add_default_entry(device);
    switch_pd_replica_type_table_add_default_entry(device);
    switch_pd_mac_table_add_default_entry(device);
    switch_pd_egress_bd_map_table_add_default_entry(device);
    switch_pd_egress_vni_table_add_default_entry(device);
    switch_pd_ip_fib_add_default_entry(device);
    switch_pd_ip_urpf_add_default_entry(device);
    switch_pd_rewrite_table_add_default_entry(device);
    switch_pd_mtu_table_add_default_entry(device);
    switch_pd_egress_vlan_xlate_table_add_default_entry(device);
    switch_pd_egress_acl_add_default_entry(device);
    switch_pd_vlan_decap_table_add_default_entry(device);
    switch_pd_tunnel_smac_rewrite_table_add_default_entry(device);
    switch_pd_tunnel_dmac_rewrite_table_add_default_entry(device);
    switch_pd_tunnel_rewrite_table_add_default_entry(device);
    switch_pd_mac_rewrite_table_add_default_entry(device);
    switch_pd_tunnel_src_rewrite_table_add_default_entry(device);
    switch_pd_tunnel_dst_rewrite_table_add_default_entry(device);
    switch_pd_tunnel_table_add_default_entry(device);

    SWITCH_API_TRACE("Programming init entries!!");
    switch_pd_learn_notify_table_add_init_entry(device);
    switch_pd_tunnel_decap_tables_init_entry(device);
    switch_pd_tunnel_encap_tables_init_entry(device);
    switch_pd_validate_outer_ethernet_table_init_entry(device);
    switch_pd_vlan_decap_table_init_entry(device);
    switch_pd_fwd_result_table_add_init_entry(device);
    switch_pd_validate_mpls_packet_table_init_entry(device);
    switch_pd_fabric_header_table_init_entry(device);
    switch_pd_egress_port_mapping_table_init_entry(device);
    switch_pd_compute_multicast_hashes_init_entry(device);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_init_default_acl_entries(switch_device_t device)
{
    switch_handle_t                    acl_handle;
    switch_acl_action_params_t         action_params;

    memset(&action_params, 0, sizeof(switch_acl_action_params_t));

    /*
     * System acl for urpf check failure
     * (urpf check failure, action is drop)
     */
    switch_acl_system_key_value_pair_t    urpf_check_acl_kvp;
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(&urpf_check_acl_kvp, 0, sizeof(switch_acl_system_key_value_pair_t));
    urpf_check_acl_kvp.field = SWITCH_ACL_SYSTEM_FIELD_URPF_CHECK;
    urpf_check_acl_kvp.value.urpf_check_fail = 1;
    urpf_check_acl_kvp.mask.u.mask = 0xFF;
    switch_api_acl_rule_create(device, acl_handle, 1001, 1,
                               &urpf_check_acl_kvp, SWITCH_ACL_ACTION_DROP,
                               &action_params);
    switch_api_acl_reference(device, acl_handle, 0);

    /*
     * System acl for ACL_DENY check failure
     * (urpf check failure, action is drop)
     */
    switch_acl_system_key_value_pair_t    acl_deny_acl_kvp;
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(&acl_deny_acl_kvp, 0, sizeof(switch_acl_system_key_value_pair_t));
    acl_deny_acl_kvp.field = SWITCH_ACL_SYSTEM_FIELD_ACL_DENY;
    acl_deny_acl_kvp.value.acl_deny = 1;
    acl_deny_acl_kvp.mask.u.mask = 0xFF;
    switch_api_acl_rule_create(device, acl_handle, 10000, 1,
                               &acl_deny_acl_kvp, SWITCH_ACL_ACTION_DROP,
                               &action_params);
    switch_api_acl_reference(device, acl_handle, 0);

    //create an ACL to capture STP packets to CPU
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    switch_acl_system_key_value_pair_t stp_acl_kvp;
    memset(&stp_acl_kvp, 0, sizeof(switch_acl_system_key_value_pair_t));
    stp_acl_kvp.field = SWITCH_ACL_SYSTEM_FIELD_DEST_MAC;
    stp_acl_kvp.value.dest_mac.mac_addr[0] = 0x01;
    stp_acl_kvp.value.dest_mac.mac_addr[1] = 0x80;
    stp_acl_kvp.value.dest_mac.mac_addr[2] = 0xC2;
    stp_acl_kvp.value.dest_mac.mac_addr[3] = 0x00;
    stp_acl_kvp.value.dest_mac.mac_addr[4] = 0x00;
    stp_acl_kvp.value.dest_mac.mac_addr[5] = 0x00;
    stp_acl_kvp.mask.u.mask = 0xFFFFFFFFFFFF;
    switch_api_acl_rule_create(device, acl_handle, 1902, 1,
                               &stp_acl_kvp, SWITCH_ACL_ACTION_REDIRECT_TO_CPU,
                               &action_params);
    switch_api_acl_reference(device, acl_handle, 0);

    switch_acl_system_key_value_pair_t pim_acl_kvp;
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(&pim_acl_kvp, 0, sizeof(switch_acl_system_key_value_pair_t));
    pim_acl_kvp.field = SWITCH_ACL_SYSTEM_FIELD_IP_PROTO;
    pim_acl_kvp.value.ip_proto = 103;
    pim_acl_kvp.mask.u.mask = 0xFFFF;
    switch_api_acl_rule_create(device, acl_handle, 1903, 1, &pim_acl_kvp,
                               SWITCH_ACL_ACTION_REDIRECT_TO_CPU,
                               &action_params);
    switch_api_acl_reference(device, acl_handle, 0);

    switch_acl_system_key_value_pair_t igmp_acl_kvp;
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(&igmp_acl_kvp, 0, sizeof(switch_acl_system_key_value_pair_t));
    igmp_acl_kvp.field = SWITCH_ACL_SYSTEM_FIELD_IP_PROTO;
    igmp_acl_kvp.value.ip_proto = 2;
    igmp_acl_kvp.mask.u.mask = 0xFFFF;
    switch_api_acl_rule_create(device, acl_handle, 1904, 1,
                               &igmp_acl_kvp, SWITCH_ACL_ACTION_REDIRECT_TO_CPU,
                               &action_params);
    switch_api_acl_reference(device, acl_handle, 0);

    switch_acl_system_key_value_pair_t mcast_ipv4_catch_all;
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(&mcast_ipv4_catch_all, 0, sizeof(switch_acl_system_key_value_pair_t));
    mcast_ipv4_catch_all.field = SWITCH_ACL_SYSTEM_FIELD_IPV4_DEST;
    mcast_ipv4_catch_all.value.ipv4_dest = 0xE0000000;
    mcast_ipv4_catch_all.mask.u.mask = 0xF0000000;
    switch_api_acl_rule_create(device, acl_handle, 11000, 1,
                               &mcast_ipv4_catch_all, SWITCH_ACL_ACTION_REDIRECT_TO_CPU,
                               &action_params);
    switch_api_acl_reference(device, acl_handle, 0);

    // STP state == blocked, drop
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(&stp_acl_kvp, 0, sizeof(switch_acl_system_key_value_pair_t));
    stp_acl_kvp.field = SWITCH_ACL_SYSTEM_FIELD_STP_STATE;
    stp_acl_kvp.value.stp_state = SWITCH_PORT_STP_STATE_BLOCKING;
    stp_acl_kvp.mask.u.mask = 0xFF;
    switch_api_acl_rule_create(device, acl_handle, 11001, 1,
                               &stp_acl_kvp, SWITCH_ACL_ACTION_DROP,
                               &action_params);
    switch_api_acl_reference(device, acl_handle, 0);
    // STP state == learning, drop
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(&stp_acl_kvp, 0, sizeof(switch_acl_system_key_value_pair_t));
    stp_acl_kvp.field = SWITCH_ACL_SYSTEM_FIELD_STP_STATE;
    stp_acl_kvp.value.stp_state = SWITCH_PORT_STP_STATE_LEARNING;
    stp_acl_kvp.mask.u.mask = 0xFF;
    switch_api_acl_rule_create(device, acl_handle, 11002, 1,
                               &stp_acl_kvp, SWITCH_ACL_ACTION_DROP,
                               &action_params);
    switch_api_acl_reference(device, acl_handle, 0);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_init(switch_device_t device)
{
    if(_api_inited == 0) {
        switch_api_lib_init(device);
        switch_api_init_default_acl_entries(device);
        switch_api_init_default_entries(device);
        _api_inited = 1;
    }
    return SWITCH_STATUS_SUCCESS;
}
