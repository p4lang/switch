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

#include "switch_hostif_int.h"
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
#include "switch_mirror_int.h"
#include "switch_meter_int.h"
#include "switch_pd.h"

#include <string.h>
#include <pthread.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static int _api_lib_inited = 0;
static int _dev_inited[SWITCH_MAX_DEVICE];

extern unsigned int switch_max_configured_ports;

static pthread_t stats_thread;

switch_status_t
switch_api_lib_init(switch_device_t device)
{
    SWITCH_API_TRACE("Initializing switch api!!");
    switch_pd_client_init(device);
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
    switch_acl_init(device);
    switch_stp_init(device);
    switch_tunnel_init(device);
    switch_mirror_init(device);
    switch_hostif_init(device);
    switch_capability_init(device);
    switch_meter_init(device);

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
    switch_pd_port_vlan_mapping_table_add_default_entry(device);
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
    switch_pd_ip_mcast_add_default_entry(device);
    switch_pd_rewrite_table_add_default_entry(device);
    switch_pd_rewrite_multicast_table_add_default_entry(device);
    switch_pd_egress_vlan_xlate_table_add_default_entry(device);
    switch_pd_egress_acl_add_default_entry(device);
    switch_pd_vlan_decap_table_add_default_entry(device);
    switch_pd_tunnel_smac_rewrite_table_add_default_entry(device);
    switch_pd_tunnel_dmac_rewrite_table_add_default_entry(device);
    switch_pd_tunnel_rewrite_table_add_default_entry(device);
    switch_pd_tunnel_src_rewrite_table_add_default_entry(device);
    switch_pd_tunnel_dst_rewrite_table_add_default_entry(device);
    switch_pd_tunnel_table_add_default_entry(device);
    switch_pd_bd_stats_table_add_default_entry(device);
    switch_pd_bd_flood_table_add_default_entry(device);
    switch_pd_mirror_table_add_default_entry(device);
    switch_pd_mtu_table_add_default_entry(device);
    switch_pd_storm_control_table_add_default_entry(device);
    switch_pd_meter_index_table_add_default_entry(device);
    switch_pd_meter_action_table_add_default_entry(device);
    switch_pd_l3_rewrite_table_add_default_entry(device);

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
    switch_pd_compute_hashes_init_entry(device);
    switch_pd_switch_config_params_table_init(device);
    switch_pd_replica_type_table_init_entry(device);
    switch_pd_rewrite_multicast_table_init_entry(device);
    switch_pd_l3_rewrite_table_init_entry(device);
#ifdef P4_INT_ENABLE
    // Setup INT tables
    switch_pd_int_tables_init(device);
#endif

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
switch_api_init_default_acl_entries(switch_device_t device)
{
    switch_acl_system_key_value_pair_t acl_kvp[5];
    switch_acl_egr_key_value_pair_t    egr_acl_kvp[3];
    switch_acl_action_params_t         action_params;
    switch_acl_opt_action_params_t     opt_action_params;
    switch_handle_t                    acl_handle;
    switch_handle_t                    handle;
    int                                priority = 100;

    memset(&opt_action_params, 0, sizeof(switch_acl_opt_action_params_t));

    // system acl for acl copy + dropped packets
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_DROP;
    acl_kvp[0].value.drop_flag = 1;
    acl_kvp[0].mask.u.mask = 0xFF;
    acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_ACL_COPY;
    acl_kvp[1].value.acl_copy = true;
    acl_kvp[1].mask.u.mask = 0xFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    switch_api_acl_rule_create(device, acl_handle, priority++, 2,
                               acl_kvp, SWITCH_ACL_ACTION_REDIRECT_TO_CPU,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // system acl for dropped packets
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_DROP;
    acl_kvp[0].value.drop_flag = 1;
    acl_kvp[0].mask.u.mask = 0xFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    switch_api_acl_rule_create(device, acl_handle, priority++, 1,
                               acl_kvp, SWITCH_ACL_ACTION_DROP,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // mac sa is zero, drop
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_SOURCE_MAC;
    acl_kvp[0].mask.u.mask = 0xFFFFFFFFFFFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    action_params.drop.reason_code = DROP_SRC_MAC_ZERO;
    switch_api_acl_rule_create(device, acl_handle, priority++, 1,
                               acl_kvp, SWITCH_ACL_ACTION_DROP,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // port vlan mapping miss, drop
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_PORT_VLAN_MAPPING_MISS;
    acl_kvp[0].value.port_vlan_mapping_miss = 1;
    acl_kvp[0].mask.u.mask = 0xFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    action_params.drop.reason_code = DROP_PORT_VLAN_MAPPING_MISS;
    switch_api_acl_rule_create(device, acl_handle, priority++, 1,
                               acl_kvp, SWITCH_ACL_ACTION_DROP,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // STP state == blocked, drop
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_STP_STATE;
    acl_kvp[0].value.stp_state = SWITCH_PORT_STP_STATE_BLOCKING;
    acl_kvp[0].mask.u.mask = 0xFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    action_params.drop.reason_code = DROP_STP_STATE_BLOCKING;
    switch_api_acl_rule_create(device, acl_handle, priority++, 1,
                               acl_kvp, SWITCH_ACL_ACTION_DROP,
                               &action_params,
                               &opt_action_params,
                               &handle);
    // STP state == learning, drop
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_STP_STATE;
    acl_kvp[0].value.stp_state = SWITCH_PORT_STP_STATE_LEARNING;
    acl_kvp[0].mask.u.mask = 0xFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    action_params.drop.reason_code = DROP_STP_STATE_LEARNING;
    switch_api_acl_rule_create(device, acl_handle, priority++, 1,
                               acl_kvp, SWITCH_ACL_ACTION_DROP,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // ACL deny, drop
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_ACL_DENY;
    acl_kvp[0].value.acl_deny = 1;
    acl_kvp[0].mask.u.mask = 0xFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    action_params.drop.reason_code = DROP_ACL_DENY;
    switch_api_acl_rule_create(device, acl_handle, priority++, 1,
                               acl_kvp, SWITCH_ACL_ACTION_DROP,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // URPF check fail, drop
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_URPF_CHECK;
    acl_kvp[0].value.urpf_check_fail = 1;
    acl_kvp[0].mask.u.mask = 0xFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    action_params.drop.reason_code = DROP_URPF_CHECK_FAIL;
    switch_api_acl_rule_create(device, acl_handle, priority++, 1,
                               acl_kvp, SWITCH_ACL_ACTION_DROP,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // same if check fail, drop
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_IF_CHECK;
    acl_kvp[0].value.if_check = 0;
    acl_kvp[0].mask.u.mask = 0xFFFF;
    acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_BD_CHECK;
    acl_kvp[1].value.bd_check = 0;
    acl_kvp[1].mask.u.mask = 0xFFFF;
    acl_kvp[2].field = SWITCH_ACL_SYSTEM_FIELD_ROUTED;
    acl_kvp[2].value.routed = 0;
    acl_kvp[2].mask.u.mask = 0xFFFF;
    acl_kvp[3].field = SWITCH_ACL_SYSTEM_FIELD_TUNNEL_IF_CHECK;
    acl_kvp[3].value.tunnel_if_check = 0;
    acl_kvp[3].mask.u.mask = 0xFFFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    action_params.drop.reason_code = DROP_SAME_IFINDEX;
    switch_api_acl_rule_create(device, acl_handle, priority++, 4,
                               acl_kvp, SWITCH_ACL_ACTION_DROP,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // egress ifindex is drop ifindex, drop
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_EGRESS_IFINDEX;
    acl_kvp[0].value.out_ifindex = switch_api_drop_ifindex();
    acl_kvp[0].mask.u.mask = 0xFFFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    action_params.drop.reason_code = DROP_IFINDEX;
    switch_api_acl_rule_create(device, acl_handle, priority++, 1,
                               acl_kvp, SWITCH_ACL_ACTION_DROP,
                               &action_params,
                               &opt_action_params,
                               &handle);

     // routed, ttl == 1, egress_ifindex == cpu, permit
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_ROUTED;
    acl_kvp[0].value.routed = true;
    acl_kvp[0].mask.u.mask = 0xFF;
    acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_TTL;
    acl_kvp[1].value.ttl = 1;
    acl_kvp[1].mask.u.mask = 0xFF;
    acl_kvp[2].field = SWITCH_ACL_SYSTEM_FIELD_EGRESS_IFINDEX;
    acl_kvp[2].value.out_ifindex = switch_api_cpu_glean_ifindex();
    acl_kvp[2].mask.u.mask = 0xFFFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    switch_api_acl_rule_create(device, acl_handle, priority++, 3,
                               acl_kvp, SWITCH_ACL_ACTION_PERMIT,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // routed, ttl == 1, redirect to cpu
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_ROUTED;
    acl_kvp[0].value.routed = true;
    acl_kvp[0].mask.u.mask = 0xFF;
    acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_TTL;
    acl_kvp[1].value.ttl = 1;
    acl_kvp[1].mask.u.mask = 0xFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    action_params.cpu_redirect.reason_code =
        SWITCH_HOSTIF_REASON_CODE_TTL_ERROR;
    switch_api_acl_rule_create(device, acl_handle, priority++, 2,
                               acl_kvp, SWITCH_ACL_ACTION_REDIRECT_TO_CPU,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // routed, ipv6_src_is_link_local == 1, egress_ifindex == cpu, permit
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_ROUTED;
    acl_kvp[0].value.routed = true;
    acl_kvp[0].mask.u.mask = 0xFF;
    acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_LINK_LOCAL;
    acl_kvp[1].value.src_is_link_local = 1;
    acl_kvp[1].mask.u.mask = 0xFF;
    acl_kvp[2].field = SWITCH_ACL_SYSTEM_FIELD_EGRESS_IFINDEX;
    acl_kvp[2].value.out_ifindex = switch_api_cpu_glean_ifindex();
    acl_kvp[2].mask.u.mask = 0xFFFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    action_params.cpu_redirect.reason_code =
        SWITCH_HOSTIF_REASON_CODE_SRC_IS_LINK_LOCAL;
    switch_api_acl_rule_create(device, acl_handle, priority++, 3,
                               acl_kvp, SWITCH_ACL_ACTION_PERMIT,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // routed, ipv6_src_is_link_local == 1, redirect to cpu
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_ROUTED;
    acl_kvp[0].value.routed = true;
    acl_kvp[0].mask.u.mask = 0xFF;
    acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_LINK_LOCAL;
    acl_kvp[1].value.src_is_link_local = 1;
    acl_kvp[1].mask.u.mask = 0xFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    action_params.cpu_redirect.reason_code =
        SWITCH_HOSTIF_REASON_CODE_SRC_IS_LINK_LOCAL;
    switch_api_acl_rule_create(device, acl_handle, priority++, 2,
                               acl_kvp, SWITCH_ACL_ACTION_REDIRECT_TO_CPU,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // routed, ingress bd == egress bd, copy to cpu
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_ROUTED;
    acl_kvp[0].value.routed = true;
    acl_kvp[0].mask.u.mask = 0xFF;
    acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_BD_CHECK;
    acl_kvp[1].value.bd_check = 0;
    acl_kvp[1].mask.u.mask = 0xFFFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    action_params.cpu_redirect.reason_code =
        SWITCH_HOSTIF_REASON_CODE_ICMP_REDIRECT;
    switch_api_acl_rule_create(device, acl_handle, priority++, 2,
                               acl_kvp, SWITCH_ACL_ACTION_COPY_TO_CPU,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // acl_copy, copy to cpu
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_ACL_COPY;
    acl_kvp[0].value.acl_copy = true;
    acl_kvp[0].mask.u.mask = 0xFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    switch_api_acl_rule_create(device, acl_handle, priority++, 1,
                               acl_kvp, SWITCH_ACL_ACTION_COPY_TO_CPU,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // l3_copy to cpu
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_L3_COPY;
    acl_kvp[0].value.l3_copy = true;
    acl_kvp[0].mask.u.mask = 0xFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    switch_api_acl_rule_create(device, acl_handle, priority++, 1,
                               acl_kvp, SWITCH_ACL_ACTION_COPY_TO_CPU,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // Broadcast packet on routed interfaces, copy to cpu
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(acl_kvp, 0, sizeof(acl_kvp));
    acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_DEST_MAC;
    acl_kvp[0].value.dest_mac.mac_addr[0] = 0xFF;
    acl_kvp[0].value.dest_mac.mac_addr[1] = 0xFF;
    acl_kvp[0].value.dest_mac.mac_addr[2] = 0xFF;
    acl_kvp[0].value.dest_mac.mac_addr[3] = 0xFF;
    acl_kvp[0].value.dest_mac.mac_addr[4] = 0xFF;
    acl_kvp[0].value.dest_mac.mac_addr[5] = 0xFF;
    acl_kvp[0].mask.u.mask = 0xFFFFFFFFFFFF;
    acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_IPV4_ENABLED;
    acl_kvp[1].value.ipv4_enabled = 1;
    acl_kvp[1].mask.u.mask = 0xFFFFFFFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    action_params.cpu_redirect.reason_code = 0;
    switch_api_acl_rule_create(device, acl_handle, priority++, 2,
                               acl_kvp, SWITCH_ACL_ACTION_COPY_TO_CPU,
                               &action_params,
                               &opt_action_params,
                               &handle);

    // egress l3_mtu_check
    acl_handle = switch_api_acl_list_create(device,
                                            SWITCH_ACL_TYPE_EGRESS_SYSTEM);
    memset(egr_acl_kvp, 0, sizeof(egr_acl_kvp));
    egr_acl_kvp[0].field = SWITCH_ACL_EGR_L3_MTU_CHECK;
    egr_acl_kvp[0].value.l3_mtu_check = 0;
    egr_acl_kvp[0].mask.u.mask = 0xFFFF;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    action_params.cpu_redirect.reason_code =
        SWITCH_HOSTIF_REASON_CODE_L3_MTU_ERROR;
    switch_api_acl_rule_create(device, acl_handle, priority++, 1,
                               egr_acl_kvp,
                               SWITCH_ACL_EGR_ACTION_REDIRECT_TO_CPU,
                               &action_params,
                               &opt_action_params,
                               &handle);
    switch_api_acl_reference(device, acl_handle, 0);

    return SWITCH_STATUS_SUCCESS;
}

void *
switch_api_stats_poll(void *args)
{
    switch_device_t device = SWITCH_DEV_ID;
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    while (true) {
        status = switch_pd_stats_update(device);
        if (status != SWITCH_STATUS_SUCCESS) {
            break;
        }
        sleep(60);
    }

    return NULL;
}

switch_status_t
switch_api_stats_poll_server(void)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    UNUSED(stats_thread);

    pthread_create(
         &stats_thread,
         NULL,
         switch_api_stats_poll,
         NULL);
    return status;
}

switch_status_t
switch_api_init(switch_device_t device, unsigned int num_ports)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    if (device > SWITCH_MAX_DEVICE) {
        return SWITCH_STATUS_INVALID_DEVICE;
    }

    if (num_ports) {
        switch_max_configured_ports = num_ports;
    }

    if(_api_lib_inited == 0) {
        switch_api_lib_init(device);
        _api_lib_inited = 1;
        switch_api_stats_poll_server();
    }

    if (_dev_inited[device] == 0) {
        status = switch_api_init_default_acl_entries(device);
        status = switch_api_init_default_entries(device);
        _dev_inited[device] = 1;
    }

    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_STATUS_FAILURE;
    }

    return status;
}

switch_status_t
switch_api_init0(char *args)
{
    switch_device_t device = 0;
    unsigned int num_ports;
    sscanf(args, "%c %d", &device, &num_ports);
    return switch_api_init(device, num_ports);
}

#ifdef __cplusplus
}
#endif
