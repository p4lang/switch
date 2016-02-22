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

#include "p4features.h"
#include "switch_pd.h"
#include "switch_log.h"
#include "switch_lag_int.h"
#include "switch_nhop_int.h"
#include "switch_defines.h"
#include "switch_mirror_int.h"
#include "switch_tunnel_int.h"
//#include "model_flags.h"
#include "switch_config_int.h"
#include <string.h>

#define SWITCH_MAX_TXN_SZ  10

p4_pd_sess_hdl_t g_sess_hdl = 0;
p4_pd_sess_hdl_t g_mc_sess_hdl = 0;

p4_pd_status_t
switch_pd_client_init(switch_device_t device)
{
#ifndef P4_MULTICAST_DISABLE
    p4_pd_status_t sts = 0;
    sts = p4_pd_mc_create_session(&g_mc_sess_hdl);
    if (sts) return sts;
#endif
    return p4_pd_client_init(&g_sess_hdl, SWITCH_MAX_TXN_SZ);
}

p4_pd_status_t
switch_pd_dmac_table_add_entry(switch_device_t device,
                               switch_api_mac_entry_t *mac_entry,
                               uint16_t nhop_index,
                               uint16_t mgid_index,
                               uint32_t aging_time,
                               switch_interface_info_t *intf_info,
                               p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_L2_DISABLE
    p4_pd_dc_dmac_match_spec_t match_spec;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_dmac_match_spec_t));

    match_spec.ingress_metadata_bd = handle_to_id(mac_entry->vlan_handle);
    memcpy(match_spec.l2_metadata_lkp_mac_da, &mac_entry->mac, ETH_LEN);

    if (mac_entry->mac_action == SWITCH_MAC_ACTION_FORWARD) {
        if (mgid_index) {
            p4_pd_dc_dmac_multicast_hit_action_spec_t action_spec;
            memset(&action_spec, 0, sizeof(p4_pd_dc_dmac_multicast_hit_action_spec_t));
            action_spec.action_mc_index = mgid_index;
            status = p4_pd_dc_dmac_table_add_with_dmac_multicast_hit(g_sess_hdl,
                                                               p4_pd_device,
                                                               &match_spec,
                                                               &action_spec,
                                                               aging_time,
                                                               entry_hdl);
        } else {
            switch(SWITCH_INTF_TYPE(intf_info)) {
                case SWITCH_API_INTERFACE_L2_VLAN_ACCESS:
                case SWITCH_API_INTERFACE_L2_VLAN_TRUNK:
                case SWITCH_API_INTERFACE_L2_PORT_VLAN:
                {
                    p4_pd_dc_dmac_hit_action_spec_t hit_action_spec;
                    memset(&hit_action_spec, 0, sizeof(p4_pd_dc_dmac_hit_action_spec_t));
                    hit_action_spec.action_ifindex = intf_info->ifindex;
                    status = p4_pd_dc_dmac_table_add_with_dmac_hit(g_sess_hdl,
                                                            p4_pd_device,
                                                            &match_spec,
                                                            &hit_action_spec,
                                                            aging_time,
                                                            entry_hdl);
                }
                break;
                case SWITCH_API_INTERFACE_TUNNEL:
                {
                    p4_pd_dc_dmac_redirect_nexthop_action_spec_t nhop_action_spec;
                    memset(&nhop_action_spec, 0, sizeof(p4_pd_dc_dmac_redirect_nexthop_action_spec_t));
                    nhop_action_spec.action_nexthop_index = nhop_index;
                    status = p4_pd_dc_dmac_table_add_with_dmac_redirect_nexthop(g_sess_hdl,
                                                                          p4_pd_device,
                                                                          &match_spec,
                                                                          &nhop_action_spec,
                                                                          aging_time,
                                                                          entry_hdl);
                }
                break;
                default:
                    status = SWITCH_STATUS_INVALID_INTERFACE;
                    break;
            }
        }
    } else {
        status = p4_pd_dc_dmac_table_add_with_dmac_drop(g_sess_hdl,
                                                        p4_pd_device,
                                                        &match_spec,
                                                        aging_time,
                                                        entry_hdl);

    }
#endif /* P4_L2_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_dmac_table_update_entry(switch_device_t device,
                                  switch_api_mac_entry_t *mac_entry,
                                  uint16_t nhop_index,
                                  uint16_t mgid_index,
                                  switch_interface_info_t *intf_info,
                                  p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
    UNUSED(mac_entry);
#ifndef P4_L2_DISABLE

    if (mgid_index) {
        p4_pd_dc_dmac_multicast_hit_action_spec_t action_spec;
        memset(&action_spec, 0, sizeof(p4_pd_dc_dmac_multicast_hit_action_spec_t));
        action_spec.action_mc_index = mgid_index;
        status = p4_pd_dc_dmac_table_modify_with_dmac_multicast_hit(g_sess_hdl,
                                                           device,
                                                           entry_hdl,
                                                           &action_spec);
    } else {
        switch(SWITCH_INTF_TYPE(intf_info)) {
            case SWITCH_API_INTERFACE_L2_VLAN_ACCESS:
            case SWITCH_API_INTERFACE_L2_VLAN_TRUNK:
            {
                p4_pd_dc_dmac_hit_action_spec_t hit_action_spec;
                memset(&hit_action_spec, 0, sizeof(p4_pd_dc_dmac_hit_action_spec_t));
                hit_action_spec.action_ifindex = intf_info->ifindex;
                status = p4_pd_dc_dmac_table_modify_with_dmac_hit(g_sess_hdl,
                                                            device,
                                                            entry_hdl,
                                                            &hit_action_spec);
            }
            break;
            case SWITCH_API_INTERFACE_TUNNEL:
            {
                p4_pd_dc_dmac_redirect_nexthop_action_spec_t nhop_action_spec;
                memset(&nhop_action_spec, 0, sizeof(p4_pd_dc_dmac_redirect_nexthop_action_spec_t));
                nhop_action_spec.action_nexthop_index = nhop_index;
                status = p4_pd_dc_dmac_table_modify_with_dmac_redirect_nexthop(g_sess_hdl,
                                                                          device,
                                                                          entry_hdl,
                                                                          &nhop_action_spec);
            }
            break;
            default:
                status = SWITCH_STATUS_INVALID_INTERFACE;
        }
    }
#endif /* P4_L2_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_dmac_table_delete_entry(switch_device_t device,
                              p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_L2_DISABLE

    status = p4_pd_dc_dmac_table_delete(g_sess_hdl, device,
                                           entry_hdl);
#endif /* P4_L2_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_smac_table_add_entry(switch_device_t device,
                               switch_api_mac_entry_t *mac_entry,
                               switch_interface_info_t *intf_info,
                               p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_L2_DISABLE
    p4_pd_dc_smac_match_spec_t match_spec;
    p4_pd_dc_smac_hit_action_spec_t action_spec;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_smac_match_spec_t));
    memset(&action_spec, 0, sizeof(p4_pd_dc_smac_hit_action_spec_t));

    match_spec.ingress_metadata_bd = handle_to_id(mac_entry->vlan_handle);
    memcpy(match_spec.l2_metadata_lkp_mac_sa, &mac_entry->mac, ETH_LEN);

    action_spec.action_ifindex = intf_info->ifindex;

    status = p4_pd_dc_smac_table_add_with_smac_hit(g_sess_hdl,
                                                     p4_pd_device,
                                                     &match_spec,
                                                     &action_spec,
                                                     entry_hdl);
#endif /* P4_L2_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_smac_table_update_entry(switch_device_t device,
                                  switch_api_mac_entry_t *mac_entry,
                                  switch_interface_info_t *intf_info,
                                  p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_L2_DISABLE
    p4_pd_dc_smac_hit_action_spec_t action_spec;

    memset(&action_spec, 0, sizeof(p4_pd_dc_smac_hit_action_spec_t));
    action_spec.action_ifindex = intf_info->ifindex;

    status = p4_pd_dc_smac_table_modify_with_smac_hit(g_sess_hdl,
                                                     device,
                                                     entry_hdl,
                                                     &action_spec);
#endif /* P4_L2_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_smac_table_delete_entry(switch_device_t device,
                                  p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_L2_DISABLE

    status = p4_pd_dc_smac_table_delete(g_sess_hdl, device,
                                           entry_hdl);
#endif /* P4_L2_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mac_table_set_learning_timeout(switch_device_t device, uint32_t timeout)
{
    p4_pd_status_t status = 0;
#ifndef P4_L2_DISABLE
    p4_pd_dc_set_learning_timeout(g_sess_hdl, device, timeout);
#endif /* P4_L2_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_nexthop_table_add_entry(switch_device_t device,
                                  uint16_t nhop_index,
                                  uint16_t bd,
                                  switch_ifindex_t ifindex,
                                  bool flood,
                                  uint32_t mc_index,
                                  bool tunnel,
                                  p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_dc_nexthop_match_spec_t match_spec;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_nexthop_match_spec_t));
    match_spec.l3_metadata_nexthop_index = nhop_index;


    if (flood) {
        p4_pd_dc_set_nexthop_details_for_post_routed_flood_action_spec_t action_spec;
        memset(&action_spec, 0, sizeof(p4_pd_dc_set_nexthop_details_for_post_routed_flood_action_spec_t));
        action_spec.action_bd = bd;
        action_spec.action_uuc_mc_index= mc_index;
        status = p4_pd_dc_nexthop_table_add_with_set_nexthop_details_for_post_routed_flood(
                                                                 g_sess_hdl,
                                                                 p4_pd_device,
                                                                 &match_spec,
                                                                 &action_spec,
                                                                 entry_hdl);
    } else {
        p4_pd_dc_set_nexthop_details_action_spec_t action_spec;
        memset(&action_spec, 0, sizeof(p4_pd_dc_set_nexthop_details_action_spec_t));
        action_spec.action_bd = bd;
        action_spec.action_ifindex = ifindex;
        action_spec.action_tunnel = tunnel;
        status = p4_pd_dc_nexthop_table_add_with_set_nexthop_details(g_sess_hdl,
                                                                 p4_pd_device,
                                                                 &match_spec,
                                                                 &action_spec,
                                                                 entry_hdl);
    }
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_nexthop_table_update_entry(switch_device_t device,
                                     uint16_t nhop_index,
                                     uint16_t bd,
                                     switch_ifindex_t ifindex,
                                     bool flood,
                                     uint32_t mc_index,
                                     bool tunnel,
                                     p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;

    UNUSED(nhop_index);

    if (flood) {
        p4_pd_dc_set_nexthop_details_for_post_routed_flood_action_spec_t action_spec;
        memset(&action_spec, 0, sizeof(p4_pd_dc_set_nexthop_details_for_post_routed_flood_action_spec_t));
        action_spec.action_bd = bd;
        action_spec.action_uuc_mc_index = mc_index;
        status = p4_pd_dc_nexthop_table_modify_with_set_nexthop_details_for_post_routed_flood(
                                                                    g_sess_hdl,
                                                                    device,
                                                                    *entry_hdl,
                                                                    &action_spec);
    } else {
        p4_pd_dc_set_nexthop_details_action_spec_t action_spec;
        memset(&action_spec, 0, sizeof(p4_pd_dc_set_nexthop_details_action_spec_t));
        action_spec.action_bd = bd;
        action_spec.action_ifindex = ifindex;
        action_spec.action_tunnel = tunnel;
        status = p4_pd_dc_nexthop_table_modify_with_set_nexthop_details(g_sess_hdl,
                                                                    device,
                                                                    *entry_hdl,
                                                                    &action_spec);
    }
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ecmp_group_create(switch_device_t device,
                            p4_pd_grp_hdl_t *pd_group_hdl)
{
    switch_status_t status = 0;
    p4_pd_dev_target_t                             p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_ecmp_action_profile_create_group(g_sess_hdl,
                                                       p4_pd_device,
                                                       MAX_ECMP_GROUP_SIZE,
                                                       pd_group_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ecmp_group_delete(switch_device_t device,
                            p4_pd_grp_hdl_t pd_group_hdl)
{
    switch_status_t status = 0;
    status = p4_pd_dc_ecmp_action_profile_del_group(g_sess_hdl, device,
                                                    pd_group_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ecmp_member_add(switch_device_t device,
                          p4_pd_grp_hdl_t pd_group_hdl,
                          uint16_t nhop_index,
                          switch_interface_info_t *intf_info,
                          p4_pd_mbr_hdl_t *mbr_hdl)
{
    p4_pd_status_t status = 0;
    p4_pd_dev_target_t                             pd_device;
    p4_pd_dc_set_ecmp_nexthop_details_action_spec_t action_spec;

    pd_device.device_id = device;
    pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&action_spec, 0,
           sizeof(p4_pd_dc_set_ecmp_nexthop_details_action_spec_t));

    action_spec.action_ifindex = intf_info->ifindex;
    action_spec.action_bd = handle_to_id(intf_info->bd_handle);
    action_spec.action_nhop_index = nhop_index;
    action_spec.action_tunnel =
        (SWITCH_INTF_TYPE(intf_info) == SWITCH_API_INTERFACE_TUNNEL);

    status =
        p4_pd_dc_ecmp_action_profile_add_member_with_set_ecmp_nexthop_details(
            g_sess_hdl,
            pd_device, &action_spec, mbr_hdl);

    status = p4_pd_dc_ecmp_action_profile_add_member_to_group(g_sess_hdl,
                    device, pd_group_hdl, *mbr_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ecmp_group_table_delete_entry(switch_device_t device,
                                        p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
    status = p4_pd_dc_ecmp_group_table_delete(g_sess_hdl,
                                                   device,
                                                   entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ecmp_member_delete(switch_device_t device,
                             p4_pd_grp_hdl_t pd_group_hdl,
                             p4_pd_mbr_hdl_t mbr_hdl)
{
    p4_pd_dc_ecmp_action_profile_del_member_from_group(g_sess_hdl,
                                                       device, pd_group_hdl,
                                                       mbr_hdl);

    p4_pd_dc_ecmp_action_profile_del_member(g_sess_hdl, device, mbr_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return 0;
}

p4_pd_status_t
switch_pd_ecmp_group_table_add_entry_with_selector(switch_device_t device,
                                                   uint16_t ecmp_index,
                                                   p4_pd_grp_hdl_t grp_hdl,
                                                   p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t                                 status = 0;
    p4_pd_dc_ecmp_group_match_spec_t               match_spec;
    p4_pd_dev_target_t                             pd_device;

    pd_device.device_id = device;
    pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_ecmp_group_match_spec_t));
    match_spec.l3_metadata_nexthop_index = ecmp_index;
    status = p4_pd_dc_ecmp_group_add_entry_with_selector(g_sess_hdl, pd_device,
                    &match_spec, grp_hdl, entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
p4_pd_ecmp_group_table_delete_entry(switch_device_t device,
                                    p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
    status = p4_pd_dc_ecmp_group_table_delete(g_sess_hdl,
                                                   device,
                                                   entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_nexthop_table_delete_entry(switch_device_t device,
                                     p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status;

    status = p4_pd_dc_nexthop_table_delete(g_sess_hdl, device,
                                             entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ip_fib_add_entry(switch_device_t device, switch_handle_t vrf,
                           switch_ip_addr_t *ip_addr, bool ecmp,
                           switch_handle_t nexthop, p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_L3_DISABLE
    p4_pd_dev_target_t p4_pd_device;
    bool host_entry = FALSE;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    if (ip_addr->type == SWITCH_API_IP_ADDR_V4) {
#ifndef P4_IPV4_DISABLE
        host_entry = ip_addr->prefix_len == SWITCH_IPV4_PREFIX_LENGTH ? TRUE : FALSE;
        if (ecmp) {
            if (host_entry) {
                p4_pd_dc_ipv4_fib_match_spec_t v4_match_spec;
                p4_pd_dc_fib_hit_ecmp_action_spec_t v4_action_spec;

                memset(&v4_match_spec, 0, sizeof(p4_pd_dc_ipv4_fib_match_spec_t));
                memset(&v4_action_spec, 0, sizeof(p4_pd_dc_fib_hit_ecmp_action_spec_t));

                v4_match_spec.l3_metadata_vrf = vrf;
                v4_match_spec.ipv4_metadata_lkp_ipv4_da = ip_addr->ip.v4addr;
                v4_action_spec.action_ecmp_index = nexthop;
                status = p4_pd_dc_ipv4_fib_table_add_with_fib_hit_ecmp(g_sess_hdl,
                                                           p4_pd_device,
                                                           &v4_match_spec,
                                                           &v4_action_spec,
                                                           entry_hdl);
            } else {
                p4_pd_dc_ipv4_fib_lpm_match_spec_t v4_match_spec;
                p4_pd_dc_fib_hit_ecmp_action_spec_t v4_action_spec;

                memset(&v4_match_spec, 0, sizeof(p4_pd_dc_ipv4_fib_lpm_match_spec_t));
                memset(&v4_action_spec, 0, sizeof(p4_pd_dc_fib_hit_ecmp_action_spec_t));
                v4_match_spec.l3_metadata_vrf = vrf;
                v4_match_spec.ipv4_metadata_lkp_ipv4_da = ip_addr->ip.v4addr;
                v4_match_spec.ipv4_metadata_lkp_ipv4_da_prefix_length =
                                            ip_addr->prefix_len;
                v4_action_spec.action_ecmp_index = nexthop;
                status = p4_pd_dc_ipv4_fib_lpm_table_add_with_fib_hit_ecmp(g_sess_hdl,
                                                           p4_pd_device,
                                                           &v4_match_spec,
                                                           &v4_action_spec,
                                                           entry_hdl);
            }
        } else {
            if (host_entry) {
                p4_pd_dc_ipv4_fib_match_spec_t v4_match_spec;
                p4_pd_dc_fib_hit_nexthop_action_spec_t v4_action_spec;

                memset(&v4_match_spec, 0, sizeof(p4_pd_dc_ipv4_fib_match_spec_t));
                memset(&v4_action_spec, 0, sizeof(p4_pd_dc_fib_hit_nexthop_action_spec_t));

                v4_match_spec.l3_metadata_vrf = vrf;
                v4_match_spec.ipv4_metadata_lkp_ipv4_da = ip_addr->ip.v4addr;
                v4_action_spec.action_nexthop_index = nexthop;
                status =  p4_pd_dc_ipv4_fib_table_add_with_fib_hit_nexthop(g_sess_hdl,
                                                           p4_pd_device,
                                                           &v4_match_spec,
                                                           &v4_action_spec,
                                                           entry_hdl);
            } else {
                p4_pd_dc_ipv4_fib_lpm_match_spec_t v4_match_spec;
                p4_pd_dc_fib_hit_nexthop_action_spec_t v4_action_spec;

                memset(&v4_match_spec, 0, sizeof(p4_pd_dc_ipv4_fib_lpm_match_spec_t));
                memset(&v4_action_spec, 0, sizeof(p4_pd_dc_fib_hit_nexthop_action_spec_t));

                v4_match_spec.l3_metadata_vrf = vrf;
                v4_match_spec.ipv4_metadata_lkp_ipv4_da = ip_addr->ip.v4addr;
                v4_match_spec.ipv4_metadata_lkp_ipv4_da_prefix_length =
                                            ip_addr->prefix_len;
                v4_action_spec.action_nexthop_index = nexthop;
                status = p4_pd_dc_ipv4_fib_lpm_table_add_with_fib_hit_nexthop(g_sess_hdl,
                                                           p4_pd_device,
                                                           &v4_match_spec,
                                                           &v4_action_spec,
                                                           entry_hdl);
            }
        }
#endif /* P4_IPV4_DISABLE */
    } else {
#ifndef P4_IPV6_DISABLE
        host_entry = ip_addr->prefix_len == SWITCH_IPV6_PREFIX_LENGTH ? TRUE : FALSE;
        if (ecmp) {
            if (host_entry) {
                p4_pd_dc_ipv6_fib_match_spec_t v6_match_spec;
                p4_pd_dc_fib_hit_ecmp_action_spec_t v6_action_spec;

                memset(&v6_match_spec, 0, sizeof(p4_pd_dc_ipv6_fib_match_spec_t));
                memset(&v6_action_spec, 0, sizeof(p4_pd_dc_fib_hit_ecmp_action_spec_t));

                v6_match_spec.l3_metadata_vrf = vrf;
                memcpy(&v6_match_spec.ipv6_metadata_lkp_ipv6_da,
                       ip_addr->ip.v6addr, 16);
                v6_action_spec.action_ecmp_index = nexthop;
                status = p4_pd_dc_ipv6_fib_table_add_with_fib_hit_ecmp(g_sess_hdl,
                                                           p4_pd_device,
                                                           &v6_match_spec,
                                                           &v6_action_spec,
                                                           entry_hdl);
            } else {
                p4_pd_dc_ipv6_fib_lpm_match_spec_t v6_match_spec;
                p4_pd_dc_fib_hit_ecmp_action_spec_t v6_action_spec;

                memset(&v6_match_spec, 0, sizeof(p4_pd_dc_ipv6_fib_lpm_match_spec_t));
                memset(&v6_action_spec, 0, sizeof(p4_pd_dc_fib_hit_ecmp_action_spec_t));

                v6_match_spec.l3_metadata_vrf = vrf;
                memcpy(&v6_match_spec.ipv6_metadata_lkp_ipv6_da,
                        ip_addr->ip.v6addr, 16);
                v6_match_spec.ipv6_metadata_lkp_ipv6_da_prefix_length =
                                            ip_addr->prefix_len;
                v6_action_spec.action_ecmp_index = nexthop;
                status = p4_pd_dc_ipv6_fib_lpm_table_add_with_fib_hit_ecmp(g_sess_hdl,
                                                           p4_pd_device,
                                                           &v6_match_spec,
                                                           &v6_action_spec,
                                                           entry_hdl);
            }
        } else {
            if (host_entry) {
                p4_pd_dc_ipv6_fib_match_spec_t v6_match_spec;
                p4_pd_dc_fib_hit_nexthop_action_spec_t v6_action_spec;

                memset(&v6_match_spec, 0, sizeof(p4_pd_dc_ipv6_fib_match_spec_t));
                memset(&v6_action_spec, 0, sizeof(p4_pd_dc_fib_hit_nexthop_action_spec_t));

                v6_match_spec.l3_metadata_vrf = vrf;
                memcpy(&v6_match_spec.ipv6_metadata_lkp_ipv6_da,
                       ip_addr->ip.v6addr, 16);
                v6_action_spec.action_nexthop_index = nexthop;
                status = p4_pd_dc_ipv6_fib_table_add_with_fib_hit_nexthop(g_sess_hdl,
                                                           p4_pd_device,
                                                           &v6_match_spec,
                                                           &v6_action_spec,
                                                           entry_hdl);
            } else {
                p4_pd_dc_ipv6_fib_lpm_match_spec_t v6_match_spec;
                p4_pd_dc_fib_hit_nexthop_action_spec_t v6_action_spec;

                memset(&v6_match_spec, 0, sizeof(p4_pd_dc_ipv6_fib_lpm_match_spec_t));
                memset(&v6_action_spec, 0, sizeof(p4_pd_dc_fib_hit_nexthop_action_spec_t));

                v6_match_spec.l3_metadata_vrf = vrf;
                memcpy(&v6_match_spec.ipv6_metadata_lkp_ipv6_da,
                        ip_addr->ip.v6addr, 16);
                v6_match_spec.ipv6_metadata_lkp_ipv6_da_prefix_length =
                                            ip_addr->prefix_len;
                v6_action_spec.action_nexthop_index = nexthop;
                status = p4_pd_dc_ipv6_fib_lpm_table_add_with_fib_hit_nexthop(g_sess_hdl,
                                                           p4_pd_device,
                                                           &v6_match_spec,
                                                           &v6_action_spec,
                                                           entry_hdl);
            }
        }
#endif /* P4_IPV6_DISABLE */
    }
#endif /* L3_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ip_fib_update_entry(switch_device_t device, switch_handle_t vrf,
                              switch_ip_addr_t *ip_addr, bool ecmp,
                              switch_handle_t nexthop, p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
    UNUSED(vrf);
#ifndef P4_L3_DISABLE
    bool host_entry = FALSE;

    if (ip_addr->type == SWITCH_API_IP_ADDR_V4) {
#ifndef P4_IPV4_DISABLE
        host_entry = ip_addr->prefix_len == SWITCH_IPV4_PREFIX_LENGTH ? TRUE : FALSE;
        if (ecmp) {
            if (host_entry) {
                p4_pd_dc_fib_hit_ecmp_action_spec_t v4_action_spec;
                memset(&v4_action_spec, 0, sizeof(p4_pd_dc_fib_hit_ecmp_action_spec_t));
                v4_action_spec.action_ecmp_index = nexthop;
                status = p4_pd_dc_ipv4_fib_table_modify_with_fib_hit_ecmp(g_sess_hdl,
                                                           device,
                                                           entry_hdl,
                                                           &v4_action_spec);
            } else {
                p4_pd_dc_fib_hit_ecmp_action_spec_t v4_action_spec;
                memset(&v4_action_spec, 0, sizeof(p4_pd_dc_fib_hit_ecmp_action_spec_t));
                v4_action_spec.action_ecmp_index = nexthop;
                status = p4_pd_dc_ipv4_fib_lpm_table_modify_with_fib_hit_ecmp(g_sess_hdl,
                                                           device,
                                                           entry_hdl,
                                                           &v4_action_spec);
            }
        } else {
            if (host_entry) {
                p4_pd_dc_fib_hit_nexthop_action_spec_t v4_action_spec;
                memset(&v4_action_spec, 0, sizeof(p4_pd_dc_fib_hit_nexthop_action_spec_t));
                v4_action_spec.action_nexthop_index = nexthop;
                status = p4_pd_dc_ipv4_fib_table_modify_with_fib_hit_nexthop(g_sess_hdl,
                                                           device,
                                                           entry_hdl,
                                                           &v4_action_spec);
            } else {
                p4_pd_dc_fib_hit_nexthop_action_spec_t v4_action_spec;
                memset(&v4_action_spec, 0, sizeof(p4_pd_dc_fib_hit_nexthop_action_spec_t));
                v4_action_spec.action_nexthop_index = nexthop;
                status = p4_pd_dc_ipv4_fib_lpm_table_modify_with_fib_hit_nexthop(g_sess_hdl,
                                                           device,
                                                           entry_hdl,
                                                           &v4_action_spec);
            }
        }
#endif /* P4_IPV4_DISABLE */
    } else {
#ifndef P4_IPV6_DISABLE
        host_entry = ip_addr->prefix_len == SWITCH_IPV6_PREFIX_LENGTH ? TRUE : FALSE;
        if (ecmp) {
            if (host_entry) {
                p4_pd_dc_fib_hit_ecmp_action_spec_t v6_action_spec;
                memset(&v6_action_spec, 0, sizeof(p4_pd_dc_fib_hit_ecmp_action_spec_t));
                v6_action_spec.action_ecmp_index = nexthop;
                status = p4_pd_dc_ipv6_fib_table_modify_with_fib_hit_ecmp(g_sess_hdl,
                                                           device,
                                                           entry_hdl,
                                                           &v6_action_spec);
            } else {
                p4_pd_dc_fib_hit_ecmp_action_spec_t v6_action_spec;
                memset(&v6_action_spec, 0, sizeof(p4_pd_dc_fib_hit_ecmp_action_spec_t));
                v6_action_spec.action_ecmp_index = nexthop;
                status = p4_pd_dc_ipv6_fib_lpm_table_modify_with_fib_hit_ecmp(g_sess_hdl,
                                                           device,
                                                           entry_hdl,
                                                           &v6_action_spec);
            }
        } else {
            if (host_entry) {
                p4_pd_dc_fib_hit_nexthop_action_spec_t v6_action_spec;
                memset(&v6_action_spec, 0, sizeof(p4_pd_dc_fib_hit_nexthop_action_spec_t));
                v6_action_spec.action_nexthop_index = nexthop;
                status = p4_pd_dc_ipv6_fib_table_modify_with_fib_hit_nexthop(g_sess_hdl,
                                                           device,
                                                           entry_hdl,
                                                           &v6_action_spec);
            } else {
                p4_pd_dc_fib_hit_nexthop_action_spec_t v6_action_spec;
                memset(&v6_action_spec, 0, sizeof(p4_pd_dc_fib_hit_nexthop_action_spec_t));
                v6_action_spec.action_nexthop_index = nexthop;
                status = p4_pd_dc_ipv6_fib_lpm_table_modify_with_fib_hit_nexthop(g_sess_hdl,
                                                           device,
                                                           entry_hdl,
                                                           &v6_action_spec);
            }
        }
#endif /* P4_IPV6_DISABLE */
    }
#endif /* P4_L3_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ip_fib_delete_entry(switch_device_t device,
                              switch_ip_addr_t *ip_addr,
                              p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef L3_DISABLE
    bool host_entry = FALSE;

    if (ip_addr->type == SWITCH_API_IP_ADDR_V4) {
#ifndef IPV4_DISABLE
        host_entry = ip_addr->prefix_len == SWITCH_IPV4_PREFIX_LENGTH ? TRUE : FALSE;
        if (host_entry) {
            status = p4_pd_dc_ipv4_fib_table_delete(g_sess_hdl,
                                                         device,
                                                         entry_hdl);
        } else {
            status = p4_pd_dc_ipv4_fib_lpm_table_delete(g_sess_hdl,
                                                         device,
                                                         entry_hdl);
        }
#endif /* IPV4_DISABLE */
    } else {
#ifndef P4_IPV6_DISABLE
        host_entry = ip_addr->prefix_len == SWITCH_IPV6_PREFIX_LENGTH ? TRUE : FALSE;
        if (host_entry) {
            status = p4_pd_dc_ipv6_fib_table_delete(g_sess_hdl,
                                                         device,
                                                         entry_hdl);
        } else {
            status = p4_pd_dc_ipv6_fib_lpm_table_delete(g_sess_hdl,
                                                         device,
                                                         entry_hdl);
        }
#endif /* P4_IPV6_DISABLE */
    }
#endif /* L3_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_inner_rmac_table_add_entry(switch_device_t device,
                                     switch_handle_t rmac_group,
                                     switch_mac_addr_t *mac,
                                     p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_rmac_match_spec_t match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_rmac_match_spec_t));
    match_spec.l3_metadata_rmac_group = rmac_group;
    memcpy(match_spec.l2_metadata_lkp_mac_da, mac, ETH_LEN);

    status = p4_pd_dc_rmac_table_add_with_rmac_hit(g_sess_hdl,
                                                     p4_pd_device,
                                                     &match_spec,
                                                     entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_inner_rmac_table_delete_entry(switch_device_t device,
                                        p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;

    status = p4_pd_dc_rmac_table_delete(g_sess_hdl,
                                          device,
                                          entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_outer_rmac_table_add_entry(switch_device_t device,
                                     switch_handle_t rmac_group,
                                     switch_mac_addr_t *mac,
                                     p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_outer_rmac_match_spec_t match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_rmac_match_spec_t));
    match_spec.l3_metadata_rmac_group = rmac_group;
    memcpy(match_spec.l2_metadata_lkp_mac_da, mac, ETH_LEN);

    p4_pd_dc_outer_rmac_table_add_with_outer_rmac_hit(g_sess_hdl,
                                                      p4_pd_device,
                                                      &match_spec,
                                                      entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_outer_rmac_table_delete_entry(switch_device_t device,
                                        p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE

    status = p4_pd_dc_outer_rmac_table_delete(g_sess_hdl,
                                                device,
                                                entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_src_vtep_table_add_entry(switch_device_t device,
                                   switch_ip_encap_t *ip_encap,
                                   switch_ifindex_t ifindex,
                                   p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_TUNNEL_DISABLE) && !defined(P4_L3_DISABLE)
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    if (SWITCH_IP_ENCAP_SRC_IP_TYPE(ip_encap) == SWITCH_API_IP_ADDR_V4) {
#ifndef P4_IPV4_DISABLE
        p4_pd_dc_ipv4_src_vtep_match_spec_t v4_match_spec;
        p4_pd_dc_src_vtep_hit_action_spec_t v4_action_spec;

        memset(&v4_match_spec, 0, sizeof(p4_pd_dc_ipv4_src_vtep_match_spec_t));
        memset(&v4_action_spec, 0, sizeof(p4_pd_dc_src_vtep_hit_action_spec_t));

        v4_match_spec.l3_metadata_vrf = handle_to_id(ip_encap->vrf_handle);
        v4_match_spec.ipv4_metadata_lkp_ipv4_sa = SWITCH_IP_ENCAP_IPV4_SRC_IP(ip_encap);
        v4_action_spec.action_ifindex = ifindex;

        status = p4_pd_dc_ipv4_src_vtep_table_add_with_src_vtep_hit(
            g_sess_hdl,
            p4_pd_device,
            &v4_match_spec,
            &v4_action_spec,
            entry_hdl);
#endif /* P4_IPV4_DISABLE */
    } else {
#ifndef P4_IPV6_DISABLE
        p4_pd_dc_ipv6_src_vtep_match_spec_t v6_match_spec;
        p4_pd_dc_src_vtep_hit_action_spec_t v6_action_spec;

        memset(&v6_match_spec, 0, sizeof(p4_pd_dc_ipv6_src_vtep_match_spec_t));
        memset(&v6_action_spec, 0, sizeof(p4_pd_dc_src_vtep_hit_action_spec_t));

        v6_match_spec.l3_metadata_vrf = handle_to_id(ip_encap->vrf_handle);
        memcpy(&v6_match_spec.ipv6_metadata_lkp_ipv6_sa,
                SWITCH_IP_ENCAP_IPV6_SRC_IP(ip_encap), 16);
        v6_action_spec.action_ifindex = ifindex;

        status = p4_pd_dc_ipv6_src_vtep_table_add_with_src_vtep_hit(
            g_sess_hdl,
            p4_pd_device,
            &v6_match_spec,
            &v6_action_spec,
            entry_hdl);
#endif /* P4_IPV6_DISABLE */
    }
#endif /* P4_TUNNEL_DISABLE && P4_L3_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_src_vtep_table_delete_entry(switch_device_t device,
                                      switch_ip_encap_t *ip_encap,
                                      p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_TUNNEL_DISABLE) && !defined(P4_L3_DISABLE)
    if (SWITCH_IP_ENCAP_SRC_IP_TYPE(ip_encap) == SWITCH_API_IP_ADDR_V4) {
#ifndef P4_IPV4_DISABLE
        status = p4_pd_dc_ipv4_src_vtep_table_delete(g_sess_hdl,
                                                      device,
                                                      entry_hdl);
#endif /* P4_IPV4_DISABLE */
    } else {
#ifndef P4_IPV6_DISABLE
        status = p4_pd_dc_ipv6_src_vtep_table_delete(g_sess_hdl,
                                                      device,
                                                      entry_hdl);
#endif /* P4_IPV6_DISABLE */
    }
#endif /* P4_TUNNEL_DISABLE && P4_L3_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_dest_vtep_table_add_entry(switch_device_t device,
                                    switch_ip_encap_t *ip_encap,
                                    p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_TUNNEL_DISABLE) && !defined(P4_L3_DISABLE)
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    if (SWITCH_IP_ENCAP_DST_IP_TYPE(ip_encap) == SWITCH_API_IP_ADDR_V4) {
#ifndef P4_IPV4_DISABLE
        p4_pd_dc_ipv4_dest_vtep_match_spec_t v4_match_spec;
        memset(&v4_match_spec, 0, sizeof(p4_pd_dc_ipv4_dest_vtep_match_spec_t));
        v4_match_spec.l3_metadata_vrf = handle_to_id(ip_encap->vrf_handle);
        v4_match_spec.ipv4_metadata_lkp_ipv4_da =
            SWITCH_IP_ENCAP_IPV4_DST_IP(ip_encap);
        v4_match_spec.tunnel_metadata_ingress_tunnel_type =
            switch_tunnel_get_ingress_tunnel_type(ip_encap);
        status = p4_pd_dc_ipv4_dest_vtep_table_add_with_set_tunnel_termination_flag(
            g_sess_hdl,
            p4_pd_device,
            &v4_match_spec,
            entry_hdl);
#endif /* P4_IPV4_DISABLE */
    } else {
#ifndef P4_IPV6_DISABLE
        p4_pd_dc_ipv6_dest_vtep_match_spec_t v6_match_spec;
        memset(&v6_match_spec, 0, sizeof(p4_pd_dc_ipv6_dest_vtep_match_spec_t));
        v6_match_spec.l3_metadata_vrf = handle_to_id(ip_encap->vrf_handle);
        memcpy(&v6_match_spec.ipv6_metadata_lkp_ipv6_da,
               SWITCH_IP_ENCAP_IPV6_DST_IP(ip_encap), 16);
        v6_match_spec.tunnel_metadata_ingress_tunnel_type =
            switch_tunnel_get_ingress_tunnel_type(ip_encap);
        status = p4_pd_dc_ipv6_dest_vtep_table_add_with_set_tunnel_termination_flag(
            g_sess_hdl,
            p4_pd_device,
            &v6_match_spec,
            entry_hdl);
#endif /* P4_IPV6_DISABLE */
    }
#endif /* P4_TUNNEL_DISABLE && P4_L3_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_dest_vtep_table_delete_entry(switch_device_t device,
                                       switch_ip_encap_t *ip_encap,
                                       p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;

#if !defined(P4_TUNNEL_DISABLE) && !defined(P4_L3_DISABLE)
    if (SWITCH_IP_ENCAP_SRC_IP_TYPE(ip_encap) == SWITCH_API_IP_ADDR_V4) {
#ifndef P4_IPV4_DISABLE
        status = p4_pd_dc_ipv4_dest_vtep_table_delete(g_sess_hdl,
                                                       device,
                                                       entry_hdl);
#endif /* P4_IPV4_DISABLE */
    } else {
#ifndef P4_IPV6_DISABLE
        status = p4_pd_dc_ipv6_dest_vtep_table_delete(g_sess_hdl,
                                                       device,
                                                       entry_hdl);
#endif /* P4_IPV6_DISABLE */
    }
#endif /* P4_TUNNEL_DISABLE && P4_L3_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_smac_rewrite_table_add_entry(switch_device_t device,
                                              uint16_t smac_index,
                                              switch_mac_addr_t *mac,
                                              p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_tunnel_smac_rewrite_match_spec_t match_spec;
    p4_pd_dc_rewrite_tunnel_smac_action_spec_t action_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_tunnel_smac_rewrite_match_spec_t));
    memset(&action_spec, 0, sizeof(p4_pd_dc_rewrite_tunnel_smac_action_spec_t));

    match_spec.tunnel_metadata_tunnel_smac_index = smac_index;
    memcpy(action_spec.action_smac, mac->mac_addr, ETH_LEN);

    status = p4_pd_dc_tunnel_smac_rewrite_table_add_with_rewrite_tunnel_smac(g_sess_hdl,
                                                                        p4_pd_device,
                                                                        &match_spec,
                                                                        &action_spec,
                                                                        entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_smac_rewrite_table_delete_entry(switch_device_t device,
                                                 p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    status = p4_pd_dc_tunnel_smac_rewrite_table_delete(g_sess_hdl,
                                                            device,
                                                            entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_dmac_rewrite_table_add_entry(switch_device_t device,
                                              uint16_t dmac_index,
                                              switch_mac_addr_t *mac,
                                              p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_tunnel_dmac_rewrite_match_spec_t match_spec;
    p4_pd_dc_rewrite_tunnel_dmac_action_spec_t action_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_tunnel_dmac_rewrite_match_spec_t));
    memset(&action_spec, 0, sizeof(p4_pd_dc_rewrite_tunnel_dmac_action_spec_t));

    match_spec.tunnel_metadata_tunnel_dmac_index = dmac_index;
    memcpy(action_spec.action_dmac, mac->mac_addr, ETH_LEN);

    status = p4_pd_dc_tunnel_dmac_rewrite_table_add_with_rewrite_tunnel_dmac(g_sess_hdl,
                                                                        p4_pd_device,
                                                                        &match_spec,
                                                                        &action_spec,
                                                                        entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;

}

p4_pd_status_t
switch_pd_tunnel_dmac_rewrite_table_delete_entry(switch_device_t device,
                                                 p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    status = p4_pd_dc_tunnel_dmac_rewrite_table_delete(g_sess_hdl,
                                                            device,
                                                            entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_rewrite_table_add_entry(switch_device_t device, uint16_t tunnel_index,
                                         uint16_t sip_index, uint16_t dip_index,
                                         uint16_t smac_index, uint16_t dmac_index,
                                         p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_tunnel_rewrite_match_spec_t match_spec;
    p4_pd_dc_set_tunnel_rewrite_details_action_spec_t action_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_tunnel_rewrite_match_spec_t));
    memset(&action_spec, 0, sizeof(p4_pd_dc_set_tunnel_rewrite_details_action_spec_t));

    match_spec.tunnel_metadata_tunnel_index = tunnel_index;
    action_spec.action_smac_idx = smac_index;
    action_spec.action_dmac_idx = dmac_index;
    action_spec.action_sip_index = sip_index;
    action_spec.action_dip_index = dip_index;

    status = p4_pd_dc_tunnel_rewrite_table_add_with_set_tunnel_rewrite_details(
        g_sess_hdl, p4_pd_device, &match_spec,
        &action_spec, entry_hdl);

#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_rewrite_table_delete_entry(switch_device_t device, p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    status = p4_pd_dc_tunnel_rewrite_table_delete(g_sess_hdl,
                                                       device,
                                                       entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_table_add_entry(switch_device_t device,
                                 switch_encap_type_t encap_type,
                                 uint16_t tunnel_vni,
                                 switch_rid_t ingress_rid,
                                 switch_bd_info_t *bd_info,
                                 switch_ip_encap_t *ip_encap,
                                 switch_handle_t bd_handle,
                                 p4_pd_entry_hdl_t entry_hdl[])
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_dev_target_t p4_pd_device;
    uint16_t ingress_tunnel_type = 0;
    switch_logical_network_t *ln_info = NULL;
    int entry = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    switch(encap_type) {
        case SWITCH_API_ENCAP_TYPE_VXLAN:
            ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_VXLAN;
            break;
        case SWITCH_API_ENCAP_TYPE_GENEVE:
            ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_GENEVE;
            break;
        case SWITCH_API_ENCAP_TYPE_NVGRE:
            ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_NVGRE;
            break;
        case SWITCH_API_ENCAP_TYPE_GRE:
        case SWITCH_API_ENCAP_TYPE_ERSPAN_T3:
            ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_GRE;
            break;
        default:
            return SWITCH_STATUS_INVALID_TUNNEL_TYPE;
    }

    ln_info = &bd_info->ln_info;
    p4_pd_dc_tunnel_match_spec_t match_spec;

    if ((ingress_tunnel_type == SWITCH_INGRESS_TUNNEL_TYPE_VXLAN) ||
        (ingress_tunnel_type == SWITCH_INGRESS_TUNNEL_TYPE_GENEVE) ||
        (ingress_tunnel_type == SWITCH_INGRESS_TUNNEL_TYPE_NVGRE)) {

        memset(&match_spec, 0, sizeof(p4_pd_dc_tunnel_match_spec_t));
        match_spec.tunnel_metadata_tunnel_vni = tunnel_vni;
        match_spec.tunnel_metadata_ingress_tunnel_type = ingress_tunnel_type;
        match_spec.inner_ipv6_valid = FALSE;
        match_spec.inner_ipv4_valid = FALSE;

        p4_pd_dc_terminate_tunnel_inner_non_ip_action_spec_t non_ip_action_spec;
        memset(&non_ip_action_spec, 0,
               sizeof(p4_pd_dc_terminate_tunnel_inner_non_ip_action_spec_t));
        non_ip_action_spec.action_bd = bd_handle;
        non_ip_action_spec.action_bd_label = handle_to_id(ln_info->bd_label);
        non_ip_action_spec.action_stats_idx = SWITCH_BD_STATS_START_INDEX(bd_info);

        status = p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_non_ip(
            g_sess_hdl,
            p4_pd_device,
            &match_spec,
            &non_ip_action_spec,
            &entry_hdl[entry++]);

#ifndef P4_IPV4_DISABLE
        memset(&match_spec, 0, sizeof(p4_pd_dc_tunnel_match_spec_t));
        match_spec.tunnel_metadata_tunnel_vni = tunnel_vni;
        match_spec.tunnel_metadata_ingress_tunnel_type = ingress_tunnel_type;
        match_spec.inner_ipv4_valid = TRUE;
        match_spec.inner_ipv6_valid = FALSE;

        p4_pd_dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t v4_action_spec;
        memset(&v4_action_spec, 0,
               sizeof(p4_pd_dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t));
        v4_action_spec.action_bd = bd_handle;
        v4_action_spec.action_vrf = handle_to_id(ln_info->vrf_handle);
        v4_action_spec.action_rmac_group = handle_to_id(ln_info->rmac_handle);
        v4_action_spec.action_mrpf_group = handle_to_id(ln_info->mrpf_group);
        v4_action_spec.action_bd_label = handle_to_id(ln_info->bd_label);
        v4_action_spec.action_ipv4_unicast_enabled = SWITCH_LN_IPV4_UNICAST_ENABLED(bd_info);
        v4_action_spec.action_ipv4_multicast_enabled = SWITCH_LN_IPV4_MULTICAST_ENABLED(bd_info);
        v4_action_spec.action_igmp_snooping_enabled = SWITCH_LN_IGMP_SNOOPING_ENABLED(bd_info);
        v4_action_spec.action_ipv4_urpf_mode = bd_info->ipv4_urpf_mode;
        v4_action_spec.action_stats_idx = SWITCH_BD_STATS_START_INDEX(bd_info);

        status = p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_ethernet_ipv4(
            g_sess_hdl,
            p4_pd_device,
            &match_spec,
            &v4_action_spec,
            &entry_hdl[entry++]);
#endif /* P4_IPV4_DISABLE */

#ifndef P4_IPV6_DISABLE
        memset(&match_spec, 0, sizeof(p4_pd_dc_tunnel_match_spec_t));
        match_spec.tunnel_metadata_tunnel_vni = tunnel_vni;
        match_spec.tunnel_metadata_ingress_tunnel_type = ingress_tunnel_type;
        match_spec.inner_ipv6_valid = TRUE;
        match_spec.inner_ipv4_valid = FALSE;

        p4_pd_dc_terminate_tunnel_inner_ethernet_ipv6_action_spec_t v6_action_spec;
        memset(&v6_action_spec, 0,
               sizeof(p4_pd_dc_terminate_tunnel_inner_ethernet_ipv6_action_spec_t));
        v6_action_spec.action_bd = bd_handle;
        v6_action_spec.action_vrf = handle_to_id(ln_info->vrf_handle);
        v6_action_spec.action_rmac_group = handle_to_id(ln_info->rmac_handle);
        v6_action_spec.action_mrpf_group = handle_to_id(ln_info->mrpf_group);
        v6_action_spec.action_bd_label = handle_to_id(ln_info->bd_label);
        v6_action_spec.action_ipv6_unicast_enabled = SWITCH_LN_IPV4_UNICAST_ENABLED(bd_info);
        v6_action_spec.action_ipv6_multicast_enabled = SWITCH_LN_IPV4_MULTICAST_ENABLED(bd_info);
        v6_action_spec.action_mld_snooping_enabled = SWITCH_LN_MLD_SNOOPING_ENABLED(bd_info);
        v6_action_spec.action_ipv6_urpf_mode = bd_info->ipv6_urpf_mode;
        v6_action_spec.action_stats_idx = SWITCH_BD_STATS_START_INDEX(bd_info);

        status = p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_ethernet_ipv6(
            g_sess_hdl,
            p4_pd_device,
            &match_spec,
            &v6_action_spec,
            &entry_hdl[entry++]);
#endif /* P4_IPV6_DISABLE */
    } else {
#ifndef P4_IPV4_DISABLE
        memset(&match_spec, 0, sizeof(p4_pd_dc_tunnel_match_spec_t));
        match_spec.tunnel_metadata_tunnel_vni = tunnel_vni;
        match_spec.tunnel_metadata_ingress_tunnel_type = ingress_tunnel_type;
        match_spec.inner_ipv4_valid = TRUE;
        match_spec.inner_ipv6_valid = FALSE;

        p4_pd_dc_terminate_tunnel_inner_ipv4_action_spec_t v4_action_spec;
        memset(&v4_action_spec, 0,
               sizeof(p4_pd_dc_terminate_tunnel_inner_ipv4_action_spec_t));
        v4_action_spec.action_vrf = handle_to_id(ln_info->vrf_handle);
        v4_action_spec.action_rmac_group = handle_to_id(ln_info->rmac_handle);
        v4_action_spec.action_mrpf_group = handle_to_id(ln_info->mrpf_group);
        v4_action_spec.action_ipv4_unicast_enabled = SWITCH_LN_IPV4_UNICAST_ENABLED(bd_info);
        v4_action_spec.action_ipv4_multicast_enabled = SWITCH_LN_IPV4_MULTICAST_ENABLED(bd_info);
        v4_action_spec.action_ipv4_urpf_mode = bd_info->ipv4_urpf_mode;

        status = p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_ipv4(
            g_sess_hdl,
            p4_pd_device,
            &match_spec,
            &v4_action_spec,
            &entry_hdl[entry++]);
#endif /* P4_IPV4_DISABLE */

#ifndef P4_IPV6_DISABLE
        memset(&match_spec, 0, sizeof(p4_pd_dc_tunnel_match_spec_t));
        match_spec.tunnel_metadata_tunnel_vni = tunnel_vni;
        match_spec.tunnel_metadata_ingress_tunnel_type = ingress_tunnel_type;
        match_spec.inner_ipv6_valid = TRUE;
        match_spec.inner_ipv4_valid = FALSE;

        p4_pd_dc_terminate_tunnel_inner_ipv6_action_spec_t v6_action_spec;
        memset(&v6_action_spec, 0,
               sizeof(p4_pd_dc_terminate_tunnel_inner_ipv6_action_spec_t));
        v6_action_spec.action_vrf = handle_to_id(ln_info->vrf_handle);
        v6_action_spec.action_rmac_group = handle_to_id(ln_info->rmac_handle);
        v6_action_spec.action_mrpf_group = handle_to_id(ln_info->mrpf_group);
        v6_action_spec.action_ipv6_unicast_enabled = SWITCH_LN_IPV4_UNICAST_ENABLED(bd_info);
        v6_action_spec.action_ipv6_multicast_enabled = SWITCH_LN_IPV4_MULTICAST_ENABLED(bd_info);
        v6_action_spec.action_ipv6_urpf_mode = bd_info->ipv6_urpf_mode;

        status = p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_ipv6(
            g_sess_hdl,
            p4_pd_device,
            &match_spec,
            &v6_action_spec,
            &entry_hdl[entry++]);
#endif /* P4_IPV6_DISABLE */
    }

#endif /* P4_TUNNEL_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_table_delete_entry(switch_device_t device,
                                    p4_pd_entry_hdl_t entry_hdl[])
{
    p4_pd_status_t status = 0;
    int entry = 0;
#ifndef P4_TUNNEL_DISABLE
    for (entry = 0; entry < 3; entry++) {
        if (entry_hdl[entry]) {
            status = p4_pd_dc_tunnel_table_delete(g_sess_hdl,
                                                  device, entry_hdl[entry]);
        }
    }
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_egress_vni_table_add_entry(switch_device_t device,
                                     switch_handle_t egress_bd,
                                     uint16_t tunnel_vni,
                                     uint8_t tunnel_type,
                                     p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_dc_egress_vni_match_spec_t match_spec;
    p4_pd_dc_set_egress_tunnel_vni_action_spec_t action_spec;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_egress_vni_match_spec_t));
    memset(&action_spec, 0, sizeof(p4_pd_dc_set_egress_tunnel_vni_action_spec_t));

    match_spec.egress_metadata_bd = egress_bd;
    match_spec.tunnel_metadata_egress_tunnel_type = tunnel_type;
    action_spec.action_vnid = tunnel_vni;

    status = p4_pd_dc_egress_vni_table_add_with_set_egress_tunnel_vni(g_sess_hdl,
                                                                         p4_pd_device,
                                                                         &match_spec,
                                                                         &action_spec,
                                                                         entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_egress_vni_table_delete_entry(switch_device_t device_id,
                                        p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE

    status = p4_pd_dc_egress_vni_table_delete(g_sess_hdl,
                                                   device_id,
                                                   entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_decap_tables_init_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;

#ifndef P4_TUNNEL_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_tunnel_decap_process_inner_match_spec_t i_match_spec;
    p4_pd_dc_tunnel_decap_process_outer_match_spec_t o_match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    /* inner tcp */
    memset(&i_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_inner_match_spec_t));
    i_match_spec.inner_tcp_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_inner_table_add_with_decap_inner_tcp(
        g_sess_hdl,
        p4_pd_device,
        &i_match_spec,
        &entry_hdl);

    /* inner udp */
    memset(&i_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_inner_match_spec_t));
    i_match_spec.inner_udp_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_inner_table_add_with_decap_inner_udp(
        g_sess_hdl,
        p4_pd_device,
        &i_match_spec,
        &entry_hdl);

    /* inner icmp */
    memset(&i_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_inner_match_spec_t));
    i_match_spec.inner_icmp_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_inner_table_add_with_decap_inner_icmp(
        g_sess_hdl,
        p4_pd_device,
        &i_match_spec,
        &entry_hdl);

    /* inner uknown */
    memset(&i_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_inner_match_spec_t));
    status = p4_pd_dc_tunnel_decap_process_inner_table_add_with_decap_inner_unknown(
        g_sess_hdl,
        p4_pd_device,
        &i_match_spec,
        &entry_hdl);

    /* vxlan, inner ipv4 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_VXLAN;
    o_match_spec.inner_ipv4_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_vxlan_inner_ipv4(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

#ifndef P4_IPV6_DISABLE
    /* vxlan, inner ipv6 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_VXLAN;
    o_match_spec.inner_ipv6_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_vxlan_inner_ipv6(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
#endif /* P4_IPV6_DISABLE */

    /* vxlan, inner non ip */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_VXLAN;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_vxlan_inner_non_ip(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* geneve, inner ipv4 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_GENEVE;
    o_match_spec.inner_ipv4_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_genv_inner_ipv4(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

#ifndef P4_IPV6_DISABLE
    /* geneve, inner ipv6 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_GENEVE;
    o_match_spec.inner_ipv6_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_genv_inner_ipv6(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
#endif /* P4_IPV6_DISABLE */

    /* geneve, inner non ip */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_GENEVE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_genv_inner_non_ip(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* nvgre, inner ipv4 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_NVGRE;
    o_match_spec.inner_ipv4_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_nvgre_inner_ipv4(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

#ifndef P4_IPV6_DISABLE
    /* nvgre, inner ipv6 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_NVGRE;
    o_match_spec.inner_ipv6_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_nvgre_inner_ipv6(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
#endif /* P4_IPV6_DISABLE */

    /* nvgre, inner non ip */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_NVGRE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_nvgre_inner_non_ip(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

#ifndef P4_MPLS_DISABLE
    /* mpls, inner_ipv4, pop 1 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type =
        SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L3VPN_NUM_LABELS_1;
    o_match_spec.inner_ipv4_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv4_pop1(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* mpls, inner_ipv4, pop 2 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type =
        SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L3VPN_NUM_LABELS_2;
    o_match_spec.inner_ipv4_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv4_pop2(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* mpls, inner_ipv4, pop 3 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type =
        SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L3VPN_NUM_LABELS_3;
    o_match_spec.inner_ipv4_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv4_pop3(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

#ifndef P4_IPV6_DISABLE
    /* mpls, inner_ipv6, pop 1 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type =
        SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L3VPN_NUM_LABELS_1;
    o_match_spec.inner_ipv6_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv6_pop1(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* mpls, inner_ipv6, pop 2 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type =
        SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L3VPN_NUM_LABELS_2;
    o_match_spec.inner_ipv6_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv6_pop2(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* mpls, inner_ipv6, pop 3 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type =
        SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L3VPN_NUM_LABELS_3;
    o_match_spec.inner_ipv6_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ipv6_pop3(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
#endif /* P4_IPV6_DISABLE */

    /* mpls, ethernet, inner_ipv4, pop 1 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type =
        SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L2VPN_NUM_LABELS_1;
    o_match_spec.inner_ipv4_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv4_pop1(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* mpls, ethernet, inner_ipv4, pop 2 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type =
        SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L2VPN_NUM_LABELS_2;
    o_match_spec.inner_ipv4_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv4_pop2(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* mpls, ethernet, inner_ipv4, pop 3 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type =
        SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L2VPN_NUM_LABELS_3;
    o_match_spec.inner_ipv4_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv4_pop3(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

#ifndef P4_IPV6_DISABLE
    /* mpls, ethernet, inner_ipv6, pop 1 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type =
        SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L2VPN_NUM_LABELS_1;
    o_match_spec.inner_ipv6_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv6_pop1(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* mpls, ethernet, inner_ipv6, pop 2 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type =
        SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L2VPN_NUM_LABELS_2;
    o_match_spec.inner_ipv6_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv6_pop2(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* mpls, ethernet, inner_ipv6, pop 3 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type =
        SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L2VPN_NUM_LABELS_3;
    o_match_spec.inner_ipv6_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_ipv6_pop3(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
#endif /* P4_IPV6_DISABLE */

    /* mpls, ethernet, non_ip, pop 1 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type =
        SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L2VPN_NUM_LABELS_1;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_non_ip_pop1(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* mpls, ethernet, inner_ipv6, pop 2 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type =
        SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L2VPN_NUM_LABELS_2;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_non_ip_pop2(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* mpls, ethernet, inner_ipv6, pop 3 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type =
        SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L2VPN_NUM_LABELS_3;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_mpls_inner_ethernet_non_ip_pop3(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
#endif /* P4_MPLS_DISABLE */
#endif /* P4_TUNNEL_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_encap_tables_init_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;

#ifndef P4_TUNNEL_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_tunnel_encap_process_inner_match_spec_t i_match_spec;
    p4_pd_dc_tunnel_encap_process_outer_match_spec_t o_match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    /* ipv4, tcp */
    memset(&i_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_inner_match_spec_t));
    i_match_spec.ipv4_valid = TRUE;
    i_match_spec.tcp_valid = TRUE;
    status = p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv4_tcp_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &i_match_spec,
        &entry_hdl);

    /* ipv4, udp */
    memset(&i_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_inner_match_spec_t));
    i_match_spec.ipv4_valid = TRUE;
    i_match_spec.udp_valid = TRUE;
    status = p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv4_udp_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &i_match_spec,
        &entry_hdl);

    /* ipv4, icmp */
    memset(&i_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_inner_match_spec_t));
    i_match_spec.ipv4_valid = TRUE;
    i_match_spec.icmp_valid = TRUE;
    status = p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv4_icmp_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &i_match_spec,
        &entry_hdl);

    /* ipv4, uknown */
    memset(&i_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_inner_match_spec_t));
    i_match_spec.ipv4_valid = TRUE;
    status = p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv4_unknown_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &i_match_spec,
        &entry_hdl);

    /* ipv6, tcp */
    memset(&i_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_inner_match_spec_t));
    i_match_spec.ipv6_valid = TRUE;
    i_match_spec.tcp_valid = TRUE;
    status = p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv6_tcp_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &i_match_spec,
        &entry_hdl);

    /* ipv6, udp */
    memset(&i_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_inner_match_spec_t));
    i_match_spec.ipv6_valid = TRUE;
    i_match_spec.udp_valid = TRUE;
    status = p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv6_udp_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &i_match_spec,
        &entry_hdl);

    /* ipv6, icmp */
    memset(&i_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_inner_match_spec_t));
    i_match_spec.ipv6_valid = TRUE;
    i_match_spec.icmp_valid = TRUE;
    status = p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv6_icmp_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &i_match_spec,
        &entry_hdl);

    /* ipv6, uknown */
    memset(&i_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_inner_match_spec_t));
    i_match_spec.ipv6_valid = TRUE;
    status = p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_ipv6_unknown_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &i_match_spec,
        &entry_hdl);

    /* non ip */
    memset(&i_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_inner_match_spec_t));
    status = p4_pd_dc_tunnel_encap_process_inner_table_add_with_inner_non_ip_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &i_match_spec,
        &entry_hdl);

    /* default entry */
    status = p4_pd_dc_tunnel_encap_process_outer_set_default_action_nop(
        g_sess_hdl,
        p4_pd_device,
        &entry_hdl);

    /* ipv4 vxlan */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_VXLAN;
    o_match_spec.multicast_metadata_replica = false;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_vxlan_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
     memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_VXLAN;
    o_match_spec.multicast_metadata_replica = true;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_vxlan_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* ipv6 vxlan */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_VXLAN;
    o_match_spec.multicast_metadata_replica = false;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_vxlan_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_VXLAN;
    o_match_spec.multicast_metadata_replica = true;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_vxlan_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* ipv4 geneve */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_GENEVE;
    o_match_spec.multicast_metadata_replica = false;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_genv_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_GENEVE;
    o_match_spec.multicast_metadata_replica = true;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_genv_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* ipv6 geneve */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_GENEVE;
    o_match_spec.multicast_metadata_replica = false;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_genv_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_GENEVE;
    o_match_spec.multicast_metadata_replica = true;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_genv_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* ipv4 nvgre */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_NVGRE;
    o_match_spec.multicast_metadata_replica = false;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_nvgre_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_NVGRE;
    o_match_spec.multicast_metadata_replica = true;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_nvgre_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* ipv6 nvgre */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_NVGRE;
    o_match_spec.multicast_metadata_replica = false;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_nvgre_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_NVGRE;
    o_match_spec.multicast_metadata_replica = true;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv6_nvgre_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

#ifndef P4_MPLS_DISABLE
    /* mpls, ethernet, push 1 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_MPLS_L2VPN;
    o_match_spec.tunnel_metadata_egress_header_count = 1;
    o_match_spec.multicast_metadata_replica = false;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ethernet_push1_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_MPLS_L2VPN;
    o_match_spec.tunnel_metadata_egress_header_count = 1;
    o_match_spec.multicast_metadata_replica = true;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ethernet_push1_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* mpls, ethernet, push 2 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_MPLS_L2VPN;
    o_match_spec.tunnel_metadata_egress_header_count = 2;
    o_match_spec.multicast_metadata_replica = false;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ethernet_push2_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_MPLS_L2VPN;
    o_match_spec.tunnel_metadata_egress_header_count = 2;
    o_match_spec.multicast_metadata_replica = true;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ethernet_push2_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* mpls, ethernet, push 3 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_MPLS_L2VPN;
    o_match_spec.tunnel_metadata_egress_header_count = 3;
    o_match_spec.multicast_metadata_replica = false;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ethernet_push3_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_MPLS_L2VPN;
    o_match_spec.tunnel_metadata_egress_header_count = 3;
    o_match_spec.multicast_metadata_replica = true;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ethernet_push3_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* mpls, ip, push 1 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_MPLS_L3VPN;
    o_match_spec.tunnel_metadata_egress_header_count = 1;
    o_match_spec.multicast_metadata_replica = false;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ip_push1_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_MPLS_L3VPN;
    o_match_spec.tunnel_metadata_egress_header_count = 1;
    o_match_spec.multicast_metadata_replica = true;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ip_push1_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* mpls, ip, push 2 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_MPLS_L3VPN;
    o_match_spec.tunnel_metadata_egress_header_count = 2;
    o_match_spec.multicast_metadata_replica = false;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ip_push2_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_MPLS_L3VPN;
    o_match_spec.tunnel_metadata_egress_header_count = 2;
    o_match_spec.multicast_metadata_replica = true;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ip_push2_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

    /* mpls, ip, push 3 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_MPLS_L3VPN;
    o_match_spec.tunnel_metadata_egress_header_count = 3;
    o_match_spec.multicast_metadata_replica = false;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ip_push3_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_MPLS_L3VPN;
    o_match_spec.tunnel_metadata_egress_header_count = 3;
    o_match_spec.multicast_metadata_replica = true;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_mpls_ip_push3_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

#endif /* P4_MPLS_DISABLE */
#ifndef P4_MIRROR_DISABLE
    /* ipv4 erspan */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_ERSPAN_T3;
    o_match_spec.multicast_metadata_replica = false;
    status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_ipv4_erspan_t3_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

#endif /* P4_MIRROR_DISABLE */
#endif /* P4_TUNNEL_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_rewrite_table_fabric_add_entry(switch_device_t device,
                                         switch_tunnel_type_egress_t tunnel_type,
                                         uint16_t tunnel_index,
                                         p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    p4_pd_dc_tunnel_encap_process_outer_match_spec_t match_spec;
    p4_pd_dc_fabric_rewrite_action_spec_t action_spec;
    switch (tunnel_type) {
        case SWITCH_EGRESS_TUNNEL_TYPE_CPU:
            memset(&match_spec, 0, sizeof(p4_pd_dc_tunnel_encap_process_outer_match_spec_t));
            memset(&action_spec, 0, sizeof(p4_pd_dc_fabric_rewrite_action_spec_t));
            match_spec.tunnel_metadata_egress_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_CPU;
            match_spec.tunnel_metadata_egress_header_count = 0;
            match_spec.multicast_metadata_replica = false;
            action_spec.action_tunnel_index = tunnel_index;
            status = p4_pd_dc_tunnel_encap_process_outer_table_add_with_fabric_rewrite(
                                                   g_sess_hdl,
                                                   p4_pd_device,
                                                   &match_spec,
                                                   &action_spec,
                                                   entry_hdl);
            break;
        default:
            break;
    }
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_rewrite_cpu_add_entry(switch_device_t device,
                                       uint16_t tunnel_index,
                                       p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    p4_pd_dc_tunnel_rewrite_match_spec_t match_spec;
    memset(&match_spec, 0, sizeof(p4_pd_dc_tunnel_rewrite_match_spec_t));
    match_spec.tunnel_metadata_tunnel_index = tunnel_index;
    status = p4_pd_dc_tunnel_rewrite_table_add_with_cpu_rx_rewrite(
                                                   g_sess_hdl,
                                                   p4_pd_device,
                                                   &match_spec,
                                                   entry_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_src_rewrite_table_add_entry(switch_device_t device,
                                             uint16_t tunnel_src_index,
                                             switch_ip_encap_t *ip_encap,
                                             p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    if (SWITCH_IP_ENCAP_SRC_IP_TYPE(ip_encap) == SWITCH_API_IP_ADDR_V4) {
        p4_pd_dc_tunnel_src_rewrite_match_spec_t v4_match_spec;
        p4_pd_dc_rewrite_tunnel_ipv4_src_action_spec_t v4_action_spec;
        memset(&v4_match_spec, 0, sizeof(p4_pd_dc_tunnel_src_rewrite_match_spec_t));
        memset(&v4_action_spec, 0, sizeof(p4_pd_dc_rewrite_tunnel_ipv4_src_action_spec_t));
        v4_match_spec.tunnel_metadata_tunnel_src_index = tunnel_src_index;
        v4_action_spec.action_ip = SWITCH_IP_ENCAP_IPV4_SRC_IP(ip_encap);
        status = p4_pd_dc_tunnel_src_rewrite_table_add_with_rewrite_tunnel_ipv4_src(
                                                                           g_sess_hdl,
                                                                           p4_pd_device,
                                                                           &v4_match_spec,
                                                                           &v4_action_spec,
                                                                           entry_hdl);
    } else {
#ifndef P4_IPV6_DISABLE
        p4_pd_dc_tunnel_src_rewrite_match_spec_t v6_match_spec;
        p4_pd_dc_rewrite_tunnel_ipv6_src_action_spec_t v6_action_spec;
        memset(&v6_match_spec, 0, sizeof(p4_pd_dc_tunnel_src_rewrite_match_spec_t));
        memset(&v6_action_spec, 0, sizeof(p4_pd_dc_rewrite_tunnel_ipv6_src_action_spec_t));
        v6_match_spec.tunnel_metadata_tunnel_src_index = tunnel_src_index;
        memcpy(&v6_action_spec.action_ip, SWITCH_IP_ENCAP_IPV6_SRC_IP(ip_encap), 16);
        status = p4_pd_dc_tunnel_src_rewrite_table_add_with_rewrite_tunnel_ipv6_src(
                                                                           g_sess_hdl,
                                                                           p4_pd_device,
                                                                           &v6_match_spec,
                                                                           &v6_action_spec,
                                                                           entry_hdl);
#endif /* P4_IPV6_DISABLE */
    }
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_src_rewrite_table_delete_entry(switch_device_t device,
                                                p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE

    status = p4_pd_dc_tunnel_src_rewrite_table_delete(g_sess_hdl,
                                                        device,
                                                        entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_dst_rewrite_table_add_entry(switch_device_t device,
                                             uint16_t tunnel_dst_index,
                                             switch_ip_encap_t *ip_encap,
                                             p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    if (SWITCH_IP_ENCAP_DST_IP_TYPE(ip_encap) == SWITCH_API_IP_ADDR_V4) {
        p4_pd_dc_tunnel_dst_rewrite_match_spec_t v4_match_spec;
        p4_pd_dc_rewrite_tunnel_ipv4_dst_action_spec_t v4_action_spec;
        memset(&v4_match_spec, 0, sizeof(p4_pd_dc_tunnel_dst_rewrite_match_spec_t));
        memset(&v4_action_spec, 0, sizeof(p4_pd_dc_rewrite_tunnel_ipv4_dst_action_spec_t));
        v4_match_spec.tunnel_metadata_tunnel_dst_index = tunnel_dst_index;
        v4_action_spec.action_ip = SWITCH_IP_ENCAP_IPV4_DST_IP(ip_encap);
        status = p4_pd_dc_tunnel_dst_rewrite_table_add_with_rewrite_tunnel_ipv4_dst(
                                                                           g_sess_hdl,
                                                                           p4_pd_device,
                                                                           &v4_match_spec,
                                                                           &v4_action_spec,
                                                                           entry_hdl);
    } else {
#ifndef P4_IPV6_DISABLE
        p4_pd_dc_tunnel_dst_rewrite_match_spec_t v6_match_spec;
        p4_pd_dc_rewrite_tunnel_ipv6_dst_action_spec_t v6_action_spec;
        memset(&v6_match_spec, 0, sizeof(p4_pd_dc_tunnel_dst_rewrite_match_spec_t));
        memset(&v6_action_spec, 0, sizeof(p4_pd_dc_rewrite_tunnel_ipv6_dst_action_spec_t));
        v6_match_spec.tunnel_metadata_tunnel_dst_index = tunnel_dst_index;
        memcpy(&v6_action_spec.action_ip, SWITCH_IP_ENCAP_IPV6_DST_IP(ip_encap), 16);
        status = p4_pd_dc_tunnel_dst_rewrite_table_add_with_rewrite_tunnel_ipv6_dst(
                                                                           g_sess_hdl,
                                                                           p4_pd_device,
                                                                           &v6_match_spec,
                                                                           &v6_action_spec,
                                                                           entry_hdl);
#endif /* P4_IPV6_DISABLE */
    }
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_dst_rewrite_table_delete_entry(switch_device_t device,
                                                p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE

    status = p4_pd_dc_tunnel_dst_rewrite_table_delete(g_sess_hdl,
                                                      device,
                                                      entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_bd_table_add_entry(switch_device_t device,
                             uint16_t bd,
                             switch_bd_info_t *bd_info,
                             p4_pd_mbr_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
    p4_pd_dev_target_t p4_pd_device;
    switch_logical_network_t *ln_info = NULL;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    ln_info = &bd_info->ln_info;
    p4_pd_dc_set_bd_properties_action_spec_t action_spec;
    memset(&action_spec, 0, sizeof(p4_pd_dc_set_bd_properties_action_spec_t));
    action_spec.action_bd = bd;
    action_spec.action_vrf = handle_to_id(ln_info->vrf_handle);
    action_spec.action_rmac_group = handle_to_id(ln_info->rmac_handle);
    action_spec.action_mrpf_group = handle_to_id(ln_info->mrpf_group);
    action_spec.action_bd_label = handle_to_id(ln_info->bd_label);
    action_spec.action_ipv4_unicast_enabled =
        SWITCH_LN_IPV4_UNICAST_ENABLED(bd_info);
    action_spec.action_ipv6_unicast_enabled =
        SWITCH_LN_IPV6_UNICAST_ENABLED(bd_info);
    action_spec.action_ipv4_multicast_enabled =
        SWITCH_LN_IPV4_MULTICAST_ENABLED(bd_info);
    action_spec.action_ipv6_multicast_enabled =
        SWITCH_LN_IPV6_MULTICAST_ENABLED(bd_info);
    action_spec.action_igmp_snooping_enabled =
        SWITCH_LN_IGMP_SNOOPING_ENABLED(bd_info);
    action_spec.action_mld_snooping_enabled =
        SWITCH_LN_MLD_SNOOPING_ENABLED(bd_info);
    action_spec.action_ipv4_urpf_mode = bd_info->ipv4_urpf_mode;
    action_spec.action_ipv6_urpf_mode = bd_info->ipv6_urpf_mode;
    action_spec.action_stp_group = handle_to_id(bd_info->stp_handle);
    action_spec.action_stats_idx = SWITCH_BD_STATS_START_INDEX(bd_info);
    action_spec.action_learning_enabled = SWITCH_LN_LEARN_ENABLED(bd_info);

    if (SWITCH_LN_IPV4_MULTICAST_ENABLED(bd_info)) {
        action_spec.action_ipv4_mcast_key_type = 1;
        action_spec.action_ipv4_mcast_key = handle_to_id(ln_info->vrf_handle);
    } else {
        action_spec.action_ipv4_mcast_key_type = 0;
        action_spec.action_ipv4_mcast_key = bd;
    }

    if (SWITCH_LN_IPV6_MULTICAST_ENABLED(bd_info)) {
        action_spec.action_ipv6_mcast_key_type = 1;
        action_spec.action_ipv6_mcast_key = handle_to_id(ln_info->vrf_handle);
    } else {
        action_spec.action_ipv6_mcast_key_type = 0;
        action_spec.action_ipv6_mcast_key = bd;
    }

    status = p4_pd_dc_bd_action_profile_add_member_with_set_bd_properties(
        g_sess_hdl,
        p4_pd_device,
        &action_spec,
        entry_hdl);

#ifndef P4_MULTICAST_DISABLE
    /* Unknown unicast flood */
    p4_pd_dc_bd_flood_match_spec_t flood_match_spec;
    p4_pd_dc_set_bd_flood_mc_index_action_spec_t flood_action_spec;
    memset(&flood_match_spec, 0, sizeof(p4_pd_dc_bd_flood_match_spec_t));
    memset(&flood_action_spec, 0,
           sizeof(p4_pd_dc_set_bd_flood_mc_index_action_spec_t));
    flood_match_spec.ingress_metadata_bd = bd;
    flood_match_spec.l2_metadata_lkp_pkt_type = SWITCH_VLAN_FLOOD_UUC;
    flood_action_spec.action_mc_index = handle_to_id(bd_info->uuc_mc_index);
    status = p4_pd_dc_bd_flood_table_add_with_set_bd_flood_mc_index(
            g_sess_hdl,
            p4_pd_device,
            &flood_match_spec,
            &flood_action_spec,
            &bd_info->uuc_entry);

    /* Unknown multicast flood */
    memset(&flood_match_spec, 0, sizeof(p4_pd_dc_bd_flood_match_spec_t));
    memset(&flood_action_spec, 0,
           sizeof(p4_pd_dc_set_bd_flood_mc_index_action_spec_t));
    flood_match_spec.ingress_metadata_bd = bd;
    flood_match_spec.l2_metadata_lkp_pkt_type = SWITCH_VLAN_FLOOD_UMC;
    flood_action_spec.action_mc_index = handle_to_id(bd_info->umc_mc_index);
    status = p4_pd_dc_bd_flood_table_add_with_set_bd_flood_mc_index(
            g_sess_hdl,
            p4_pd_device,
            &flood_match_spec,
            &flood_action_spec,
            &bd_info->umc_entry);

    /* Unknown broadcast flood */
    memset(&flood_match_spec, 0, sizeof(p4_pd_dc_bd_flood_match_spec_t));
    memset(&flood_action_spec, 0,
           sizeof(p4_pd_dc_set_bd_flood_mc_index_action_spec_t));
    flood_match_spec.ingress_metadata_bd = bd;
    flood_match_spec.l2_metadata_lkp_pkt_type = SWITCH_VLAN_FLOOD_BCAST;
    flood_action_spec.action_mc_index = handle_to_id(bd_info->bcast_mc_index);
    status = p4_pd_dc_bd_flood_table_add_with_set_bd_flood_mc_index(
            g_sess_hdl,
            p4_pd_device,
            &flood_match_spec,
            &flood_action_spec,
            &bd_info->bcast_entry);
#endif
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_bd_table_update_entry(switch_device_t device,
                                uint16_t bd,
                                switch_bd_info_t *bd_info,
                                p4_pd_mbr_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
    switch_logical_network_t *ln_info = NULL;

    ln_info = &bd_info->ln_info;

    p4_pd_dc_set_bd_properties_action_spec_t action_spec;
    memset(&action_spec, 0, sizeof(p4_pd_dc_set_bd_properties_action_spec_t));
    action_spec.action_bd = bd;
    action_spec.action_vrf = handle_to_id(ln_info->vrf_handle);
    action_spec.action_rmac_group = handle_to_id(ln_info->rmac_handle);
    action_spec.action_mrpf_group = handle_to_id(ln_info->mrpf_group);
    action_spec.action_bd_label = handle_to_id(ln_info->bd_label);
    action_spec.action_ipv4_unicast_enabled =
        SWITCH_LN_IPV4_UNICAST_ENABLED(bd_info);
    action_spec.action_ipv6_unicast_enabled =
        SWITCH_LN_IPV6_UNICAST_ENABLED(bd_info);
    action_spec.action_ipv4_multicast_enabled =
        SWITCH_LN_IPV4_MULTICAST_ENABLED(bd_info);
    action_spec.action_ipv6_multicast_enabled =
        SWITCH_LN_IPV6_MULTICAST_ENABLED(bd_info);
    action_spec.action_igmp_snooping_enabled =
        SWITCH_LN_IGMP_SNOOPING_ENABLED(bd_info);
    action_spec.action_mld_snooping_enabled =
        SWITCH_LN_MLD_SNOOPING_ENABLED(bd_info);
    action_spec.action_ipv4_urpf_mode = bd_info->ipv4_urpf_mode;
    action_spec.action_ipv6_urpf_mode = bd_info->ipv6_urpf_mode;
    action_spec.action_stp_group = handle_to_id(bd_info->stp_handle);
    action_spec.action_stats_idx = SWITCH_BD_STATS_START_INDEX(bd_info);
    action_spec.action_learning_enabled = SWITCH_LN_LEARN_ENABLED(bd_info);

    if (SWITCH_LN_IPV4_MULTICAST_ENABLED(bd_info)) {
        action_spec.action_ipv4_mcast_key_type = 1;
        action_spec.action_ipv4_mcast_key = handle_to_id(ln_info->vrf_handle);
    } else {
        action_spec.action_ipv4_mcast_key_type = 0;
        action_spec.action_ipv4_mcast_key = bd;
    }

    if (SWITCH_LN_IPV6_MULTICAST_ENABLED(bd_info)) {
        action_spec.action_ipv6_mcast_key_type = 1;
        action_spec.action_ipv6_mcast_key = handle_to_id(ln_info->vrf_handle);
    } else {
        action_spec.action_ipv6_mcast_key_type = 0;
        action_spec.action_ipv6_mcast_key = bd;
    }

    status = p4_pd_dc_bd_action_profile_modify_member_with_set_bd_properties(
        g_sess_hdl,
        device,
        entry_hdl,
        &action_spec);

#ifndef P4_MULTICAST_DISABLE
    /* Unknown unicast flood */
    p4_pd_dc_set_bd_flood_mc_index_action_spec_t flood_action_spec;
    memset(&flood_action_spec, 0,
           sizeof(p4_pd_dc_set_bd_flood_mc_index_action_spec_t));
    flood_action_spec.action_mc_index = handle_to_id(bd_info->uuc_mc_index);
    status = p4_pd_dc_bd_flood_table_modify_with_set_bd_flood_mc_index(
            g_sess_hdl,
            device,
            bd_info->uuc_entry,
            &flood_action_spec);

    /* Unknown multicast flood */
    memset(&flood_action_spec, 0,
           sizeof(p4_pd_dc_set_bd_flood_mc_index_action_spec_t));
    flood_action_spec.action_mc_index = handle_to_id(bd_info->umc_mc_index);
    status = p4_pd_dc_bd_flood_table_modify_with_set_bd_flood_mc_index(
            g_sess_hdl,
            device,
            bd_info->umc_entry,
            &flood_action_spec);

    /* Unknown broadcast flood */
    memset(&flood_action_spec, 0,
           sizeof(p4_pd_dc_set_bd_flood_mc_index_action_spec_t));
    flood_action_spec.action_mc_index = handle_to_id(bd_info->bcast_mc_index);
    status = p4_pd_dc_bd_flood_table_modify_with_set_bd_flood_mc_index(
            g_sess_hdl,
            device,
            bd_info->bcast_entry,
            &flood_action_spec);
#endif

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_bd_table_delete_entry(switch_device_t device,
                                switch_bd_info_t *bd_info)
{
    p4_pd_status_t status = 0;

    status = p4_pd_dc_bd_action_profile_del_member(g_sess_hdl, device,
                                                   bd_info->bd_entry);

#ifndef P4_MULTICAST_DISABLE
    status = p4_pd_dc_bd_flood_table_delete(g_sess_hdl, device,
                                            bd_info->uuc_entry);
    status = p4_pd_dc_bd_flood_table_delete(g_sess_hdl, device,
                                            bd_info->umc_entry);
    status = p4_pd_dc_bd_flood_table_delete(g_sess_hdl, device,
                                            bd_info->bcast_entry);
#endif

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_egress_bd_map_table_add_entry(switch_device_t device,
                                        switch_handle_t bd_handle,
                                        switch_bd_info_t *bd_info)
{
    p4_pd_status_t status = 0;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_egress_bd_map_match_spec_t match_spec;
    p4_pd_dc_set_egress_bd_properties_action_spec_t action_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(match_spec));
    memset(&action_spec, 0, sizeof(action_spec));
    match_spec.egress_metadata_bd = handle_to_id(bd_handle);
    action_spec.action_smac_idx = bd_info->smac_index;

    status = p4_pd_dc_egress_bd_map_table_add_with_set_egress_bd_properties(
        g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
        &bd_info->egress_bd_entry);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_egress_bd_map_table_update_entry(switch_device_t device,
                                           switch_handle_t bd_handle,
                                           switch_bd_info_t *bd_info)
{
    p4_pd_status_t status = 0;
    p4_pd_dc_egress_bd_map_match_spec_t match_spec;
    p4_pd_dc_set_egress_bd_properties_action_spec_t action_spec;

    memset(&match_spec, 0, sizeof(match_spec));
    memset(&action_spec, 0, sizeof(action_spec));
    match_spec.egress_metadata_bd = handle_to_id(bd_handle);
    action_spec.action_smac_idx = bd_info->smac_index;

    status = p4_pd_dc_egress_bd_map_table_modify_with_set_egress_bd_properties(
        g_sess_hdl, device, bd_info->egress_bd_entry, &action_spec);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_egress_bd_map_table_delete_entry(switch_device_t device,
                                           switch_bd_info_t *bd_info)
{
    p4_pd_status_t status = 0;
    if (!bd_info->egress_bd_entry) {
        return status;
    }

    status = p4_pd_dc_egress_bd_map_table_delete(g_sess_hdl, device,
                                                 bd_info->egress_bd_entry);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_egress_bd_stats_table_add_entry(
        switch_device_t device,
        uint16_t bd,
        p4_pd_entry_hdl_t *entry_hdl)
{

    p4_pd_status_t status = 0;
#ifndef P4_STATS_DISABLE
    int index = 0;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_egress_bd_stats_match_spec_t match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_egress_bd_stats_match_spec_t));

    match_spec.egress_metadata_bd = bd;
    match_spec.l2_metadata_lkp_pkt_type = 1;

    status = p4_pd_dc_egress_bd_stats_table_add_with_nop(
                             g_sess_hdl,
                             p4_pd_device,
                             &match_spec,
                             &entry_hdl[index++]);

    match_spec.l2_metadata_lkp_pkt_type = 2;
    status = p4_pd_dc_egress_bd_stats_table_add_with_nop(
                             g_sess_hdl,
                             p4_pd_device,
                             &match_spec,
                             &entry_hdl[index++]);

    match_spec.l2_metadata_lkp_pkt_type = 4;
    status = p4_pd_dc_egress_bd_stats_table_add_with_nop(
                             g_sess_hdl,
                             p4_pd_device,
                             &match_spec,
                             &entry_hdl[index++]);
#endif /* P4_STATS_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}


p4_pd_status_t
switch_pd_egress_bd_stats_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t *entry_hdl)
{

    p4_pd_status_t status = 0;
#ifndef P4_STATS_DISABLE
    int index = 0;

    status = p4_pd_dc_egress_bd_stats_table_delete(
                             g_sess_hdl,
                             device,
                             entry_hdl[index++]);

    status = p4_pd_dc_egress_bd_stats_table_delete(
                             g_sess_hdl,
                             device,
                             entry_hdl[index++]);

    status = p4_pd_dc_egress_bd_stats_table_delete(
                             g_sess_hdl,
                             device,
                             entry_hdl[index++]);
#endif /* P4_STATS_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_port_vlan_mapping_table_add_entry(switch_device_t device,
                                            switch_vlan_t vlan_id0,
                                            switch_vlan_t vlan_id1,
                                            switch_interface_info_t *info,
                                            p4_pd_mbr_hdl_t bd_hdl,
                                            p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
    p4_pd_dc_port_vlan_mapping_match_spec_t match_spec;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_port_vlan_mapping_match_spec_t));

    match_spec.ingress_metadata_ifindex = info->ifindex;
    if (vlan_id0) {
        match_spec.vlan_tag__0__valid = TRUE;
        match_spec.vlan_tag__0__vid = vlan_id0;
    }
    if (vlan_id1) {
        match_spec.vlan_tag__1__valid = TRUE;
        match_spec.vlan_tag__1__vid = vlan_id1;
    }

    status = p4_pd_dc_port_vlan_mapping_add_entry(g_sess_hdl,
                                                       p4_pd_device,
                                                       &match_spec,
                                                       bd_hdl,
                                                       entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_port_vlan_mapping_table_delete_entry(switch_device_t device,
                                               p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;

    status = p4_pd_dc_port_vlan_mapping_table_delete(g_sess_hdl,
                                                       device,
                                                       entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_egress_vlan_xlate_table_add_entry(switch_device_t device, switch_port_t port,
                                            uint16_t egress_bd, switch_vlan_t vlan_id,
                                            p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
    p4_pd_dc_egress_vlan_xlate_match_spec_t match_spec;
    p4_pd_dc_set_egress_packet_vlan_tagged_action_spec_t action_spec;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_egress_vlan_xlate_match_spec_t));
    memset(&action_spec, 0, sizeof(p4_pd_dc_set_egress_packet_vlan_tagged_action_spec_t));

    match_spec.standard_metadata_egress_port = port;
    match_spec.egress_metadata_bd = egress_bd;
    if (vlan_id != 0) {
        action_spec.action_vlan_id = vlan_id;
        status = p4_pd_dc_egress_vlan_xlate_table_add_with_set_egress_packet_vlan_tagged(g_sess_hdl,
                                                                                          p4_pd_device,
                                                                                          &match_spec,
                                                                                          &action_spec,
                                                                                          entry_hdl);
    } else {
        status = p4_pd_dc_egress_vlan_xlate_table_add_with_set_egress_packet_vlan_untagged(g_sess_hdl,
                                                                                          p4_pd_device,
                                                                                          &match_spec,
                                                                                          entry_hdl);
    }
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_egress_vlan_xlate_table_delete_entry(switch_device_t device, p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
    status = p4_pd_dc_egress_vlan_xlate_table_delete(g_sess_hdl, device, entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_port_mapping_table_add_entry(switch_device_t device,
                                       switch_port_t port_id,
                                       switch_ifindex_t ifindex,
                                       switch_port_type_t port_type,
                                       p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_dc_ingress_port_mapping_match_spec_t  match_spec;
    p4_pd_dc_set_ifindex_action_spec_t          action_spec;
    p4_pd_status_t                              status = 0;
    bool                                        modify = FALSE;
    p4_pd_dev_target_t                          p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_ingress_port_mapping_match_spec_t));
    memset(&action_spec, 0, sizeof(p4_pd_dc_set_ifindex_action_spec_t));

    match_spec.standard_metadata_ingress_port = port_id;
    action_spec.action_ifindex = ifindex;
    action_spec.action_if_label = port_id;
    action_spec.action_port_type = port_type;

    modify = (*entry_hdl != SWITCH_HW_INVALID_HANDLE) ? TRUE : FALSE;
    if (modify) {
        status = p4_pd_dc_ingress_port_mapping_table_modify_with_set_ifindex(
            g_sess_hdl, 0,
            *entry_hdl,
            &action_spec);
    } else {
        status = p4_pd_dc_ingress_port_mapping_table_add_with_set_ifindex(
            g_sess_hdl,
            p4_pd_device,
            &match_spec,
            &action_spec,
            entry_hdl);
    }

    if (!modify) {
        p4_pd_dc_egress_port_mapping_match_spec_t   egress_match_spec;
        p4_pd_entry_hdl_t                           egress_entry_hdl;
        memset(&egress_match_spec, 0,
               sizeof(p4_pd_dc_egress_port_mapping_match_spec_t));
        egress_match_spec.standard_metadata_egress_port = port_id;
        if (port_type == SWITCH_PORT_TYPE_NORMAL) {
            p4_pd_dc_egress_port_mapping_table_add_with_egress_port_type_normal(
                g_sess_hdl,
                p4_pd_device,
                &egress_match_spec,
                &egress_entry_hdl);
        } else if (port_type == SWITCH_PORT_TYPE_FABRIC) {
            p4_pd_dc_egress_port_mapping_table_add_with_egress_port_type_fabric(
                g_sess_hdl,
                p4_pd_device,
                &egress_match_spec,
                &egress_entry_hdl);
        } else if (port_type == SWITCH_PORT_TYPE_CPU) {
            p4_pd_dc_egress_port_mapping_table_add_with_egress_port_type_cpu(
                g_sess_hdl,
                p4_pd_device,
                &egress_match_spec,
                &egress_entry_hdl);
        }
    }

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_port_mapping_table_delete_entry(switch_device_t device,
                                          p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;

    status = p4_pd_dc_ingress_port_mapping_table_delete(g_sess_hdl,
                                                        device,
                                                        entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_rewrite_table_unicast_rewrite_add_entry(switch_device_t device,
                                                  uint16_t bd,
                                                  uint16_t nhop_index,
                                                  switch_mac_addr_t dmac,
                                                  switch_neighbor_rw_type_t rw_type,
                                                  p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_dc_rewrite_match_spec_t               match_spec;
    p4_pd_status_t                              status = 0;
    p4_pd_dev_target_t                          p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_rewrite_match_spec_t));
    match_spec.l3_metadata_nexthop_index = nhop_index;

    if (rw_type == SWITCH_API_NEIGHBOR_RW_TYPE_L2) {
        status = p4_pd_dc_rewrite_table_add_with_set_l2_rewrite(
            g_sess_hdl,
            p4_pd_device,
            &match_spec,
            entry_hdl);
    } else {
        p4_pd_dc_set_l3_rewrite_action_spec_t action_spec;
        memset(&action_spec, 0,
               sizeof(p4_pd_dc_set_l3_rewrite_action_spec_t));
        action_spec.action_bd = bd;
        memcpy(action_spec.action_dmac, &dmac, ETH_LEN);

        status = p4_pd_dc_rewrite_table_add_with_set_l3_rewrite(
            g_sess_hdl,
            p4_pd_device,
            &match_spec,
            &action_spec,
            entry_hdl);
    }

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_rewrite_table_tunnel_rewrite_add_entry(switch_device_t device,
                                                 uint16_t bd,
                                                 uint16_t nhop_index,
                                                 switch_mac_addr_t dmac,
                                                 switch_neighbor_type_t neigh_type,
                                                 switch_neighbor_rw_type_t rw_type,
                                                 uint16_t tunnel_index,
                                                 switch_encap_type_t encap_type,
                                                 p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t                              status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_dc_rewrite_match_spec_t               match_spec;
    p4_pd_dev_target_t                          p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_rewrite_match_spec_t));
    match_spec.l3_metadata_nexthop_index = nhop_index;

    switch_tunnel_type_egress_t tunnel_type;
    switch(encap_type) {
        case SWITCH_API_ENCAP_TYPE_VXLAN:
            if (neigh_type == SWITCH_API_NEIGHBOR_IPV4_TUNNEL) {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_VXLAN;
            } else {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_VXLAN;
            }
            break;
        case SWITCH_API_ENCAP_TYPE_GENEVE:
            if (neigh_type == SWITCH_API_NEIGHBOR_IPV4_TUNNEL) {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_GENEVE;
            } else {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_GENEVE;
            }
            break;
        case SWITCH_API_ENCAP_TYPE_NVGRE:
            if (neigh_type == SWITCH_API_NEIGHBOR_IPV4_TUNNEL) {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_NVGRE;
            } else {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_NVGRE;
            }
            break;
        case SWITCH_API_ENCAP_TYPE_ERSPAN_T3:
            if (neigh_type == SWITCH_API_NEIGHBOR_IPV4_TUNNEL) {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_ERSPAN_T3;
            } else {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_ERSPAN_T3;
            }
            break;
        default:
            status = SWITCH_STATUS_INVALID_TUNNEL_TYPE;
            return status;
    }

    if (rw_type == SWITCH_API_NEIGHBOR_RW_TYPE_L2) {
        p4_pd_dc_set_l2_rewrite_with_tunnel_action_spec_t action_spec;
        action_spec.action_tunnel_type = tunnel_type;
        action_spec.action_tunnel_index = tunnel_index;
        status = p4_pd_dc_rewrite_table_add_with_set_l2_rewrite_with_tunnel(g_sess_hdl,
                                                                p4_pd_device,
                                                                &match_spec,
                                                                &action_spec,
                                                                entry_hdl);
    } else {
        p4_pd_dc_set_l3_rewrite_with_tunnel_action_spec_t action_spec;
        memset(&action_spec, 0,
               sizeof(p4_pd_dc_set_l3_rewrite_with_tunnel_action_spec_t));
        action_spec.action_bd = bd;
        memcpy(action_spec.action_dmac, &dmac, ETH_LEN);
        action_spec.action_tunnel_type = tunnel_type;
        action_spec.action_tunnel_index = tunnel_index;
        status = p4_pd_dc_rewrite_table_add_with_set_l3_rewrite_with_tunnel(
            g_sess_hdl,
            p4_pd_device,
            &match_spec,
            &action_spec,
            entry_hdl);
    }
#endif /* P4_TUNNEL_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_rewrite_table_unicast_rewrite_update_entry(switch_device_t device,
                                                     uint16_t bd,
                                                     uint16_t nhop_index,
                                                     switch_mac_addr_t dmac,
                                                     switch_neighbor_rw_type_t rw_type,
                                                     p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t                              status = 0;

    UNUSED(bd);
    UNUSED(nhop_index);
    if (rw_type == SWITCH_API_NEIGHBOR_RW_TYPE_L2) {
        status = p4_pd_dc_rewrite_table_modify_with_set_l2_rewrite(
            g_sess_hdl,
            device,
            entry_hdl);
    } else {
        p4_pd_dc_set_l3_rewrite_action_spec_t action_spec;
        memset(&action_spec, 0, sizeof(p4_pd_dc_set_l3_rewrite_action_spec_t));
        memcpy(action_spec.action_dmac, &dmac, ETH_LEN);
        status = p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite(
            g_sess_hdl,
            device,
            entry_hdl,
            &action_spec);
    }

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_rewrite_table_tunnel_rewrite_update_entry(switch_device_t device,
                                                 uint16_t bd,
                                                 uint16_t nhop_index,
                                                 switch_mac_addr_t dmac,
                                                 switch_neighbor_type_t neigh_type,
                                                 switch_neighbor_rw_type_t rw_type,
                                                 uint16_t tunnel_index,
                                                 switch_encap_type_t encap_type,
                                                 p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t    status = 0;

    UNUSED(nhop_index);
#ifndef P4_TUNNEL_DISABLE
    switch_tunnel_type_egress_t tunnel_type;
    switch (encap_type) {
        case SWITCH_API_ENCAP_TYPE_VXLAN:
            if (neigh_type == SWITCH_API_NEIGHBOR_IPV4_TUNNEL) {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_VXLAN;
            } else {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_VXLAN;
            }
            break;
        case SWITCH_API_ENCAP_TYPE_GENEVE:
            if (neigh_type == SWITCH_API_NEIGHBOR_IPV4_TUNNEL) {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_GENEVE;
            } else {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_GENEVE;
            }
            break;
        case SWITCH_API_ENCAP_TYPE_NVGRE:
            if (neigh_type == SWITCH_API_NEIGHBOR_IPV4_TUNNEL) {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_NVGRE;
            } else {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_NVGRE;
            }
            break;
        case SWITCH_API_ENCAP_TYPE_ERSPAN_T3:
            if (neigh_type == SWITCH_API_NEIGHBOR_IPV4_TUNNEL) {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV4_ERSPAN_T3;
            } else {
                tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_IPV6_ERSPAN_T3;
            }
            break;
        default:
            status = SWITCH_STATUS_INVALID_TUNNEL_TYPE;
            return status;
    }

    if (rw_type == SWITCH_API_NEIGHBOR_RW_TYPE_L2) {
        p4_pd_dc_set_l2_rewrite_with_tunnel_action_spec_t action_spec;
        action_spec.action_tunnel_type = tunnel_type;
        action_spec.action_tunnel_index = tunnel_index;
        status = p4_pd_dc_rewrite_table_modify_with_set_l2_rewrite_with_tunnel(g_sess_hdl,
                                                                   device,
                                                                   entry_hdl,
                                                                   &action_spec);
    } else {
        p4_pd_dc_set_l3_rewrite_with_tunnel_action_spec_t action_spec;
        memset(&action_spec, 0,
               sizeof(p4_pd_dc_set_l3_rewrite_with_tunnel_action_spec_t));
        action_spec.action_bd = bd;
        memcpy(action_spec.action_dmac, &dmac, ETH_LEN);
        action_spec.action_tunnel_type = tunnel_type;
        action_spec.action_tunnel_index = tunnel_index;
        status = p4_pd_dc_rewrite_table_modify_with_set_l3_rewrite_with_tunnel(
            g_sess_hdl,
            device,
            entry_hdl,
            &action_spec);
    }
#endif /* P4_TUNNEL_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_rewrite_table_delete_entry(switch_device_t device, p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;

    status = p4_pd_dc_rewrite_table_delete(g_sess_hdl, device, entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_lag_group_create(switch_device_t device, p4_pd_grp_hdl_t *pd_group_hdl)
{
    switch_status_t status = 0;
    p4_pd_dev_target_t                             pd_device;

    pd_device.device_id = device;
    pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_lag_action_profile_create_group(g_sess_hdl, pd_device, MAX_LAG_GROUP_SIZE, pd_group_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}


p4_pd_status_t
switch_pd_lag_group_delete(switch_device_t device, p4_pd_grp_hdl_t pd_group_hdl)
{
    switch_status_t status = 0;

    status = p4_pd_dc_lag_action_profile_del_group(g_sess_hdl, device, pd_group_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}


p4_pd_status_t
switch_pd_lag_group_table_add_entry(switch_device_t device,
                                    switch_ifindex_t ifindex,
                                    unsigned int port,
                                    p4_pd_mbr_hdl_t *mbr_hdl,
                                    p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t                                 status = 0;
    p4_pd_dc_lag_group_match_spec_t                lg_match_spec;
    bool                                           modify = FALSE;
    p4_pd_dev_target_t                             pd_device;
    p4_pd_dc_set_lag_port_action_spec_t            action_spec;

    pd_device.device_id = device;
    pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&lg_match_spec, 0, sizeof(p4_pd_dc_lag_group_match_spec_t));

    lg_match_spec.ingress_metadata_egress_ifindex = ifindex;

    memset(&action_spec, 0, sizeof(p4_pd_dc_set_lag_port_action_spec_t));
    action_spec.action_port = port;

    modify = (*entry_hdl != 0 ) ? TRUE : FALSE;
    if (modify) {
#if 0
        // TBD
        status = p4_pd_dc_lag_group_modify_entry(g_sess_hdl, 0,
                                       *entry_hdl,
                                       &lg_action_spec);
#endif
    } else {
        status = p4_pd_dc_lag_action_profile_add_member_with_set_lag_port(g_sess_hdl,
                        pd_device,
                        &action_spec, mbr_hdl);
        status = p4_pd_dc_lag_group_add_entry(g_sess_hdl, pd_device,
                        &lg_match_spec, *mbr_hdl,
                        entry_hdl);
    }
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_lag_group_table_add_entry_with_selector(switch_device_t device,
                                                  switch_ifindex_t ifindex,
                                                  p4_pd_grp_hdl_t pd_group_hdl,
                                                  p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t                                 status = 0;
    p4_pd_dc_lag_group_match_spec_t                lg_match_spec;
    bool                                           modify = FALSE;
    p4_pd_dev_target_t                             pd_device;

    pd_device.device_id = device;
    pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&lg_match_spec, 0, sizeof(p4_pd_dc_lag_group_match_spec_t));

    lg_match_spec.ingress_metadata_egress_ifindex = ifindex;

    modify = (*entry_hdl != 0 ) ? TRUE : FALSE;
    if (modify) {
#if 0
        // TBD
        status = p4_pd_dc_lag_group_modify_entry(g_sess_hdl, 0,
                                                                       *entry_hdl,
                                                                       &lg_action_spec);
#endif
    } else {
        status = p4_pd_dc_lag_group_add_entry_with_selector(g_sess_hdl, pd_device,
                        &lg_match_spec, pd_group_hdl,
                        entry_hdl);
    }
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_lag_member_add(switch_device_t device, p4_pd_grp_hdl_t pd_group_hdl,
                         unsigned int port, p4_pd_mbr_hdl_t *mbr_hdl)
{
    p4_pd_dev_target_t                             pd_device;
    p4_pd_dc_set_lag_port_action_spec_t            action_spec;

    pd_device.device_id = device;
    pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    action_spec.action_port = port;
    p4_pd_dc_lag_action_profile_add_member_with_set_lag_port(g_sess_hdl, pd_device, &action_spec, mbr_hdl);
    p4_pd_dc_lag_action_profile_add_member_to_group(g_sess_hdl, device, pd_group_hdl, *mbr_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return 0;
}

p4_pd_status_t
switch_pd_lag_member_delete(switch_device_t device, p4_pd_grp_hdl_t pd_group_hdl,
                            p4_pd_mbr_hdl_t mbr_hdl)
{
    p4_pd_dc_lag_action_profile_del_member_from_group(g_sess_hdl, device, pd_group_hdl, mbr_hdl);

    p4_pd_dc_lag_action_profile_del_member(g_sess_hdl, device, mbr_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return 0;
}


p4_pd_status_t
switch_pd_lag_group_table_delete_entry(switch_device_t device,
                                       p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
    status = p4_pd_dc_lag_group_table_delete(g_sess_hdl,
                                             device,
                                             entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_egress_lag_table_add_entry(switch_device_t device,
                                     switch_port_t port_id,
                                     switch_ifindex_t ifindex,
                                     p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t                                      status = 0;
#ifdef EGRESS_FILTER
    p4_pd_dc_egress_lag_match_spec_t                    match_spec;
    p4_pd_dc_set_egress_ifindex_action_spec_t           action_spec;
    p4_pd_dev_target_t                                  p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_egress_lag_match_spec_t));
    memset(&action_spec, 0, sizeof(p4_pd_dc_set_egress_ifindex_action_spec_t));
    match_spec.standard_metadata_egress_port = port_id;
    action_spec.action_egress_ifindex = ifindex;
    if (*entry_hdl != SWITCH_HW_INVALID_HANDLE) {
        status = p4_pd_dc_egress_lag_table_modify_with_set_egress_ifindex(
                                                       g_sess_hdl,
                                                       device,
                                                       *entry_hdl,
                                                       &action_spec);
    } else {
        status = p4_pd_dc_egress_lag_table_add_with_set_egress_ifindex(
                                                        g_sess_hdl,
                                                        p4_pd_device,
                                                        &match_spec,
                                                        &action_spec,
                                                        entry_hdl);
    }
#endif /* EGRESS_FILTER */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_egress_lag_table_delete_entry(switch_device_t device,
                                        p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#ifdef EGRESS_FILTER
    status = p4_pd_dc_egress_lag_table_delete(g_sess_hdl,
                                              device,
                                              entry_hdl);
#endif /* EGRESS_FILTER */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_smac_rewrite_table_add_entry(switch_device_t device,
                                       switch_smac_entry_t *smac_entry)
{
    p4_pd_dc_smac_rewrite_match_spec_t                  match_spec;
    p4_pd_dc_rewrite_smac_action_spec_t                 action_spec;
    p4_pd_status_t                                      status = 0;
    p4_pd_dev_target_t                                  p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_smac_rewrite_match_spec_t));
    memset(&action_spec, 0, sizeof(p4_pd_dc_rewrite_smac_action_spec_t));
    match_spec.egress_metadata_smac_idx = smac_entry->smac_index;
    memcpy(action_spec.action_smac, &smac_entry->mac, ETH_LEN);

    status = p4_pd_dc_smac_rewrite_table_add_with_rewrite_smac(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        &action_spec,
        &smac_entry->hw_smac_entry);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_smac_rewrite_table_delete_entry(switch_device_t device,
                                          switch_smac_entry_t *smac_entry)
{
    p4_pd_status_t        status = 0;
    status = p4_pd_dc_smac_rewrite_table_delete(g_sess_hdl,
                                               device,
                                               smac_entry->hw_smac_entry);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_rid_table_add_entry(switch_device_t device,
                              uint16_t rid,
                              uint32_t bd,
                              bool inner_replica,
                              uint8_t tunnel_type, uint16_t tunnel_index,
                              p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t                          status = 0;
#ifndef P4_MULTICAST_DISABLE
    p4_pd_dc_rid_match_spec_t               match_spec;
    p4_pd_dev_target_t                      p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_rid_match_spec_t));
    match_spec.intrinsic_metadata_egress_rid = rid;

    if (!inner_replica) {
        p4_pd_dc_outer_replica_from_rid_action_spec_t action_spec;
        memset(&action_spec, 0,
               sizeof(p4_pd_dc_outer_replica_from_rid_action_spec_t));
        action_spec.action_bd = bd;
        action_spec.action_tunnel_type = tunnel_type;
        action_spec.action_tunnel_index = tunnel_index;
        status = p4_pd_dc_rid_table_add_with_outer_replica_from_rid(
            g_sess_hdl, p4_pd_device, &match_spec,
            &action_spec, entry_hdl);
    } else {
        p4_pd_dc_inner_replica_from_rid_action_spec_t action_spec;
        memset(&action_spec, 0,
               sizeof(p4_pd_dc_inner_replica_from_rid_action_spec_t));
        action_spec.action_bd = bd;
        action_spec.action_tunnel_type = tunnel_type;
        action_spec.action_tunnel_index = tunnel_index;
        status = p4_pd_dc_rid_table_add_with_inner_replica_from_rid(
            g_sess_hdl, p4_pd_device, &match_spec,
            &action_spec, entry_hdl);
    }
#endif /* P4_MULTICAST_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_rid_table_delete_entry(switch_device_t device,
                                 p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t        status = 0;
#ifndef P4_MULTICAST_DISABLE

    status = p4_pd_dc_rid_table_delete(g_sess_hdl,
                                         device,
                                         entry_hdl);
#endif /* P4_MULTICAST_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}


p4_pd_status_t
switch_pd_spanning_tree_table_add_entry(switch_device_t device,
                                        uint16_t stp_group,
                                        switch_ifindex_t ifindex,
                                        switch_stp_state_t stp_state,
                                        p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t                                  status = 0;
#if !defined(P4_L2_DISABLE) && !defined(P4_STP_DISABLE)
    p4_pd_dc_spanning_tree_match_spec_t             match_spec;
    p4_pd_dc_set_stp_state_action_spec_t            action_spec;
    p4_pd_dev_target_t                              p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_spanning_tree_match_spec_t));
    memset(&action_spec, 0, sizeof(p4_pd_dc_set_stp_state_action_spec_t));

    match_spec.ingress_metadata_ifindex = ifindex;
    match_spec.l2_metadata_stp_group = stp_group;
    action_spec.action_stp_state = stp_state;

    status = p4_pd_dc_spanning_tree_table_add_with_set_stp_state(g_sess_hdl,
                                                                       p4_pd_device,
                                                                       &match_spec,
                                                                       &action_spec,
                                                                       entry_hdl);
#endif /* P4_L2_DISABLE && P4_STP_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_spanning_tree_table_update_entry(switch_device_t device,
                                           uint16_t stp_group,
                                           switch_ifindex_t ifindex,
                                           switch_stp_state_t stp_state,
                                           p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t                                  status = 0;
    UNUSED(stp_group);
    UNUSED(ifindex);
#if !defined(P4_L2_DISABLE) && !defined(P4_STP_DISABLE)
    p4_pd_dc_set_stp_state_action_spec_t       action_spec;

    memset(&action_spec, 0, sizeof(p4_pd_dc_set_stp_state_action_spec_t));
    action_spec.action_stp_state = stp_state;

    status = p4_pd_dc_spanning_tree_table_modify_with_set_stp_state(g_sess_hdl,
                                                                       device,
                                                                       entry_hdl,
                                                                       &action_spec);
#endif /* P4_L2_DISABLE && P4_STP_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_spanning_tree_table_delete_entry(switch_device_t device,
                                           p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t                          status = 0;
#if !defined(P4_L2_DISABLE) && !defined(P4_STP_DISABLE)
    status = p4_pd_dc_spanning_tree_table_delete(g_sess_hdl, device, entry_hdl);
#endif /* P4_L2_DISABLE && P4_STP_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_urpf_bd_table_add_entry(switch_device_t device,
                                  uint16_t urpf_group,
                                  uint16_t bd_index,
                                  p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t                          status = 0;
#if !defined(P4_L3_DISABLE) && !defined(P4_URPF_DISABLE)
    p4_pd_dev_target_t                      p4_pd_device;
    p4_pd_dc_urpf_bd_match_spec_t      match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_urpf_bd_match_spec_t));
    match_spec.l3_metadata_urpf_bd_group = urpf_group;
    match_spec.ingress_metadata_bd = bd_index;
    status = p4_pd_dc_urpf_bd_table_add_with_nop(g_sess_hdl,
                                                   p4_pd_device,
                                                   &match_spec,
                                                   entry_hdl);
#endif /* P4_L3_DISABLE && P4_URPF_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_urpf_bd_table_delete_entry(switch_device_t device,
                                     p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t                          status = 0;
#if !defined(P4_L3_DISABLE) && !defined(P4_URPF_DISABLE)

    status = p4_pd_dc_urpf_bd_table_delete(g_sess_hdl, device, entry_hdl);
#endif /* P4_L3_DISABLE && P4_URPF_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_urpf_add_entry(switch_device_t device,
                         switch_vrf_id_t vrf_id,
                         switch_ip_addr_t *ip_addr,
                         uint16_t urpf_group,
                         p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;

#if !defined(P4_L3_DISABLE) && !defined(P4_URPF_DISABLE)
    p4_pd_dev_target_t p4_pd_device;
    bool host_entry = FALSE;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    if (ip_addr->type == SWITCH_API_IP_ADDR_V4) {
#ifndef IPV4_DISABLE
        host_entry = (ip_addr->prefix_len == SWITCH_IPV4_PREFIX_LENGTH) ? TRUE : FALSE;
        p4_pd_dc_ipv4_urpf_hit_action_spec_t v4_action_spec;
        memset(&v4_action_spec, 0, sizeof(p4_pd_dc_ipv4_urpf_hit_action_spec_t));
        v4_action_spec.action_urpf_bd_group = urpf_group;
        if (host_entry) {
            p4_pd_dc_ipv4_urpf_match_spec_t v4_match_spec;
            memset(&v4_match_spec, 0, sizeof(p4_pd_dc_urpf_bd_match_spec_t));
            v4_match_spec.l3_metadata_vrf = vrf_id;
            v4_match_spec.ipv4_metadata_lkp_ipv4_sa = ip_addr->ip.v4addr;
            status = p4_pd_dc_ipv4_urpf_table_add_with_ipv4_urpf_hit(
                                                           g_sess_hdl,
                                                           p4_pd_device,
                                                           &v4_match_spec,
                                                           &v4_action_spec,
                                                           entry_hdl);
        } else {
            p4_pd_dc_ipv4_urpf_lpm_match_spec_t v4_match_spec;
            memset(&v4_match_spec, 0, sizeof(p4_pd_dc_urpf_bd_match_spec_t));
            v4_match_spec.l3_metadata_vrf = vrf_id;
            v4_match_spec.ipv4_metadata_lkp_ipv4_sa = ip_addr->ip.v4addr;
            v4_match_spec.ipv4_metadata_lkp_ipv4_sa_prefix_length = ip_addr->prefix_len;
            status = p4_pd_dc_ipv4_urpf_lpm_table_add_with_ipv4_urpf_hit(
                                                           g_sess_hdl,
                                                           p4_pd_device,
                                                           &v4_match_spec,
                                                           &v4_action_spec,
                                                           entry_hdl);
        }
#endif /* IPV4_DISABLE */
    } else {
#ifndef P4_IPV6_DISABLE
        host_entry = (ip_addr->prefix_len == SWITCH_IPV6_PREFIX_LENGTH) ? TRUE : FALSE;
        p4_pd_dc_ipv6_urpf_hit_action_spec_t v6_action_spec;
        memset(&v6_action_spec, 0, sizeof(p4_pd_dc_ipv6_urpf_hit_action_spec_t));
        v6_action_spec.action_urpf_bd_group = urpf_group;
        if (host_entry) {
            p4_pd_dc_ipv6_urpf_match_spec_t v6_match_spec;
            memset(&v6_match_spec, 0, sizeof(p4_pd_dc_urpf_bd_match_spec_t));
            v6_match_spec.l3_metadata_vrf = vrf_id;
            memcpy(&v6_match_spec.ipv6_metadata_lkp_ipv6_sa, ip_addr->ip.v6addr, 16);
            status = p4_pd_dc_ipv6_urpf_table_add_with_ipv6_urpf_hit(
                                                           g_sess_hdl,
                                                           p4_pd_device,
                                                           &v6_match_spec,
                                                           &v6_action_spec,
                                                           entry_hdl);
        } else {
            p4_pd_dc_ipv6_urpf_lpm_match_spec_t v6_match_spec;
            memset(&v6_match_spec, 0, sizeof(p4_pd_dc_urpf_bd_match_spec_t));
            v6_match_spec.l3_metadata_vrf = vrf_id;
            memcpy(&v6_match_spec.ipv6_metadata_lkp_ipv6_sa, ip_addr->ip.v6addr, 16);
            v6_match_spec.ipv6_metadata_lkp_ipv6_sa_prefix_length = ip_addr->prefix_len;
            status = p4_pd_dc_ipv6_urpf_lpm_table_add_with_ipv6_urpf_hit(
                                                            g_sess_hdl,
                                                            p4_pd_device,
                                                            &v6_match_spec,
                                                            &v6_action_spec,
                                                            entry_hdl);
        }
#endif /* P4_IPV6_DISABLE */
    }
#endif /* P4_L3_DISABLE && P4_URPF_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_urpf_update_entry(switch_device_t device,
                            switch_vrf_id_t vrf_id,
                            switch_ip_addr_t *ip_addr,
                            uint16_t urpf_group,
                            p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;

    UNUSED(vrf_id);
#if !defined(P4_L3_DISABLE) && !defined(P4_URPF_DISABLE)
    bool host_entry = FALSE;
    if (ip_addr->type == SWITCH_API_IP_ADDR_V4) {
#ifndef IPV4_DISABLE
        host_entry = (ip_addr->prefix_len == SWITCH_IPV4_PREFIX_LENGTH) ? TRUE : FALSE;
        p4_pd_dc_ipv4_urpf_hit_action_spec_t v4_action_spec;
        memset(&v4_action_spec, 0, sizeof(p4_pd_dc_ipv4_urpf_hit_action_spec_t));
        v4_action_spec.action_urpf_bd_group = urpf_group;
        if (host_entry) {
            status = p4_pd_dc_ipv4_urpf_table_modify_with_ipv4_urpf_hit(
                                                           g_sess_hdl,
                                                           device,
                                                           entry_hdl,
                                                           &v4_action_spec);
        } else {
            status = p4_pd_dc_ipv4_urpf_lpm_table_modify_with_ipv4_urpf_hit(
                                                           g_sess_hdl,
                                                           device,
                                                           entry_hdl,
                                                           &v4_action_spec);
        }
#endif /* P4_IPV4_DISABLE */
    } else {
#ifndef P4_IPV6_DISABLE
        host_entry = (ip_addr->prefix_len == SWITCH_IPV6_PREFIX_LENGTH) ? TRUE : FALSE;
        p4_pd_dc_ipv6_urpf_hit_action_spec_t v6_action_spec;
        memset(&v6_action_spec, 0, sizeof(p4_pd_dc_ipv6_urpf_hit_action_spec_t));
        v6_action_spec.action_urpf_bd_group = urpf_group;
        if (host_entry) {
            status = p4_pd_dc_ipv6_urpf_table_modify_with_ipv6_urpf_hit(
                                                           g_sess_hdl,
                                                           device,
                                                           entry_hdl,
                                                           &v6_action_spec);
        } else {
            status = p4_pd_dc_ipv6_urpf_lpm_table_modify_with_ipv6_urpf_hit(
                                                           g_sess_hdl,
                                                           device,
                                                           entry_hdl,
                                                           &v6_action_spec);
        }
#endif /* P4_IPV6_DISABLE */
    }
#endif /* P4_L3_DISABLE && P4_URPF_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_urpf_delete_entry(switch_device_t device,
                            switch_vrf_id_t vrf_id,
                            switch_ip_addr_t *ip_addr,
                            p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;

    UNUSED(vrf_id);
#if !defined(P4_L3_DISABLE) && !defined(P4_URPF_DISABLE)
    bool host_entry = FALSE;
    if (ip_addr->type == SWITCH_API_IP_ADDR_V4) {
#ifndef IPV4_DISABLE
        host_entry = (ip_addr->prefix_len == SWITCH_IPV4_PREFIX_LENGTH) ? TRUE : FALSE;
        if (host_entry) {
            status = p4_pd_dc_ipv4_urpf_table_delete(g_sess_hdl,
                                                     device,
                                                     entry_hdl);
        } else {
            status = p4_pd_dc_ipv4_urpf_lpm_table_delete(g_sess_hdl,
                                                     device,
                                                     entry_hdl);
        }
#endif /* P4_IPV4_DISABLE */
    } else {
#ifndef P4_IPV6_DISABLE
        host_entry = (ip_addr->prefix_len == SWITCH_IPV6_PREFIX_LENGTH) ? TRUE : FALSE;
        if (host_entry) {
            status = p4_pd_dc_ipv6_urpf_table_delete(g_sess_hdl,
                                                     device,
                                                     entry_hdl);
        } else {
            status = p4_pd_dc_ipv6_urpf_lpm_table_delete(g_sess_hdl,
                                                     device,
                                                     entry_hdl);
        }
#endif /* P4_IPV6_DISABLE */
    }
#endif /* P4_L3_DISABLE && P4_URPF_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mcast_mgrp_tree_create(switch_device_t device, uint16_t mgid_index,
                                 switch_mcast_info_t *mcast_info)
{
    p4_pd_status_t             status = 0;
#ifndef P4_MULTICAST_DISABLE
    p4_pd_dev_target_t         p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_mc_mgrp_create(g_mc_sess_hdl, p4_pd_device.device_id,
                            mgid_index, &mcast_info->mgrp_hdl);
    p4_pd_mc_complete_operations(g_mc_sess_hdl);
#endif /* P4_MULTICAST_DISABLE */
    return status;
}

p4_pd_status_t
switch_pd_mcast_mgrp_tree_delete(switch_device_t device,
                                 switch_mcast_info_t *mcast_info)
{
    p4_pd_status_t             status = 0;
    UNUSED(device);
#ifndef P4_MULTICAST_DISABLE
    status = p4_pd_mc_mgrp_destroy(g_mc_sess_hdl, device, mcast_info->mgrp_hdl);
    p4_pd_mc_complete_operations(g_mc_sess_hdl);
#endif /* P4_MULTICAST_DISABLE */
    return status;
}

p4_pd_status_t
switch_pd_mcast_add_entry(switch_device_t device, switch_mcast_node_t *node)
{
    p4_pd_status_t            status = 0;
#ifndef P4_MULTICAST_DISABLE
    status = p4_pd_mc_node_create(g_mc_sess_hdl, device,
                 SWITCH_MCAST_NODE_RID(node),
                 SWITCH_MCAST_NODE_INFO_PORT_MAP(node),
                 SWITCH_MCAST_NODE_INFO_LAG_MAP(node),
                 &(SWITCH_MCAST_NODE_INFO_HW_ENTRY(node)));
    p4_pd_mc_complete_operations(g_mc_sess_hdl);
#endif /* P4_MULTICAST_DISABLE */
    return status;
}

p4_pd_status_t
switch_pd_mcast_update_entry(switch_device_t device, switch_mcast_node_t *node)
{
    p4_pd_status_t            status = 0;
#ifndef P4_MULTICAST_DISABLE
    status = p4_pd_mc_node_update(g_mc_sess_hdl, device,
                 SWITCH_MCAST_NODE_INFO_HW_ENTRY(node),
                 SWITCH_MCAST_NODE_INFO_PORT_MAP(node),
                 SWITCH_MCAST_NODE_INFO_LAG_MAP(node));
    p4_pd_mc_complete_operations(g_mc_sess_hdl);
#endif /* P4_MULTICAST_DISABLE */
    return status;
}

p4_pd_status_t
switch_pd_mcast_delete_entry(switch_device_t device, switch_mcast_node_t *node)
{
    p4_pd_status_t            status = 0;
    UNUSED(device);
#ifndef P4_MULTICAST_DISABLE
    status = p4_pd_mc_node_destroy(g_mc_sess_hdl, device,
                             SWITCH_MCAST_NODE_INFO_HW_ENTRY(node));
    SWITCH_MCAST_NODE_INFO_HW_ENTRY(node) = 0;
    p4_pd_mc_complete_operations(g_mc_sess_hdl);
#endif /* P4_MULTICAST_DISABLE */
    return status;
}

p4_pd_status_t
switch_pd_mcast_mgid_table_add_entry(switch_device_t device,
                                     mc_mgrp_hdl_t mgid_hdl,
                                     switch_mcast_node_t *node)
{
    p4_pd_status_t               status = 0;
#ifndef P4_MULTICAST_DISABLE
    status = p4_pd_mc_associate_node(
                             g_mc_sess_hdl,
                             device,
                             mgid_hdl,
                             SWITCH_MCAST_NODE_INFO_HW_ENTRY(node),
                             0, FALSE);
    p4_pd_mc_complete_operations(g_mc_sess_hdl);
#endif /* P4_MULTICAST_DISABLE */
    return status;
}

p4_pd_status_t
switch_pd_mcast_mgid_table_delete_entry(switch_device_t device,
                                        mc_mgrp_hdl_t mgid_hdl,
                                        switch_mcast_node_t *node)
{
    p4_pd_status_t               status = 0;
    UNUSED(device);
#ifndef P4_MULTICAST_DISABLE
    status = p4_pd_mc_dissociate_node(g_mc_sess_hdl, device, mgid_hdl,
                                SWITCH_MCAST_NODE_INFO_HW_ENTRY(node));
    p4_pd_mc_complete_operations(g_mc_sess_hdl);
#endif /* P4_MULTICAST_DISABLE */
    return status;
}

p4_pd_status_t
switch_pd_mcast_lag_port_map_update(switch_device_t device, uint16_t lag_index,
                                    switch_mc_port_map_t port_map)
{
    p4_pd_status_t            status = 0;
#ifndef P4_MULTICAST_DISABLE
    status = p4_pd_mc_set_lag_membership(g_mc_sess_hdl, device, lag_index, port_map);
    p4_pd_mc_complete_operations(g_mc_sess_hdl);
#endif /* P4_MULTICAST_DISABLE */
    return status;
}

p4_pd_status_t
switch_pd_system_acl_table_add_entry(switch_device_t device,
                                     uint16_t if_label, uint16_t bd_label,
                                     uint16_t priority,
                                     unsigned int count,
                                     switch_acl_system_key_value_pair_t *system_acl,
                                     switch_acl_system_action_t action_type,
                                     switch_acl_action_params_t *action_params,
                                     switch_acl_opt_action_params_t *opt_action_params,
                                     p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t                             status = 0;
    p4_pd_dev_target_t                         p4_pd_device;
    p4_pd_dc_system_acl_match_spec_t      match_spec;
    unsigned int i = 0;
    bool copy_only = false;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_system_acl_match_spec_t));
    if (if_label) {
        match_spec.acl_metadata_if_label = if_label;
        match_spec.acl_metadata_if_label_mask = 0xFFFF;
    }
    if (bd_label) {
        match_spec.acl_metadata_bd_label = bd_label;
        match_spec.acl_metadata_bd_label_mask = 0xFFFF;
    }

    for (i = 0; i < count; i++) {
        switch (system_acl[i].field) {
            case SWITCH_ACL_SYSTEM_FIELD_ETH_TYPE:
                match_spec.l2_metadata_lkp_mac_type = system_acl[i].value.eth_type;
                match_spec.l2_metadata_lkp_mac_type_mask = system_acl[i].mask.u.mask & 0xFFFF;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_SOURCE_MAC:
                memcpy(match_spec.l2_metadata_lkp_mac_sa, system_acl[i].value.source_mac.mac_addr, ETH_LEN);
                memcpy(match_spec.l2_metadata_lkp_mac_sa_mask, &system_acl[i].mask.u.mask, ETH_LEN);
                break;
            case SWITCH_ACL_SYSTEM_FIELD_DEST_MAC:
                memcpy(match_spec.l2_metadata_lkp_mac_da, system_acl[i].value.dest_mac.mac_addr, ETH_LEN);
                memcpy(match_spec.l2_metadata_lkp_mac_da_mask, &system_acl[i].mask.u.mask, ETH_LEN);
                break;
            case SWITCH_ACL_SYSTEM_FIELD_URPF_CHECK:
                match_spec.l3_metadata_urpf_check_fail = system_acl[i].value.urpf_check_fail;
                match_spec.l3_metadata_urpf_check_fail_mask = system_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_PORT_VLAN_MAPPING_MISS:
                match_spec.l2_metadata_port_vlan_mapping_miss = system_acl[i].value.port_vlan_mapping_miss;
                match_spec.l2_metadata_port_vlan_mapping_miss_mask = system_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_ACL_DENY:
                match_spec.acl_metadata_acl_deny = system_acl[i].value.acl_deny;
                match_spec.acl_metadata_acl_deny_mask = system_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_ACL_COPY:
                copy_only = true;
                match_spec.acl_metadata_acl_copy = system_acl[i].value.acl_copy;
                match_spec.acl_metadata_acl_copy_mask = system_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_L3_COPY:
                copy_only = true;
                match_spec.l3_metadata_l3_copy = system_acl[i].value.l3_copy;
                match_spec.l3_metadata_l3_copy_mask = system_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_IPSG_CHECK:
                match_spec.security_metadata_ipsg_check_fail = system_acl[i].value.ipsg_check;
                match_spec.security_metadata_ipsg_check_fail_mask = system_acl[i].mask.u.mask & 0x1;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_RACL_DENY:
                match_spec.acl_metadata_racl_deny = system_acl[i].value.racl_deny;
                match_spec.acl_metadata_racl_deny_mask = system_acl[i].mask.u.mask & 0x1;
                break;
          case SWITCH_ACL_SYSTEM_FIELD_DROP:
                match_spec.ingress_metadata_drop_flag = system_acl[i].value.drop_flag;
                match_spec.ingress_metadata_drop_flag_mask = system_acl[i].mask.u.mask & 0x1;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_ROUTED:
                match_spec.l3_metadata_routed = system_acl[i].value.routed;
                match_spec.l3_metadata_routed_mask = system_acl[i].mask.u.mask & 0x1;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_LINK_LOCAL:
                match_spec.ipv6_metadata_ipv6_src_is_link_local = system_acl[i].value.src_is_link_local;
                match_spec.ipv6_metadata_ipv6_src_is_link_local_mask = system_acl[i].mask.u.mask & 0x1;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_BD_CHECK:
                match_spec.l3_metadata_same_bd_check = system_acl[i].value.bd_check;
                match_spec.l3_metadata_same_bd_check_mask = system_acl[i].mask.u.mask & 0xFFFF;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_IF_CHECK:
                match_spec.l2_metadata_same_if_check = system_acl[i].value.if_check;
                match_spec.l2_metadata_same_if_check_mask = system_acl[i].mask.u.mask & 0xFFFF;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_TUNNEL_IF_CHECK:
                match_spec.tunnel_metadata_tunnel_if_check = system_acl[i].value.tunnel_if_check;
                match_spec.tunnel_metadata_tunnel_if_check_mask = system_acl[i].mask.u.mask & 0x1;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_TTL:
                match_spec.l3_metadata_lkp_ip_ttl = system_acl[i].value.ttl;
                match_spec.l3_metadata_lkp_ip_ttl_mask = system_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_EGRESS_IFINDEX:
                match_spec.ingress_metadata_egress_ifindex = system_acl[i].value.out_ifindex;
                match_spec.ingress_metadata_egress_ifindex_mask = system_acl[i].mask.u.mask & 0xFFFF;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_STP_STATE:
                match_spec.l2_metadata_stp_state = system_acl[i].value.stp_state;
                match_spec.l2_metadata_stp_state_mask = system_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_CONTROL_FRAME:
                match_spec.ingress_metadata_control_frame = system_acl[i].value.control_frame;
                match_spec.ingress_metadata_control_frame_mask = system_acl[i].mask.u.mask & 0x1;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_IPV4_ENABLED:
                match_spec.ipv4_metadata_ipv4_unicast_enabled = system_acl[i].value.ipv4_enabled;
                match_spec.ipv4_metadata_ipv4_unicast_enabled_mask = system_acl[i].mask.u.mask & 0x1;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_IPV6_ENABLED:
                match_spec.ipv6_metadata_ipv6_unicast_enabled = system_acl[i].value.ipv6_enabled;
                match_spec.ipv6_metadata_ipv6_unicast_enabled_mask = system_acl[i].mask.u.mask & 0x1;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_RMAC_HIT:
                match_spec.l3_metadata_rmac_hit = system_acl[i].value.rmac_hit;
                match_spec.l3_metadata_rmac_hit_mask = system_acl[i].mask.u.mask & 0x1;
                break;
            default:
                break;
        }
    }

    switch (action_type) {
        case SWITCH_ACL_ACTION_NOP:
        case SWITCH_ACL_ACTION_PERMIT:
            status = p4_pd_dc_system_acl_table_add_with_nop(
                g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            break;
        case SWITCH_ACL_ACTION_REDIRECT_TO_CPU:
            {
                p4_pd_dc_redirect_to_cpu_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(p4_pd_dc_redirect_to_cpu_action_spec_t));
                action_spec.action_reason_code = action_params->cpu_redirect.reason_code;
                status = p4_pd_dc_system_acl_table_add_with_redirect_to_cpu(
                    g_sess_hdl, p4_pd_device, &match_spec, priority,
                    &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_COPY_TO_CPU:
            {
                if (copy_only) {
                    status = p4_pd_dc_system_acl_table_add_with_copy_to_cpu(
                        g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
                } else {
                    p4_pd_dc_copy_to_cpu_with_reason_action_spec_t action_spec;
                    memset(&action_spec, 0, sizeof(p4_pd_dc_copy_to_cpu_with_reason_action_spec_t));
                    action_spec.action_reason_code = action_params->cpu_redirect.reason_code;
                    status = p4_pd_dc_system_acl_table_add_with_copy_to_cpu_with_reason(
                        g_sess_hdl, p4_pd_device, &match_spec, priority,
                        &action_spec, entry_hdl);
                }
            }
            break;
        case SWITCH_ACL_ACTION_NEGATIVE_MIRROR:
            {
#ifndef BMV2
                p4_pd_dc_negative_mirror_action_spec_t action_spec;
                action_spec.action_session_id = handle_to_id(opt_action_params->mirror_handle);
#endif
                status = p4_pd_dc_system_acl_table_add_with_negative_mirror(
                    g_sess_hdl, p4_pd_device, &match_spec, priority,
#ifndef BMV2
                    &action_spec,
#endif
                    entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_DROP:
            if (action_params->drop.reason_code) {
#ifndef P4_STATS_DISABLE
                p4_pd_dc_drop_packet_with_reason_action_spec_t action_spec;
                memset(&action_spec, 0,
                       sizeof(p4_pd_dc_drop_packet_with_reason_action_spec_t));
                action_spec.action_drop_reason =
                    action_params->drop.reason_code;
#endif
                status = p4_pd_dc_system_acl_table_add_with_drop_packet_with_reason(
                    g_sess_hdl, p4_pd_device, &match_spec, priority,
#ifndef P4_STATS_DISABLE
                    &action_spec,
#endif
                    entry_hdl);
            } else {
                status = p4_pd_dc_system_acl_table_add_with_drop_packet(
                    g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            }
            break;
        default:
            break;
    }

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_system_acl_table_delete_entry(switch_device_t device, p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
    p4_pd_dc_system_acl_table_delete (g_sess_hdl, device, entry_hdl);
    return status;
}

#if !defined(P4_MPLS_DISABLE) && !defined(P4_TUNNEL_DISABLE)
static switch_tunnel_type_ingress_t
switch_pd_get_mpls_tunnel_type(switch_mpls_encap_t *mpls_encap)
{
    switch_tunnel_type_ingress_t tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_NONE;
    switch (mpls_encap->mpls_type) {
        case SWITCH_API_MPLS_TYPE_EOMPLS:
        case SWITCH_API_MPLS_TYPE_VPLS:
            switch (SWITCH_MPLS_POP_HEADER_COUNT(mpls_encap)) {
                case 1:
                    tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L2VPN_NUM_LABELS_1;
                    break;
                case 2:
                    tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L2VPN_NUM_LABELS_2;
                    break;
                case 3:
                    tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L2VPN_NUM_LABELS_3;
                    break;
                default:
                    break;
            }
            break;
        case SWITCH_API_MPLS_TYPE_IPV4_MPLS:
        case SWITCH_API_MPLS_TYPE_IPV6_MPLS:
            switch (SWITCH_MPLS_POP_HEADER_COUNT(mpls_encap)) {
                case 1:
                    tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L3VPN_NUM_LABELS_1;
                    break;
                case 2:
                    tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L3VPN_NUM_LABELS_2;
                    break;
                case 3:
                    tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L3VPN_NUM_LABELS_3;
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }
    return tunnel_type;
}
#endif /* !defined(P4_MPLS_DISABLE) && !defined(P4_TUNNEL_DISABLE) */

p4_pd_status_t
switch_pd_mpls_table_add_entry(switch_device_t device, switch_mpls_encap_t *mpls_encap,
                               uint32_t bd_index, uint32_t label,
                               switch_bd_info_t *bd_info,
                               uint16_t egress_ifindex, p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_MPLS_DISABLE) && !defined(P4_TUNNEL_DISABLE)
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_mpls_match_spec_t match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_mpls_match_spec_t));
    match_spec.tunnel_metadata_mpls_label = label;

    switch (mpls_encap->mpls_mode) {
        case SWITCH_API_MPLS_TERMINATE:
        {
            switch (mpls_encap->mpls_type) {
                case SWITCH_API_MPLS_TYPE_EOMPLS:
                {
                    p4_pd_dc_terminate_eompls_action_spec_t action_spec;
                    memset(&action_spec, 0, sizeof(p4_pd_dc_terminate_eompls_action_spec_t));
                    //TODO: This is a hack. Eompls will work only when the inner packet is IPV4.
                    //This is just to avoid programming 3 entries - v4, v6 and non-ip.
                    // Ideally, irrespective of inner header, eompls has to terminate but
                    // since we are parsing the inner header, either v4 or v6 valid will be set.
                    match_spec.inner_ipv4_valid = TRUE;
                    match_spec.inner_ipv6_valid = FALSE;
                    action_spec.action_bd = bd_index;
                    action_spec.action_tunnel_type =
                        switch_pd_get_mpls_tunnel_type(mpls_encap);
                    status = p4_pd_dc_mpls_table_add_with_terminate_eompls(
                                                               g_sess_hdl,
                                                               p4_pd_device,
                                                               &match_spec,
                                                               &action_spec,
                                                               entry_hdl);
                }
                break;
                case SWITCH_API_MPLS_TYPE_VPLS:
                {
                    p4_pd_dc_terminate_vpls_action_spec_t action_spec;
                    memset(&action_spec, 0, sizeof(p4_pd_dc_terminate_vpls_action_spec_t));
                    //TODO: This is a hack. Eompls will work only when the inner packet is IPV4.
                    //This is just to avoid programming 3 entries - v4, v6 and non-ip.
                    // Ideally, irrespective of inner header, eompls has to terminate but
                    // since we are parsing the inner header, either v4 or v6 valid will be set.
                    match_spec.inner_ipv4_valid = TRUE;
                    match_spec.inner_ipv6_valid = FALSE;
                    action_spec.action_bd = bd_index;
                    action_spec.action_tunnel_type =
                        switch_pd_get_mpls_tunnel_type(mpls_encap);
                    status = p4_pd_dc_mpls_table_add_with_terminate_vpls(
                                                               g_sess_hdl,
                                                               p4_pd_device,
                                                               &match_spec,
                                                               &action_spec,
                                                               entry_hdl);
                }
                break;
                case SWITCH_API_MPLS_TYPE_PW:
                {
                    p4_pd_dc_terminate_pw_action_spec_t action_spec;
                    memset(&action_spec, 0, sizeof(p4_pd_dc_terminate_pw_action_spec_t));
                    match_spec.inner_ipv4_valid = FALSE;
                    match_spec.inner_ipv6_valid = FALSE;
                    action_spec.action_ifindex = egress_ifindex;
                    status = p4_pd_dc_mpls_table_add_with_terminate_pw(
                                                               g_sess_hdl,
                                                               p4_pd_device,
                                                               &match_spec,
                                                               &action_spec,
                                                               entry_hdl);
                }
                break;
                case SWITCH_API_MPLS_TYPE_IPV4_MPLS:
                {
#ifndef P4_IPV4_DISABLE
                    p4_pd_dc_terminate_ipv4_over_mpls_action_spec_t action_spec;
                    memset(&action_spec, 0, sizeof(p4_pd_dc_terminate_ipv4_over_mpls_action_spec_t));
                    match_spec.inner_ipv4_valid = TRUE;
                    match_spec.inner_ipv6_valid = FALSE;
                    action_spec.action_vrf = handle_to_id(mpls_encap->vrf_handle);
                    action_spec.action_tunnel_type =
                        switch_pd_get_mpls_tunnel_type(mpls_encap);
                    status = p4_pd_dc_mpls_table_add_with_terminate_ipv4_over_mpls(
                                                              g_sess_hdl,
                                                              p4_pd_device,
                                                              &match_spec,
                                                              &action_spec,
                                                              entry_hdl);
#endif /* P4_IPV4_DISABLE */
                }
                break;
                case SWITCH_API_MPLS_TYPE_IPV6_MPLS:
                {
#ifndef P4_IPV6_DISABLE
                    p4_pd_dc_terminate_ipv6_over_mpls_action_spec_t action_spec;
                    memset(&action_spec, 0, sizeof(p4_pd_dc_terminate_ipv6_over_mpls_action_spec_t));
                    match_spec.inner_ipv4_valid = FALSE;
                    match_spec.inner_ipv6_valid = TRUE;
                    action_spec.action_vrf = handle_to_id(mpls_encap->vrf_handle);
                    action_spec.action_tunnel_type =
                        switch_pd_get_mpls_tunnel_type(mpls_encap);
                    status = p4_pd_dc_mpls_table_add_with_terminate_ipv6_over_mpls(
                                                              g_sess_hdl,
                                                              p4_pd_device,
                                                              &match_spec,
                                                              &action_spec,
                                                              entry_hdl);
#endif /* P4_IPV6_DISABLE */
                }
                break;
                default:
                    status = SWITCH_STATUS_INVALID_ENCAP_TYPE;
            }
        }
        break;
        case SWITCH_API_MPLS_TRANSIT:
        {
            p4_pd_dc_forward_mpls_action_spec_t action_spec;
            //TODO: This is a hack. Swap will work only when the inner packet is IPV4.
            //This is just to avoid programming 3 entries - v4, v6 and non-ip.
            match_spec.inner_ipv4_valid = TRUE;
            match_spec.inner_ipv6_valid = FALSE;
            memset(&action_spec, 0, sizeof(p4_pd_dc_forward_mpls_action_spec_t));
            action_spec.action_nexthop_index = handle_to_id(mpls_encap->nhop_handle);
            status = p4_pd_dc_mpls_table_add_with_forward_mpls(
                                                            g_sess_hdl,
                                                            p4_pd_device,
                                                            &match_spec,
                                                            &action_spec,
                                                            entry_hdl);
        }
        break;
        default:
            status = SWITCH_STATUS_INVALID_ENCAP_TYPE;
    }
#endif /* !defined(P4_MPLS_DISABLE) && !defined(P4_TUNNEL_DISABLE) */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mpls_table_delete_entry(switch_device_t device, p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t                          status = 0;
#if !defined(P4_MPLS_DISABLE) && !defined(P4_TUNNEL_DISABLE)
    status = p4_pd_dc_mpls_table_delete(g_sess_hdl, device, entry_hdl);
#endif /* !defined(P4_MPLS_DISABLE) && !defined(P4_TUNNEL_DISABLE) */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_rewrite_table_mpls_add_entry(switch_device_t device, uint32_t tunnel_index,
                                              uint16_t smac_index, uint16_t dmac_index,
                                              switch_mpls_encap_t *mpls_encap,
                                              p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_MPLS_DISABLE) && !defined(P4_TUNNEL_DISABLE)
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_tunnel_rewrite_match_spec_t match_spec;
    switch_mpls_t *mpls_stack = NULL;
    uint8_t header_count = 1;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_tunnel_rewrite_match_spec_t));
    match_spec.tunnel_metadata_tunnel_index = tunnel_index;

    switch (mpls_encap->mpls_action) {
        case SWITCH_API_MPLS_ACTION_PUSH:
            header_count = SWITCH_MPLS_PUSH_HEADER_COUNT(mpls_encap);
            mpls_stack = SWITCH_MPLS_PUSH_HEADER(mpls_encap);
            break;
        case SWITCH_API_MPLS_ACTION_SWAP_PUSH:
            header_count = SWITCH_MPLS_SWAP_PUSH_HEADER_COUNT(mpls_encap);
            mpls_stack = SWITCH_MPLS_SWAP_PUSH_HEADER(mpls_encap);
            break;
        default:
            header_count = 0;
    }

    switch (header_count) {
        case 1:
        {
            p4_pd_dc_set_mpls_rewrite_push1_action_spec_t action_spec;
            memset(&action_spec, 0, sizeof(p4_pd_dc_set_mpls_rewrite_push1_action_spec_t));
            action_spec.action_smac_idx = smac_index;
            action_spec.action_dmac_idx = dmac_index;
            action_spec.action_label1 = mpls_stack[0].label;
            action_spec.action_ttl1 = mpls_stack[0].ttl;
            action_spec.action_exp1 = mpls_stack[0].exp;
            status = p4_pd_dc_tunnel_rewrite_table_add_with_set_mpls_rewrite_push1(g_sess_hdl,
                                                                              p4_pd_device,
                                                                              &match_spec,
                                                                              &action_spec,
                                                                              entry_hdl);
        }
        break;
        case 2:
        {
            p4_pd_dc_set_mpls_rewrite_push2_action_spec_t action_spec;
            memset(&action_spec, 0, sizeof(p4_pd_dc_set_mpls_rewrite_push2_action_spec_t));
            action_spec.action_smac_idx = smac_index;
            action_spec.action_dmac_idx = dmac_index;
            action_spec.action_label1 = mpls_stack[0].label;
            action_spec.action_ttl1 = mpls_stack[0].ttl;
            action_spec.action_exp1 = mpls_stack[0].exp;
            action_spec.action_label2 = mpls_stack[1].label;
            action_spec.action_ttl2 = mpls_stack[1].ttl;
            action_spec.action_exp2 = mpls_stack[1].exp;
            status = p4_pd_dc_tunnel_rewrite_table_add_with_set_mpls_rewrite_push2(g_sess_hdl,
                                                                              p4_pd_device,
                                                                              &match_spec,
                                                                              &action_spec,
                                                                              entry_hdl);
        }
        break;
        case 3:
        {
            p4_pd_dc_set_mpls_rewrite_push3_action_spec_t action_spec;
            memset(&action_spec, 0, sizeof(p4_pd_dc_set_mpls_rewrite_push3_action_spec_t));
            action_spec.action_smac_idx = smac_index;
            action_spec.action_dmac_idx = dmac_index;
            action_spec.action_label1 = mpls_stack[0].label;
            action_spec.action_ttl1 = mpls_stack[0].ttl;
            action_spec.action_exp1 = mpls_stack[0].exp;
            action_spec.action_label2 = mpls_stack[1].label;
            action_spec.action_ttl2 = mpls_stack[1].ttl;
            action_spec.action_exp2 = mpls_stack[1].exp;
            action_spec.action_label3 = mpls_stack[2].label;
            action_spec.action_ttl3 = mpls_stack[2].ttl;
            action_spec.action_exp3 = mpls_stack[2].exp;
            status = p4_pd_dc_tunnel_rewrite_table_add_with_set_mpls_rewrite_push3(g_sess_hdl,
                                                                              p4_pd_device,
                                                                              &match_spec,
                                                                              &action_spec,
                                                                              entry_hdl);
        }
        break;
        default:
            status = SWITCH_STATUS_INVALID_ENCAP_TYPE;
    }
#endif /* !defined(P4_MPLS_DISABLE) && !defined(P4_TUNNEL_DISABLE) */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_rewrite_table_mpls_rewrite_add_entry(switch_device_t device,
                                               uint16_t bd,
                                               uint16_t nhop_index,
                                               uint16_t tunnel_index,
                                               switch_neighbor_type_t neigh_type,
                                               switch_mac_addr_t dmac,
                                               uint32_t label,
                                               uint8_t header_count,
                                               p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_MPLS_DISABLE
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_rewrite_match_spec_t match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_rewrite_match_spec_t));
    match_spec.l3_metadata_nexthop_index = nhop_index;
    switch (neigh_type) {
        case SWITCH_API_NEIGHBOR_MPLS_PUSH_L2VPN:
        {
            p4_pd_dc_set_mpls_push_rewrite_l2_action_spec_t action_spec;
            memset(&action_spec, 0, sizeof(p4_pd_dc_set_mpls_push_rewrite_l2_action_spec_t));
            action_spec.action_tunnel_index = tunnel_index;
            action_spec.action_header_count = header_count;
            status = p4_pd_dc_rewrite_table_add_with_set_mpls_push_rewrite_l2(g_sess_hdl,
                                                                           p4_pd_device,
                                                                           &match_spec,
                                                                           &action_spec,
                                                                           entry_hdl);
        }
        break;
        case SWITCH_API_NEIGHBOR_MPLS_PUSH_L3VPN:
        {
            p4_pd_dc_set_mpls_push_rewrite_l3_action_spec_t action_spec;
            memset(&action_spec, 0, sizeof(p4_pd_dc_set_mpls_push_rewrite_l3_action_spec_t));
            action_spec.action_bd = bd;
            action_spec.action_tunnel_index = tunnel_index;
            action_spec.action_header_count = header_count;
            memcpy(action_spec.action_dmac, &dmac, ETH_LEN);
            status = p4_pd_dc_rewrite_table_add_with_set_mpls_push_rewrite_l3(g_sess_hdl,
                                                                           p4_pd_device,
                                                                           &match_spec,
                                                                           &action_spec,
                                                                           entry_hdl);
        }
        break;
        case SWITCH_API_NEIGHBOR_MPLS_SWAP_PUSH_L2VPN:
        {
            p4_pd_dc_set_mpls_swap_push_rewrite_l2_action_spec_t action_spec;
            memset(&action_spec, 0, sizeof(p4_pd_dc_set_mpls_swap_push_rewrite_l2_action_spec_t));
            action_spec.action_label = label;
            action_spec.action_tunnel_index = tunnel_index;
            action_spec.action_header_count = header_count;
            status = p4_pd_dc_rewrite_table_add_with_set_mpls_swap_push_rewrite_l2(g_sess_hdl,
                                                                           p4_pd_device,
                                                                           &match_spec,
                                                                           &action_spec,
                                                                           entry_hdl);
        }
        break;
        case SWITCH_API_NEIGHBOR_MPLS_SWAP_PUSH_L3VPN:
        {
            p4_pd_dc_set_mpls_swap_push_rewrite_l3_action_spec_t action_spec;
            memset(&action_spec, 0, sizeof(p4_pd_dc_set_mpls_swap_push_rewrite_l3_action_spec_t));
            action_spec.action_bd = bd;
            action_spec.action_label = label;
            action_spec.action_tunnel_index = tunnel_index;
            action_spec.action_header_count = header_count;
            memcpy(action_spec.action_dmac, &dmac, ETH_LEN);
            status = p4_pd_dc_rewrite_table_add_with_set_mpls_swap_push_rewrite_l3(g_sess_hdl,
                                                                           p4_pd_device,
                                                                           &match_spec,
                                                                           &action_spec,
                                                                           entry_hdl);
        }
        break;
        case SWITCH_API_NEIGHBOR_MPLS_SWAP_L2VPN:
        {
            header_count = 0;
            p4_pd_dc_set_mpls_swap_push_rewrite_l2_action_spec_t action_spec;
            memset(&action_spec, 0, sizeof(p4_pd_dc_set_mpls_swap_push_rewrite_l2_action_spec_t));
            action_spec.action_label = label;
            action_spec.action_tunnel_index = tunnel_index;
            action_spec.action_header_count = header_count;
            status = p4_pd_dc_rewrite_table_add_with_set_mpls_swap_push_rewrite_l2(g_sess_hdl,
                                                                           p4_pd_device,
                                                                           &match_spec,
                                                                           &action_spec,
                                                                           entry_hdl);
        }
        break;
        case SWITCH_API_NEIGHBOR_MPLS_SWAP_L3VPN:
        {
            header_count = 0;
            p4_pd_dc_set_mpls_swap_push_rewrite_l3_action_spec_t action_spec;
            memset(&action_spec, 0, sizeof(p4_pd_dc_set_mpls_swap_push_rewrite_l3_action_spec_t));
            action_spec.action_bd = bd;
            action_spec.action_label = label;
            action_spec.action_tunnel_index = tunnel_index;
            action_spec.action_header_count = header_count;
            memcpy(action_spec.action_dmac, &dmac, ETH_LEN);
            status = p4_pd_dc_rewrite_table_add_with_set_mpls_swap_push_rewrite_l3(g_sess_hdl,
                                                                           p4_pd_device,
                                                                           &match_spec,
                                                                           &action_spec,
                                                                           entry_hdl);
        }
        break;
        default:
            header_count = 0;
    }
#endif /* P4_MPLS_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ipv4_acl_table_add_entry(switch_device_t device, uint16_t if_label,
                                   uint16_t bd_label, uint16_t priority,
                                   unsigned int count,
                                   switch_acl_ip_key_value_pair_t *ip_acl,
                                   switch_acl_ip_action_t action,
                                   switch_acl_action_params_t *action_params,
                                   switch_acl_opt_action_params_t *opt_action_params,
                                   p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_ACL_DISABLE) && !defined(P4_IPV4_DISABLE)
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_ip_acl_match_spec_t match_spec;
    unsigned int i = 0;
    switch_meter_idx_t meter_index = 0;
    switch_stats_idx_t stats_index = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    if (opt_action_params) {
        meter_index = handle_to_id(opt_action_params->meter_handle);
        stats_index = handle_to_id(opt_action_params->counter_handle);
    }

    memset(&match_spec, 0, sizeof(p4_pd_dc_ip_acl_match_spec_t));

    if (if_label) {
        match_spec.acl_metadata_if_label = if_label;
        match_spec.acl_metadata_if_label_mask = 0xFFFF;
    }
    if (bd_label) {
        match_spec.acl_metadata_bd_label = bd_label;
        match_spec.acl_metadata_bd_label_mask = 0xFFFF;
    }
    for (i = 0; i < count; i++) {
        switch(ip_acl[i].field) {
            case SWITCH_ACL_IP_FIELD_IPV4_SRC:
                match_spec.ipv4_metadata_lkp_ipv4_sa = ip_acl[i].value.ipv4_source;
                match_spec.ipv4_metadata_lkp_ipv4_sa_mask = ip_acl[i].mask.u.mask & 0xFFFFFFFF;
                break;
            case SWITCH_ACL_IP_FIELD_IPV4_DEST:
                match_spec.ipv4_metadata_lkp_ipv4_da = ip_acl[i].value.ipv4_dest;
                match_spec.ipv4_metadata_lkp_ipv4_da_mask = ip_acl[i].mask.u.mask & 0xFFFFFFFF;;
                break;
            case SWITCH_ACL_IP_FIELD_IP_PROTO:
                match_spec.l3_metadata_lkp_ip_proto = ip_acl[i].value.ip_proto;
                match_spec.l3_metadata_lkp_ip_proto_mask = ip_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_IP_FIELD_L4_SOURCE_PORT:
                match_spec.l3_metadata_lkp_l4_sport = ip_acl[i].value.l4_source_port;
                match_spec.l3_metadata_lkp_l4_sport_mask = ip_acl[i].mask.u.mask & 0xFFFF;
                break;
            case SWITCH_ACL_IP_FIELD_L4_DEST_PORT:
                match_spec.l3_metadata_lkp_l4_dport = ip_acl[i].value.l4_dest_port;
                match_spec.l3_metadata_lkp_l4_dport_mask = ip_acl[i].mask.u.mask & 0xFFFF;
                break;
            case SWITCH_ACL_IP_FIELD_ICMP_TYPE:
                match_spec.l3_metadata_lkp_l4_sport |= ip_acl[i].value.icmp_type << 8;
                match_spec.l3_metadata_lkp_l4_sport_mask |= (ip_acl[i].mask.u.mask & 0xFF) << 8;
                break;
            case SWITCH_ACL_IP_FIELD_ICMP_CODE:
                match_spec.l3_metadata_lkp_l4_sport |= ip_acl[i].value.icmp_code;
                match_spec.l3_metadata_lkp_l4_sport_mask |= ip_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_IP_FIELD_TCP_FLAGS:
                match_spec.tcp_flags = ip_acl[i].value.tcp_flags;
                match_spec.tcp_flags_mask = ip_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_IP_FIELD_TTL:
                match_spec.l3_metadata_lkp_ip_ttl = ip_acl[i].value.ttl;
                match_spec.l3_metadata_lkp_ip_ttl_mask = ip_acl[i].mask.u.mask & 0xFF;
                break;
            default:
                break;
        }
    }
    switch (action) {
        case SWITCH_ACL_ACTION_DROP:
            {
                p4_pd_dc_acl_deny_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_meter_index = meter_index;
                action_spec.action_acl_stats_index = stats_index;
                status = p4_pd_dc_ip_acl_table_add_with_acl_deny(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_PERMIT:
            {
                p4_pd_dc_acl_permit_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_meter_index = meter_index;
                action_spec.action_acl_stats_index = stats_index;
                status = p4_pd_dc_ip_acl_table_add_with_acl_permit(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_REDIRECT:
            {
                switch_handle_t handle = action_params->redirect.handle;
                if(switch_handle_get_type(handle) == SWITCH_HANDLE_TYPE_NHOP) {
                    p4_pd_dc_acl_redirect_nexthop_action_spec_t action_spec;
                    memset(&action_spec, 0, sizeof(action_spec));
                    action_spec.action_acl_meter_index = meter_index;
                    action_spec.action_acl_stats_index = stats_index;
                    action_spec.action_nexthop_index = handle_to_id(handle);
                    p4_pd_dc_ip_acl_table_add_with_acl_redirect_nexthop(
                        g_sess_hdl, p4_pd_device,
                        &match_spec, priority, &action_spec, entry_hdl);
                }
            }
            break;
       case SWITCH_ACL_ACTION_SET_MIRROR:
            {
                p4_pd_dc_acl_mirror_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_meter_index = meter_index;
                action_spec.action_acl_stats_index = stats_index;
                action_spec.action_session_id =
                    handle_to_id(opt_action_params->mirror_handle);
                status = p4_pd_dc_ip_acl_table_add_with_acl_mirror(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_REDIRECT_TO_CPU:
            {
                p4_pd_dc_acl_redirect_nexthop_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_meter_index = meter_index;
                action_spec.action_acl_stats_index = stats_index;
                action_spec.action_nexthop_index =
                    switch_api_cpu_nhop_get(SWITCH_HOSTIF_REASON_CODE_GLEAN);
                status = p4_pd_dc_ip_acl_table_add_with_acl_redirect_nexthop(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_COPY_TO_CPU:
            {
                p4_pd_dc_acl_permit_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_copy = true;
                action_spec.action_acl_copy_reason =
                    action_params->cpu_redirect.reason_code;
                action_spec.action_acl_meter_index = meter_index;
                action_spec.action_acl_stats_index = stats_index;
                status = p4_pd_dc_ip_acl_table_add_with_acl_permit(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        default:
            break;
    }
#endif /* P4_ACL_DISABLE && P4_IPV4_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ipv4_acl_table_delete_entry(switch_device_t device, p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_IPV4_DISABLE) && !defined(P4_ACL_DISABLE)
    p4_pd_dc_ip_acl_table_delete(g_sess_hdl, device, entry_hdl);
#endif /* P4_IPV4_DISABLE & P4_ACL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ipv6_acl_table_add_entry(switch_device_t device, uint16_t if_label,
                                   uint16_t bd_label, uint16_t priority,
                                   unsigned int count,
                                   switch_acl_ipv6_key_value_pair_t *ipv6_acl,
                                   switch_acl_ipv6_action_t action,
                                   switch_acl_action_params_t *action_params,
                                   switch_acl_opt_action_params_t *opt_action_params,
                                   p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_IPV6_DISABLE) && !defined(P4_ACL_DISABLE)
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_ipv6_acl_match_spec_t match_spec;
    unsigned int i = 0;
    switch_meter_idx_t meter_index = 0;
    switch_stats_idx_t stats_index = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    if (opt_action_params) {
        meter_index = handle_to_id(opt_action_params->meter_handle);
        stats_index = handle_to_id(opt_action_params->counter_handle);
    }

    memset(&match_spec, 0, sizeof(p4_pd_dc_ipv6_acl_match_spec_t));

    if (if_label) {
        match_spec.acl_metadata_if_label = if_label;
        match_spec.acl_metadata_if_label_mask = 0xFFFF;
    }
    if (bd_label) {
        match_spec.acl_metadata_bd_label = bd_label;
        match_spec.acl_metadata_bd_label_mask = 0xFFFF;
    }
    for (i = 0; i < count; i++) {
        switch(ipv6_acl[i].field) {
            case SWITCH_ACL_IPV6_FIELD_IPV6_SRC:
                memcpy(match_spec.ipv6_metadata_lkp_ipv6_sa,
                       ipv6_acl[i].value.ipv6_source.u.addr8, 16);
                memcpy(match_spec.ipv6_metadata_lkp_ipv6_sa_mask,
                       ipv6_acl[i].mask.u.mask.u.addr8, 16);
                break;
            case SWITCH_ACL_IPV6_FIELD_IPV6_DEST:
                memcpy(match_spec.ipv6_metadata_lkp_ipv6_da,
                       ipv6_acl[i].value.ipv6_dest.u.addr8, 16);
                memcpy(match_spec.ipv6_metadata_lkp_ipv6_da_mask,
                       ipv6_acl[i].mask.u.mask.u.addr8, 16);
                break;
            case SWITCH_ACL_IPV6_FIELD_IP_PROTO:
                    match_spec.l3_metadata_lkp_ip_proto = ipv6_acl[i].value.ip_proto;
                    match_spec.l3_metadata_lkp_ip_proto_mask = ipv6_acl[i].mask.u.mask.u.addr8[0] & 0xFF;
                break;
            case SWITCH_ACL_IPV6_FIELD_L4_SOURCE_PORT:
                    match_spec.l3_metadata_lkp_l4_sport = ipv6_acl[i].value.l4_source_port;
                    match_spec.l3_metadata_lkp_l4_sport_mask = ipv6_acl[i].mask.u.mask.u.addr16[0] & 0xFFFF;
                break;
            case SWITCH_ACL_IPV6_FIELD_L4_DEST_PORT:
                    match_spec.l3_metadata_lkp_l4_dport = ipv6_acl[i].value.l4_dest_port;
                    match_spec.l3_metadata_lkp_l4_dport_mask = ipv6_acl[i].mask.u.mask.u.addr16[0] & 0xFFFF;
                break;
            case SWITCH_ACL_IPV6_FIELD_ICMP_TYPE:
                    match_spec.l3_metadata_lkp_l4_sport |= ipv6_acl[i].value.icmp_type << 8;
                    match_spec.l3_metadata_lkp_l4_sport_mask |= (ipv6_acl[i].mask.u.mask.u.addr8[0] & 0xFF) << 8;
                break;
            case SWITCH_ACL_IPV6_FIELD_ICMP_CODE:
                    match_spec.l3_metadata_lkp_l4_sport |= ipv6_acl[i].value.icmp_code;
                    match_spec.l3_metadata_lkp_l4_sport_mask |= ipv6_acl[i].mask.u.mask.u.addr8[0] & 0xFF;
                break;
            case SWITCH_ACL_IPV6_FIELD_TCP_FLAGS:
                    match_spec.tcp_flags = ipv6_acl[i].value.tcp_flags;
                    match_spec.tcp_flags_mask = ipv6_acl[i].mask.u.mask.u.addr8[0] & 0xFF;
                break;
            case SWITCH_ACL_IPV6_FIELD_TTL:
                break;
            default:
                break;
        }
    }
    switch (action) {
        case SWITCH_ACL_ACTION_DROP:
            {
                p4_pd_dc_acl_deny_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_meter_index = meter_index;
                action_spec.action_acl_stats_index = stats_index;
                status = p4_pd_dc_ipv6_acl_table_add_with_acl_deny(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_PERMIT:
            {
                p4_pd_dc_acl_permit_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_meter_index = meter_index;
                action_spec.action_acl_stats_index = stats_index;
                status = p4_pd_dc_ipv6_acl_table_add_with_acl_permit(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_REDIRECT:
            {
                switch_handle_t handle = action_params->redirect.handle;
                if(switch_handle_get_type(handle) == SWITCH_HANDLE_TYPE_NHOP) {
                    p4_pd_dc_acl_redirect_nexthop_action_spec_t action_spec;
                    memset(&action_spec, 0, sizeof(action_spec));
                    action_spec.action_acl_meter_index = meter_index;
                    action_spec.action_acl_stats_index = stats_index;
                    action_spec.action_nexthop_index = handle_to_id(handle);
                    status = p4_pd_dc_ipv6_acl_table_add_with_acl_redirect_nexthop(
                        g_sess_hdl, p4_pd_device, &match_spec,
                        priority, &action_spec, entry_hdl);
                }
            }
            break;
        case SWITCH_ACL_ACTION_REDIRECT_TO_CPU:
            {
                p4_pd_dc_acl_redirect_nexthop_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_meter_index = meter_index;
                action_spec.action_acl_stats_index = stats_index;
                action_spec.action_nexthop_index =
                    switch_api_cpu_nhop_get(SWITCH_HOSTIF_REASON_CODE_GLEAN);
                status = p4_pd_dc_ipv6_acl_table_add_with_acl_redirect_nexthop(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_COPY_TO_CPU:
            {
                p4_pd_dc_acl_permit_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_copy = true;
                action_spec.action_acl_copy_reason =
                    action_params->cpu_redirect.reason_code;
                action_spec.action_acl_meter_index = meter_index;
                action_spec.action_acl_stats_index = stats_index;
                status = p4_pd_dc_ipv6_acl_table_add_with_acl_permit(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        default:
            break;
    }

#endif /* P4_IPV6_DISABLE && P4_ACL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ipv6_acl_table_delete_entry(switch_device_t device, p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_IPV6_DISABLE) && !defined(P4_ACL_DISABLE)
    p4_pd_dc_ipv6_acl_table_delete(g_sess_hdl, device, entry_hdl);
#endif /* P4_IPV6_DISABLE & P4_ACL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ipv4_racl_table_add_entry(switch_device_t device, uint16_t if_label,
                                    uint16_t bd_label, uint16_t priority,
                                    unsigned int count,
                                    switch_acl_ip_racl_key_value_pair_t *ip_racl,
                                    switch_acl_ip_action_t action,
                                    switch_acl_action_params_t *action_params,
                                    switch_acl_opt_action_params_t *opt_action_params,
                                    p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_ACL_DISABLE) && !defined(P4_IPV4_DISABLE)
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_ipv4_racl_match_spec_t match_spec;
    unsigned int i = 0;
    switch_meter_idx_t meter_index = 0;
    switch_stats_idx_t stats_index = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_ipv4_racl_match_spec_t));

    if (opt_action_params) {
        meter_index = handle_to_id(opt_action_params->meter_handle);
        UNUSED(meter_index);
        stats_index = handle_to_id(opt_action_params->counter_handle);
    }

    if (bd_label) {
        match_spec.acl_metadata_bd_label = bd_label;
        match_spec.acl_metadata_bd_label_mask = 0xFFFF;
    }
    for (i = 0; i < count; i++) {
        switch(ip_racl[i].field) {
            case SWITCH_ACL_IP_RACL_FIELD_IPV4_SRC:
                match_spec.ipv4_metadata_lkp_ipv4_sa = ip_racl[i].value.ipv4_source;
                match_spec.ipv4_metadata_lkp_ipv4_sa_mask = ip_racl[i].mask.u.mask & 0xFFFFFFFF;
                break;
            case SWITCH_ACL_IP_RACL_FIELD_IPV4_DEST:
                match_spec.ipv4_metadata_lkp_ipv4_da = ip_racl[i].value.ipv4_dest;
                match_spec.ipv4_metadata_lkp_ipv4_da_mask = ip_racl[i].mask.u.mask & 0xFFFFFFFF;
                break;
            case SWITCH_ACL_IP_RACL_FIELD_IP_PROTO:
                match_spec.l3_metadata_lkp_ip_proto = ip_racl[i].value.ip_proto;
                match_spec.l3_metadata_lkp_ip_proto_mask = ip_racl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_IP_RACL_FIELD_L4_SOURCE_PORT:
                match_spec.l3_metadata_lkp_l4_sport = ip_racl[i].value.l4_source_port;
                match_spec.l3_metadata_lkp_l4_sport_mask = ip_racl[i].mask.u.mask & 0xFFFF;
                break;
            case SWITCH_ACL_IP_RACL_FIELD_L4_DEST_PORT:
                match_spec.l3_metadata_lkp_l4_dport = ip_racl[i].value.l4_dest_port;
                match_spec.l3_metadata_lkp_l4_dport_mask = ip_racl[i].mask.u.mask & 0xFFFF;
                break;
            default:
                break;
        }
    }
    switch (action) {
        case SWITCH_ACL_ACTION_DROP:
            {
                p4_pd_dc_racl_deny_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_stats_index = stats_index;
                status = p4_pd_dc_ipv4_racl_table_add_with_racl_deny(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_PERMIT:
            {
                p4_pd_dc_racl_permit_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_stats_index = stats_index;
                status = p4_pd_dc_ipv4_racl_table_add_with_racl_permit(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_REDIRECT:
            {
                switch_handle_t handle = action_params->redirect.handle;
                if(switch_handle_get_type(handle) == SWITCH_HANDLE_TYPE_NHOP) {
                    p4_pd_dc_racl_redirect_nexthop_action_spec_t action_spec;
                    memset(&action_spec, 0, sizeof(action_spec));
                    action_spec.action_acl_stats_index = stats_index;
                    action_spec.action_nexthop_index = handle_to_id(handle);
                    status = p4_pd_dc_ipv4_racl_table_add_with_racl_redirect_nexthop(
                        g_sess_hdl, p4_pd_device, &match_spec,
                        priority, &action_spec, entry_hdl);
                }
            }
            break;
        case SWITCH_ACL_ACTION_SET_NATMODE:
            break;
        case SWITCH_ACL_ACTION_REDIRECT_TO_CPU:
            {
                p4_pd_dc_racl_redirect_nexthop_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_stats_index = stats_index;
                action_spec.action_nexthop_index =
                    switch_api_cpu_nhop_get(SWITCH_HOSTIF_REASON_CODE_GLEAN);
                status = p4_pd_dc_ipv4_racl_table_add_with_racl_redirect_nexthop(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_COPY_TO_CPU:
            {
                p4_pd_dc_racl_permit_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_copy = true;
                action_spec.action_acl_copy_reason =
                    action_params->cpu_redirect.reason_code;
                action_spec.action_acl_stats_index = stats_index;
                status = p4_pd_dc_ipv4_racl_table_add_with_racl_permit(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        default:
            break;
    }
#endif /* P4_ACL_DISABLE && P4_IPV4_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ipv4_racl_table_delete_entry(switch_device_t device, p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_IPV4_DISABLE) && !defined(P4_ACL_DISABLE)
    p4_pd_dc_ipv4_racl_table_delete(g_sess_hdl, device, entry_hdl);
#endif /* P4_IPV4_DISABLE & P4_ACL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ipv6_racl_table_add_entry(switch_device_t device, uint16_t if_label,
                                    uint16_t bd_label, uint16_t priority,
                                    unsigned int count,
                                    switch_acl_ipv6_racl_key_value_pair_t *ipv6_racl,
                                    switch_acl_ipv6_action_t action,
                                    switch_acl_action_params_t *action_params,
                                    switch_acl_opt_action_params_t *opt_action_params,
                                    p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_IPV6_DISABLE) && !defined(P4_ACL_DISABLE)
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_ipv6_racl_match_spec_t match_spec;
    unsigned int i = 0;
    switch_meter_idx_t meter_index = 0;
    switch_stats_idx_t stats_index = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_ipv6_racl_match_spec_t));

    if (opt_action_params) {
        meter_index = handle_to_id(opt_action_params->meter_handle);
        UNUSED(meter_index);
        stats_index = handle_to_id(opt_action_params->counter_handle);
    }

    if (bd_label) {
        match_spec.acl_metadata_bd_label = bd_label;
        match_spec.acl_metadata_bd_label_mask = 0xFFFF;
    }
    for (i = 0; i < count; i++) {
        switch(ipv6_racl[i].field) {
            case SWITCH_ACL_IPV6_RACL_FIELD_IPV6_SRC:
                break;
            case SWITCH_ACL_IPV6_RACL_FIELD_IPV6_DEST:
                break;
            case SWITCH_ACL_IPV6_RACL_FIELD_IP_PROTO:
                match_spec.l3_metadata_lkp_ip_proto = ipv6_racl[i].value.ip_proto;
                match_spec.l3_metadata_lkp_ip_proto_mask = ipv6_racl[i].mask.u.mask.u.addr8[0] & 0xFF;
                break;
            case SWITCH_ACL_IPV6_RACL_FIELD_L4_SOURCE_PORT:
                match_spec.l3_metadata_lkp_l4_sport = ipv6_racl[i].value.l4_source_port;
                match_spec.l3_metadata_lkp_l4_sport_mask = ipv6_racl[i].mask.u.mask.u.addr16[0] & 0xFFFF;
                break;
            case SWITCH_ACL_IPV6_RACL_FIELD_L4_DEST_PORT:
                match_spec.l3_metadata_lkp_l4_dport = ipv6_racl[i].value.l4_dest_port;
                match_spec.l3_metadata_lkp_l4_dport_mask = ipv6_racl[i].mask.u.mask.u.addr16[0] & 0xFFFF;
                break;
            default:
                break;
        }
    }
    switch (action) {
        case SWITCH_ACL_ACTION_DROP:
            {
                p4_pd_dc_racl_deny_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_stats_index = stats_index;
                status = p4_pd_dc_ipv6_racl_table_add_with_racl_deny(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_PERMIT:
            {
                p4_pd_dc_racl_permit_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_stats_index = stats_index;
                status = p4_pd_dc_ipv6_racl_table_add_with_racl_permit(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_REDIRECT:
            {
                switch_handle_t handle = action_params->redirect.handle;
                if(switch_handle_get_type(handle) == SWITCH_HANDLE_TYPE_NHOP) {
                    p4_pd_dc_racl_redirect_nexthop_action_spec_t action_spec;
                    memset(&action_spec, 0, sizeof(action_spec));
                    action_spec.action_acl_stats_index = stats_index;
                    action_spec.action_nexthop_index = handle_to_id(handle);
                    p4_pd_dc_ipv6_racl_table_add_with_racl_redirect_nexthop(
                        g_sess_hdl, p4_pd_device, &match_spec,
                        priority, &action_spec, entry_hdl);
                }
            }
            break;
        case SWITCH_ACL_ACTION_REDIRECT_TO_CPU:
            {
                p4_pd_dc_racl_redirect_nexthop_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_stats_index = stats_index;
                action_spec.action_nexthop_index =
                    switch_api_cpu_nhop_get(SWITCH_HOSTIF_REASON_CODE_GLEAN);
                status = p4_pd_dc_ipv6_racl_table_add_with_racl_redirect_nexthop(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_COPY_TO_CPU:
            {
                p4_pd_dc_racl_permit_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_copy = true;
                action_spec.action_acl_copy_reason =
                    action_params->cpu_redirect.reason_code;
                action_spec.action_acl_stats_index = stats_index;
                status = p4_pd_dc_ipv6_racl_table_add_with_racl_permit(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_SET_NATMODE:
            break;
        default:
            break;
    }
#endif /* P4_IPV6_DISABLE & P4_ACL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ipv6_racl_table_delete_entry(switch_device_t device, p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_IPV6_DISABLE) && !defined(P4_ACL_DISABLE)
    p4_pd_dc_ipv6_racl_table_delete(g_sess_hdl, device, entry_hdl);
#endif /* P4_IPV6_DISABLE & P4_ACL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mac_acl_table_add_entry(switch_device_t device, uint16_t if_label,
                                  uint16_t bd_label, uint16_t priority,
                                  unsigned int count,
                                  switch_acl_mac_key_value_pair_t *mac_acl,
                                  switch_acl_mac_action_t action,
                                  switch_acl_action_params_t *action_params,
                                  switch_acl_opt_action_params_t *opt_action_params,
                                  p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_L2_DISABLE) && !defined(P4_ACL_DISABLE)
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_mac_acl_match_spec_t match_spec;
    unsigned int i = 0;
    switch_meter_idx_t meter_index = 0;
    switch_stats_idx_t stats_index = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_mac_acl_match_spec_t));

    if (opt_action_params) {
        meter_index = handle_to_id(opt_action_params->meter_handle);
        stats_index = handle_to_id(opt_action_params->counter_handle);
    }

    if (if_label) {
        match_spec.acl_metadata_if_label = if_label;
        match_spec.acl_metadata_if_label_mask = 0xFFFF;
    }
    if (bd_label) {
        match_spec.acl_metadata_bd_label = bd_label;
        match_spec.acl_metadata_bd_label_mask = 0xFFFF;
    }
    for (i = 0; i < count; i++) {
        switch(mac_acl[i].field) {
            case SWITCH_ACL_MAC_FIELD_ETH_TYPE:
                match_spec.l2_metadata_lkp_mac_type = mac_acl[i].value.eth_type;
                match_spec.l2_metadata_lkp_mac_type_mask = mac_acl[i].mask.u.mask16 & 0xFFFF;
                break;
            case SWITCH_ACL_MAC_FIELD_SOURCE_MAC:
                memcpy(match_spec.l2_metadata_lkp_mac_sa, mac_acl[i].value.source_mac, 6);
                memcpy(match_spec.l2_metadata_lkp_mac_sa_mask, mac_acl[i].mask.u.mac_mask, 6);
                break;
            case SWITCH_ACL_MAC_FIELD_DEST_MAC:
                memcpy(match_spec.l2_metadata_lkp_mac_da, mac_acl[i].value.dest_mac, 6);
                memcpy(match_spec.l2_metadata_lkp_mac_da_mask, mac_acl[i].mask.u.mac_mask, 6);
                break;
            default:
                break;
        }
    }
    switch (action) {
        case SWITCH_ACL_ACTION_DROP:
            {
                p4_pd_dc_acl_deny_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_meter_index = meter_index;
                action_spec.action_acl_stats_index = stats_index;
                status = p4_pd_dc_mac_acl_table_add_with_acl_deny(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_PERMIT:
            {
                p4_pd_dc_acl_permit_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_meter_index = meter_index;
                action_spec.action_acl_stats_index = stats_index;
                status = p4_pd_dc_mac_acl_table_add_with_acl_permit(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_REDIRECT_TO_CPU:
            {
                p4_pd_dc_acl_redirect_nexthop_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_meter_index = meter_index;
                action_spec.action_acl_stats_index = stats_index;
                action_spec.action_nexthop_index =
                    switch_api_cpu_nhop_get(SWITCH_HOSTIF_REASON_CODE_GLEAN);
                p4_pd_dc_mac_acl_table_add_with_acl_redirect_nexthop(
                        g_sess_hdl, p4_pd_device, &match_spec,
                        priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_COPY_TO_CPU:
            {
                p4_pd_dc_acl_permit_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(action_spec));
                action_spec.action_acl_copy = true;
                action_spec.action_acl_copy_reason =
                    action_params->cpu_redirect.reason_code;
                action_spec.action_acl_meter_index = meter_index;
                action_spec.action_acl_stats_index = stats_index;
                status = p4_pd_dc_mac_acl_table_add_with_acl_permit(
                    g_sess_hdl, p4_pd_device, &match_spec,
                    priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_REDIRECT:
            break;
        default:
            break;
    }
#endif /* P4_L2_DISABLE && P4_ACL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mac_acl_table_delete_entry(switch_device_t device, p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_L2_DISABLE) && !defined(P4_ACL_DISABLE)
    p4_pd_dc_mac_acl_table_delete(g_sess_hdl, device, entry_hdl);
#endif /* P4_L2_DISABLE & P4_ACL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_egr_acl_table_add_entry(switch_device_t device,
                           uint16_t if_label,
                           uint16_t bd_label, uint16_t priority,
                           unsigned int count,
                           switch_acl_egr_key_value_pair_t *egr_acl,
                           switch_acl_egr_action_t action,
                           switch_acl_action_params_t *action_params,
                           switch_acl_opt_action_params_t *opt_action_params,
                           p4_pd_entry_hdl_t *entry_hdl)
{
    unsigned int i;
    p4_pd_status_t status = 0;
    (void)bd_label;
    (void)if_label;

#ifndef P4_ACL_DISABLE
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_egress_acl_match_spec_t match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_egress_acl_match_spec_t));
    for (i=0; i < count; i++) {
        switch(egr_acl[i].field) {
            case SWITCH_ACL_EGR_DEST_PORT:
                {
                    match_spec.standard_metadata_egress_port =
                        handle_to_id(egr_acl[i].value.egr_port);
                    match_spec.standard_metadata_egress_port_mask = 0xFFFF;
                }
                break;
            case SWITCH_ACL_EGR_DEFLECT:
                {
                    match_spec.intrinsic_metadata_deflection_flag =
                        egr_acl[i].value.deflection_flag ? 0x1 : 0;
                    match_spec.intrinsic_metadata_deflection_flag_mask = 0xFF;
                }
                break;
            case SWITCH_ACL_EGR_L3_MTU_CHECK:
                {
                    match_spec.l3_metadata_l3_mtu_check =
                        egr_acl[i].value.l3_mtu_check;
                    match_spec.l3_metadata_l3_mtu_check_mask = 0xFFFF;
                }
                break;
            default:
                break;
        }
    }

    switch (action) {
        case SWITCH_ACL_EGR_ACTION_NOP:
            status = p4_pd_dc_egress_acl_table_add_with_nop(g_sess_hdl,
                                    p4_pd_device, &match_spec, priority,
                                    entry_hdl);
            break;
        case SWITCH_ACL_EGR_ACTION_SET_MIRROR:
        {
            p4_pd_dc_egress_mirror_action_spec_t action_spec;
            action_spec.action_session_id =
                handle_to_id(opt_action_params->mirror_handle);
            status = p4_pd_dc_egress_acl_table_add_with_egress_mirror(
                        g_sess_hdl, p4_pd_device, &match_spec, priority,
                        &action_spec, entry_hdl);
            break;
        }
        case SWITCH_ACL_EGR_ACTION_REDIRECT_TO_CPU:
        {
            p4_pd_dc_egress_redirect_to_cpu_action_spec_t action_spec;
            action_spec.action_reason_code =
                action_params->cpu_redirect.reason_code;
            status = p4_pd_dc_egress_acl_table_add_with_egress_redirect_to_cpu(
                        g_sess_hdl, p4_pd_device, &match_spec, priority,
                        &action_spec, entry_hdl);
            break;
        }
        default:
            break;
    }
#endif /* P4_ACL_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_egr_acl_table_delete_entry(switch_device_t device,
                                     p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
    status = p4_pd_dc_egress_acl_table_delete(g_sess_hdl, device, entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_qos_acl_table_add_entry(switch_device_t device, uint16_t if_label,
                                  uint16_t bd_label, uint16_t priority,
                                  unsigned int count,
                                  switch_acl_qos_key_value_pair_t *qos_acl,
                                  switch_acl_mac_action_t action,
                                  p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_ACL_DISABLE
#ifndef P4_QOS_DISABLE
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_qos_match_spec_t match_spec;
    unsigned int i = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_qos_match_spec_t));

    if (if_label) {
        match_spec.acl_metadata_if_label = if_label;
        match_spec.acl_metadata_if_label_mask = 0xFFFF;
    }
    for (i = 0; i < count; i++) {
        switch(qos_acl[i].field) {
            case SWITCH_ACL_QOS_FIELD_IPV4_SRC:
                match_spec.ipv4_metadata_lkp_ipv4_sa = qos_acl[i].value.ipv4_source;
                match_spec.ipv4_metadata_lkp_ipv4_sa_mask = qos_acl[i].mask.u.mask & 0xFFFFFFFF;
                break;
            case SWITCH_ACL_QOS_FIELD_IPV4_DEST:
                match_spec.ipv4_metadata_lkp_ipv4_da = qos_acl[i].value.ipv4_dest;
                match_spec.ipv4_metadata_lkp_ipv4_da_mask = qos_acl[i].mask.u.mask & 0xFFFFFFFF;;
                break;
            case SWITCH_ACL_QOS_FIELD_IP_PROTO:
                match_spec.l3_metadata_lkp_ip_proto = qos_acl[i].value.ip_proto;
                match_spec.l3_metadata_lkp_ip_proto_mask = qos_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_QOS_FIELD_TC:
                match_spec.l3_metadata_lkp_ip_tc = qos_acl[i].value.tc;
                match_spec.l3_metadata_lkp_ip_tc_mask = qos_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_QOS_FIELD_EXP:
                match_spec.tunnel_metadata_mpls_exp = qos_acl[i].value.exp;
                match_spec.tunnel_metadata_mpls_exp_mask = qos_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_QOS_FIELD_DSCP:
                match_spec.qos_metadata_outer_dscp = qos_acl[i].value.dscp;
                match_spec.qos_metadata_outer_dscp_mask = qos_acl[i].mask.u.mask & 0xFF;
                break;
            default:
                break;
        }
    }
    switch (action) {
        case SWITCH_ACL_QOS_ACTION_COS:
            {
                p4_pd_dc_apply_cos_marking_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(p4_pd_dc_apply_cos_marking_action_spec_t));
                status = p4_pd_dc_qos_table_add_with_apply_cos_marking(g_sess_hdl,
                                                                       p4_pd_device,
                                                                       &match_spec,
                                                                       priority,
                                                                       &action_spec,
                                                                       entry_hdl);
            }
            break;
        case SWITCH_ACL_QOS_ACTION_DSCP:
            {
                p4_pd_dc_apply_dscp_marking_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(p4_pd_dc_apply_dscp_marking_action_spec_t));
                status = p4_pd_dc_qos_table_add_with_apply_dscp_marking(g_sess_hdl,
                                                                        p4_pd_device,
                                                                        &match_spec,
                                                                        priority,
                                                                        &action_spec,
                                                                        entry_hdl);
            }
            break;
        case SWITCH_ACL_QOS_ACTION_TC:
            {
                p4_pd_dc_apply_tc_marking_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(p4_pd_dc_apply_tc_marking_action_spec_t));
                status = p4_pd_dc_qos_table_add_with_apply_tc_marking(g_sess_hdl,
                                                                      p4_pd_device,
                                                                      &match_spec,
                                                                      priority,
                                                                      &action_spec,
                                                                      entry_hdl);
            }
            break;
        default:
            break;
    }
#endif /* P4_QOS_DISABLE */
#endif /* P4_ACL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_qos_acl_table_delete_entry(switch_device_t device, p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_QOS_DISABLE) && !defined(P4_ACL_DISABLE)
    p4_pd_dc_qos_table_delete(g_sess_hdl, device, entry_hdl);
#endif /* P4_QOS_DISABLE & P4_ACL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_ingress_fabric_table_add_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dc_fabric_ingress_dst_lkp_match_spec_t match_spec;
    memset(&match_spec, 0, sizeof(p4_pd_dc_fabric_ingress_dst_lkp_match_spec_t));
    match_spec.fabric_header_dstDevice = device;
    status = p4_pd_dc_fabric_ingress_dst_lkp_table_add_with_terminate_cpu_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        &entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

/*
 * DEFAULT ENTRIES
 * TODO: Remove them once the default action can be specified in P4.
 */

p4_pd_status_t
switch_pd_ip_mcast_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_MULTICAST_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

#ifndef P4_IPV4_DISABLE
#ifndef P4_TUNNEL_DISABLE
    status = p4_pd_dc_outer_ipv4_multicast_set_default_action_on_miss(
        g_sess_hdl, p4_pd_device, &entry_hdl);
    status = p4_pd_dc_outer_ipv4_multicast_star_g_set_default_action_nop(
        g_sess_hdl, p4_pd_device, &entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    status = p4_pd_dc_ipv4_multicast_bridge_set_default_action_on_miss(
        g_sess_hdl, p4_pd_device, &entry_hdl);
    status = p4_pd_dc_ipv4_multicast_bridge_star_g_set_default_action_nop(
        g_sess_hdl, p4_pd_device, &entry_hdl);
    status = p4_pd_dc_ipv4_multicast_route_set_default_action_on_miss(
        g_sess_hdl, p4_pd_device, &entry_hdl);
    status = p4_pd_dc_ipv4_multicast_route_star_g_set_default_action_multicast_route_star_g_miss(
        g_sess_hdl, p4_pd_device, &entry_hdl);
#endif /* P4_IPV4_DISABLE */

#ifndef P4_IPV6_DISABLE
#ifndef P4_TUNNEL_DISABLE
    status = p4_pd_dc_outer_ipv6_multicast_set_default_action_on_miss(
        g_sess_hdl, p4_pd_device, &entry_hdl);
    status = p4_pd_dc_outer_ipv6_multicast_star_g_set_default_action_nop(
        g_sess_hdl, p4_pd_device, &entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    status = p4_pd_dc_ipv6_multicast_bridge_set_default_action_on_miss(
        g_sess_hdl, p4_pd_device, &entry_hdl);
    status = p4_pd_dc_ipv6_multicast_bridge_star_g_set_default_action_nop(
        g_sess_hdl, p4_pd_device, &entry_hdl);
    status = p4_pd_dc_ipv6_multicast_route_set_default_action_on_miss(
        g_sess_hdl, p4_pd_device, &entry_hdl);
    status = p4_pd_dc_ipv6_multicast_route_star_g_set_default_action_multicast_route_star_g_miss(
        g_sess_hdl, p4_pd_device, &entry_hdl);
#endif /* P4_IPV6_DISABLE */
#endif /* P4_MULTICAST_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_validate_outer_ethernet_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_malformed_outer_ethernet_packet_action_spec_t action_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&action_spec, 0,
           sizeof(p4_pd_dc_malformed_outer_ethernet_packet_action_spec_t));
    action_spec.action_drop_reason = DROP_OUTER_ETHERNET_MISS;
    status = p4_pd_dc_validate_outer_ethernet_set_default_action_malformed_outer_ethernet_packet(
        g_sess_hdl,
        p4_pd_device,
        &action_spec,
        &entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);

    return status;
}

p4_pd_status_t
switch_pd_validate_outer_ip_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_L3_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

#ifndef P4_IPV4_DISABLE
    p4_pd_dc_validate_outer_ipv4_packet_match_spec_t match_spec;
    p4_pd_dc_set_malformed_outer_ipv4_packet_action_spec_t action_spec;

    /* default entry */
    memset(&action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_outer_ipv4_packet_action_spec_t));
    action_spec.action_drop_reason = DROP_OUTER_IP_MISS;
    status = p4_pd_dc_validate_outer_ipv4_packet_set_default_action_set_malformed_outer_ipv4_packet(
        g_sess_hdl,
        p4_pd_device,
        &action_spec,
        &entry_hdl);

    /* ipv4 src is loopback */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ipv4_packet_match_spec_t));
    memset(&action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_outer_ipv4_packet_action_spec_t));
    match_spec.ipv4_metadata_lkp_ipv4_sa = 0x7f000000;
    match_spec.ipv4_metadata_lkp_ipv4_sa_mask = 0xff000000;
    action_spec.action_drop_reason = DROP_OUTER_IP_SRC_LOOPBACK;
    status = p4_pd_dc_validate_outer_ipv4_packet_table_add_with_set_malformed_outer_ipv4_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        10,
        &action_spec,
        &entry_hdl);

    /* ipv4 src is multicast */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ipv4_packet_match_spec_t));
    memset(&action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_outer_ipv4_packet_action_spec_t));
    match_spec.ipv4_metadata_lkp_ipv4_sa = 0xe0000000;
    match_spec.ipv4_metadata_lkp_ipv4_sa_mask = 0xf0000000;
    action_spec.action_drop_reason = DROP_OUTER_IP_SRC_MULTICAST;
    status = p4_pd_dc_validate_outer_ipv4_packet_table_add_with_set_malformed_outer_ipv4_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        11,
        &action_spec,
        &entry_hdl);

    /* ttl is zero */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ipv4_packet_match_spec_t));
    memset(&action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_outer_ipv4_packet_action_spec_t));
    match_spec.l3_metadata_lkp_ip_ttl_mask = 0xff;
    action_spec.action_drop_reason = DROP_OUTER_IP_TTL_ZERO;
    status = p4_pd_dc_validate_outer_ipv4_packet_table_add_with_set_malformed_outer_ipv4_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        12,
        &action_spec,
        &entry_hdl);

    /* version is 4 and packet is okay */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ipv4_packet_match_spec_t));
    match_spec.ipv4_version = 0x04;
    match_spec.ipv4_version_mask = 0xff;
    status = p4_pd_dc_validate_outer_ipv4_packet_table_add_with_set_valid_outer_ipv4_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        13,
        &entry_hdl);

    /* invalid version */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ipv4_packet_match_spec_t));
    memset(&action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_outer_ipv4_packet_action_spec_t));
    action_spec.action_drop_reason = DROP_OUTER_IP_VERSION_INVALID;
    status = p4_pd_dc_validate_outer_ipv4_packet_table_add_with_set_malformed_outer_ipv4_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        14,
        &action_spec,
        &entry_hdl);
#endif /* P4_IPV4_DISABLE */

#ifndef P4_IPV6_DISABLE
    p4_pd_dc_validate_outer_ipv6_packet_match_spec_t v6_match_spec;
    p4_pd_dc_set_malformed_outer_ipv6_packet_action_spec_t v6_action_spec;

    /* default entry */
    memset(&v6_action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_outer_ipv6_packet_action_spec_t));
    v6_action_spec.action_drop_reason = DROP_OUTER_IP_MISS;
    status = p4_pd_dc_validate_outer_ipv6_packet_set_default_action_set_malformed_outer_ipv6_packet(
        g_sess_hdl,
        p4_pd_device,
        &v6_action_spec,
        &entry_hdl);

    /* ipv6 src is multicast */
    memset(&v6_match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ipv6_packet_match_spec_t));
    memset(&v6_action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_outer_ipv6_packet_action_spec_t));
    v6_match_spec.ipv6_metadata_lkp_ipv6_sa[0] = 0xff;
    v6_match_spec.ipv6_metadata_lkp_ipv6_sa_mask[0] = 0xff;
    v6_action_spec.action_drop_reason = DROP_OUTER_IP_SRC_MULTICAST;
    status = p4_pd_dc_validate_outer_ipv6_packet_table_add_with_set_malformed_outer_ipv6_packet(
        g_sess_hdl,
        p4_pd_device,
        &v6_match_spec,
        11,
        &v6_action_spec,
        &entry_hdl);

    /* ttl is zero */
    memset(&v6_match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ipv6_packet_match_spec_t));
    memset(&v6_action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_outer_ipv6_packet_action_spec_t));
    v6_match_spec.l3_metadata_lkp_ip_ttl_mask = 0xff;
    v6_action_spec.action_drop_reason = DROP_OUTER_IP_TTL_ZERO;
    status = p4_pd_dc_validate_outer_ipv6_packet_table_add_with_set_malformed_outer_ipv6_packet(
        g_sess_hdl,
        p4_pd_device,
        &v6_match_spec,
        12,
        &v6_action_spec,
        &entry_hdl);

    /* version is 6 and packet is okay */
    memset(&v6_match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ipv6_packet_match_spec_t));
    v6_match_spec.ipv6_version = 0x06;
    v6_match_spec.ipv6_version_mask = 0xff;
    status = p4_pd_dc_validate_outer_ipv6_packet_table_add_with_set_valid_outer_ipv6_packet(
        g_sess_hdl,
        p4_pd_device,
        &v6_match_spec,
        13,
        &entry_hdl);

    /* invalid version */
    memset(&v6_match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ipv6_packet_match_spec_t));
    memset(&v6_action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_outer_ipv6_packet_action_spec_t));
    v6_action_spec.action_drop_reason = DROP_OUTER_IP_VERSION_INVALID;
    status = p4_pd_dc_validate_outer_ipv6_packet_table_add_with_set_malformed_outer_ipv6_packet(
        g_sess_hdl,
        p4_pd_device,
        &v6_match_spec,
        14,
        &v6_action_spec,
        &entry_hdl);
#endif /* P4_IPV6_DISABLE */

#endif /* P4_L3_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_outer_rmac_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_outer_rmac_set_default_action_on_miss(g_sess_hdl,
                                                                 p4_pd_device,
                                                                 &entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_src_vtep_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#if !defined(P4_TUNNEL_DISABLE) && !defined(P4_L3_DISABLE)
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

#ifndef P4_IPV4_DISABLE
    status = p4_pd_dc_ipv4_src_vtep_set_default_action_on_miss(g_sess_hdl,
                                                               p4_pd_device,
                                                               &entry_hdl);
#endif /* P4_IPV4_DISABLE */
#ifndef P4_IPV6_DISABLE
    status = p4_pd_dc_ipv6_src_vtep_set_default_action_on_miss(g_sess_hdl,
                                                               p4_pd_device,
                                                               &entry_hdl);
#endif /* P4_IPV6_DISABLE */

#endif /* P4_TUNNEL_DISABLE && P4_L3_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_dest_vtep_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#if !defined(P4_TUNNEL_DISABLE) && !defined(P4_L3_DISABLE)
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

#ifndef P4_IPV4_DISABLE
    status = p4_pd_dc_ipv4_dest_vtep_set_default_action_nop(g_sess_hdl,
                                                             p4_pd_device,
                                                             &entry_hdl);
#endif /* P4_IPV4_DISABLE */
#ifndef P4_IPV6_DISABLE
    status = p4_pd_dc_ipv6_dest_vtep_set_default_action_nop(g_sess_hdl,
                                                             p4_pd_device,
                                                             &entry_hdl);
#endif /* P4_IPV6_DISABLE */

#endif /* P4_TUNNEL_DISABLE && P4_L3_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_smac_rewrite_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_tunnel_smac_rewrite_set_default_action_nop(g_sess_hdl,
                                                             p4_pd_device,
                                                             &entry_hdl);

#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_dmac_rewrite_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_tunnel_dmac_rewrite_set_default_action_nop(g_sess_hdl,
                                                             p4_pd_device,
                                                             &entry_hdl);

#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_rewrite_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_tunnel_rewrite_set_default_action_nop(g_sess_hdl,
                                                             p4_pd_device,
                                                             &entry_hdl);

#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_port_vlan_mapping_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
    p4_pd_mbr_hdl_t mbr_hdl;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_bd_action_profile_add_member_with_port_vlan_mapping_miss(
        g_sess_hdl,
        p4_pd_device,
        &mbr_hdl);
    status = p4_pd_dc_port_vlan_mapping_set_default_entry(g_sess_hdl,
                                                          p4_pd_device,
                                                          mbr_hdl,
                                                          &entry_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_validate_packet_table_add_default_entry(switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;
    int priority = 100;
    int i;
    p4_pd_dc_validate_packet_match_spec_t match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_validate_packet_set_default_action_nop(g_sess_hdl,
                                                               p4_pd_device,
                                                               &entry_hdl);

    /* src is multicast */
    p4_pd_dc_set_malformed_packet_action_spec_t action_spec;
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_packet_match_spec_t));
    match_spec.l2_metadata_lkp_mac_sa[0] = 0x01;
    match_spec.l2_metadata_lkp_mac_sa_mask[0] = 0x01;
    memset(&action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_packet_action_spec_t));
    action_spec.action_drop_reason = DROP_SRC_MAC_MULTICAST;
    status = p4_pd_dc_validate_packet_table_add_with_set_malformed_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        priority++,
        &action_spec,
        &entry_hdl);

    /* dst is zero */
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_packet_match_spec_t));
    match_spec.l2_metadata_lkp_mac_da_mask[0] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[1] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[2] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[3] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[4] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[5] = 0xff;
    memset(&action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_packet_action_spec_t));
    action_spec.action_drop_reason = DROP_DST_MAC_ZERO;
    status = p4_pd_dc_validate_packet_table_add_with_set_malformed_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        priority++,
        &action_spec,
        &entry_hdl);

    /* IPv4 TTL is zero */
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_packet_match_spec_t));
    match_spec.l3_metadata_lkp_ip_type = SWITCH_IP_TYPE_IPv4;
    match_spec.l3_metadata_lkp_ip_type_mask = 0xff;
    match_spec.l3_metadata_lkp_ip_ttl = 0;
    match_spec.l3_metadata_lkp_ip_ttl_mask = 0xff;
    memset(&action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_packet_action_spec_t));
    action_spec.action_drop_reason = DROP_IP_TTL_ZERO;
    status = p4_pd_dc_validate_packet_table_add_with_set_malformed_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        priority++,
        &action_spec,
        &entry_hdl);

    /* IPv6 TTL is zero */
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_packet_match_spec_t));
    match_spec.l3_metadata_lkp_ip_type = SWITCH_IP_TYPE_IPv6;
    match_spec.l3_metadata_lkp_ip_type_mask = 0xff;
    match_spec.l3_metadata_lkp_ip_ttl = 0;
    match_spec.l3_metadata_lkp_ip_ttl_mask = 0xff;
    memset(&action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_packet_action_spec_t));
    action_spec.action_drop_reason = DROP_IP_TTL_ZERO;
    status = p4_pd_dc_validate_packet_table_add_with_set_malformed_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        priority++,
        &action_spec,
        &entry_hdl);

    /* ipv4 src is loopback */
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_packet_match_spec_t));
    match_spec.l3_metadata_lkp_ip_type = SWITCH_IP_TYPE_IPv4;
    match_spec.l3_metadata_lkp_ip_type_mask = 0xff;
    match_spec.ipv4_metadata_lkp_ipv4_sa = 0x7f000000;
    match_spec.ipv4_metadata_lkp_ipv4_sa_mask = 0xff000000;
    memset(&action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_packet_action_spec_t));
    action_spec.action_drop_reason = DROP_IP_SRC_LOOPBACK;
    status = p4_pd_dc_validate_packet_table_add_with_set_malformed_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        priority++,
        &action_spec,
        &entry_hdl);

    /* ipv4 src is multicast */
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_packet_match_spec_t));
    match_spec.l3_metadata_lkp_ip_type = SWITCH_IP_TYPE_IPv4;
    match_spec.l3_metadata_lkp_ip_type_mask = 0xff;
    match_spec.ipv4_metadata_lkp_ipv4_sa = 0xe0000000;
    match_spec.ipv4_metadata_lkp_ipv4_sa_mask = 0xf0000000;
    memset(&action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_packet_action_spec_t));
    action_spec.action_drop_reason = DROP_IP_SRC_MULTICAST;
    status = p4_pd_dc_validate_packet_table_add_with_set_malformed_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        priority++,
        &action_spec,
        &entry_hdl);

    /* ipv4 version invalid */
    for (i = 0; i < 16; i++) {
        if (i == 4) {
            continue;
        }
        memset(&match_spec, 0, sizeof(p4_pd_dc_validate_packet_match_spec_t));
        match_spec.l3_metadata_lkp_ip_type = SWITCH_IP_TYPE_IPv4;
        match_spec.l3_metadata_lkp_ip_type_mask = 0xff;
        match_spec.l3_metadata_lkp_ip_version = i;
        match_spec.l3_metadata_lkp_ip_version_mask = 0xff;
        memset(&action_spec, 0,
               sizeof(p4_pd_dc_set_malformed_packet_action_spec_t));
        action_spec.action_drop_reason = DROP_IP_VERSION_INVALID;
        status = p4_pd_dc_validate_packet_table_add_with_set_malformed_packet(
            g_sess_hdl,
            p4_pd_device,
            &match_spec,
            priority++,
            &action_spec,
            &entry_hdl);
    }

#ifndef IPV6_DISABLE
    /* ipv6 version invalid */
    for (i = 0; i < 16; i++) {
        if (i == 6) {
            continue;
        }
        memset(&match_spec, 0, sizeof(p4_pd_dc_validate_packet_match_spec_t));
        match_spec.l3_metadata_lkp_ip_type = SWITCH_IP_TYPE_IPv6;
        match_spec.l3_metadata_lkp_ip_type_mask = 0xff;
        match_spec.l3_metadata_lkp_ip_version = i;
        match_spec.l3_metadata_lkp_ip_version_mask = 0xff;
        memset(&action_spec, 0,
               sizeof(p4_pd_dc_set_malformed_packet_action_spec_t));
        action_spec.action_drop_reason = DROP_IP_VERSION_INVALID;
        status = p4_pd_dc_validate_packet_table_add_with_set_malformed_packet(
            g_sess_hdl,
            p4_pd_device,
            &match_spec,
            priority++,
            &action_spec,
            &entry_hdl);
    }

    /* ipv6 src is multicast */
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_packet_match_spec_t));
    match_spec.l3_metadata_lkp_ip_type = SWITCH_IP_TYPE_IPv6;
    match_spec.l3_metadata_lkp_ip_type_mask = 0xff;
    match_spec.ipv6_metadata_lkp_ipv6_sa[0] = 0xff;
    match_spec.ipv6_metadata_lkp_ipv6_sa_mask[0] = 0xff;
    memset(&action_spec, 0,
           sizeof(p4_pd_dc_set_malformed_packet_action_spec_t));
    action_spec.action_drop_reason = DROP_IP_SRC_MULTICAST;
    status = p4_pd_dc_validate_packet_table_add_with_set_malformed_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        priority++,
        &action_spec,
        &entry_hdl);
#endif /* IPV6_DISABLE */

    /* broadcast */
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_packet_match_spec_t));
    match_spec.l2_metadata_lkp_mac_da[0] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[1] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[2] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[3] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[4] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[5] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[0] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[1] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[2] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[3] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[4] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[5] = 0xff;
    status = p4_pd_dc_validate_packet_table_add_with_set_broadcast(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        priority++,
        &entry_hdl);

#ifndef IPV6_DISABLE
    /* multicast, source is ipv6 link local */
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_packet_match_spec_t));
    match_spec.l2_metadata_lkp_mac_da[0] = 0x01;
    match_spec.l2_metadata_lkp_mac_da_mask[0] = 0x01;
    match_spec.l3_metadata_lkp_ip_type = SWITCH_IP_TYPE_IPv6;
    match_spec.l3_metadata_lkp_ip_type_mask = 0xff;
    match_spec.ipv6_metadata_lkp_ipv6_sa[0] = 0xfe;
    match_spec.ipv6_metadata_lkp_ipv6_sa[1] = 0x80;
    match_spec.ipv6_metadata_lkp_ipv6_sa_mask[0] = 0xff;
    match_spec.ipv6_metadata_lkp_ipv6_sa_mask[1] = 0xff;
    status = p4_pd_dc_validate_packet_table_add_with_set_multicast_and_ipv6_src_is_link_local(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        priority++,
        &entry_hdl);
#endif /* IPV6_DISABLE */

    /* multicast */
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_packet_match_spec_t));
    match_spec.l2_metadata_lkp_mac_da[0] = 0x01;
    match_spec.l2_metadata_lkp_mac_da_mask[0] = 0x01;
    status = p4_pd_dc_validate_packet_table_add_with_set_multicast(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        priority++,
        &entry_hdl);

#ifndef IPV6_DISABLE
    /* unicast, source is ipv6 link local */
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_packet_match_spec_t));
    match_spec.l3_metadata_lkp_ip_type = SWITCH_IP_TYPE_IPv6;
    match_spec.l3_metadata_lkp_ip_type_mask = 0xff;
    match_spec.ipv6_metadata_lkp_ipv6_sa[0] = 0xfe;
    match_spec.ipv6_metadata_lkp_ipv6_sa[1] = 0x80;
    match_spec.ipv6_metadata_lkp_ipv6_sa_mask[0] = 0xfe;
    match_spec.ipv6_metadata_lkp_ipv6_sa_mask[1] = 0x80;
    status = p4_pd_dc_validate_packet_table_add_with_set_unicast_and_ipv6_src_is_link_local(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        priority++,
        &entry_hdl);
#endif /* IPV6_DISABLE */

    /* unicast */
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_packet_match_spec_t));
    status = p4_pd_dc_validate_packet_table_add_with_set_unicast(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        priority++,
        &entry_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_acl_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_system_acl_set_default_action_nop(g_sess_hdl,
                                                          p4_pd_device,
                                                          &entry_hdl);
#ifndef P4_ACL_DISABLE
#ifndef P4_L2_DISABLE
    status = p4_pd_dc_mac_acl_set_default_action_nop(g_sess_hdl,
                                                       p4_pd_device,
                                                       &entry_hdl);
#endif /* P4_L2_DISABLE */

#ifndef P4_IPV4_DISABLE
    status = p4_pd_dc_ip_acl_set_default_action_nop(g_sess_hdl,
                                                      p4_pd_device,
                                                      &entry_hdl);

    status = p4_pd_dc_ipv4_racl_set_default_action_nop(g_sess_hdl,
                                                       p4_pd_device,
                                                       &entry_hdl);

#endif /* P4_IPV4_DISABLE */
#ifndef P4_IPV6_DISABLE
    status = p4_pd_dc_ipv6_acl_set_default_action_nop(g_sess_hdl,
                                                        p4_pd_device,
                                                        &entry_hdl);

    status = p4_pd_dc_ipv6_racl_set_default_action_nop(g_sess_hdl,
                                                         p4_pd_device,
                                                         &entry_hdl);
#endif /* P4_IPV6_DISABLE */
#endif /* P4_ACL_DISABLE */

#ifndef P4_QOS_DISABLE
    status = p4_pd_dc_qos_set_default_action_nop(g_sess_hdl,
                                                   p4_pd_device,
                                                   &entry_hdl);
#endif /* P4_QOS_DISABLE */

#ifndef P4_STATS_DISABLE
    status = p4_pd_dc_drop_stats_set_default_action_drop_stats_update(
        g_sess_hdl,
        p4_pd_device,
        &entry_hdl);

    status = p4_pd_dc_acl_stats_set_default_action_acl_stats_update(
        g_sess_hdl,
        p4_pd_device,
        &entry_hdl);
#endif /* P4_STATS_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_inner_rmac_table_add_default_entry(switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_rmac_set_default_action_rmac_miss(g_sess_hdl,
                                                             p4_pd_device,
                                                             &entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_fwd_result_table_add_default_entry(switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_fwd_result_set_default_action_nop(g_sess_hdl,
                                                          p4_pd_device,
                                                          &entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}


switch_status_t
switch_pd_nexthop_table_add_default_entry(switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_nexthop_set_default_action_nop(g_sess_hdl,
                                                       p4_pd_device,
                                                       &entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_lag_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
    p4_pd_mbr_hdl_t mbr_hdl;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_lag_action_profile_add_member_with_set_lag_miss(g_sess_hdl,
                                                                      p4_pd_device,
                                                                      &mbr_hdl);

    status = p4_pd_dc_lag_group_set_default_entry(g_sess_hdl,
                                                       p4_pd_device,
                                                       mbr_hdl,
                                                       &entry_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_egress_lag_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifdef EGRESS_FILTER
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_egress_filter_table_add_with_set_egress_filter_drop(
                                                        g_sess_hdl,
                                                        p4_pd_device,
                                                        &entry_hdl);
#endif /* EGRESS_FILTER */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_rid_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_MULTICAST_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_rid_set_default_action_nop(g_sess_hdl,
                                                   p4_pd_device,
                                                   &entry_hdl);
#endif /* P4_MULTICAST_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_replica_type_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_MULTICAST_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_replica_type_set_default_action_nop(g_sess_hdl,
                                                            p4_pd_device,
                                                            &entry_hdl);
#endif /* P4_MULTICAST_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_mac_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_L2_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_smac_set_default_action_smac_miss(g_sess_hdl,
                                                    p4_pd_device,
                                                    &entry_hdl);
    status = p4_pd_dc_dmac_set_default_action_dmac_miss(g_sess_hdl,
                                                          p4_pd_device,
                                                          &entry_hdl);
#endif /* P4_L2_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_egress_bd_map_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_egress_bd_map_set_default_action_nop(g_sess_hdl,
                                                           p4_pd_device,
                                                           &entry_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_egress_vni_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_egress_vni_set_default_action_nop(g_sess_hdl,
                                                             p4_pd_device,
                                                             &entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_ip_fib_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_L3_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

#ifndef P4_IPV4_DISABLE
    status = p4_pd_dc_ipv4_fib_set_default_action_on_miss(g_sess_hdl,
                                                            p4_pd_device,
                                                            &entry_hdl);
    status = p4_pd_dc_ipv4_fib_lpm_set_default_action_on_miss(g_sess_hdl,
                                                            p4_pd_device,
                                                            &entry_hdl);
#endif /* P4_IPV4_DISABLE */
#ifndef P4_IPV6_DISABLE
    status = p4_pd_dc_ipv6_fib_set_default_action_on_miss(g_sess_hdl,
                                                            p4_pd_device,
                                                            &entry_hdl);
    status = p4_pd_dc_ipv6_fib_lpm_set_default_action_on_miss(g_sess_hdl,
                                                            p4_pd_device,
                                                            &entry_hdl);
#endif /* P4_IPV6_DISABLE */
#endif /* P4_L3_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_ip_urpf_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#if !defined(P4_L3_DISABLE) && !defined(P4_URPF_DISABLE)
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

#ifndef P4_IPV4_DISABLE
    status = p4_pd_dc_ipv4_urpf_set_default_action_on_miss(
                                                 g_sess_hdl,
                                                 p4_pd_device,
                                                 &entry_hdl);
    status = p4_pd_dc_ipv4_urpf_lpm_set_default_action_urpf_miss(
                                                 g_sess_hdl,
                                                 p4_pd_device,
                                                 &entry_hdl);
#endif /* P4_IPV4_DISABLE */
#ifndef P4_IPV6_DISABLE
    status = p4_pd_dc_ipv6_urpf_set_default_action_on_miss(
                                                 g_sess_hdl,
                                                 p4_pd_device,
                                                 &entry_hdl);
    status = p4_pd_dc_ipv6_urpf_lpm_set_default_action_urpf_miss(
                                                 g_sess_hdl,
                                                 p4_pd_device,
                                                 &entry_hdl);
#endif /* P4_IPV6_DISABLE */
    status = p4_pd_dc_urpf_bd_set_default_action_urpf_bd_miss(
                                                 g_sess_hdl,
                                                 p4_pd_device,
                                                 &entry_hdl);
#endif /* P4_L3_DISABLE && P4_URPF_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_rewrite_table_add_default_entry(switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_rewrite_set_default_action_set_l2_rewrite(
        g_sess_hdl,
        p4_pd_device,
        &entry_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_rewrite_multicast_table_add_default_entry(switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_rewrite_multicast_set_default_action_nop(
        g_sess_hdl, p4_pd_device, &entry_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_egress_vlan_xlate_table_add_default_entry(switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_egress_vlan_xlate_set_default_action_set_egress_packet_vlan_untagged(
                                                            g_sess_hdl,
                                                            p4_pd_device,
                                                            &entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_egress_acl_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_ACL_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_egress_acl_set_default_action_nop(g_sess_hdl,
                                                        p4_pd_device,
                                                        &entry_hdl);
#endif /* P4_ACL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_vlan_decap_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_vlan_decap_set_default_action_nop(g_sess_hdl,
                                                        p4_pd_device,
                                                        &entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_src_rewrite_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_tunnel_src_rewrite_set_default_action_nop(g_sess_hdl,
                                                             p4_pd_device,
                                                             &entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_dst_rewrite_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_tunnel_dst_rewrite_set_default_action_nop(g_sess_hdl,
                                                             p4_pd_device,
                                                             &entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_tunnel_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_tunnel_set_default_action_tunnel_lookup_miss(
        g_sess_hdl, p4_pd_device, &entry_hdl);
    status = p4_pd_dc_tunnel_miss_set_default_action_tunnel_lookup_miss(
        g_sess_hdl, p4_pd_device, &entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_bd_stats_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_STATS_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_ingress_bd_stats_set_default_action_update_ingress_bd_stats(
        g_sess_hdl,
        p4_pd_device,
        &entry_hdl);

    status = p4_pd_dc_egress_bd_stats_set_default_action_nop(
        g_sess_hdl,
        p4_pd_device,
        &entry_hdl);
#endif /* P4_STATS_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_bd_flood_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;

#ifndef MULTICAST_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_bd_flood_set_default_action_nop(g_sess_hdl,
                                                      p4_pd_device,
                                                      &entry_hdl);
#endif /* MULTICAST_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

/*************** INIT Entries ***************************/
p4_pd_status_t
switch_pd_fwd_result_table_add_init_entry(switch_device_t device)
{
    p4_pd_dc_fwd_result_match_spec_t          match_spec;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;
    uint16_t prio = 1000;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.acl_metadata_acl_redirect = 1;
    match_spec.acl_metadata_acl_redirect_mask = 1;
    status = p4_pd_dc_fwd_result_table_add_with_set_acl_redirect_action(
        g_sess_hdl, p4_pd_device, &match_spec, prio++, &entry_hdl);

    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.l3_metadata_fib_hit = 1;
    match_spec.l3_metadata_fib_hit_mask = 1;
    status = p4_pd_dc_fwd_result_table_add_with_set_fib_redirect_action(
        g_sess_hdl, p4_pd_device, &match_spec, prio++, &entry_hdl);

    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.l2_metadata_l2_redirect = 1;
    match_spec.l2_metadata_l2_redirect_mask = 1;
    status = p4_pd_dc_fwd_result_table_add_with_set_l2_redirect_action(
        g_sess_hdl, p4_pd_device, &match_spec, prio++, &entry_hdl);

    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.l3_metadata_rmac_hit = 1;
    match_spec.l3_metadata_rmac_hit_mask = 1;
    match_spec.l3_metadata_fib_hit = 0;
    match_spec.l3_metadata_fib_hit_mask = 1;
    status = p4_pd_dc_fwd_result_table_add_with_set_cpu_redirect_action(
        g_sess_hdl, p4_pd_device, &match_spec, prio++, &entry_hdl);

#ifndef P4_MULTICAST_DISABLE
    prio = 2000;
    // mroute = hit, bridge = x, rpf = pass
    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.multicast_metadata_mcast_route_hit = 1;
    match_spec.multicast_metadata_mcast_route_hit_mask = 1;
    match_spec.multicast_metadata_mcast_rpf_group = 0;
    match_spec.multicast_metadata_mcast_rpf_group_mask = 0xFFFF;
    match_spec.multicast_metadata_mcast_mode = SWITCH_API_MCAST_IPMC_PIM_SM;
    match_spec.multicast_metadata_mcast_mode_mask = 0xff;
    status = p4_pd_dc_fwd_result_table_add_with_set_multicast_route_action(
        g_sess_hdl, p4_pd_device, &match_spec, prio++, &entry_hdl);

    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.multicast_metadata_mcast_route_hit = 1;
    match_spec.multicast_metadata_mcast_route_hit_mask = 1;
    match_spec.multicast_metadata_mcast_rpf_group = 0xFFFF;
    match_spec.multicast_metadata_mcast_rpf_group_mask = 0xFFFF;
    match_spec.multicast_metadata_mcast_mode = SWITCH_API_MCAST_IPMC_PIM_BIDIR;
    match_spec.multicast_metadata_mcast_mode_mask = 0xff;
    status = p4_pd_dc_fwd_result_table_add_with_set_multicast_route_action(
        g_sess_hdl, p4_pd_device, &match_spec, prio++, &entry_hdl);

    // mroute = hit, bridge = hit, rpf = fail
    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.multicast_metadata_mcast_route_hit = 1;
    match_spec.multicast_metadata_mcast_route_hit_mask = 1;
    match_spec.multicast_metadata_mcast_bridge_hit = 1;
    match_spec.multicast_metadata_mcast_bridge_hit_mask = 1;
    match_spec.multicast_metadata_mcast_mode = SWITCH_API_MCAST_IPMC_PIM_SM;
    match_spec.multicast_metadata_mcast_mode_mask = 0xff;
    status = p4_pd_dc_fwd_result_table_add_with_set_multicast_bridge_action(
        g_sess_hdl, p4_pd_device, &match_spec, prio++, &entry_hdl);

    // mroute = hit, bridge = miss, rpf = fail, igmp snooping enabled
    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.multicast_metadata_mcast_route_hit = 1;
    match_spec.multicast_metadata_mcast_route_hit_mask = 1;
    match_spec.multicast_metadata_mcast_bridge_hit = 0;
    match_spec.multicast_metadata_mcast_bridge_hit_mask = 1;
    match_spec.multicast_metadata_mcast_mode = SWITCH_API_MCAST_IPMC_PIM_SM;
    match_spec.multicast_metadata_mcast_mode_mask = 0xff;
    match_spec.l3_metadata_lkp_ip_type = SWITCH_IP_TYPE_IPv4;
    match_spec.l3_metadata_lkp_ip_type_mask = 0xff;
    match_spec.multicast_metadata_igmp_snooping_enabled = 1;
    match_spec.multicast_metadata_igmp_snooping_enabled_mask = 1;
    status = p4_pd_dc_fwd_result_table_add_with_set_multicast_drop(
        g_sess_hdl, p4_pd_device, &match_spec, prio++, &entry_hdl);

    // mroute = hit, bridge = miss, rpf = fail, mld snooping enabled
    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.multicast_metadata_mcast_route_hit = 1;
    match_spec.multicast_metadata_mcast_route_hit_mask = 1;
    match_spec.multicast_metadata_mcast_bridge_hit = 0;
    match_spec.multicast_metadata_mcast_bridge_hit_mask = 1;
    match_spec.multicast_metadata_mcast_mode = SWITCH_API_MCAST_IPMC_PIM_SM;
    match_spec.multicast_metadata_mcast_mode_mask = 0xff;
    match_spec.l3_metadata_lkp_ip_type = SWITCH_IP_TYPE_IPv6;
    match_spec.l3_metadata_lkp_ip_type_mask = 0xff;
    match_spec.multicast_metadata_mld_snooping_enabled = 1;
    match_spec.multicast_metadata_mld_snooping_enabled_mask = 1;
    status = p4_pd_dc_fwd_result_table_add_with_set_multicast_drop(
        g_sess_hdl, p4_pd_device, &match_spec, prio++, &entry_hdl);

    // mroute = hit, bridge = miss, rpf = fail, igmp/mld snooping disabled
    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.multicast_metadata_mcast_route_hit = 1;
    match_spec.multicast_metadata_mcast_route_hit_mask = 1;
    match_spec.multicast_metadata_mcast_bridge_hit = 0;
    match_spec.multicast_metadata_mcast_bridge_hit_mask = 1;
    match_spec.multicast_metadata_mcast_mode = SWITCH_API_MCAST_IPMC_PIM_SM;
    match_spec.multicast_metadata_mcast_mode_mask = 0xff;
    status = p4_pd_dc_fwd_result_table_add_with_set_multicast_flood(
        g_sess_hdl, p4_pd_device, &match_spec, prio++, &entry_hdl);

    // bridge = hit
    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.multicast_metadata_mcast_bridge_hit = 1;
    match_spec.multicast_metadata_mcast_bridge_hit_mask = 1;
    status = p4_pd_dc_fwd_result_table_add_with_set_multicast_bridge_action(
        g_sess_hdl, p4_pd_device, &match_spec, prio++, &entry_hdl);

    // bridge = miss, pkt_type = multicast, igmp snooping enabled
    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.l2_metadata_lkp_pkt_type = SWITCH_VLAN_FLOOD_UMC;
    match_spec.l2_metadata_lkp_pkt_type_mask = 0xff;
    match_spec.l3_metadata_lkp_ip_type = SWITCH_IP_TYPE_IPv4;
    match_spec.l3_metadata_lkp_ip_type_mask = 0xff;
    match_spec.multicast_metadata_igmp_snooping_enabled = 1;
    match_spec.multicast_metadata_igmp_snooping_enabled_mask = 1;
    status = p4_pd_dc_fwd_result_table_add_with_set_multicast_drop(
        g_sess_hdl, p4_pd_device, &match_spec, prio++, &entry_hdl);

    // bridge = miss, pkt_type = multicast, mld snooping enabled
    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.l2_metadata_lkp_pkt_type = SWITCH_VLAN_FLOOD_UMC;
    match_spec.l2_metadata_lkp_pkt_type_mask = 0xff;
    match_spec.l3_metadata_lkp_ip_type = SWITCH_IP_TYPE_IPv6;
    match_spec.l3_metadata_lkp_ip_type_mask = 0xff;
    match_spec.multicast_metadata_mld_snooping_enabled = 1;
    match_spec.multicast_metadata_mld_snooping_enabled_mask = 1;
    status = p4_pd_dc_fwd_result_table_add_with_set_multicast_drop(
        g_sess_hdl, p4_pd_device, &match_spec, prio++, &entry_hdl);

    // bridge = miss, pkt_type = multicast, igmp/mld snooping disabled
    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.l2_metadata_lkp_pkt_type = SWITCH_VLAN_FLOOD_UMC;
    match_spec.l2_metadata_lkp_pkt_type_mask = 0xff;
    match_spec.l3_metadata_lkp_ip_type = SWITCH_IP_TYPE_IPv4;
    match_spec.l3_metadata_lkp_ip_type_mask = 0xff;
    status = p4_pd_dc_fwd_result_table_add_with_set_multicast_flood(
        g_sess_hdl, p4_pd_device, &match_spec, prio++, &entry_hdl);

    // bridge = miss, pkt_type = multicast, igmp/mld snooping disabled
    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.l2_metadata_lkp_pkt_type = SWITCH_VLAN_FLOOD_UMC;
    match_spec.l2_metadata_lkp_pkt_type_mask = 0xff;
    match_spec.l3_metadata_lkp_ip_type = SWITCH_IP_TYPE_IPv6;
    match_spec.l3_metadata_lkp_ip_type_mask = 0xff;
    status = p4_pd_dc_fwd_result_table_add_with_set_multicast_flood(
        g_sess_hdl, p4_pd_device, &match_spec, prio++, &entry_hdl);
#endif /* P4_MULTICAST_DISABLE */
    (void)prio;

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_learn_notify_table_add_init_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef L2_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_learn_notify_match_spec_t match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    // add default entry
    status = p4_pd_dc_learn_notify_set_default_action_nop(g_sess_hdl,
                                                          p4_pd_device,
                                                          &entry_hdl);

    // stp_state == none and l2 src miss
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_l2_src_miss = 1;
    match_spec.l2_metadata_l2_src_miss_mask = 1;
    match_spec.l2_metadata_stp_state = SWITCH_PORT_STP_STATE_NONE;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_generate_learn_notify(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        900,
        &entry_hdl);

    // stp_state == disabled and l2 src miss
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_l2_src_miss = 1;
    match_spec.l2_metadata_l2_src_miss_mask = 1;
    match_spec.l2_metadata_stp_state = SWITCH_PORT_STP_STATE_DISABLED;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_generate_learn_notify(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        901,
        &entry_hdl);

    // stp_state == learning and l2 src miss
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_l2_src_miss = 1;
    match_spec.l2_metadata_l2_src_miss_mask = 1;
    match_spec.l2_metadata_stp_state = SWITCH_PORT_STP_STATE_LEARNING;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_generate_learn_notify(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        902,
        &entry_hdl);

    // stp_state == forwarding and l2 src miss
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_l2_src_miss = 1;
    match_spec.l2_metadata_l2_src_miss_mask = 1;
    match_spec.l2_metadata_stp_state = SWITCH_PORT_STP_STATE_FORWARDING;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_generate_learn_notify(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        903,
        &entry_hdl);

    // stp_state == none and l2 src move
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_l2_src_move = 0;
    match_spec.l2_metadata_l2_src_move_mask = 0xFFFF;
    match_spec.l2_metadata_stp_state = SWITCH_PORT_STP_STATE_NONE;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_nop(g_sess_hdl,
                                                           p4_pd_device,
                                                           &match_spec,
                                                           1000,
                                                           &entry_hdl);
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_stp_state = SWITCH_PORT_STP_STATE_NONE;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_generate_learn_notify(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        1001,
        &entry_hdl);

    // stp_state == disabled and l2 src move
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_l2_src_move = 0;
    match_spec.l2_metadata_l2_src_move_mask = 0xFFFF;
    match_spec.l2_metadata_stp_state = SWITCH_PORT_STP_STATE_DISABLED;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_nop(g_sess_hdl,
                                                           p4_pd_device,
                                                           &match_spec,
                                                           1002,
                                                           &entry_hdl);
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_stp_state = SWITCH_PORT_STP_STATE_DISABLED;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_generate_learn_notify(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        1003,
        &entry_hdl);

    // stp_state == learning and l2 src move
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_l2_src_move = 0;
    match_spec.l2_metadata_l2_src_move_mask = 0xFFFF;
    match_spec.l2_metadata_stp_state = SWITCH_PORT_STP_STATE_LEARNING;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_nop(g_sess_hdl,
                                                   p4_pd_device,
                                                   &match_spec,
                                                   1004,
                                                   &entry_hdl);
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_stp_state = SWITCH_PORT_STP_STATE_LEARNING;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_generate_learn_notify(
                                                    g_sess_hdl,
                                                    p4_pd_device,
                                                    &match_spec,
                                                    1005,
                                                    &entry_hdl);

    // stp_state == forwarding and l2 src move
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_l2_src_move = 0;
    match_spec.l2_metadata_l2_src_move_mask = 0xFFFF;
    match_spec.l2_metadata_stp_state = SWITCH_PORT_STP_STATE_FORWARDING;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_nop(g_sess_hdl,
                                                      p4_pd_device,
                                                      &match_spec,
                                                      1006,
                                                      &entry_hdl);
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_stp_state = SWITCH_PORT_STP_STATE_FORWARDING;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_generate_learn_notify(
                                                      g_sess_hdl,
                                                      p4_pd_device,
                                                      &match_spec,
                                                      1007,
                                                      &entry_hdl);

    p4_pd_complete_operations(g_sess_hdl);
#endif
    return status;
}

p4_pd_status_t
switch_pd_validate_outer_ethernet_table_init_entry(switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;
    p4_pd_dc_validate_outer_ethernet_match_spec_t match_spec;
    p4_pd_dc_malformed_outer_ethernet_packet_action_spec_t action_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    /* mac sa is zeros */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ethernet_match_spec_t));
    memset(&action_spec, 0,
           sizeof(p4_pd_dc_malformed_outer_ethernet_packet_action_spec_t));
    match_spec.l2_metadata_lkp_mac_sa_mask[0] = 0xff;
    match_spec.l2_metadata_lkp_mac_sa_mask[1] = 0xff;
    match_spec.l2_metadata_lkp_mac_sa_mask[2] = 0xff;
    match_spec.l2_metadata_lkp_mac_sa_mask[3] = 0xff;
    match_spec.l2_metadata_lkp_mac_sa_mask[4] = 0xff;
    match_spec.l2_metadata_lkp_mac_sa_mask[5] = 0xff;
    action_spec.action_drop_reason = DROP_OUTER_SRC_MAC_ZERO;
    status = p4_pd_dc_validate_outer_ethernet_table_add_with_malformed_outer_ethernet_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        10,
        &action_spec,
        &entry_hdl);

    /* mac sa is multicast */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ethernet_match_spec_t));
    memset(&action_spec, 0,
           sizeof(p4_pd_dc_malformed_outer_ethernet_packet_action_spec_t));
    match_spec.l2_metadata_lkp_mac_sa[0] = 0x01;
    match_spec.l2_metadata_lkp_mac_sa_mask[0] = 0x01;
    action_spec.action_drop_reason = DROP_OUTER_SRC_MAC_MULTICAST;
    status = p4_pd_dc_validate_outer_ethernet_table_add_with_malformed_outer_ethernet_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        11,
        &action_spec,
        &entry_hdl);

    /* mac da is zeros */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ethernet_match_spec_t));
    memset(&action_spec, 0,
           sizeof(p4_pd_dc_malformed_outer_ethernet_packet_action_spec_t));
    match_spec.l2_metadata_lkp_mac_da_mask[0] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[1] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[2] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[3] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[4] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[5] = 0xff;
    action_spec.action_drop_reason = DROP_OUTER_DST_MAC_ZERO;
    status = p4_pd_dc_validate_outer_ethernet_table_add_with_malformed_outer_ethernet_packet(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        12,
        &action_spec,
        &entry_hdl);

    /* double tagged broadcast */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ethernet_match_spec_t));
    match_spec.l2_metadata_lkp_mac_da[0] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[1] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[2] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[3] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[4] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[5] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[0] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[1] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[2] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[3] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[4] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[5] = 0xff;
    match_spec.vlan_tag__0__valid = 1;
    match_spec.vlan_tag__1__valid = 1;
    status = p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_broadcast_packet_double_tagged(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        1000,
        &entry_hdl);

    /* double tagged multicast */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ethernet_match_spec_t));
    match_spec.l2_metadata_lkp_mac_da[0] = 0x01;
    match_spec.l2_metadata_lkp_mac_da_mask[0] = 0x01;
    match_spec.vlan_tag__0__valid = 1;
    match_spec.vlan_tag__1__valid = 1;
    status = p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_multicast_packet_double_tagged(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        1001,
        &entry_hdl);

    /* double tagged unicast */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ethernet_match_spec_t));
    match_spec.vlan_tag__0__valid = 1;
    match_spec.vlan_tag__1__valid = 1;
    status = p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_unicast_packet_double_tagged(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        1002,
        &entry_hdl);

    /* single tagged broadcast */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ethernet_match_spec_t));
    match_spec.l2_metadata_lkp_mac_da[0] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[1] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[2] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[3] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[4] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[5] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[0] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[1] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[2] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[3] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[4] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[5] = 0xff;
    match_spec.vlan_tag__0__valid = 1;
    match_spec.vlan_tag__1__valid = 0;
    status = p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_broadcast_packet_single_tagged(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        2000,
        &entry_hdl);

    /* single tagged multicast */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ethernet_match_spec_t));
    match_spec.l2_metadata_lkp_mac_da[0] = 0x01;
    match_spec.l2_metadata_lkp_mac_da_mask[0] = 0x01;
    match_spec.vlan_tag__0__valid = 1;
    match_spec.vlan_tag__1__valid = 0;
    status = p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_multicast_packet_single_tagged(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        2001,
        &entry_hdl);

    /* single tagged unicast */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ethernet_match_spec_t));
    match_spec.vlan_tag__0__valid = 1;
    match_spec.vlan_tag__1__valid = 0;
    status = p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_unicast_packet_single_tagged(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        2002,
        &entry_hdl);

    /* untagged packet broadcast */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ethernet_match_spec_t));
    match_spec.l2_metadata_lkp_mac_da[0] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[1] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[2] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[3] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[4] = 0xff;
    match_spec.l2_metadata_lkp_mac_da[5] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[0] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[1] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[2] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[3] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[4] = 0xff;
    match_spec.l2_metadata_lkp_mac_da_mask[5] = 0xff;
    match_spec.vlan_tag__0__valid = 0;
    match_spec.vlan_tag__1__valid = 0;
    status = p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_broadcast_packet_untagged(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        3000,
        &entry_hdl);

    /* untagged packet multicast */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ethernet_match_spec_t));
    match_spec.l2_metadata_lkp_mac_da[0] = 0x01;
    match_spec.l2_metadata_lkp_mac_da_mask[0] = 0x01;
    match_spec.vlan_tag__0__valid = 0;
    match_spec.vlan_tag__1__valid = 0;
    status = p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_multicast_packet_untagged(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        3001,
        &entry_hdl);

    /* untagged packet unicast */
    memset(&match_spec, 0,
           sizeof(p4_pd_dc_validate_outer_ethernet_match_spec_t));
    match_spec.vlan_tag__0__valid = 0;
    match_spec.vlan_tag__1__valid = 0;
    status = p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_unicast_packet_untagged(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        3002,
        &entry_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_vlan_decap_table_init_entry(switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;
    p4_pd_dc_vlan_decap_match_spec_t match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_vlan_decap_match_spec_t));
    match_spec.vlan_tag__0__valid = 1;
    match_spec.vlan_tag__1__valid = 0;
    status = p4_pd_dc_vlan_decap_table_add_with_remove_vlan_single_tagged(
                                                            g_sess_hdl,
                                                            p4_pd_device,
                                                            &match_spec,
                                                            &entry_hdl);

    memset(&match_spec, 0, sizeof(p4_pd_dc_vlan_decap_match_spec_t));
    match_spec.vlan_tag__0__valid = 1;
    match_spec.vlan_tag__1__valid = 1;
    status = p4_pd_dc_vlan_decap_table_add_with_remove_vlan_double_tagged(
                                                            g_sess_hdl,
                                                            p4_pd_device,
                                                            &match_spec,
                                                            &entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_validate_mpls_packet_table_init_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#if !defined(P4_TUNNEL_DISABLE) && !defined(P4_MPLS_DISABLE)
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    uint16_t priority = 1;
    p4_pd_dc_validate_mpls_packet_match_spec_t match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    priority++;
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_mpls_packet_match_spec_t));
    match_spec.mpls_0__valid = 0x1;
    match_spec.mpls_1__valid = 0x1;
    match_spec.mpls_2__valid = 0x1;
    status = p4_pd_dc_validate_mpls_packet_table_add_with_set_valid_mpls_label1(
                                                           g_sess_hdl,
                                                           p4_pd_device,
                                                           &match_spec,
                                                           priority,
                                                           &entry_hdl);


    priority++;
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_mpls_packet_match_spec_t));
    match_spec.mpls_0__valid = 0x1;
    match_spec.mpls_1__valid = 0x1;
    match_spec.mpls_2__valid = 0x1;
    match_spec.mpls_2__bos = 0x1;
    match_spec.mpls_2__bos_mask = 0x1;
    status = p4_pd_dc_validate_mpls_packet_table_add_with_set_valid_mpls_label1(
                                                           g_sess_hdl,
                                                           p4_pd_device,
                                                           &match_spec,
                                                           priority,
                                                           &entry_hdl);

    priority++;
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_mpls_packet_match_spec_t));
    match_spec.mpls_0__valid = 0x1;
    match_spec.mpls_1__valid = 0x1;
    match_spec.mpls_1__bos = 0x1;
    match_spec.mpls_1__bos_mask = 0x1;
    status = p4_pd_dc_validate_mpls_packet_table_add_with_set_valid_mpls_label1(
                                                           g_sess_hdl,
                                                           p4_pd_device,
                                                           &match_spec,
                                                           priority,
                                                           &entry_hdl);

    priority++;
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_mpls_packet_match_spec_t));
    match_spec.mpls_0__valid = 0x1;
    match_spec.mpls_0__bos = 0x1;
    match_spec.mpls_0__bos_mask = 0x1;
    status = p4_pd_dc_validate_mpls_packet_table_add_with_set_valid_mpls_label1(
                                                           g_sess_hdl,
                                                           p4_pd_device,
                                                           &match_spec,
                                                           priority,
                                                           &entry_hdl);

#endif /* !defined(P4_TUNNEL_DISABLE) && !defined(P4_MPLS_DISABLE) */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_fabric_header_table_init_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifdef FABRIC_ENABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_mbr_hdl_t mbr_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_fabric_lag_action_profile_add_member_with_nop(
                                                            g_sess_hdl,
                                                            p4_pd_device,
                                                            &mbr_hdl);
    status = p4_pd_dc_fabric_lag_set_default_entry(g_sess_hdl,
                                                   p4_pd_device,
                                                   mbr_hdl,
                                                   &entry_hdl);
#endif /* FABRIC_ENABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_egress_port_mapping_table_init_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status =
        p4_pd_dc_egress_port_mapping_set_default_action_egress_port_type_normal(
            g_sess_hdl,
            p4_pd_device,
            &entry_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_compute_hashes_init_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_compute_ipv4_hashes_set_default_action_compute_lkp_ipv4_hash(
            g_sess_hdl, p4_pd_device, &entry_hdl);
#ifndef P4_IPV6_DISABLE
    status = p4_pd_dc_compute_ipv6_hashes_set_default_action_compute_lkp_ipv6_hash(
            g_sess_hdl, p4_pd_device, &entry_hdl);
#endif /* P4_IPV6_DISABLE */
    status = p4_pd_dc_compute_non_ip_hashes_set_default_action_compute_lkp_non_ip_hash(
            g_sess_hdl, p4_pd_device, &entry_hdl);

    p4_pd_dc_compute_other_hashes_match_spec_t match_spec_other;
    memset(&match_spec_other, 0, sizeof(match_spec_other));
    match_spec_other.hash_metadata_hash1 = 0;
    status = p4_pd_dc_compute_other_hashes_table_add_with_computed_one_hash(
        g_sess_hdl, p4_pd_device, &match_spec_other, &entry_hdl);
    status = p4_pd_dc_compute_other_hashes_set_default_action_computed_two_hashes(
            g_sess_hdl, p4_pd_device, &entry_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_replica_type_table_init_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_MULTICAST_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    p4_pd_dc_replica_type_match_spec_t match_spec;
    memset(&match_spec, 0, sizeof(match_spec));

    match_spec.multicast_metadata_replica = 0x1;
    match_spec.egress_metadata_same_bd_check = 0;
    match_spec.egress_metadata_same_bd_check_mask = 0xFFFF;

    status = p4_pd_dc_replica_type_table_add_with_set_replica_copy_bridged(
        g_sess_hdl, p4_pd_device, &match_spec, 100, &entry_hdl);
#endif /* P4_MULTICAST_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_rewrite_multicast_table_init_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_rewrite_multicast_match_spec_t match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

#ifndef P4_MULTICAST_DISABLE
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.ipv4_valid = 0x1;
    match_spec.ipv6_valid = 0x0;
    match_spec.ipv4_dstAddr = 0xe0000000;
    match_spec.ipv4_dstAddr_mask = 0xf0000000;
    status = p4_pd_dc_rewrite_multicast_table_add_with_rewrite_ipv4_multicast(
        g_sess_hdl, p4_pd_device, &match_spec, 100, &entry_hdl);
#else
    (void)entry_hdl; (void)p4_pd_device; (void)match_spec;
#endif

#if !defined(P4_IPV6_DISABLE) && !defined(P4_MULTICAST_DISABLE)
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.ipv4_valid = 0x0;
    match_spec.ipv6_valid = 0x1;
    match_spec.ipv6_dstAddr[0] = 0xff;
    match_spec.ipv6_dstAddr_mask[0] = 0xff;
    status = p4_pd_dc_rewrite_multicast_table_add_with_rewrite_ipv6_multicast(
        g_sess_hdl, p4_pd_device, &match_spec, 101, &entry_hdl);
#endif /* P4_IPV6_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_l3_rewrite_table_init_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_l3_rewrite_match_spec_t match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

#ifndef P4_MULTICAST_DISABLE
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.ipv4_valid = 0x1;
    match_spec.ipv4_dstAddr = 0xe0000000;
    match_spec.ipv4_dstAddr_mask = 0xf0000000;
    status = p4_pd_dc_l3_rewrite_table_add_with_ipv4_multicast_rewrite(
        g_sess_hdl, p4_pd_device, &match_spec, 100, &entry_hdl);
#endif /* P4_MULTICAST_DISABLE */

    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.ipv4_valid = 0x1;
    status = p4_pd_dc_l3_rewrite_table_add_with_ipv4_unicast_rewrite(
        g_sess_hdl, p4_pd_device, &match_spec, 101, &entry_hdl);

#if !defined(P4_IPV6_DISABLE) && !defined(P4_MULTICAST_DISABLE)
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.ipv6_valid = 0x1;
    match_spec.ipv6_dstAddr[0] = 0xff;
    match_spec.ipv6_dstAddr_mask[0] = 0xff;
    status = p4_pd_dc_l3_rewrite_table_add_with_ipv6_multicast_rewrite(
        g_sess_hdl, p4_pd_device, &match_spec, 200, &entry_hdl);

    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.ipv6_valid = 0x1;
    status = p4_pd_dc_l3_rewrite_table_add_with_ipv6_unicast_rewrite(
        g_sess_hdl, p4_pd_device, &match_spec, 201, &entry_hdl);
#endif /* !P4_IPV6_DISABLE && !P4_MULTICAST_DISABLE */

#ifndef P4_MPLS_DISABLE
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.mpls_0__valid = 0x1;
    status = p4_pd_dc_l3_rewrite_table_add_with_mpls_rewrite(
        g_sess_hdl, p4_pd_device, &match_spec, 300, &entry_hdl);
#endif /* P4_MPLS_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_vlan_ingress_stats_get(switch_device_t device, switch_bd_stats_t *bd_stats)
{
    p4_pd_status_t status = 0;
#ifndef P4_STATS_DISABLE
    p4_pd_counter_value_t counter;
    p4_pd_dev_target_t p4_pd_device;
    int index = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    for (index = 0; index < SWITCH_VLAN_STATS_OUT_UCAST; index++) {
        counter = p4_pd_dc_counter_read_ingress_bd_stats(
                                                 g_sess_hdl,
                                                 p4_pd_device,
                                                 bd_stats->stats_idx[index],
                                                 COUNTER_READ_HW_SYNC);
        bd_stats->counters[index].num_packets = counter.packets;
        bd_stats->counters[index].num_bytes = counter.bytes;
    }
#endif /* P4_STATS_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_vlan_egress_stats_get(switch_device_t device, switch_bd_stats_t *bd_stats)
{
    p4_pd_status_t status = 0;
#ifndef P4_STATS_DISABLE
    p4_pd_counter_value_t counter;
    p4_pd_dev_target_t p4_pd_device;
    int index = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    for (index = 0; index < 3; index++) {
        counter = p4_pd_dc_counter_read_egress_bd_stats(
                                                 g_sess_hdl,
                                                 p4_pd_device,
                                                 bd_stats->stats_hw_entry[index],
                                                 COUNTER_READ_HW_SYNC);
        bd_stats->counters[index + SWITCH_VLAN_STATS_OUT_UCAST].num_packets = counter.packets;
        bd_stats->counters[index + SWITCH_VLAN_STATS_OUT_UCAST].num_bytes = counter.bytes;
    }
#endif /* P4_STATS_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_drop_stats_get(switch_device_t device, int num_counters,
                         uint64_t *counters)
{
    p4_pd_status_t status = 0;
#ifndef P4_STATS_DISABLE
    p4_pd_counter_value_t counter;
    p4_pd_dev_target_t p4_pd_device;
    int index = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    for (index = 0; index < num_counters; index++) {
        counter = p4_pd_dc_counter_read_drop_stats(g_sess_hdl,
                                                   p4_pd_device,
                                                   index,
                                                   COUNTER_READ_HW_SYNC);
        *(counters + index) = counter.packets;
        counter = p4_pd_dc_counter_read_drop_stats_2(g_sess_hdl,
                                                     p4_pd_device,
                                                     index,
                                                     COUNTER_READ_HW_SYNC);
        *(counters + index) += counter.packets;
    }
#endif /* P4_STATS_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_meter_stats_get(switch_device_t device, switch_meter_info_t *meter_info)
{
    p4_pd_status_t status = 0;
#if !defined(P4_METER_DISABLE) && !defined(P4_STATS_DISABLE)
    p4_pd_counter_value_t counter;
    p4_pd_dev_target_t p4_pd_device;
    int index = 0;
    switch_meter_stats_info_t *stats_info = NULL;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    stats_info = meter_info->stats_info;

    for (index = 0; index < SWITCH_METER_COLOR_MAX; index++) {
        counter = p4_pd_dc_counter_read_meter_stats(
                                                 g_sess_hdl,
                                                 p4_pd_device,
                                                 meter_info->action_pd_hdl[index],
                                                 COUNTER_READ_HW_SYNC);
        stats_info->counters[index].num_packets = counter.packets;
        stats_info->counters[index].num_bytes = counter.bytes;
    }
#endif /* P4_METER_DISABLE && P4_STATS_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_storm_control_stats_get(switch_device_t device, switch_meter_info_t *meter_info)
{
    p4_pd_status_t status = 0;
#ifndef P4_STATS_DISABLE
    p4_pd_counter_value_t counter;
    p4_pd_dev_target_t p4_pd_device;
    int index = 0;
    switch_meter_stats_info_t *stats_info = NULL;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    stats_info = meter_info->stats_info;

    for (index = 0; index < SWITCH_METER_STATS_MAX; index++) {
        counter = p4_pd_dc_counter_read_storm_control_stats(
                                                 g_sess_hdl,
                                                 p4_pd_device,
                                                 meter_info->action_pd_hdl[index],
                                                 COUNTER_READ_HW_SYNC);
        stats_info->counters[index].num_packets = counter.packets;
        stats_info->counters[index].num_bytes = counter.bytes;
    }
#endif /* P4_STATS_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_acl_stats_get(switch_device_t device,
                        uint16_t acl_stats_index,
                        switch_counter_t *acl_counter)
{
    p4_pd_status_t status = 0;
#ifndef P4_STATS_DISABLE
    p4_pd_counter_value_t counter;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    counter = p4_pd_dc_counter_read_acl_stats(
                                             g_sess_hdl,
                                             p4_pd_device,
                                             acl_stats_index,
                                             COUNTER_READ_HW_SYNC);
    acl_counter->num_packets = counter.packets;
    acl_counter->num_bytes = counter.bytes;
#endif /* P4_STATS_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

/* Mirror session manager APIs */

// conversion utils
p4_pd_mirror_type_e
switch_pd_p4_pd_mirror_type(switch_mirror_session_type_t type)
{
    p4_pd_mirror_type_e pd_mirror_type = 0;
    switch (type)
    {
        case SWITCH_MIRROR_SESSION_TYPE_SIMPLE:
            pd_mirror_type = PD_MIRROR_TYPE_NORM;
            break;
        case SWITCH_MIRROR_SESSION_TYPE_COALESCE:
            pd_mirror_type = PD_MIRROR_TYPE_COAL;
            break;
        case SWITCH_MIRROR_SESSION_TYPE_TRUNCATE:
        default:
            pd_mirror_type = PD_MIRROR_TYPE_MAX;
            break;
    }
    return pd_mirror_type;
}

p4_pd_direction_t
switch_pd_p4_pd_direction(switch_direction_t dir)
{
    switch(dir) {
        case SWITCH_API_DIRECTION_BOTH: return PD_DIR_BOTH;
        case SWITCH_API_DIRECTION_INGRESS: return PD_DIR_INGRESS;
        case SWITCH_API_DIRECTION_EGRESS: return PD_DIR_EGRESS;
        default: break;
    }
    return PD_DIR_NONE;
}

p4_pd_status_t
switch_pd_mirror_session_update(switch_device_t device,
                                switch_handle_t mirror_handle,
                                switch_mirror_info_t *mirror_info)
{
    p4_pd_status_t  status = 0;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;
    switch_api_mirror_info_t *api_mirror_info = NULL;

    api_mirror_info = &mirror_info->api_mirror_info;
    status = p4_pd_dc_mirror_session_update(g_sess_hdl, p4_pd_device,
                                switch_pd_p4_pd_mirror_type(api_mirror_info->session_type),
                                switch_pd_p4_pd_direction(api_mirror_info->direction),
                                handle_to_id(mirror_handle),
                                handle_to_id(api_mirror_info->egress_port),
                                api_mirror_info->max_pkt_len,
                                api_mirror_info->cos,
                                false, /*c2c*/
                                api_mirror_info->extract_len,
                                api_mirror_info->timeout_usec,
                                (uint32_t *)&mirror_info->pkt_hdr,
                                mirror_info->hdr_len,
                                api_mirror_info->enable);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mirror_session_delete(switch_device_t device,
                                switch_handle_t mirror_handle)
{
    p4_pd_status_t  status = 0;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    status = p4_pd_dc_mirror_session_delete(g_sess_hdl,
                                            p4_pd_device,
                                            handle_to_id(mirror_handle));

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mirror_table_entry_add(switch_device_t device,
                             switch_handle_t mirror_handle,
                             switch_mirror_info_t *mirror_info)
{
    p4_pd_status_t  status = 0;
    p4_pd_dc_mirror_match_spec_t match_spec;
    p4_pd_dev_target_t p4_pd_device;
    switch_api_mirror_info_t *api_mirror_info = NULL;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    match_spec.i2e_metadata_mirror_session_id = handle_to_id(mirror_handle);
    api_mirror_info = &mirror_info->api_mirror_info;

    switch (api_mirror_info->mirror_type) {
        case SWITCH_MIRROR_TYPE_LOCAL:
            break;
        case SWITCH_MIRROR_TYPE_REMOTE:
            {
                p4_pd_dc_set_mirror_bd_action_spec_t action_spec;
                action_spec.action_bd = handle_to_id(mirror_info->vlan_handle);
                status = p4_pd_dc_mirror_table_add_with_set_mirror_bd(g_sess_hdl,
                                       p4_pd_device, &match_spec, &action_spec,
                                       &mirror_info->pd_hdl);
            }
            break;
        case SWITCH_MIRROR_TYPE_ENHANCED_REMOTE:
            {
                p4_pd_dc_set_mirror_nhop_action_spec_t action_spec;
                action_spec.action_nhop_idx = handle_to_id(api_mirror_info->nhop_handle);
                status = p4_pd_dc_mirror_table_add_with_set_mirror_nhop(g_sess_hdl,
                                       p4_pd_device, &match_spec, &action_spec,
                                       &mirror_info->pd_hdl);
            }
            break;

        default:
            break;
    }

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mirror_table_entry_delete(switch_device_t device,
                             switch_mirror_info_t *mirror_info)
{
    p4_pd_status_t  status = 0;

    status = p4_pd_dc_mirror_table_delete(g_sess_hdl, device,
                mirror_info->pd_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_mirror_table_add_default_entry(switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    status = p4_pd_dc_mirror_set_default_action_nop(g_sess_hdl,
                                                    p4_pd_device,
                                                    &entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_mtu_table_add_default_entry(switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    status = p4_pd_dc_mtu_set_default_action_mtu_miss(g_sess_hdl,
                                                      p4_pd_device,
                                                      &entry_hdl);
    status = p4_pd_dc_tunnel_mtu_set_default_action_tunnel_mtu_miss(
        g_sess_hdl, p4_pd_device, &entry_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_l3_rewrite_table_add_default_entry(switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    status = p4_pd_dc_l3_rewrite_set_default_action_nop(g_sess_hdl,
                                                        p4_pd_device,
                                                        &entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_neg_mirror_add_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#if !defined(P4_ACL_DISABLE)
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    // create an entry for negative mirroring
    // Key: egr_port = 0, deflection_flag = 1
    p4_pd_dc_egress_acl_match_spec_t match_spec;
    memset(&match_spec, 0, sizeof(p4_pd_dc_egress_acl_match_spec_t));
    match_spec.intrinsic_metadata_deflection_flag =  0x1;
    match_spec.intrinsic_metadata_deflection_flag_mask =  0xFF;

    // Action: egress_mirror_drop
    p4_pd_dc_egress_mirror_drop_action_spec_t action_spec;
    action_spec.action_session_id = SWITCH_NEGATIVE_MIRROR_SESSION_ID;

    status = p4_pd_dc_egress_acl_table_add_with_egress_mirror_drop(
        g_sess_hdl, p4_pd_device, &match_spec, 0, /* highest priority */
        &action_spec, &entry_hdl);
#endif

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

#ifdef P4_INT_EP_ENABLE
static int bit_count_array[16]={0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4};
static int
_bit_count(uint64_t val)
{
    int i, count;
    count =0;
    i= 0;
    while (i < (int)sizeof(val)*2) {
        count += bit_count_array[val & 0xF];
        val >>= 4;
        i++;
    }
    return count;
}
#endif

#ifdef P4_INT_TRANSIT_ENABLE
p4_pd_status_t
switch_pd_int_transit_enable(switch_device_t device, int32_t switch_id,
            int32_t prio, p4_pd_entry_hdl_t *entry_hdl)
{
    // supports only vxlan-GPE. Add more underlay encap later
    p4_pd_dc_int_insert_match_spec_t    match_spec;
    p4_pd_dc_int_transit_action_spec_t  action_spec;
    p4_pd_dev_target_t                  p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    match_spec.int_metadata_i2e_source = 0;
    match_spec.int_metadata_i2e_source_mask = (uint8_t)-1;
    match_spec.int_metadata_i2e_sink = 0;
    match_spec.int_metadata_i2e_sink_mask = (uint8_t)-1;
    match_spec.int_header_valid = 1;

    action_spec.action_switch_id = switch_id;

    (void) prio; // remove
    status = p4_pd_dc_int_insert_table_add_with_int_transit(g_sess_hdl,
                                p4_pd_device, &match_spec, 0,
                                &action_spec, entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_int_transit_disable(switch_device_t device,
                                p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
    status = p4_pd_dc_int_insert_table_delete(g_sess_hdl, device, entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}
#endif

#ifdef P4_INT_EP_ENABLE
p4_pd_status_t
switch_pd_int_src_enable(switch_device_t device, int32_t switch_id,
            switch_ip_addr_t *src,
            switch_ip_addr_t *dst,
            uint8_t hop_cnt, uint16_t ins_mask,
            int32_t prio, p4_pd_entry_hdl_t *entry_hdl, bool vtep_src)
{
    // currently assume vxlan-GPE as underlay,
    // Program two tables - int_source and int_insert
    // ip addresses are client IP addresses
    p4_pd_dc_int_insert_match_spec_t            insert_match_spec;
    p4_pd_dc_int_src_action_spec_t              insert_action_spec;

    p4_pd_dc_int_source_match_spec_t            src_match_spec;

    p4_pd_dev_target_t                          p4_pd_device;
    int                                         ins_cnt;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    insert_match_spec.int_metadata_i2e_source = 1;
    insert_match_spec.int_metadata_i2e_source_mask = (uint8_t)-1;
    insert_match_spec.int_metadata_i2e_sink = 0;
    insert_match_spec.int_metadata_i2e_sink_mask = (uint8_t)-1;
    insert_match_spec.int_header_valid = 0;

    insert_action_spec.action_switch_id = switch_id;
    insert_action_spec.action_hop_cnt = hop_cnt;
    insert_action_spec.action_ins_mask0003 = (ins_mask >> 12) & 0xF;
    insert_action_spec.action_ins_mask0407 = (ins_mask >> 8) & 0xF;
    ins_cnt = _bit_count((uint64_t)ins_mask);
    insert_action_spec.action_ins_cnt = ins_cnt;
    insert_action_spec.action_ins_byte_cnt = (ins_cnt * 4) + 12; // 12 for headers
    insert_action_spec.action_total_words =
                            (insert_action_spec.action_ins_byte_cnt / 4);

    status = p4_pd_dc_int_insert_table_add_with_int_src(g_sess_hdl,
                                p4_pd_device, &insert_match_spec, 0,
                                &insert_action_spec, entry_hdl);

    if (status) {
        p4_pd_complete_operations(g_sess_hdl);
        return status;
    }
    // make sure upstream device has not already added INT info
    src_match_spec.int_header_valid = 0;
    if (vtep_src) {
        // use outer(no inner present) addrs since frame is not encapped yet
        src_match_spec.ipv4_valid = 1;
        src_match_spec.ipv4_metadata_lkp_ipv4_sa = src->ip.v4addr;
        src_match_spec.ipv4_metadata_lkp_ipv4_sa_mask = (uint32_t)-1;

        src_match_spec.ipv4_metadata_lkp_ipv4_da = dst->ip.v4addr;
        src_match_spec.ipv4_metadata_lkp_ipv4_da_mask = (uint32_t)-1;
        // inner are not valid
        src_match_spec.inner_ipv4_valid = 0;
        src_match_spec.inner_ipv4_srcAddr = 0;
        src_match_spec.inner_ipv4_srcAddr_mask = 0; // ignore
        src_match_spec.inner_ipv4_dstAddr = 0;
        src_match_spec.inner_ipv4_dstAddr_mask = 0; // ignore
    } else {
        // use inner addr since frame is already encapped upstream
        src_match_spec.ipv4_valid = 1;
        src_match_spec.ipv4_metadata_lkp_ipv4_sa = 0;
        src_match_spec.ipv4_metadata_lkp_ipv4_sa_mask = 0;   // ignore
        src_match_spec.ipv4_metadata_lkp_ipv4_da = 0;
        src_match_spec.ipv4_metadata_lkp_ipv4_da_mask = 0;   // ignore
        // inner are not valid
        src_match_spec.inner_ipv4_valid = 1;
        src_match_spec.inner_ipv4_srcAddr = src->ip.v4addr;
        src_match_spec.inner_ipv4_srcAddr_mask = (uint32_t)-1;
        src_match_spec.inner_ipv4_dstAddr = dst->ip.v4addr;
        src_match_spec.inner_ipv4_dstAddr_mask = (uint32_t)-1;
    }

    // cleanup on failure - TBD
    status = p4_pd_dc_int_source_table_add_with_int_set_src (g_sess_hdl,
                                p4_pd_device, &src_match_spec, prio,
                                entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}
#endif

#ifdef P4_INT_EP_ENABLE
p4_pd_status_t
switch_pd_int_sink_enable(switch_device_t device,
            switch_ip_addr_t *dst,
            uint32_t mirror_id,
            int32_t prio, p4_pd_entry_hdl_t *entry_hdl, bool use_client_ip)
{
    // XXX currently assume vxlan-GPE, need underlay-type parameter
    p4_pd_dc_int_terminate_match_spec_t         match_spec;
    p4_pd_dc_int_sink_gpe_action_spec_t         action_spec;
    p4_pd_dev_target_t                          p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    match_spec.int_header_valid = 1;
    match_spec.vxlan_gpe_int_header_valid = 1;
    if (use_client_ip) {
        match_spec.inner_ipv4_valid = 1;
        match_spec.inner_ipv4_dstAddr = dst->ip.v4addr;
        match_spec.inner_ipv4_dstAddr_mask = (uint32_t)-1;
        // ignore outer ips
        match_spec.ipv4_valid = 1;
        match_spec.ipv4_metadata_lkp_ipv4_da = 0;
        match_spec.ipv4_metadata_lkp_ipv4_da_mask = 0; // *
    } else {
        // ignore inner ip
        match_spec.inner_ipv4_valid = 1;
        match_spec.inner_ipv4_dstAddr = 0;
        match_spec.inner_ipv4_dstAddr_mask = 0; // *
        // use outer ips
        match_spec.ipv4_valid = 1;
        match_spec.ipv4_metadata_lkp_ipv4_da = dst->ip.v4addr;
        match_spec.ipv4_metadata_lkp_ipv4_da_mask =  (uint32_t)-1;
    }

    action_spec.action_mirror_id = mirror_id;

    status = p4_pd_dc_int_terminate_table_add_with_int_sink_gpe(g_sess_hdl,
                                p4_pd_device, &match_spec, prio,
                                &action_spec, entry_hdl);

    // program int_sink_update_outer table to remove and update any outer
    // headers
    {
        p4_pd_dc_int_sink_update_outer_match_spec_t   match_spec;

        match_spec.vxlan_gpe_int_header_valid = 1;
        match_spec.ipv4_valid = 1;
        match_spec.int_metadata_i2e_sink = 1;

        status = p4_pd_dc_int_sink_update_outer_table_add_with_int_sink_update_vxlan_gpe_v4(g_sess_hdl, p4_pd_device, &match_spec, entry_hdl);
    }

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}
#endif

#ifdef P4_INT_ENABLE
p4_pd_status_t
switch_pd_int_tables_init(switch_device_t device)
{
    p4_pd_entry_hdl_t                   entry_hdl;
    int                                 i;
    uint16_t                            key, mask;
    p4_pd_dev_target_t                  p4_pd_device;
    p4_pd_status_t                      status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

#ifdef P4_INT_EP_ENABLE
    // int_source Table
    p4_pd_dc_int_source_set_default_action_int_set_no_src(g_sess_hdl,
                                                    p4_pd_device, &entry_hdl);
    // int_terminate - default is no_terminate
    p4_pd_dc_int_terminate_set_default_action_int_no_sink(g_sess_hdl,
        p4_pd_device, &entry_hdl);

    // int_sink_update_outer
    p4_pd_dc_int_sink_update_outer_set_default_action_nop(g_sess_hdl,
                p4_pd_device, &entry_hdl);
#endif
    // int_insert - default :  do not insert INT information
    p4_pd_dc_int_insert_set_default_action_int_reset(g_sess_hdl, p4_pd_device,
                                                   &entry_hdl);
    // int_meta_header_update - increment total_cnt (default) on
    // successful addition of INT data. Else set E bit
    p4_pd_dc_int_meta_header_update_set_default_action_int_update_total_hop_cnt(
        g_sess_hdl, p4_pd_device, &entry_hdl);

    // int_meta_header_update - Set E bit if insert_cnt is 0
    {
        p4_pd_dc_int_meta_header_update_match_spec_t    match_spec;
        match_spec.int_metadata_insert_cnt = 0;
        match_spec.int_metadata_insert_cnt_mask = 0xFF;
        p4_pd_dc_int_meta_header_update_table_add_with_int_set_e_bit(
            g_sess_hdl, p4_pd_device, &match_spec, 0, &entry_hdl);
    }

    // INT encap - outer header update
    p4_pd_dc_int_outer_encap_set_default_action_nop (g_sess_hdl,
        p4_pd_device, &entry_hdl);
#ifdef P4_INT_TRANSIT_ENABLE
    {
        // Trasit
        p4_pd_dc_int_outer_encap_match_spec_t match_spec;

        match_spec.int_metadata_i2e_source = 0;
        match_spec.ipv4_valid = 1;
        match_spec.vxlan_gpe_valid = 1;
        match_spec.tunnel_metadata_egress_tunnel_type = 0;
        match_spec.tunnel_metadata_egress_tunnel_type_mask = 0; // *
        p4_pd_dc_int_outer_encap_table_add_with_int_update_vxlan_gpe_ipv4(
                        g_sess_hdl, p4_pd_device, &match_spec, 0, &entry_hdl);
    }
#endif
#ifdef P4_INT_EP_ENABLE
    {
        // INT source
        // create two entries to handle int src with and w/o vtep-src
        p4_pd_dc_int_outer_encap_match_spec_t    match_spec;
        match_spec.int_metadata_i2e_source = 1;
        match_spec.ipv4_valid = 1;
        match_spec.vxlan_gpe_valid = 1;     // VTEP is upstream
        // since this node is trasit for vxlan tunnel_type is not initialized
        // in the datapath
        match_spec.tunnel_metadata_egress_tunnel_type = 0;
        match_spec.tunnel_metadata_egress_tunnel_type_mask = 0; // *
        p4_pd_dc_int_outer_encap_table_add_with_int_add_update_vxlan_gpe_ipv4
                (g_sess_hdl, p4_pd_device, &match_spec, 0, &entry_hdl);

        // This node is VTEP src too
        match_spec.int_metadata_i2e_source = 1;
        match_spec.ipv4_valid = 1;
        match_spec.vxlan_gpe_valid = 0;
        match_spec.tunnel_metadata_egress_tunnel_type =
                                SWITCH_EGRESS_TUNNEL_TYPE_IPV4_VXLAN_GPE;
        match_spec.tunnel_metadata_egress_tunnel_type_mask = -1;
        p4_pd_dc_int_outer_encap_table_add_with_int_add_update_vxlan_gpe_ipv4
                        (g_sess_hdl, p4_pd_device, &match_spec, 0, &entry_hdl);
    }
#endif

    // int_inst_0003 int_inst_0407 int_inst_0811 int_inst_1215
    // Program all 16 entries with 16 unique actions for each
    // pattern in each table
    for (i=0; i<16; i++) {
        p4_pd_dc_int_inst_0003_match_spec_t match_0003_spec;
        switch (i) {
        case 0:
            match_0003_spec.int_header_instruction_mask_0003 = 0;
            p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i0(
                    g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
            break;

        case 1:
            match_0003_spec.int_header_instruction_mask_0003 = 1;
            p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i1(
                    g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
            break;

        case 2:
            match_0003_spec.int_header_instruction_mask_0003 = 2;
            p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i2(
                    g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
            break;

        case 3:
            match_0003_spec.int_header_instruction_mask_0003 = 3;
            p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i3(
                    g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
            break;

        case 4:
			match_0003_spec.int_header_instruction_mask_0003 = 4;
			p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i4(
					g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
			break;

        case 5:
			match_0003_spec.int_header_instruction_mask_0003 = 5;
			p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i5(
					g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
			break;

        case 6:
			match_0003_spec.int_header_instruction_mask_0003 = 6;
			p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i6(
					g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
			break;

        case 7:
			match_0003_spec.int_header_instruction_mask_0003 = 7;
			p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i7(
					g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
			break;

        case 8:
			match_0003_spec.int_header_instruction_mask_0003 = 8;
			p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i8(
					g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
			break;

        case 9:
			match_0003_spec.int_header_instruction_mask_0003 = 9;
			p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i9(
					g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
			break;

        case 10:
			match_0003_spec.int_header_instruction_mask_0003 = 10;
			p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i10(
					g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
			break;

        case 11:
			match_0003_spec.int_header_instruction_mask_0003 = 11;
			p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i11(
					g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
			break;

        case 12:
			match_0003_spec.int_header_instruction_mask_0003 = 12;
			p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i12(
					g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
			break;

        case 13:
			match_0003_spec.int_header_instruction_mask_0003 = 13;
			p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i13(
					g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
			break;

        case 14:
			match_0003_spec.int_header_instruction_mask_0003 = 14;
			p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i14(
					g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
			break;

        case 15:
			match_0003_spec.int_header_instruction_mask_0003 = 15;
			p4_pd_dc_int_inst_0003_table_add_with_int_set_header_0003_i15(
					g_sess_hdl, p4_pd_device, &match_0003_spec, &entry_hdl);
			break;
        }
    }
    for (i=0; i<16; i++) {
        p4_pd_dc_int_inst_0407_match_spec_t match_0407_spec;
        switch (i) {
        case 0:
            match_0407_spec.int_header_instruction_mask_0407 = 0;
            p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i0(
                    g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
            break;

        case 1:
            match_0407_spec.int_header_instruction_mask_0407 = 1;
            p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i1(
                    g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
            break;

        case 2:
            match_0407_spec.int_header_instruction_mask_0407 = 2;
            p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i2(
                    g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
            break;

        case 3:
            match_0407_spec.int_header_instruction_mask_0407 = 3;
            p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i3(
                    g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
            break;

        case 4:
			match_0407_spec.int_header_instruction_mask_0407 = 4;
			p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i4(
					g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
			break;

        case 5:
			match_0407_spec.int_header_instruction_mask_0407 = 5;
			p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i5(
					g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
			break;

        case 6:
			match_0407_spec.int_header_instruction_mask_0407 = 6;
			p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i6(
					g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
			break;

        case 7:
			match_0407_spec.int_header_instruction_mask_0407 = 7;
			p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i7(
					g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
			break;

        case 8:
			match_0407_spec.int_header_instruction_mask_0407 = 8;
			p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i8(
					g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
			break;

        case 9:
			match_0407_spec.int_header_instruction_mask_0407 = 9;
			p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i9(
					g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
			break;

        case 10:
			match_0407_spec.int_header_instruction_mask_0407 = 10;
			p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i10(
					g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
			break;

        case 11:
			match_0407_spec.int_header_instruction_mask_0407 = 11;
			p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i11(
					g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
			break;

        case 12:
			match_0407_spec.int_header_instruction_mask_0407 = 12;
			p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i12(
					g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
			break;

        case 13:
			match_0407_spec.int_header_instruction_mask_0407 = 13;
			p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i13(
					g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
			break;

        case 14:
			match_0407_spec.int_header_instruction_mask_0407 = 14;
			p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i14(
					g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
			break;

        case 15:
			match_0407_spec.int_header_instruction_mask_0407 = 15;
			p4_pd_dc_int_inst_0407_table_add_with_int_set_header_0407_i15(
					g_sess_hdl, p4_pd_device, &match_0407_spec, &entry_hdl);
			break;
        }
    }
    // bits 8-15 are not defined - not programmed - use default action
    p4_pd_dc_int_inst_0811_set_default_action_nop(g_sess_hdl, p4_pd_device,
                    &entry_hdl);
    p4_pd_dc_int_inst_1215_set_default_action_nop(g_sess_hdl, p4_pd_device,
                    &entry_hdl);
    p4_pd_dc_int_bos_set_default_action_nop(g_sess_hdl, p4_pd_device,
                    &entry_hdl);
    // Setup the table to set BOS bit on the last value
    // bits 8-15 are not defined in INT spec mask them off
    key = 0x8000; mask = 0xF000;
    for (i=0; i<16; i++) {
        // int_bos - set bos bit based on the last (least significant) bit set
        // in the instruction.. i.e. all lower bits should be 0
        // mask.. Install most specific entry at the top for MSb as
        // {key = 0x8000, mask = 0xffff}
        // {key = 0x4000, mask = 0x7fff}  ...
        // And lowest entry for LSb as
        // {key = 0x0001, mask = 0x0001}

        p4_pd_dc_int_bos_match_spec_t match_spec;

        // total_cnt must be 0 to insert BOS bit
        match_spec.int_header_total_hop_cnt = 0;
        match_spec.int_header_total_hop_cnt_mask = 0xff;
        // split the key and mask in 4 bits
        match_spec.int_header_instruction_mask_0003 = (key >> 12) & 0xF;
        match_spec.int_header_instruction_mask_0003_mask =
                                                            (mask >> 12) & 0xF;
        match_spec.int_header_instruction_mask_0407 = (key >> 8) & 0xF;
        match_spec.int_header_instruction_mask_0407_mask =
                                                            (mask >> 8) & 0xF;
        match_spec.int_header_instruction_mask_0811 = (key >> 4) & 0xF;
        match_spec.int_header_instruction_mask_0811_mask =
                                                            (mask >> 4) & 0xF;
        match_spec.int_header_instruction_mask_1215 = (key) & 0xF;
        match_spec.int_header_instruction_mask_1215_mask = (mask) & 0xF;

        switch(i) {
            case 0:
            {
                p4_pd_dc_int_bos_table_add_with_int_set_header_0_bos(g_sess_hdl,
                    p4_pd_device, &match_spec, i, &entry_hdl);
                break;
            }
            case 1:
            {
                p4_pd_dc_int_bos_table_add_with_int_set_header_1_bos(g_sess_hdl,
                    p4_pd_device, &match_spec, i, &entry_hdl);
                break;
            }
            case 2:
            {
                p4_pd_dc_int_bos_table_add_with_int_set_header_2_bos(g_sess_hdl,
                    p4_pd_device, &match_spec, i, &entry_hdl);
                break;
            }
            case 3:
            {
                p4_pd_dc_int_bos_table_add_with_int_set_header_3_bos(g_sess_hdl,
                    p4_pd_device, &match_spec, i, &entry_hdl);
                break;
            }
            case 4:
            {
                p4_pd_dc_int_bos_table_add_with_int_set_header_4_bos(g_sess_hdl,
                    p4_pd_device, &match_spec, i, &entry_hdl);
                break;
            }
            case 5:
            {
                p4_pd_dc_int_bos_table_add_with_int_set_header_5_bos(g_sess_hdl,
                    p4_pd_device, &match_spec, i, &entry_hdl);
                break;
            }
            case 6:
            {
                p4_pd_dc_int_bos_table_add_with_int_set_header_6_bos(g_sess_hdl,
                    p4_pd_device, &match_spec, i, &entry_hdl);
                break;
            }
            case 7:
            {
                p4_pd_dc_int_bos_table_add_with_int_set_header_7_bos(g_sess_hdl,
                    p4_pd_device, &match_spec, i, &entry_hdl);
                break;
            }
            case 8:
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 15:
            default:
                // NOP - not supported bits 8-15
                p4_pd_dc_int_bos_table_add_with_nop(g_sess_hdl, p4_pd_device,
                    &match_spec, 15, &entry_hdl);
                break;
        }
        key >>= 1; mask >>= 1;
    }
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

#endif // P4_INT_ENABLE

p4_pd_status_t
switch_pd_storm_control_table_add_default_entry(
        switch_device_t device)
{
    p4_pd_status_t status = 0;
#if !defined(P4_METER_DISABLE) && !defined(P4_STORM_CONTROL_DISABLE)
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_entry_hdl_t entry_hdl;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_storm_control_set_default_action_nop(
                             g_sess_hdl,
                             p4_pd_device,
                             &entry_hdl);

    status = p4_pd_dc_storm_control_stats_set_default_action_nop(
                             g_sess_hdl,
                             p4_pd_device,
                             &entry_hdl);

#endif /* P4_METER_DISABLE && P4_STORM_CONTROL_DISABLE */
    return status;
}

p4_pd_status_t
switch_pd_storm_control_meter_add_entry(
        switch_device_t device,
        switch_meter_idx_t meter_idx,
        switch_meter_info_t *meter_info)
{
    p4_pd_status_t status = 0;
#if !defined(P4_METER_DISABLE) && !defined(P4_STORM_CONTROL_DISABLE)
    p4_pd_dev_target_t p4_pd_device;
    switch_api_meter_t *api_meter_info = NULL;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    api_meter_info = &meter_info->api_meter_info;
    if (api_meter_info->meter_type == SWITCH_METER_TYPE_BYTES) {
        p4_pd_bytes_meter_spec_t meter_spec;
        memset(&meter_spec, 0, sizeof(p4_pd_bytes_meter_spec_t));
        meter_spec.cir_kbps = api_meter_info->cir;
        meter_spec.cburst_kbits = api_meter_info->cbs;
        meter_spec.pir_kbps = api_meter_info->pir;
        meter_spec.pburst_kbits = api_meter_info->pbs;
        meter_spec.meter_type = api_meter_info->color_source ==
                                SWITCH_METER_COLOR_SOURCE_BLIND ?
                                PD_METER_TYPE_COLOR_UNAWARE :
                                PD_METER_TYPE_COLOR_AWARE;
        status = p4_pd_dc_meter_set_storm_control_meter(
                             g_sess_hdl,
                             p4_pd_device,
                             meter_idx,
                             &meter_spec);
    } else {
        p4_pd_packets_meter_spec_t meter_spec;
        memset(&meter_spec, 0, sizeof(p4_pd_packets_meter_spec_t));
        meter_spec.cir_pps = api_meter_info->cir;
        meter_spec.cburst_pkts = api_meter_info->cbs;
        meter_spec.pir_pps = api_meter_info->pir;
        meter_spec.pburst_pkts = api_meter_info->pbs;
        meter_spec.meter_type = api_meter_info->color_source ==
                                SWITCH_METER_COLOR_SOURCE_BLIND ?
                                PD_METER_TYPE_COLOR_UNAWARE :
                                PD_METER_TYPE_COLOR_AWARE;
        (void) meter_spec;
    }
#endif /* P4_METER_DISABLE && P4_STORM_CONTROL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_storm_control_table_add_entry(
        switch_device_t device,
        switch_port_t port,
        uint16_t priority,
        switch_packet_type_t pkt_type,
        switch_meter_idx_t meter_idx,
        p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_METER_DISABLE) && !defined(P4_STORM_CONTROL_DISABLE)
    p4_pd_dc_storm_control_match_spec_t match_spec;
    p4_pd_dc_set_storm_control_meter_action_spec_t action_spec;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_storm_control_match_spec_t));
    memset(&action_spec, 0, sizeof(p4_pd_dc_set_storm_control_meter_action_spec_t));

    match_spec.l2_metadata_lkp_pkt_type = pkt_type;
    match_spec.l2_metadata_lkp_pkt_type_mask = 0xFF;
    match_spec.ingress_metadata_ingress_port = port;

    action_spec.action_meter_idx = meter_idx;

    status = p4_pd_dc_storm_control_table_add_with_set_storm_control_meter(
                             g_sess_hdl,
                             p4_pd_device,
                             &match_spec,
                             priority,
                             &action_spec,
                             entry_hdl);

#endif /* P4_METER_DISABLE && P4_STORM_CONTROL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_storm_control_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_METER_DISABLE) && !defined(P4_STORM_CONTROL_DISABLE)

    status = p4_pd_dc_storm_control_table_delete(
                             g_sess_hdl,
                             device,
                             entry_hdl);
#endif /* P4_METER_DISABLE && P4_STORM_CONTROL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_meter_index_table_add_default_entry(
        switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef METER_DISABLE
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_bytes_meter_spec_t meter_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&meter_spec, 0, sizeof(p4_pd_bytes_meter_spec_t));
    meter_spec.meter_type = PD_METER_TYPE_COLOR_UNAWARE;
    status = p4_pd_dc_meter_index_set_default_action_nop(
                             g_sess_hdl,
                             p4_pd_device,
                             &meter_spec,
                             &entry_hdl);
#endif /* METER_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_meter_index_table_add_entry(
        switch_device_t device,
        switch_meter_idx_t meter_idx,
        switch_meter_info_t *meter_info,
        p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef METER_DISABLE
    p4_pd_dc_meter_index_match_spec_t match_spec;
    p4_pd_dev_target_t p4_pd_device;
    switch_api_meter_t *api_meter_info = NULL;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_meter_index_match_spec_t));

    match_spec.meter_metadata_meter_index = meter_idx;

    api_meter_info = &meter_info->api_meter_info;
    if (api_meter_info->meter_type == SWITCH_METER_TYPE_BYTES) {
        p4_pd_bytes_meter_spec_t meter_spec;
        memset(&meter_spec, 0, sizeof(p4_pd_bytes_meter_spec_t));
        meter_spec.cir_kbps = api_meter_info->cir;
        meter_spec.cburst_kbits = api_meter_info->cbs;
        meter_spec.pir_kbps = api_meter_info->pir;
        meter_spec.pburst_kbits = api_meter_info->pbs;
        meter_spec.meter_type = api_meter_info->color_source ==
                                SWITCH_METER_COLOR_SOURCE_BLIND ?
                                PD_METER_TYPE_COLOR_UNAWARE :
                                PD_METER_TYPE_COLOR_AWARE;
        status = p4_pd_dc_meter_index_table_add_with_nop(
                             g_sess_hdl,
                             p4_pd_device,
                             &match_spec,
                             &meter_spec,
                             entry_hdl);
    } else {
        p4_pd_packets_meter_spec_t meter_spec;
        memset(&meter_spec, 0, sizeof(p4_pd_packets_meter_spec_t));
        meter_spec.cir_pps = api_meter_info->cir;
        meter_spec.cburst_pkts = api_meter_info->cbs;
        meter_spec.pir_pps = api_meter_info->pir;
        meter_spec.pburst_pkts = api_meter_info->pbs;
        meter_spec.meter_type = api_meter_info->color_source ==
                                SWITCH_METER_COLOR_SOURCE_BLIND ?
                                PD_METER_TYPE_COLOR_UNAWARE :
                                PD_METER_TYPE_COLOR_AWARE;
        (void) meter_spec;
    }

#endif /* METER_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_meter_index_table_update_entry(
        switch_device_t device,
        switch_meter_idx_t meter_idx,
        switch_meter_info_t *meter_info,
        p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef METER_DISABLE
    switch_api_meter_t *api_meter_info = NULL;

    api_meter_info = &meter_info->api_meter_info;
    if (api_meter_info->meter_type == SWITCH_METER_TYPE_BYTES) {
        p4_pd_bytes_meter_spec_t meter_spec;
        memset(&meter_spec, 0, sizeof(p4_pd_bytes_meter_spec_t));
        meter_spec.cir_kbps = api_meter_info->cir;
        meter_spec.cburst_kbits = api_meter_info->cbs;
        meter_spec.pir_kbps = api_meter_info->pir;
        meter_spec.pburst_kbits = api_meter_info->pbs;
        meter_spec.meter_type = api_meter_info->color_source ==
                                SWITCH_METER_COLOR_SOURCE_BLIND ?
                                PD_METER_TYPE_COLOR_UNAWARE :
                                PD_METER_TYPE_COLOR_AWARE;

        status = p4_pd_dc_meter_index_table_modify_with_nop(
                             g_sess_hdl,
                             device,
                             entry_hdl,
                             &meter_spec);
    } else {
        p4_pd_packets_meter_spec_t meter_spec;
        memset(&meter_spec, 0, sizeof(p4_pd_bytes_meter_spec_t));
        meter_spec.cir_pps = api_meter_info->cir;
        meter_spec.cburst_pkts = api_meter_info->cbs;
        meter_spec.pir_pps = api_meter_info->pir;
        meter_spec.pburst_pkts = api_meter_info->pbs;
        meter_spec.meter_type = api_meter_info->color_source ==
                                SWITCH_METER_COLOR_SOURCE_BLIND ?
                                PD_METER_TYPE_COLOR_UNAWARE :
                                PD_METER_TYPE_COLOR_AWARE;
        /*
        status = p4_pd_dc_meter_index_table_modify_with_nop(
                             g_sess_hdl,
                             device,
                             entry_hdl,
                             &meter_spec);
        */
        (void) meter_spec;
    }

#endif /* METER_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_meter_index_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef METER_DISABLE
    status = p4_pd_dc_meter_index_table_delete(
                             g_sess_hdl,
                             device,
                             entry_hdl);
#endif /* METER_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_meter_action_table_add_default_entry(
        switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef METER_DISABLE
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_entry_hdl_t entry_hdl;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_meter_action_set_default_action_meter_permit(
                             g_sess_hdl,
                             p4_pd_device,
                             &entry_hdl);
#endif /* METER_DISABLE */
    return status;
}

p4_pd_status_t
switch_pd_meter_action_table_add_entry(
        switch_device_t device,
        switch_meter_idx_t meter_idx,
        switch_meter_info_t *meter_info,
        p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef METER_DISABLE
    p4_pd_dc_meter_action_match_spec_t match_spec;
    p4_pd_dev_target_t p4_pd_device;
    switch_api_meter_t *api_meter_info = NULL;
    switch_meter_color_t color;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    api_meter_info = &meter_info->api_meter_info;

    for (color = 0; color < SWITCH_METER_COLOR_MAX; color++) {
        memset(&match_spec, 0, sizeof(p4_pd_dc_meter_index_match_spec_t));
        match_spec.meter_metadata_meter_index = meter_idx;
        match_spec.meter_metadata_meter_color = color;

        switch (api_meter_info->action[color]) {
            case SWITCH_ACL_ACTION_PERMIT:
                status = p4_pd_dc_meter_action_table_add_with_meter_permit(
                             g_sess_hdl,
                             p4_pd_device,
                             &match_spec,
                             &entry_hdl[color]);
                break;
            case SWITCH_ACL_ACTION_DROP:
                status = p4_pd_dc_meter_action_table_add_with_meter_deny(
                             g_sess_hdl,
                             p4_pd_device,
                             &match_spec,
                             &entry_hdl[color]);
                break;
            default:
                return SWITCH_STATUS_INVALID_PARAMETER;
        }
    }
#endif /* METER_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_meter_action_table_update_entry(
        switch_device_t device,
        switch_meter_idx_t meter_idx,
        switch_meter_info_t *meter_info,
        p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef METER_DISABLE
    switch_api_meter_t *api_meter_info = NULL;
    switch_meter_color_t color;

    api_meter_info = &meter_info->api_meter_info;

    for (color = 0; color < SWITCH_METER_COLOR_MAX; color++) {
        switch (api_meter_info->action[color]) {
            case SWITCH_ACL_ACTION_PERMIT:
                status = p4_pd_dc_meter_action_table_modify_with_meter_permit(
                             g_sess_hdl,
                             device,
                             entry_hdl[color]);
                break;
            case SWITCH_ACL_ACTION_DROP:
                status = p4_pd_dc_meter_action_table_modify_with_meter_deny(
                             g_sess_hdl,
                             device,
                             entry_hdl[color]);
                break;
            default:
                return SWITCH_STATUS_INVALID_PARAMETER;
        }
    }
#endif /* METER_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_meter_action_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t *entry_hdl) {
    p4_pd_status_t status = 0;
#ifndef METER_DISABLE
    switch_meter_color_t color;
    for (color = 0; color < SWITCH_METER_COLOR_MAX; color++) {
        status = p4_pd_dc_meter_action_table_delete(
                             g_sess_hdl,
                             device,
                             entry_hdl[color]);
    }
#endif /* METER_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_switch_config_params_update (switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;
    p4_pd_dc_set_config_parameters_action_spec_t cfg_action;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    memset(&cfg_action, 0, sizeof(cfg_action));
    switch_config_action_populate(device, &cfg_action);

    status =
        p4_pd_dc_switch_config_params_set_default_action_set_config_parameters(
                                        g_sess_hdl,
                                        p4_pd_device,
                                        &cfg_action,
                                        &entry_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_switch_config_params_table_init (switch_device_t device)
{
    switch_config_params_init(device);
    return switch_pd_switch_config_params_update(device);
}

#ifdef P4_SFLOW_ENABLE
// sFlow APIs
p4_pd_status_t
switch_pd_sflow_tables_init(switch_device_t device)
{
    switch_status_t     status = SWITCH_STATUS_SUCCESS;
    p4_pd_dev_target_t  p4_pd_device;
    p4_pd_entry_hdl_t   entry_hdl;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;
    // ingress_sflow
    p4_pd_dc_ingress_sflow_set_default_action_set_ing_sflow_session_disable(
        g_sess_hdl, p4_pd_device, &entry_hdl);

    // egress_sflow
    p4_pd_dc_egress_sflow_set_default_action_set_egr_sflow_session_disable(
                        g_sess_hdl, p4_pd_device, &entry_hdl);

    // sflow_session_headers
    p4_pd_dc_sflow_session_headers_set_default_action_nop(
                        g_sess_hdl, p4_pd_device, &entry_hdl);

    p4_pd_dc_i2e_mirror_set_default_action_nop(
                        g_sess_hdl, p4_pd_device, &entry_hdl);
    p4_pd_dc_sflow_take_sample_set_default_action_nop(
                        g_sess_hdl, p4_pd_device, &entry_hdl);

    return status;
}

switch_status_t
switch_pd_sflow_ingress_table_add (switch_device_t device,
                                switch_sflow_match_key_t *match_key,
                                uint32_t priority,
                                switch_sflow_info_t *sflow_info,
                                switch_sflow_match_entry_t *match_entry)
{
    switch_status_t     status = SWITCH_STATUS_FAILURE;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_ingress_sflow_match_spec_t ingress_sflow_match;
    p4_pd_dc_set_ing_sflow_session_enable_action_spec_t action_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;
    memset(&ingress_sflow_match, 0, sizeof(ingress_sflow_match));

    if (match_key->port != SWITCH_API_INVALID_HANDLE) {
        ingress_sflow_match.ingress_metadata_ifindex =
                        switch_api_interface_get(match_key->port)->ifindex;
        ingress_sflow_match.ingress_metadata_ifindex_mask = -1;
    }
    if (match_key->vlan) {
        // TBD
    }
    if (match_key->sip) {
        ingress_sflow_match.ipv4_metadata_lkp_ipv4_sa = match_key->sip;
        ingress_sflow_match.ipv4_metadata_lkp_ipv4_sa_mask =
                                                    match_key->sip_mask;
    }
    if (match_key->dip) {
        ingress_sflow_match.ipv4_metadata_lkp_ipv4_da = match_key->dip;
        ingress_sflow_match.ipv4_metadata_lkp_ipv4_da_mask =
                                                    match_key->dip_mask;
    }
    // divide the RNG space (32bits) into equal chunks based on rate
    action_spec.action_rate_thr = (uint32_t)((uint32_t)-1 /
                                sflow_info->api_info.sample_rate);
    action_spec.action_session_id = sflow_info->session_id;
    status = p4_pd_dc_ingress_sflow_table_add_with_set_ing_sflow_session_enable(
                g_sess_hdl, p4_pd_device, &ingress_sflow_match, priority,
                &action_spec, &match_entry->ingress_sflow_ent_hdl
                );
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

static switch_status_t
switch_pd_sflow_ingress_table_delete (switch_device_t device,
                                      switch_sflow_match_entry_t *match_entry)
{
    switch_status_t status = SWITCH_STATUS_FAILURE;

    status = p4_pd_dc_ingress_sflow_table_delete(g_sess_hdl, device,
                                            match_entry->ingress_sflow_ent_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_sflow_match_table_delete (switch_device_t device,
                                      switch_sflow_match_entry_t *match_entry)
{
    // XXX - batching ?
    switch_status_t status = SWITCH_STATUS_FAILURE;
    if (match_entry->ingress_sflow_ent_hdl) {
        status = switch_pd_sflow_ingress_table_delete(device, match_entry);
    }
    // XXX - add clearing egress entries if present
    return status;
}

switch_status_t
switch_pd_sflow_i2e_mirror_create (switch_device_t device,
                                        switch_sflow_info_t *sflow_info)
{
    switch_status_t                         status = SWITCH_STATUS_FAILURE;
    p4_pd_dev_target_t                      p4_pd_device;
    p4_pd_dc_i2e_mirror_match_spec_t        match_spec;
    p4_pd_dc_sflow_i2e_mirror_action_spec_t action_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    // {take_sample = max_val_32, sflow_session_id} =>
    //          sflow_i2e_mirror(mirror_id);
    memset(&match_spec, 0, sizeof(match_spec));
    memset(&action_spec, 0, sizeof(action_spec));

    match_spec.ingress_metadata_sflow_take_sample = (uint32_t)-1;
    match_spec.ingress_metadata_sflow_take_sample_mask = -1;
    match_spec.ingress_metadata_sflow_session_id = sflow_info->session_id;
    match_spec.ingress_metadata_sflow_session_id_mask = -1;

    action_spec.action_sflow_i2e_mirror_id =
                            handle_to_id(sflow_info->i2e_mirror_hdl);

    status = p4_pd_dc_i2e_mirror_table_add_with_sflow_i2e_mirror(
                g_sess_hdl, p4_pd_device, &match_spec, 0/*priority*/,
                &action_spec, &sflow_info->i2e_mirror_table_ent_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_sflow_mirror_table_sflow_i2e_create (switch_device_t device,
                                        switch_sflow_info_t *sflow_info)
{
    switch_status_t     status = SWITCH_STATUS_FAILURE;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_mirror_match_spec_t match_spec;
    p4_pd_dc_set_ingress_sflow_from_mirror_action_spec_t action_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    // mirror table {i2e_mirror_id} => set_ingress_sflow_from_mirror
    memset(&match_spec, 0, sizeof(match_spec));
    memset(&action_spec, 0, sizeof(action_spec));

    match_spec.i2e_metadata_mirror_session_id =
                            handle_to_id(sflow_info->i2e_mirror_hdl);

    action_spec.action_sflow_session_id = sflow_info->session_id;
    // add size of sflow raw header record
    action_spec.action_max_sample_len = sflow_info->api_info.extract_len + 24;

    // total sample len must be < 80B (tofino)
    if (action_spec.action_max_sample_len > 80) {
        action_spec.action_max_sample_len = 80;
    }

    status = p4_pd_dc_mirror_table_add_with_set_ingress_sflow_from_mirror(
                g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                &sflow_info->mirror_table_ent_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_sflow_session_headers_create (switch_device_t device,
                                        switch_sflow_info_t *sflow_info)
{
    switch_status_t     status = SWITCH_STATUS_FAILURE;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_sflow_session_headers_match_spec_t match_spec;
    p4_pd_dc_sflow_to_cpu_action_spec_t         action_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    // sflow_session_headers for sending the coalesced pkt to cpu
    memset(&match_spec, 0, sizeof(match_spec));
    memset(&action_spec, 0, sizeof(action_spec));

    status = p4_pd_dc_sflow_session_headers_table_add_with_sflow_to_cpu(
                g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                &sflow_info->session_headers_table_ent_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_sflow_take_sample_table_create (switch_device_t device,
                                          switch_sflow_info_t *sflow_info)
{
    switch_status_t     status = SWITCH_STATUS_FAILURE;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_sflow_take_sample_match_spec_t       match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    memset(&match_spec, 0, sizeof(match_spec));

    // create two entries,
    // 1: for ingress sflow - applied to i2e mirrored packet which is sampled
    // ingress_sflow flag is set, ignore take_sample value
    match_spec.sflow_meta_sflow_session_id = sflow_info->session_id;
    match_spec.sflow_meta_ingress_sflow = 1;
    match_spec.sflow_meta_ingress_sflow_mask = -1;
    match_spec.egress_metadata_sflow_take_sample = (uint32_t)-1;
    match_spec.egress_metadata_sflow_take_sample_mask = 0; // don't care

    status = p4_pd_dc_sflow_take_sample_table_add_with_sflow_sample_pkt_i2e(
                g_sess_hdl, p4_pd_device, &match_spec, 0,
                &sflow_info->take_sample_table_ent_hdl_i2e);
    if (status != SWITCH_STATUS_SUCCESS) {
        goto error_return;
    }

    // 2: for egress sflow - applied to packet being sampled
    match_spec.sflow_meta_sflow_session_id = sflow_info->session_id;
    match_spec.sflow_meta_ingress_sflow = 0;
    match_spec.sflow_meta_ingress_sflow_mask = -1;
    match_spec.egress_metadata_sflow_take_sample = (uint32_t)-1;
    match_spec.egress_metadata_sflow_take_sample_mask = -1;

    status = p4_pd_dc_sflow_take_sample_table_add_with_sflow_sample_pkt(
                g_sess_hdl, p4_pd_device, &match_spec, 0,
                &sflow_info->take_sample_table_ent_hdl);

error_return:
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

switch_status_t
switch_pd_sflow_session_create (switch_device_t device,
                                        switch_sflow_info_t *sflow_info)
{
    switch_status_t     status = SWITCH_STATUS_FAILURE;

    status = switch_pd_sflow_i2e_mirror_create(device, sflow_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        // caller does cleanup
        return status;
    }
    // mirror table {i2e_mirror_id} => set_ingress_sflow_from_mirror
    status = switch_pd_sflow_mirror_table_sflow_i2e_create(device, sflow_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        // caller does cleanup
        return status;
    }
    // sflow_session_headers
    status = switch_pd_sflow_session_headers_create(device, sflow_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        // caller does cleanup
        return status;
    }
    status = switch_pd_sflow_take_sample_table_create(device, sflow_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        // caller does cleanup
        return status;
    }
    return status;
}

switch_status_t
switch_pd_sflow_session_delete (switch_device_t device,
                                        switch_sflow_info_t *sflow_info)
{
    bool op_started = false;
    if (sflow_info->mirror_table_ent_hdl) {
        p4_pd_dc_mirror_table_delete(g_sess_hdl, device,
                                         sflow_info->mirror_table_ent_hdl);
        op_started = true;
    }
    if (sflow_info->session_headers_table_ent_hdl) {
        p4_pd_dc_sflow_session_headers_table_delete(g_sess_hdl, device,
                                sflow_info->session_headers_table_ent_hdl);
        op_started = true;
    }
    if (sflow_info->i2e_mirror_table_ent_hdl) {
        p4_pd_dc_i2e_mirror_table_delete(g_sess_hdl, device,
                                         sflow_info->i2e_mirror_table_ent_hdl);
        op_started = true;
    }
    if (sflow_info->take_sample_table_ent_hdl_i2e) {
        p4_pd_dc_sflow_take_sample_table_delete(g_sess_hdl, device,
                                         sflow_info->take_sample_table_ent_hdl_i2e);
        op_started = true;
    }
    if (sflow_info->take_sample_table_ent_hdl) {
        p4_pd_dc_sflow_take_sample_table_delete(g_sess_hdl, device,
                                         sflow_info->take_sample_table_ent_hdl);
        op_started = true;
    }
    if (op_started) {
        p4_pd_complete_operations(g_sess_hdl);
    }
    return SWITCH_STATUS_SUCCESS;
}
#endif

void
switch_pd_stats_update_cb(int device, void *cookie)
{
    return;
}

p4_pd_status_t
switch_pd_stats_update(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_STATS_DISABLE
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;

    status = p4_pd_dc_counter_hw_sync_storm_control_stats(
               g_sess_hdl,
               p4_pd_device,
               &switch_pd_stats_update_cb,
               NULL);

    status = p4_pd_dc_counter_hw_sync_acl_stats(
               g_sess_hdl,
               p4_pd_device,
               &switch_pd_stats_update_cb,
               NULL);

    status = p4_pd_dc_counter_hw_sync_egress_bd_stats(
               g_sess_hdl,
               p4_pd_device,
               &switch_pd_stats_update_cb,
               NULL);

    status = p4_pd_dc_counter_hw_sync_ingress_bd_stats(
               g_sess_hdl,
               p4_pd_device,
               &switch_pd_stats_update_cb,
               NULL);

#ifndef P4_METER_DISABLE
    status = p4_pd_dc_counter_hw_sync_meter_stats(
               g_sess_hdl,
               p4_pd_device,
               &switch_pd_stats_update_cb,
               NULL);
#endif /* P4_METER_DISABLE */

    status = p4_pd_dc_counter_hw_sync_drop_stats(
               g_sess_hdl,
               p4_pd_device,
               &switch_pd_stats_update_cb,
               NULL);

    status = p4_pd_dc_counter_hw_sync_drop_stats_2(
               g_sess_hdl,
               p4_pd_device,
               &switch_pd_stats_update_cb,
               NULL);
#endif /* P4_STATS_DISABLE */
    return status;
}
