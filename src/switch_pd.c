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
#include <string.h>

#define SWITCH_MAX_TXN_SZ  10

p4_pd_sess_hdl_t g_sess_hdl = 0;
p4_pd_sess_hdl_t g_mc_sess_hdl = 0;

p4_pd_status_t
switch_pd_client_init(switch_device_t device)
{
#ifndef P4_MULTICAST_DISABLE
    p4_pd_status_t sts = 0;
    sts = mc_create_session(&g_mc_sess_hdl);
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

    match_spec.ingress_metadata_ingress_bd = handle_to_id(mac_entry->vlan_handle);
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

    match_spec.ingress_metadata_ingress_bd = handle_to_id(mac_entry->vlan_handle);
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
                                  switch_interface_info_t *intf_info,
                                  p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_dc_nexthop_match_spec_t match_spec;
    p4_pd_dc_set_nexthop_details_action_spec_t action_spec;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_nexthop_match_spec_t));
    memset(&action_spec, 0, sizeof(p4_pd_dc_set_nexthop_details_action_spec_t));
    match_spec.l3_metadata_nexthop_index = nhop_index;

    action_spec.action_ifindex = intf_info->ifindex;
    action_spec.action_bd = handle_to_id(intf_info->bd_handle);

    /*
     * If the interface is part of logical network,
     * program the egress bd as LN BD instead of 
     * implicit BD
     */
    if (intf_info->ln_bd_handle) {
        action_spec.action_bd = handle_to_id(intf_info->ln_bd_handle);
    }

    status = p4_pd_dc_nexthop_table_add_with_set_nexthop_details(g_sess_hdl,
                                                               p4_pd_device,
                                                               &match_spec,
                                                               &action_spec,
                                                               entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t switch_pd_ecmp_group_create(switch_device_t device, p4_pd_grp_hdl_t *pd_group_hdl)
{
    switch_status_t status = 0;
    p4_pd_dev_target_t                             p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_ecmp_action_profile_create_group(g_sess_hdl, p4_pd_device, MAX_ECMP_GROUP_SIZE, pd_group_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t switch_pd_ecmp_group_delete(switch_device_t device, p4_pd_grp_hdl_t pd_group_hdl)
{
    switch_status_t status = 0;
    status = p4_pd_dc_ecmp_action_profile_del_group(g_sess_hdl, device, pd_group_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t switch_pd_ecmp_member_add(switch_device_t device, p4_pd_grp_hdl_t pd_group_hdl, 
                                         uint16_t nhop_index, switch_interface_info_t *intf_info,
                                         p4_pd_mbr_hdl_t *mbr_hdl)
{
    p4_pd_status_t status = 0;
    p4_pd_dev_target_t                             pd_device;
    p4_pd_dc_set_ecmp_nexthop_details_action_spec_t action_spec;

    pd_device.device_id = device;
    pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&action_spec, 0, sizeof(p4_pd_dc_set_ecmp_nexthop_details_action_spec_t));

    action_spec.action_ifindex = intf_info->ifindex;
    action_spec.action_bd = handle_to_id(intf_info->bd_handle);
    action_spec.action_nhop_index = nhop_index;

    status = p4_pd_dc_ecmp_action_profile_add_member_with_set_ecmp_nexthop_details(g_sess_hdl,
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
switch_pd_ecmp_member_delete(switch_device_t device, p4_pd_grp_hdl_t pd_group_hdl, 
                             p4_pd_mbr_hdl_t mbr_hdl)
{
    p4_pd_dc_ecmp_action_profile_del_member_from_group(g_sess_hdl, device, pd_group_hdl, mbr_hdl);

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
        v4_match_spec.ipv4_metadata_lkp_ipv4_da = SWITCH_IP_ENCAP_IPV4_DST_IP(ip_encap);
        v4_match_spec.l3_metadata_lkp_ip_proto = ip_encap->proto;
        v4_match_spec.l3_metadata_lkp_l4_dport = SWITCH_IP_ENCAP_UDP_DST_PORT(ip_encap);
        status = p4_pd_dc_ipv4_dest_vtep_table_add_with_set_tunnel_termination_flag(g_sess_hdl,
                                                                             p4_pd_device,
                                                                             &v4_match_spec,
                                                                             entry_hdl);
#endif /* P4_IPV4_DISABLE */
    } else {
#ifndef P4_IPV6_DISABLE
        p4_pd_dc_ipv6_dest_vtep_match_spec_t v6_match_spec;
        memset(&v6_match_spec, 0, sizeof(p4_pd_dc_ipv6_dest_vtep_match_spec_t));
        v6_match_spec.l3_metadata_vrf = handle_to_id(ip_encap->vrf_handle);
        memcpy(&v6_match_spec.ipv6_metadata_lkp_ipv6_da, SWITCH_IP_ENCAP_IPV6_DST_IP(ip_encap), 16);
        v6_match_spec.l3_metadata_lkp_ip_proto = ip_encap->proto;
        v6_match_spec.l3_metadata_lkp_l4_dport = SWITCH_IP_ENCAP_UDP_DST_PORT(ip_encap);
        status = p4_pd_dc_ipv6_dest_vtep_table_add_with_set_tunnel_termination_flag(g_sess_hdl,
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

    status = p4_pd_dc_tunnel_rewrite_table_add_with_set_tunnel_rewrite_details(g_sess_hdl,
                                                                    p4_pd_device,
                                                                    &match_spec,
                                                                    &action_spec,
                                                                    entry_hdl);
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
                                 switch_bd_info_t *bd_info,
                                 switch_ip_encap_t *ip_encap,
                                 switch_handle_t bd_handle,
                                 p4_pd_entry_hdl_t *entry_hdl)
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
        default:
            return SWITCH_STATUS_INVALID_TUNNEL_TYPE;
    }
            
    ln_info = &bd_info->ln_info;
    if (SWITCH_IP_ENCAP_SRC_IP_TYPE(ip_encap) == SWITCH_API_IP_ADDR_V4) {
#ifndef P4_IPV4_DISABLE
        p4_pd_dc_tunnel_match_spec_t v4_match_spec;
        p4_pd_dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t v4_action_spec;
        memset(&v4_match_spec, 0, sizeof(p4_pd_dc_tunnel_match_spec_t)); 
        memset(&v4_action_spec, 0,
               sizeof(p4_pd_dc_terminate_tunnel_inner_ethernet_ipv4_action_spec_t));
        v4_match_spec.tunnel_metadata_tunnel_vni = tunnel_vni;
        v4_match_spec.tunnel_metadata_ingress_tunnel_type = ingress_tunnel_type;
        v4_match_spec.inner_ipv4_valid = TRUE;
        v4_match_spec.inner_ipv6_valid = FALSE;

        v4_action_spec.action_bd = bd_handle;
        v4_action_spec.action_vrf = handle_to_id(ln_info->vrf_handle);
        v4_action_spec.action_rmac_group = handle_to_id(ln_info->rmac_handle);
        v4_action_spec.action_bd_label = handle_to_id(ln_info->bd_label);
        v4_action_spec.action_uuc_mc_index = handle_to_id(bd_info->uuc_mc_index);
        v4_action_spec.action_umc_mc_index = handle_to_id(bd_info->umc_mc_index);
        v4_action_spec.action_bcast_mc_index = handle_to_id(bd_info->bcast_mc_index);
        v4_action_spec.action_ipv4_unicast_enabled = SWITCH_LN_IPV4_UNICAST_ENABLED(bd_info);
        v4_action_spec.action_igmp_snooping_enabled = SWITCH_LN_IGMP_SNOOPING_ENABLED(bd_info);
        v4_action_spec.action_ipv4_urpf_mode = bd_info->ipv4_urpf_mode;

        status = p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_ethernet_ipv4(g_sess_hdl,
                                                                     p4_pd_device,
                                                                     &v4_match_spec,
                                                                     &v4_action_spec,
                                                                     &entry_hdl[entry++]);
#endif /* P4_IPV4_DISABLE */
    } else {
#ifndef P4_IPV6_DISABLE
        p4_pd_dc_tunnel_match_spec_t v6_match_spec;
        p4_pd_dc_terminate_tunnel_inner_ethernet_ipv6_action_spec_t v6_action_spec;

        memset(&v6_match_spec, 0, sizeof(p4_pd_dc_tunnel_match_spec_t)); 
        memset(&v6_action_spec, 0,
        sizeof(p4_pd_dc_terminate_tunnel_inner_ethernet_ipv6_action_spec_t));
        v6_match_spec.tunnel_metadata_tunnel_vni = tunnel_vni;
        v6_match_spec.tunnel_metadata_ingress_tunnel_type = ingress_tunnel_type;
        v6_match_spec.inner_ipv6_valid = TRUE;
        v6_match_spec.inner_ipv4_valid = FALSE;
        v6_action_spec.action_bd = bd_handle;
        v6_action_spec.action_vrf = handle_to_id(ln_info->vrf_handle);
        v6_action_spec.action_rmac_group = handle_to_id(ln_info->rmac_handle);
        v6_action_spec.action_bd_label = handle_to_id(ln_info->bd_label);
        v6_action_spec.action_uuc_mc_index = handle_to_id(bd_info->uuc_mc_index);
        v6_action_spec.action_umc_mc_index = handle_to_id(bd_info->umc_mc_index);
        v6_action_spec.action_bcast_mc_index = handle_to_id(bd_info->bcast_mc_index);
        v6_action_spec.action_ipv6_unicast_enabled = SWITCH_LN_IPV4_UNICAST_ENABLED(bd_info);
        v6_action_spec.action_mld_snooping_enabled = SWITCH_LN_MLD_SNOOPING_ENABLED(bd_info);
        v6_action_spec.action_ipv6_urpf_mode = bd_info->ipv6_urpf_mode;

        status = p4_pd_dc_tunnel_table_add_with_terminate_tunnel_inner_ethernet_ipv6(g_sess_hdl,
                                                                      p4_pd_device,
                                                                      &v6_match_spec,
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
                                    p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_TUNNEL_DISABLE
    status = p4_pd_dc_tunnel_table_delete(g_sess_hdl, device, entry_hdl);
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

    /* vxlan, inner ipv6 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_VXLAN;
    o_match_spec.inner_ipv6_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_vxlan_inner_ipv4(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

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

    /* geneve, inner ipv6 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_GENEVE;
    o_match_spec.inner_ipv6_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_genv_inner_ipv4(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

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

    /* nvgre, inner ipv6 */
    memset(&o_match_spec, 0, sizeof(p4_pd_dc_tunnel_decap_process_outer_match_spec_t));
    o_match_spec.tunnel_metadata_ingress_tunnel_type = SWITCH_INGRESS_TUNNEL_TYPE_NVGRE;
    o_match_spec.inner_ipv6_valid = TRUE;
    status = p4_pd_dc_tunnel_decap_process_outer_table_add_with_decap_nvgre_inner_ipv4(
        g_sess_hdl,
        p4_pd_device,
        &o_match_spec,
        &entry_hdl);

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
#endif /* P4_TUNNEL_DISABLE */

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
    p4_pd_dc_set_bd_action_spec_t action_spec;
    memset(&action_spec, 0, sizeof(p4_pd_dc_set_bd_action_spec_t));
    action_spec.action_bd = bd;
    action_spec.action_vrf = handle_to_id(ln_info->vrf_handle);
    action_spec.action_rmac_group = handle_to_id(ln_info->rmac_handle);
    action_spec.action_bd_label = handle_to_id(ln_info->bd_label);
    action_spec.action_uuc_mc_index = handle_to_id(bd_info->uuc_mc_index);
    action_spec.action_umc_mc_index = handle_to_id(bd_info->umc_mc_index);
    action_spec.action_bcast_mc_index = handle_to_id(bd_info->bcast_mc_index);
    action_spec.action_ipv4_unicast_enabled = SWITCH_LN_IPV4_UNICAST_ENABLED(bd_info);
    action_spec.action_ipv6_unicast_enabled = SWITCH_LN_IPV6_UNICAST_ENABLED(bd_info);
    action_spec.action_igmp_snooping_enabled = SWITCH_LN_IGMP_SNOOPING_ENABLED(bd_info);
    action_spec.action_mld_snooping_enabled = SWITCH_LN_MLD_SNOOPING_ENABLED(bd_info);
    action_spec.action_ipv4_urpf_mode = bd_info->ipv4_urpf_mode;
    action_spec.action_ipv6_urpf_mode = bd_info->ipv6_urpf_mode;
    action_spec.action_stp_group = handle_to_id(bd_info->stp_handle);

    status = p4_pd_dc_bd_action_profile_add_member_with_set_bd(
            g_sess_hdl,
            p4_pd_device,
            &action_spec,
            entry_hdl);

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

    p4_pd_dc_set_bd_action_spec_t action_spec;
    memset(&action_spec, 0, sizeof(p4_pd_dc_set_bd_action_spec_t));
    action_spec.action_bd = bd;
    action_spec.action_vrf = handle_to_id(ln_info->vrf_handle);
    action_spec.action_rmac_group = handle_to_id(ln_info->rmac_handle);
    action_spec.action_bd_label = handle_to_id(ln_info->bd_label);
    action_spec.action_uuc_mc_index = handle_to_id(bd_info->uuc_mc_index);
    action_spec.action_umc_mc_index = handle_to_id(bd_info->umc_mc_index);
    action_spec.action_bcast_mc_index = handle_to_id(bd_info->bcast_mc_index);
    action_spec.action_ipv4_unicast_enabled = SWITCH_LN_IPV4_UNICAST_ENABLED(bd_info);
    action_spec.action_ipv6_unicast_enabled = SWITCH_LN_IPV6_UNICAST_ENABLED(bd_info);
    action_spec.action_igmp_snooping_enabled = SWITCH_LN_IGMP_SNOOPING_ENABLED(bd_info);
    action_spec.action_mld_snooping_enabled = SWITCH_LN_MLD_SNOOPING_ENABLED(bd_info);
    action_spec.action_ipv4_urpf_mode = bd_info->ipv4_urpf_mode;
    action_spec.action_ipv6_urpf_mode = bd_info->ipv6_urpf_mode;
    action_spec.action_stp_group = handle_to_id(bd_info->stp_handle);

    status = p4_pd_dc_bd_action_profile_modify_member_with_set_bd(
            g_sess_hdl,
            device,
            entry_hdl,
            &action_spec);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_bd_table_delete_entry(switch_device_t device,
                                p4_pd_mbr_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;

    status = p4_pd_dc_bd_action_profile_del_member(g_sess_hdl, device, entry_hdl);
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
    action_spec.action_if_label = port_id; //TODO: Insert the right IF ACL Label

    modify = (*entry_hdl != 0) ? TRUE : FALSE;
    if (modify) {
        status = p4_pd_dc_ingress_port_mapping_table_modify_with_set_ifindex(g_sess_hdl, 0,
                                                                     *entry_hdl,
                                                                     &action_spec);
    } else {
        status = p4_pd_dc_ingress_port_mapping_table_add_with_set_ifindex(g_sess_hdl,
                                                                  p4_pd_device,
                                                                  &match_spec,
                                                                  &action_spec,
                                                                  entry_hdl);
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
                                                  uint16_t smac_index,
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
        p4_pd_dc_set_l2_rewrite_action_spec_t action_spec;
        memset(&action_spec, 0, sizeof(p4_pd_dc_set_l2_rewrite_action_spec_t));
        action_spec.action_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_NONE;
        action_spec.action_tunnel_index = 0;

        status = p4_pd_dc_rewrite_table_add_with_set_l2_rewrite(
            g_sess_hdl,
            p4_pd_device,
            &match_spec,
            &action_spec,
            entry_hdl);
    } else {
        p4_pd_dc_set_l3_unicast_rewrite_action_spec_t action_spec;
        memset(&action_spec, 0,
               sizeof(p4_pd_dc_set_l3_unicast_rewrite_action_spec_t));
        action_spec.action_bd = bd;
        action_spec.action_smac_idx = smac_index;
        memcpy(action_spec.action_dmac, &dmac, ETH_LEN); 
        action_spec.action_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_NONE;
        action_spec.action_tunnel_index = 0;

        status = p4_pd_dc_rewrite_table_add_with_set_l3_unicast_rewrite(
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
                                                 uint16_t smac_index,
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
        default:
            status = SWITCH_STATUS_INVALID_TUNNEL_TYPE;
            return status;
    }

    if (rw_type == SWITCH_API_NEIGHBOR_RW_TYPE_L2) {
        p4_pd_dc_set_l2_rewrite_action_spec_t action_spec;
        action_spec.action_tunnel_type = tunnel_type;
        action_spec.action_tunnel_index = tunnel_index;
        status = p4_pd_dc_rewrite_table_add_with_set_l2_rewrite(g_sess_hdl,
                                                                p4_pd_device,
                                                                &match_spec,
                                                                &action_spec,
                                                                entry_hdl);
    } else {
        p4_pd_dc_set_l3_unicast_rewrite_action_spec_t action_spec;
        memset(&action_spec, 0,
               sizeof(p4_pd_dc_set_l3_unicast_rewrite_action_spec_t));
        action_spec.action_bd = bd;
        action_spec.action_smac_idx = smac_index;
        memcpy(action_spec.action_dmac, &dmac, ETH_LEN); 
        action_spec.action_tunnel_type = tunnel_type;
        action_spec.action_tunnel_index = tunnel_index;
        status = p4_pd_dc_rewrite_table_add_with_set_l3_unicast_rewrite(
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
                                                     uint16_t smac_index,
                                                     switch_mac_addr_t dmac,
                                                     switch_neighbor_rw_type_t rw_type,
                                                     p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t                              status = 0;

    if (rw_type == SWITCH_API_NEIGHBOR_RW_TYPE_L2) {
        p4_pd_dc_set_l2_rewrite_action_spec_t action_spec;
        memset(&action_spec, 0, sizeof(p4_pd_dc_set_l2_rewrite_action_spec_t));
        action_spec.action_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_NONE;
        action_spec.action_tunnel_index = 0;
        status = p4_pd_dc_rewrite_table_modify_with_set_l2_rewrite(
            g_sess_hdl,
            device,
            entry_hdl,
            &action_spec);
    } else {
        p4_pd_dc_set_l3_unicast_rewrite_action_spec_t action_spec;
        memset(&action_spec, 0, sizeof(p4_pd_dc_set_l3_unicast_rewrite_action_spec_t));
        action_spec.action_smac_idx = smac_index;
        memcpy(action_spec.action_dmac, &dmac, ETH_LEN); 
        action_spec.action_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_NONE;
        action_spec.action_tunnel_index = 0;
        status = p4_pd_dc_rewrite_table_modify_with_set_l3_unicast_rewrite(
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
                                                 uint16_t smac_index,
                                                 switch_mac_addr_t dmac,
                                                 switch_neighbor_type_t neigh_type,
                                                 switch_neighbor_rw_type_t rw_type,
                                                 uint16_t tunnel_index,
                                                 switch_encap_type_t encap_type,
                                                 p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t    status = 0;

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
        default:
            status = SWITCH_STATUS_INVALID_TUNNEL_TYPE;
            return status;
    }

    if (rw_type == SWITCH_API_NEIGHBOR_RW_TYPE_L2) {
        p4_pd_dc_set_l2_rewrite_action_spec_t action_spec;
        action_spec.action_tunnel_type = tunnel_type;
        action_spec.action_tunnel_index = tunnel_index;
        status = p4_pd_dc_rewrite_table_modify_with_set_l2_rewrite(g_sess_hdl,
                                                                   device,
                                                                   entry_hdl,
                                                                   &action_spec);
    } else {
        p4_pd_dc_set_l3_unicast_rewrite_action_spec_t action_spec;
        memset(&action_spec, 0,
               sizeof(p4_pd_dc_set_l3_unicast_rewrite_action_spec_t));
        action_spec.action_bd = bd;
        action_spec.action_smac_idx = smac_index;
        memcpy(action_spec.action_dmac, &dmac, ETH_LEN); 
        action_spec.action_tunnel_type = tunnel_type;
        action_spec.action_tunnel_index = tunnel_index;
        status = p4_pd_dc_rewrite_table_modify_with_set_l3_unicast_rewrite(
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
    p4_pd_dc_egress_lag_match_spec_t                    match_spec;
    p4_pd_dc_set_egress_ifindex_action_spec_t           action_spec;
    p4_pd_status_t                                      status = 0;
    p4_pd_dev_target_t                                  p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_egress_lag_match_spec_t));
    memset(&action_spec, 0, sizeof(p4_pd_dc_set_egress_ifindex_action_spec_t));
    match_spec.standard_metadata_egress_port = port_id;
    action_spec.action_egress_ifindex = ifindex;
    if (*entry_hdl) {
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
    return status;
}

p4_pd_status_t
switch_pd_egress_lag_table_delete_entry(switch_device_t device,
                                        p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t status = 0;
    status = p4_pd_dc_egress_lag_table_delete(g_sess_hdl,
                                              device,
                                              entry_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mac_rewrite_table_add_entry(switch_device_t device, uint8_t *smac)
{
    p4_pd_dc_mac_rewrite_match_spec_t                   match_spec;
    p4_pd_dc_rewrite_ipv4_unicast_mac_action_spec_t     ipv4_action_spec;
    p4_pd_status_t                                      status = 0;
    p4_pd_dev_target_t                                  p4_pd_device;
    p4_pd_entry_hdl_t                                   entry_hdl;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_mac_rewrite_match_spec_t));
    memset(&ipv4_action_spec, 0,
           sizeof(p4_pd_dc_rewrite_ipv4_unicast_mac_action_spec_t));
    match_spec.egress_metadata_smac_idx = 0;
    match_spec.ipv4_valid = true;
    match_spec.ipv6_valid = false;
    match_spec.mpls_0__valid = false;
    memcpy(ipv4_action_spec.action_smac, smac, ETH_LEN);

    status = p4_pd_dc_mac_rewrite_table_add_with_rewrite_ipv4_unicast_mac(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        &ipv4_action_spec,
        &entry_hdl);

#ifndef IPV6_DISABLE
    p4_pd_dc_rewrite_ipv6_unicast_mac_action_spec_t ipv6_action_spec;
    memset(&match_spec, 0, sizeof(p4_pd_dc_mac_rewrite_match_spec_t));
    memset(&ipv6_action_spec, 0,
           sizeof(p4_pd_dc_rewrite_ipv6_unicast_mac_action_spec_t));
    match_spec.egress_metadata_smac_idx = 0;
    match_spec.ipv4_valid = false;
    match_spec.ipv6_valid = true;
    match_spec.mpls_0__valid = false;
    memcpy(ipv6_action_spec.action_smac, smac, ETH_LEN);

    status = p4_pd_dc_mac_rewrite_table_add_with_rewrite_ipv6_unicast_mac(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        &ipv6_action_spec,
        &entry_hdl);
#endif /* IPV6_DISABLE */

#ifndef MPLS_DISABLE
    p4_pd_dc_rewrite_mpls_mac_action_spec_t mpls_action_spec;
    memset(&match_spec, 0, sizeof(p4_pd_dc_mac_rewrite_match_spec_t));
    memset(&mpls_action_spec, 0,
           sizeof(p4_pd_dc_rewrite_mpls_mac_action_spec_t));
    match_spec.egress_metadata_smac_idx = 0;
    match_spec.ipv4_valid = false;
    match_spec.ipv6_valid = false;
    match_spec.mpls_0__valid = true;
    memcpy(mpls_action_spec.action_smac, smac, ETH_LEN);

    status = p4_pd_dc_mac_rewrite_table_add_with_rewrite_mpls_mac(
        g_sess_hdl,
        p4_pd_device,
        &match_spec,
        &mpls_action_spec,
        &entry_hdl);
#endif /* MPLS_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_sup_rewrite_add_entry(switch_device_t device, switch_port_t port_id)
{
    p4_pd_status_t                          status = 0;
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_rid_table_add_entry(switch_device_t device,
                              uint16_t rid,
                              uint32_t bd,
                              bool inner_replica,
                              uint32_t nhop_index,
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
        memset(&action_spec, 0, sizeof(p4_pd_dc_outer_replica_from_rid_action_spec_t));
        action_spec.action_bd = bd;
        action_spec.action_nexthop_index = nhop_index;
        status = p4_pd_dc_rid_table_add_with_outer_replica_from_rid(g_sess_hdl,
                                                                 p4_pd_device,
                                                                 &match_spec,
                                                                 &action_spec,
                                                                 entry_hdl);
    } else {
        p4_pd_dc_inner_replica_from_rid_action_spec_t action_spec;
        memset(&action_spec, 0, sizeof(p4_pd_dc_inner_replica_from_rid_action_spec_t));
        action_spec.action_bd = bd;
        action_spec.action_nexthop_index = nhop_index;
        status = p4_pd_dc_rid_table_add_with_inner_replica_from_rid(g_sess_hdl,
                                                                 p4_pd_device,
                                                                 &match_spec,
                                                                 &action_spec,
                                                                 entry_hdl);
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
    match_spec.ingress_metadata_ingress_bd = bd_index;
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

    status = mc_mgrp_create(g_mc_sess_hdl, p4_pd_device.device_id,
                               mgid_index,
                               &mcast_info->mgrp_hdl);
#endif /* P4_MULTICAST_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mcast_mgrp_tree_delete(switch_device_t device,
                                 switch_mcast_info_t *mcast_info)
{
    p4_pd_status_t             status = 0;
#ifndef P4_MULTICAST_DISABLE
    status = mc_mgrp_destroy(g_mc_sess_hdl, mcast_info->mgrp_hdl);
#endif /* P4_MULTICAST_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mcast_l1_add_entry(switch_device_t device, switch_mcast_l1_node_t *l1_node)
{
    p4_pd_status_t            status = 0;
#ifndef P4_MULTICAST_DISABLE

    status = mc_l1_node_create(g_mc_sess_hdl,
                               SWITCH_MCAST_L1_RID(l1_node),
                               &(SWITCH_MCAST_L1_INFO_L1_HDL(l1_node)));
#endif /* P4_MULTICAST_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mcast_l1_delete_entry(switch_device_t device, switch_mcast_l1_node_t *l1_node)
{
    p4_pd_status_t            status = 0;
#ifndef P4_MULTICAST_DISABLE

    status = mc_l1_node_destroy(g_mc_sess_hdl, SWITCH_MCAST_L1_INFO_L1_HDL(l1_node));
    SWITCH_MCAST_L1_INFO_L1_HDL(l1_node) = 0;
#endif /* P4_MULTICAST_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mcast_l2_add_entry(switch_device_t device, switch_mcast_l1_node_t *l1_node)
{
    p4_pd_status_t            status = 0;
#ifndef P4_MULTICAST_DISABLE

    if (SWITCH_MCAST_L1_INFO_L2_HDL(l1_node)) {
        status = mc_l2_node_update(g_mc_sess_hdl,
                                   SWITCH_MCAST_L1_INFO_L2_HDL(l1_node),
                                   SWITCH_MCAST_L1_INFO_PORT_MAP(l1_node),
                                   SWITCH_MCAST_L1_INFO_LAG_MAP(l1_node));
    } else {
        status = mc_l2_node_create(g_mc_sess_hdl,
                                   SWITCH_MCAST_L1_INFO_L1_HDL(l1_node),
                                   SWITCH_MCAST_L1_INFO_PORT_MAP(l1_node),
                                   SWITCH_MCAST_L1_INFO_LAG_MAP(l1_node),
                                   &(SWITCH_MCAST_L1_INFO_L2_HDL(l1_node)));
    }
#endif /* P4_MULTICAST_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mcast_l2_delete_entry(switch_device_t device, switch_mcast_l1_node_t *l1_node)
{
    p4_pd_status_t            status = 0;
#ifndef P4_MULTICAST_DISABLE

    status = mc_l2_node_destroy(g_mc_sess_hdl, SWITCH_MCAST_L1_INFO_L2_HDL(l1_node));
    SWITCH_MCAST_L1_INFO_L2_HDL(l1_node) = 0;
#endif /* P4_MULTICAST_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mcast_mgid_table_add_entry(switch_device_t device, mc_mgrp_hdl_t mgid_hdl,
                                     switch_mcast_l1_node_t *l1_node)
{
    p4_pd_status_t               status = 0;
#ifndef P4_MULTICAST_DISABLE
    status = mc_l1_associate_node(g_mc_sess_hdl, mgid_hdl,
                                  SWITCH_MCAST_L1_INFO_L1_HDL(l1_node));
#endif /* P4_MULTICAST_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mcast_lag_port_map_update(switch_device_t device, uint16_t lag_index,
                                    switch_mc_port_map_t port_map)
{        
    p4_pd_status_t            status = 0;
#ifndef P4_MULTICAST_DISABLE
    status = mc_l2_lag_update(g_mc_sess_hdl, device, lag_index, port_map);
#endif /* P4_MULTICAST_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_system_acl_table_add_entry(switch_device_t device,
                                     uint16_t if_label, uint16_t bd_label,
                                     uint16_t priority,
                                     switch_acl_system_key_value_pair_t *system_acl,
                                     switch_acl_system_action_t action_type,
                                     switch_acl_action_params_t *action_params,
                                     p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t                             status = 0;
    p4_pd_dev_target_t                         p4_pd_device;
    p4_pd_dc_system_acl_match_spec_t      match_spec;
    int i = 0;

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

    for (i = 0; i < SWITCH_ACL_SYSTEM_FIELD_MAX; i++) {
        switch (i) {
            case SWITCH_ACL_SYSTEM_FIELD_IPV4_SRC:
                if(system_acl[i].field == i) {
                    match_spec.ipv4_metadata_lkp_ipv4_sa = system_acl[i].value.ipv4_source;
                    match_spec.ipv4_metadata_lkp_ipv4_sa_mask = system_acl[i].mask.u.mask & 0xFFFFFFFF;
                }
                else {
                    match_spec.ipv4_metadata_lkp_ipv4_sa_mask = 0;
                }
                break;
            case SWITCH_ACL_SYSTEM_FIELD_IPV4_DEST:
                if(system_acl[i].field == i) {
                    match_spec.ipv4_metadata_lkp_ipv4_da = system_acl[i].value.ipv4_dest;
                    match_spec.ipv4_metadata_lkp_ipv4_da_mask = system_acl[i].mask.u.mask & 0xFFFFFFFF;
                }
                else {
                    match_spec.ipv4_metadata_lkp_ipv4_da_mask = 0;
                }
                break;
            case SWITCH_ACL_SYSTEM_FIELD_IP_PROTO:
                if(system_acl[i].field == i) {
                    match_spec.l3_metadata_lkp_ip_proto = system_acl[i].value.ip_proto;
                    match_spec.l3_metadata_lkp_ip_proto_mask = system_acl[i].mask.u.mask & 0xFF;
                }
                else {
                    match_spec.l3_metadata_lkp_ip_proto_mask = 0;
                }
                break;
            case SWITCH_ACL_SYSTEM_FIELD_ETH_TYPE:
                if(system_acl[i].field == i) {
                    match_spec.l2_metadata_lkp_mac_type = system_acl[i].value.eth_type;
                    match_spec.l2_metadata_lkp_mac_type_mask = system_acl[i].mask.u.mask & 0xFFFF;
                }
                else {
                    match_spec.l2_metadata_lkp_mac_type_mask = 0;
                }
                break;
            case SWITCH_ACL_SYSTEM_FIELD_SOURCE_MAC:
                // match_spec.l2_metadata_lkp_mac_sa = system_acl[i].value.
                break;
            case SWITCH_ACL_SYSTEM_FIELD_DEST_MAC:
                // match_spec.l2_metadata_lkp_mac_da = system_acl[i].value.
                memcpy(match_spec.l2_metadata_lkp_mac_da, system_acl[i].value.dest_mac.mac_addr, ETH_LEN);
                memcpy(match_spec.l2_metadata_lkp_mac_da_mask, &system_acl[i].mask.u.mask, ETH_LEN);
                break;

            case SWITCH_ACL_SYSTEM_FIELD_URPF_CHECK:
                match_spec.l3_metadata_urpf_check_fail = system_acl[i].value.urpf_check_fail;
                match_spec.l3_metadata_urpf_check_fail_mask = system_acl[i].mask.u.mask & 0xFF;
                break;

            case SWITCH_ACL_SYSTEM_FIELD_ACL_DENY:
                match_spec.acl_metadata_acl_deny = system_acl[i].value.acl_deny;
                match_spec.acl_metadata_acl_deny_mask = system_acl[i].mask.u.mask & 0xFF;
                break;

            case SWITCH_ACL_SYSTEM_FIELD_IPSG_CHECK:
                match_spec.security_metadata_ipsg_check_fail = system_acl[i].value.ipsg_check;
                match_spec.security_metadata_ipsg_check_fail_mask = system_acl[i].mask.u.mask & 0x1;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_RACL_DENY:
                match_spec.acl_metadata_racl_deny = system_acl[i].value.racl_deny;
                match_spec.acl_metadata_racl_deny_mask = system_acl[i].mask.u.mask & 0x1;
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
                match_spec.l3_metadata_same_bd_check_mask = system_acl[i].mask.u.mask & 0x1;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_TTL:
                match_spec.l3_metadata_lkp_ip_ttl = system_acl[i].value.ttl;
                match_spec.l3_metadata_lkp_ip_ttl_mask = system_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_SYSTEM_FIELD_EGRESS_PORT:
                match_spec.standard_metadata_egress_spec = system_acl[i].value.out_port;
                match_spec.standard_metadata_egress_spec_mask = system_acl[i].mask.u.mask & 0xFF;
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
            default:
                break;
        }
    }

    switch (action_type) {
        case SWITCH_ACL_ACTION_NOP:
            status = p4_pd_dc_system_acl_table_add_with_nop(g_sess_hdl,
                                                        p4_pd_device,
                                                        &match_spec, 
                                                        priority,
                                                        entry_hdl);
            break;
        case SWITCH_ACL_ACTION_REDIRECT_TO_CPU:
            status = p4_pd_dc_system_acl_table_add_with_redirect_to_cpu(g_sess_hdl,
                                                        p4_pd_device,
                                                        &match_spec, 
                                                        priority,
                                                        entry_hdl);
            break;
        case SWITCH_ACL_ACTION_COPY_TO_CPU:
            status = p4_pd_dc_system_acl_table_add_with_copy_to_cpu(g_sess_hdl,
                                                        p4_pd_device,
                                                        &match_spec,
                                                        priority,
                                                        entry_hdl);
            break;
        case SWITCH_ACL_ACTION_DROP:
            status = p4_pd_dc_system_acl_table_add_with_drop_packet(g_sess_hdl,
                                                        p4_pd_device,
                                                        &match_spec, 
                                                        priority,
                                                        entry_hdl);
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
#ifndef P4_MPLS_DISABLE
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
                    action_spec.action_uuc_mc_index = handle_to_id(bd_info->uuc_mc_index);
                    action_spec.action_umc_mc_index = handle_to_id(bd_info->umc_mc_index);
                    action_spec.action_bcast_mc_index = handle_to_id(bd_info->bcast_mc_index);
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
                    action_spec.action_tunnel_type =
                        switch_pd_get_mpls_tunnel_type(mpls_encap);
                    action_spec.action_vrf = handle_to_id(mpls_encap->vrf_handle);
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
#endif /* P4_MPLS_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mpls_table_delete_entry(switch_device_t device, p4_pd_entry_hdl_t entry_hdl)
{
    p4_pd_status_t                          status = 0;
#ifndef P4_MPLS_DISABLE
    status = p4_pd_dc_mpls_table_delete(g_sess_hdl, device, entry_hdl);
#endif /* P4_MPLS_DISABLE */
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
#ifndef P4_MPLS_DISABLE
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_tunnel_rewrite_match_spec_t match_spec;
    switch_mpls_t *mpls_stack = NULL;
    uint8_t header_count = 1;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_tunnel_rewrite_match_spec_t));
    match_spec.tunnel_metadata_tunnel_index = tunnel_index;

    memset(&mpls_stack, 0, SWITCH_MPLS_LABEL_MAX * sizeof(switch_mpls_t));

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
#endif /* P4_MPLS_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_rewrite_table_mpls_rewrite_add_entry(switch_device_t device,
                                               uint16_t bd,
                                               uint16_t nhop_index,
                                               uint16_t tunnel_index,
                                               switch_neighbor_type_t neigh_type,
                                               uint16_t smac_index,
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
            action_spec.action_tunnel_index = tunnel_index;
            action_spec.action_header_count = header_count;
            action_spec.action_smac_idx = smac_index;
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
            action_spec.action_label = label;
            action_spec.action_tunnel_index = tunnel_index;
            action_spec.action_header_count = header_count;
            action_spec.action_smac_idx = smac_index;
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
            p4_pd_dc_set_mpls_swap_push_rewrite_l3_action_spec_t action_spec;
            memset(&action_spec, 0, sizeof(p4_pd_dc_set_mpls_swap_push_rewrite_l3_action_spec_t));
            action_spec.action_label = label;
            action_spec.action_tunnel_index = tunnel_index;
            action_spec.action_header_count = header_count;
            action_spec.action_smac_idx = smac_index;
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
                                   switch_acl_ip_key_value_pair_t *ip_acl,
                                   switch_acl_ip_action_t action,
                                   p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_ACL_DISABLE) && !defined(P4_IPV4_DISABLE)
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_ip_acl_match_spec_t match_spec;
    int i = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_ip_acl_match_spec_t));

    if (if_label) {
        match_spec.acl_metadata_if_label = if_label;
        match_spec.acl_metadata_if_label_mask = 0xFFFF;
    }
    if (bd_label) {
        match_spec.acl_metadata_bd_label = bd_label;
        match_spec.acl_metadata_bd_label_mask = 0xFFFF;
    }
    for (i = 0; i < SWITCH_ACL_IP_FIELD_MAX; i++) {
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
                match_spec.l3_metadata_lkp_icmp_type = ip_acl[i].value.icmp_type;
                match_spec.l3_metadata_lkp_icmp_type_mask = ip_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_IP_FIELD_ICMP_CODE:
                match_spec.l3_metadata_lkp_icmp_code = ip_acl[i].value.icmp_code;
                match_spec.l3_metadata_lkp_icmp_code_mask = ip_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_IP_FIELD_TCP_FLAGS:
                match_spec.tcp_flags = ip_acl[i].value.tcp_flags;
                match_spec.tcp_flags_mask = ip_acl[i].mask.u.mask & 0xFF;
                break;
            case SWITCH_ACL_IP_FIELD_TTL:
                match_spec.l3_metadata_lkp_ip_ttl = ip_acl[i].value.ttl;
                match_spec.l3_metadata_lkp_ip_ttl_mask = ip_acl[i].mask.u.mask & 0xFF;
                break;

            case SWITCH_ACL_IP_FIELD_ETH_TYPE:
                match_spec.l2_metadata_lkp_mac_type = ip_acl[i].value.eth_type;
                match_spec.l2_metadata_lkp_mac_type_mask = ip_acl[i].mask.u.mask & 0xFFFF;
                break;
            default:
                break;
        }
    }
    switch (action) {
        case SWITCH_ACL_ACTION_DROP:
            status = p4_pd_dc_ip_acl_table_add_with_acl_deny(g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            break;
        case SWITCH_ACL_ACTION_PERMIT:
            status = p4_pd_dc_ip_acl_table_add_with_acl_permit(g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            break;
        case SWITCH_ACL_ACTION_LOG:
            status = p4_pd_dc_ip_acl_table_add_with_acl_log(g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            break;
        case SWITCH_ACL_ACTION_REDIRECT:
            {
                p4_pd_dc_acl_redirect_nexthop_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(p4_pd_dc_acl_redirect_nexthop_action_spec_t));
                p4_pd_dc_ip_acl_table_add_with_acl_redirect_nexthop(g_sess_hdl, p4_pd_device, &match_spec,
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
    return status;
}

p4_pd_status_t
switch_pd_ipv6_acl_table_add_entry(switch_device_t device, uint16_t if_label,
                                   uint16_t bd_label, uint16_t priority,
                                   switch_acl_ipv6_key_value_pair_t *ipv6_acl,
                                   switch_acl_ipv6_action_t action,
                                   p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_IPV6_DISABLE) && !defined(P4_ACL_DISABLE)
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_ipv6_acl_match_spec_t match_spec;
    int i = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_ipv6_acl_match_spec_t));

    if (if_label) {
        match_spec.acl_metadata_if_label = if_label;
        match_spec.acl_metadata_if_label_mask = 0xFFFF;
    }
    if (bd_label) {
        match_spec.acl_metadata_bd_label = bd_label;
        match_spec.acl_metadata_bd_label_mask = 0xFFFF;
    }
    for (i = 0; i < SWITCH_ACL_IPV6_FIELD_MAX; i++) {
        switch(ipv6_acl[i].field) {
            case SWITCH_ACL_IPV6_FIELD_IPV6_SRC:
                break;
            case SWITCH_ACL_IPV6_FIELD_IPV6_DEST:
                break;
            case SWITCH_ACL_IPV6_FIELD_IP_PROTO:
                    match_spec.l3_metadata_lkp_ip_proto = ipv6_acl[i].value.ip_proto;
                    match_spec.l3_metadata_lkp_ip_proto_mask = ipv6_acl[i].mask.u.mask.low & 0xFF;
                break;
            case SWITCH_ACL_IPV6_FIELD_L4_SOURCE_PORT:
                    match_spec.l3_metadata_lkp_l4_sport = ipv6_acl[i].value.l4_source_port;
                    match_spec.l3_metadata_lkp_l4_sport_mask = ipv6_acl[i].mask.u.mask.low & 0xFFFF;
                break;
            case SWITCH_ACL_IPV6_FIELD_L4_DEST_PORT:
                    match_spec.l3_metadata_lkp_l4_dport = ipv6_acl[i].value.l4_dest_port;
                    match_spec.l3_metadata_lkp_l4_dport_mask = ipv6_acl[i].mask.u.mask.low & 0xFFFF;
                break;
            case SWITCH_ACL_IPV6_FIELD_ICMP_TYPE:
                    match_spec.l3_metadata_lkp_icmp_type = ipv6_acl[i].value.icmp_type;
                    match_spec.l3_metadata_lkp_icmp_type_mask = ipv6_acl[i].mask.u.mask.low & 0xFF;
                break;
            case SWITCH_ACL_IPV6_FIELD_ICMP_CODE:
                    match_spec.l3_metadata_lkp_icmp_code = ipv6_acl[i].value.icmp_code;
                    match_spec.l3_metadata_lkp_icmp_code_mask = ipv6_acl[i].mask.u.mask.low & 0xFF;
                break;
            case SWITCH_ACL_IPV6_FIELD_TCP_FLAGS:
                    match_spec.tcp_flags = ipv6_acl[i].value.tcp_flags;
                    match_spec.tcp_flags_mask = ipv6_acl[i].mask.u.mask.low & 0xFF;
                break;
            case SWITCH_ACL_IPV6_FIELD_TTL:
                break;
            case SWITCH_ACL_IPV6_FIELD_ETH_TYPE:
                break;
            default:
                break;
        }
    }
    switch (action) {
        case SWITCH_ACL_ACTION_DROP:
            status = p4_pd_dc_ipv6_acl_table_add_with_acl_deny(g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            break;
        case SWITCH_ACL_ACTION_PERMIT:
            status = p4_pd_dc_ipv6_acl_table_add_with_acl_permit(g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            break;
        case SWITCH_ACL_ACTION_LOG:
            status = p4_pd_dc_ipv6_acl_table_add_with_acl_log(g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            break;
        case SWITCH_ACL_ACTION_REDIRECT:
            {
                p4_pd_dc_acl_redirect_nexthop_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(p4_pd_dc_acl_redirect_nexthop_action_spec_t));
                status = p4_pd_dc_ipv6_acl_table_add_with_acl_redirect_nexthop(g_sess_hdl, p4_pd_device, &match_spec,
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
    return status;
}

p4_pd_status_t
switch_pd_ipv4_racl_table_add_entry(switch_device_t device, uint16_t if_label,
                                    uint16_t bd_label, uint16_t priority,
                                    switch_acl_ip_racl_key_value_pair_t *ip_racl,
                                    switch_acl_ip_action_t action,
                                    p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_ACL_DISABLE) && !defined(P4_IPV4_DISABLE)
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_ipv4_racl_match_spec_t match_spec;
    int i = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_ipv6_racl_match_spec_t));

    if (bd_label) {
        match_spec.acl_metadata_bd_label = bd_label;
        match_spec.acl_metadata_bd_label_mask = 0xFFFF;
    }
    for (i = 0; i < SWITCH_ACL_IP_RACL_FIELD_MAX; i++) {
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
            status = p4_pd_dc_ipv4_racl_table_add_with_racl_deny(g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            break;
        case SWITCH_ACL_ACTION_PERMIT:
            status = p4_pd_dc_ipv4_racl_table_add_with_racl_permit(g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            break;
        case SWITCH_ACL_ACTION_LOG:
            status = p4_pd_dc_ipv4_racl_table_add_with_racl_log(g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            break;
        case SWITCH_ACL_ACTION_REDIRECT:
            {
                p4_pd_dc_racl_redirect_nexthop_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(p4_pd_dc_racl_redirect_nexthop_action_spec_t));
                status = p4_pd_dc_ipv4_racl_table_add_with_racl_redirect_nexthop(g_sess_hdl, p4_pd_device, &match_spec,
                                                                                 priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_SET_NATMODE:
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
    return status;
}

p4_pd_status_t
switch_pd_ipv6_racl_table_add_entry(switch_device_t device, uint16_t if_label,
                                    uint16_t bd_label, uint16_t priority,
                                    switch_acl_ipv6_racl_key_value_pair_t *ipv6_racl,
                                    switch_acl_ipv6_action_t action,
                                    p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_ACL_DISABLE
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_ipv6_racl_match_spec_t match_spec;
    int i = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_ipv6_racl_match_spec_t));

    if (bd_label) {
        match_spec.acl_metadata_bd_label = bd_label;
        match_spec.acl_metadata_bd_label_mask = 0xFFFF;
    }
    for (i = 0; i < SWITCH_ACL_IPV6_RACL_FIELD_MAX; i++) {
        switch(ipv6_racl[i].field) {
            case SWITCH_ACL_IPV6_RACL_FIELD_IPV6_SRC:
                break;
            case SWITCH_ACL_IPV6_RACL_FIELD_IPV6_DEST:
                break;
            case SWITCH_ACL_IPV6_RACL_FIELD_IP_PROTO:
                match_spec.l3_metadata_lkp_ip_proto = ipv6_racl[i].value.ip_proto;
                match_spec.l3_metadata_lkp_ip_proto_mask = ipv6_racl[i].mask.u.mask.low & 0xFF;
                break;
            case SWITCH_ACL_IPV6_RACL_FIELD_L4_SOURCE_PORT:
                match_spec.l3_metadata_lkp_l4_sport = ipv6_racl[i].value.l4_source_port;
                match_spec.l3_metadata_lkp_l4_sport_mask = ipv6_racl[i].mask.u.mask.low & 0xFFFF;
                break;
            case SWITCH_ACL_IPV6_RACL_FIELD_L4_DEST_PORT:
                match_spec.l3_metadata_lkp_l4_dport = ipv6_racl[i].value.l4_dest_port;
                match_spec.l3_metadata_lkp_l4_dport_mask = ipv6_racl[i].mask.u.mask.low & 0xFFFF;
                break;
            default:
                break;
        }
    }
    switch (action) {
        case SWITCH_ACL_ACTION_DROP:
            status = p4_pd_dc_ipv6_racl_table_add_with_racl_deny(g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            break;
        case SWITCH_ACL_ACTION_PERMIT:
            status = p4_pd_dc_ipv6_racl_table_add_with_racl_permit(g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            break;
        case SWITCH_ACL_ACTION_LOG:
            status = p4_pd_dc_ipv6_racl_table_add_with_racl_log(g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            break;
        case SWITCH_ACL_ACTION_REDIRECT:
            {
                p4_pd_dc_racl_redirect_nexthop_action_spec_t action_spec;
                memset(&action_spec, 0, sizeof(p4_pd_dc_racl_redirect_nexthop_action_spec_t));
                p4_pd_dc_ipv6_racl_table_add_with_racl_redirect_nexthop(g_sess_hdl, p4_pd_device, &match_spec,
                                                                        priority, &action_spec, entry_hdl);
            }
            break;
        case SWITCH_ACL_ACTION_SET_NATMODE:
            break;
        default:
            break;
    }
#endif /* P4_ACL_DISABLE */
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
    return status;
}

p4_pd_status_t
switch_pd_mac_acl_table_add_entry(switch_device_t device, uint16_t if_label,
                                  uint16_t bd_label, uint16_t priority,
                                  switch_acl_mac_key_value_pair_t *mac_acl,
                                  switch_acl_mac_action_t action,
                                  p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#if !defined(P4_L2_DISABLE) && !defined(P4_ACL_DISABLE)
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_mac_acl_match_spec_t match_spec;
    int i = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_mac_acl_match_spec_t));

    if (if_label) {
        match_spec.acl_metadata_if_label = if_label;
        match_spec.acl_metadata_if_label_mask = 0xFFFF;
    }
    if (bd_label) {
        match_spec.acl_metadata_bd_label = bd_label;
        match_spec.acl_metadata_bd_label_mask = 0xFFFF;
    }
    for (i = 0; i < SWITCH_ACL_MAC_FIELD_MAX; i++) {
        switch(mac_acl[i].field) {
            case SWITCH_ACL_MAC_FIELD_ETH_TYPE:
                match_spec.l2_metadata_lkp_mac_type = mac_acl[i].value.eth_type;
                match_spec.l2_metadata_lkp_mac_type_mask = mac_acl[i].mask.u.mask & 0xFFFF;
                break;
            case SWITCH_ACL_MAC_FIELD_SOURCE_MAC:
                //match_spec.l2_metadata_lkp_mac_sa = mac_acl[i].value.source_mac;
                //match_spec.l2_metadata_lkp_mac_sa_mask = mac_acl[i].mask.u.mask & 0xFFFFFFFFFFFFFFFFULL;
                break;
            case SWITCH_ACL_MAC_FIELD_DEST_MAC:
                //match_spec.l2_metadata_lkp_mac_da = mac_acl[i].value.dest_mac;
                //match_spec.l2_metadata_lkp_mac_da_mask = mac_acl[i].mask.u.mask & 0xFFFFFFFFFFFFFFFFULL;
                break;
            default:
                break;
        }
    }
    switch (action) {
        case SWITCH_ACL_ACTION_DROP:
            status = p4_pd_dc_mac_acl_table_add_with_acl_deny(g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            break;
        case SWITCH_ACL_ACTION_PERMIT:
            status = p4_pd_dc_mac_acl_table_add_with_acl_permit(g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
            break;
        case SWITCH_ACL_ACTION_LOG:
            status = p4_pd_dc_mac_acl_table_add_with_acl_log(g_sess_hdl, p4_pd_device, &match_spec, priority, entry_hdl);
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
    return status;
}

p4_pd_status_t
switch_pd_qos_acl_table_add_entry(switch_device_t device, uint16_t if_label,
                                  uint16_t bd_label, uint16_t priority,
                                  switch_acl_qos_key_value_pair_t *qos_acl,
                                  switch_acl_mac_action_t action,
                                  p4_pd_entry_hdl_t *entry_hdl)
{
    p4_pd_status_t status = 0;
#ifndef P4_ACL_DISABLE
#ifndef P4_QOS_DISABLE
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_dc_qos_match_spec_t match_spec;
    int i = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_qos_match_spec_t));

    if (if_label) {
        match_spec.acl_metadata_if_label = if_label;
        match_spec.acl_metadata_if_label_mask = 0xFFFF;
    }
    for (i = 0; i < SWITCH_ACL_QOS_FIELD_MAX; i++) {
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
    return status;
}
/*
 * DEFAULT ENTRIES
 * TODO: Remove them once the default action can be specified in P4.
 */

p4_pd_status_t
switch_pd_validate_outer_ethernet_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_validate_outer_ethernet_set_default_action_set_valid_outer_unicast_packet_untagged(
                                                                                g_sess_hdl,
                                                                                p4_pd_device,
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
    status = p4_pd_dc_validate_outer_ipv4_packet_set_default_action_set_valid_outer_ipv4_packet(
                                                                                g_sess_hdl,
                                                                                p4_pd_device,
                                                                                &entry_hdl);
#endif /* P4_IPV4_DISABLE */
#ifndef P4_IPV6_DISABLE
    status = p4_pd_dc_validate_outer_ipv6_packet_set_default_action_set_valid_outer_ipv6_packet(
                                                                                g_sess_hdl,
                                                                                p4_pd_device,
                                                                                &entry_hdl);
#endif /* P4_IPV6_DISABLE */
#endif /* P4_L3_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_storm_control_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_STORM_CONTROL_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_storm_control_set_default_action_nop(g_sess_hdl,
                                                             p4_pd_device,
                                                             &entry_hdl);
#endif /* P4_STORM_CONTROL_DISABLE */
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
switch_pd_validate_packet_table_add_default_entry(switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_validate_packet_set_default_action_nop(g_sess_hdl,
                                                               p4_pd_device,
                                                               &entry_hdl);

    p4_pd_dc_validate_packet_match_spec_t vp_match_spec;
    memset(&vp_match_spec, 0, sizeof(p4_pd_dc_validate_packet_match_spec_t));
    vp_match_spec.l2_metadata_lkp_mac_da[0] = 0x01;
    vp_match_spec.l2_metadata_lkp_mac_da_mask[0] = 0xff;
    vp_match_spec.l2_metadata_lkp_mac_da[1] = 0x00;
    vp_match_spec.l2_metadata_lkp_mac_da_mask[1] = 0xff;
    vp_match_spec.l2_metadata_lkp_mac_da[2] = 0x5e;
    vp_match_spec.l2_metadata_lkp_mac_da_mask[2] = 0xff;

    status = p4_pd_dc_validate_packet_table_add_with_set_ip_multicast(g_sess_hdl,
                                                                        p4_pd_device,
                                                                        &vp_match_spec,
                                                                        1000,
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
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_egress_filter_table_add_with_set_egress_filter_drop(
                                                        g_sess_hdl,
                                                        p4_pd_device,
                                                        &entry_hdl);
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
#ifndef P4_TUNNEL_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;
    
    status = p4_pd_dc_egress_bd_map_set_default_action_nop(
                                                             g_sess_hdl,
                                                             p4_pd_device,
                                                             &entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
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
    
    p4_pd_dc_set_l2_rewrite_action_spec_t action_spec;
    memset(&action_spec, 0, sizeof(p4_pd_dc_set_l2_rewrite_action_spec_t));
    action_spec.action_tunnel_type = SWITCH_EGRESS_TUNNEL_TYPE_NONE;
    action_spec.action_tunnel_index = 0;
    status = p4_pd_dc_rewrite_set_default_action_set_l2_rewrite(
                                                       g_sess_hdl,
                                                       p4_pd_device,
                                                       &action_spec,
                                                       &entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mtu_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#if !defined(P4_L3_DISABLE) && !defined(P4_MTU_DISABLE)
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;
    
    status = p4_pd_dc_mtu_set_default_action_nop(g_sess_hdl,
                                                   p4_pd_device,
                                                   &entry_hdl);
#endif /* P4_L3_DISABLE && P4_MTU_DISABLE */
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
switch_pd_mac_rewrite_table_add_default_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;
    
    status = p4_pd_dc_mac_rewrite_set_default_action_nop(g_sess_hdl,
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
    
    status = p4_pd_dc_tunnel_set_default_action_nop(g_sess_hdl,
                                                    p4_pd_device,
                                                    &entry_hdl);
#endif /* P4_TUNNEL_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

/*************** INIT Entries ***************************/

//TODO: This table has to be initialized with the proper
// combination to override the result
p4_pd_status_t
switch_pd_fwd_result_table_add_init_entry(switch_device_t device)
{
    p4_pd_dc_fwd_result_match_spec_t          match_spec;
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.l3_metadata_fib_hit = 1;
    match_spec.l3_metadata_fib_hit_mask = 1;

    status = p4_pd_dc_fwd_result_table_add_with_set_fib_redirect_action(g_sess_hdl,
                                                                        p4_pd_device,
                                                                        &match_spec,
                                                                        1000,
                                                                        &entry_hdl);

    memset(&match_spec, 0, sizeof(p4_pd_dc_fwd_result_match_spec_t));
    match_spec.l2_metadata_l2_redirect = 1;
    match_spec.l2_metadata_l2_redirect_mask = 1;
    status = p4_pd_dc_fwd_result_table_add_with_set_l2_redirect_action(g_sess_hdl,
                                                                       p4_pd_device,
                                                                       &match_spec,
                                                                       1000,
                                                                       &entry_hdl);
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_learn_notify_table_add_init_entry(switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;
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
    match_spec.l2_metadata_stp_state = 0;
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
    match_spec.l2_metadata_stp_state = 1;
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
    match_spec.l2_metadata_stp_state = 2;
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
    match_spec.l2_metadata_stp_state = 3;
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
    match_spec.l2_metadata_stp_state = 0;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_nop(g_sess_hdl,
                                                           p4_pd_device,
                                                           &match_spec,
                                                           1000,
                                                           &entry_hdl);
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_stp_state = 0;
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
    match_spec.l2_metadata_stp_state = 1;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_nop(g_sess_hdl,
                                                           p4_pd_device,
                                                           &match_spec,
                                                           1002,
                                                           &entry_hdl);
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_stp_state = 1;
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
    match_spec.l2_metadata_stp_state = 2;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_nop(g_sess_hdl,
                                                   p4_pd_device,
                                                   &match_spec,
                                                   1004,
                                                   &entry_hdl);
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_stp_state = 2;
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
    match_spec.l2_metadata_stp_state = 3;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_nop(g_sess_hdl,
                                                      p4_pd_device,
                                                      &match_spec,
                                                      1006,
                                                      &entry_hdl);
    memset(&match_spec, 0, sizeof(match_spec));
    match_spec.l2_metadata_stp_state = 3;
    match_spec.l2_metadata_stp_state_mask = 0xF;
    status = p4_pd_dc_learn_notify_table_add_with_generate_learn_notify(
                                                      g_sess_hdl,
                                                      p4_pd_device,
                                                      &match_spec,
                                                      1007,
                                                      &entry_hdl);

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_validate_outer_ethernet_table_init_entry(switch_device_t device)
{
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;
    p4_pd_status_t status = 0;
    p4_pd_dc_validate_outer_ethernet_match_spec_t match_spec;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_outer_ethernet_match_spec_t));
    match_spec.vlan_tag__0__valid = 0;
    match_spec.vlan_tag__1__valid = 0;
    status = p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_unicast_packet_untagged(
                                                              g_sess_hdl,
                                                              p4_pd_device,
                                                              &match_spec,
                                                              1000,
                                                              &entry_hdl);
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_outer_ethernet_match_spec_t));
    match_spec.vlan_tag__0__valid = 1;
    match_spec.vlan_tag__1__valid = 0;
    status = p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_unicast_packet_single_tagged(
                                                              g_sess_hdl,
                                                              p4_pd_device,
                                                              &match_spec,
                                                              1000,
                                                              &entry_hdl);
    memset(&match_spec, 0, sizeof(p4_pd_dc_validate_outer_ethernet_match_spec_t));
    match_spec.vlan_tag__0__valid = 1;
    match_spec.vlan_tag__1__valid = 1;
    status = p4_pd_dc_validate_outer_ethernet_table_add_with_set_valid_outer_unicast_packet_double_tagged(
                                                              g_sess_hdl,
                                                              p4_pd_device,
                                                              &match_spec,
                                                              1000,
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
#ifndef P4_MPLS_DISABLE
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

#endif /* P4_MPLS_DISABLE */
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
switch_pd_compute_multicast_hashes_init_entry(switch_device_t device)
{
    p4_pd_status_t status = 0;
#ifndef P4_MULTICAST_DISABLE
    p4_pd_entry_hdl_t entry_hdl;
    p4_pd_dev_target_t p4_pd_device;

    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    status = p4_pd_dc_compute_multicast_hashes_set_default_action_compute_lkp_ipv4_hash(
            g_sess_hdl,
            p4_pd_device,
            &entry_hdl);

#endif /* P4_MULTICAST_DISABLE */
    p4_pd_complete_operations(g_sess_hdl);
    return status;
}
