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
#include "switch_defines.h"

//#define OUTER_MULTICAST_TREE_ENABLED 0

extern p4_pd_sess_hdl_t g_sess_hdl;

p4_pd_status_t
switch_pd_mcast_table_add_entry(switch_device_t device,
                                uint16_t mgid_index,
                                switch_mcast_mode_t mc_mode,
                                switch_mcast_group_info_t *group_info,
                                bool core_entry, bool vrf_entry,
                                uint16_t rpf_group)
{
    p4_pd_status_t                          status = 0;
#ifndef P4_MULTICAST_DISABLE
    p4_pd_dev_target_t                      p4_pd_device;
    switch_mcast_group_key_t               *group_key;

    group_key = &(group_info->group_key);
    p4_pd_device.device_id = device;
    p4_pd_device.dev_pipe_id = SWITCH_DEV_PIPE_ID;

    if (core_entry) {
#ifndef P4_TUNNEL_DISABLE
        if (group_key->sg_entry) {
            if (SWITCH_MCAST_GROUP_IP_TYPE(group_key) == SWITCH_API_IP_ADDR_V4) {
#ifndef P4_IPV4_DISABLE
                if (vrf_entry) {
                    p4_pd_dc_outer_ipv4_multicast_match_spec_t match_spec;
                    p4_pd_dc_outer_multicast_route_s_g_hit_action_spec_t action_spec;

                    memset(&match_spec, 0, sizeof(p4_pd_dc_outer_ipv4_multicast_match_spec_t));
                    memset(&action_spec, 0, sizeof(p4_pd_dc_outer_multicast_route_s_g_hit_action_spec_t));

                    match_spec.multicast_metadata_ipv4_mcast_key_type = SWITCH_MCAST_KEY_TYPE_VRF;
                    match_spec.multicast_metadata_ipv4_mcast_key = handle_to_id(group_key->bd_vrf_handle);
                    match_spec.ipv4_metadata_lkp_ipv4_sa = SWITCH_MCAST_GROUP_IPV4_SRC_IP(group_key);
                    match_spec.ipv4_metadata_lkp_ipv4_da = SWITCH_MCAST_GROUP_IPV4_GRP_IP(group_key);

#ifdef OUTER_MULTICAST_TREE_ENABLED
                    action_spec.action_mc_index = mgid_index;
#endif /* OUTER_MULTICAST_TREE_ENABLED */
                    action_spec.action_mcast_rpf_group = rpf_group;

                    status = p4_pd_dc_outer_ipv4_multicast_table_add_with_outer_multicast_route_s_g_hit(
                        g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                        &(group_info->outer_hw_entry));
                } else {
                    p4_pd_dc_outer_ipv4_multicast_match_spec_t match_spec;
                    p4_pd_dc_outer_multicast_bridge_s_g_hit_action_spec_t action_spec;

                    memset(&match_spec, 0, sizeof(p4_pd_dc_outer_ipv4_multicast_match_spec_t));
                    memset(&action_spec, 0, sizeof(p4_pd_dc_outer_multicast_bridge_s_g_hit_action_spec_t));

                    match_spec.multicast_metadata_ipv4_mcast_key_type = SWITCH_MCAST_KEY_TYPE_BD;
                    match_spec.multicast_metadata_ipv4_mcast_key = handle_to_id(group_key->bd_vrf_handle);
                    match_spec.ipv4_metadata_lkp_ipv4_sa = SWITCH_MCAST_GROUP_IPV4_SRC_IP(group_key);
                    match_spec.ipv4_metadata_lkp_ipv4_da = SWITCH_MCAST_GROUP_IPV4_GRP_IP(group_key);

#ifdef OUTER_MULTICAST_TREE_ENABLED
                    action_spec.action_mc_index = mgid_index;
#endif /* OUTER_MULTICAST_TREE_ENABLED */

                    status = p4_pd_dc_outer_ipv4_multicast_table_add_with_outer_multicast_bridge_s_g_hit(
                        g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                        &(group_info->outer_hw_entry));
                }
#endif /* P4_IPV4_DISABLE */
            } else {
#ifndef P4_IPV6_DISABLE
                if (vrf_entry) {
                    p4_pd_dc_outer_ipv6_multicast_match_spec_t match_spec;
                    p4_pd_dc_outer_multicast_route_s_g_hit_action_spec_t action_spec;

                    memset(&match_spec, 0, sizeof(p4_pd_dc_outer_ipv6_multicast_match_spec_t));
                    memset(&action_spec, 0, sizeof(p4_pd_dc_outer_multicast_route_s_g_hit_action_spec_t));

                    match_spec.multicast_metadata_ipv6_mcast_key_type = SWITCH_MCAST_KEY_TYPE_VRF;
                    match_spec.multicast_metadata_ipv6_mcast_key = handle_to_id(group_key->bd_vrf_handle);
                    memcpy(&(match_spec.ipv6_metadata_lkp_ipv6_sa),
                           &(SWITCH_MCAST_GROUP_IPV6_SRC_IP(group_key)), 16);
                    memcpy(&(match_spec.ipv6_metadata_lkp_ipv6_da),
                           &(SWITCH_MCAST_GROUP_IPV6_GRP_IP(group_key)), 16);

#ifdef OUTER_MULTICAST_TREE_ENABLED
                    action_spec.action_mc_index = mgid_index;
#endif /* OUTER_MULTICAST_TREE_ENABLED */
                    action_spec.action_mcast_rpf_group = rpf_group;

                    status = p4_pd_dc_outer_ipv6_multicast_table_add_with_outer_multicast_route_s_g_hit(
                        g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                        &(group_info->outer_hw_entry));
                } else {
                    p4_pd_dc_outer_ipv6_multicast_match_spec_t match_spec;
                    p4_pd_dc_outer_multicast_bridge_s_g_hit_action_spec_t action_spec;

                    memset(&match_spec, 0, sizeof(p4_pd_dc_outer_ipv6_multicast_match_spec_t));
                    memset(&action_spec, 0, sizeof(p4_pd_dc_outer_multicast_bridge_s_g_hit_action_spec_t));

                    match_spec.multicast_metadata_ipv6_mcast_key_type = SWITCH_MCAST_KEY_TYPE_BD;
                    match_spec.multicast_metadata_ipv6_mcast_key = handle_to_id(group_key->bd_vrf_handle);
                    memcpy(&(match_spec.ipv6_metadata_lkp_ipv6_sa),
                           &(SWITCH_MCAST_GROUP_IPV6_SRC_IP(group_key)), 16);
                    memcpy(&(match_spec.ipv6_metadata_lkp_ipv6_da),
                           &(SWITCH_MCAST_GROUP_IPV6_GRP_IP(group_key)), 16);

#ifdef OUTER_MULTICAST_TREE_ENABLED
                    action_spec.action_mc_index = mgid_index;
#endif /* OUTER_MULTICAST_TREE_ENABLED */

                    status = p4_pd_dc_outer_ipv6_multicast_table_add_with_outer_multicast_bridge_s_g_hit(
                        g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                        &(group_info->outer_hw_entry));
                }
#endif /* P4_IPV6_DISABLE */
            }
        } else {
            if (SWITCH_MCAST_GROUP_IP_TYPE(group_key) == SWITCH_API_IP_ADDR_V4) {
#ifndef P4_IPV4_DISABLE
                if (vrf_entry) {
                    if (mc_mode == SWITCH_API_MCAST_IPMC_PIM_SM) {
                        p4_pd_dc_outer_ipv4_multicast_star_g_match_spec_t match_spec;
                        p4_pd_dc_outer_multicast_route_sm_star_g_hit_action_spec_t action_spec;

                        memset(&match_spec, 0, sizeof(p4_pd_dc_outer_ipv4_multicast_match_spec_t));
                        memset(&action_spec, 0, sizeof(p4_pd_dc_outer_multicast_route_sm_star_g_hit_action_spec_t));

                        match_spec.multicast_metadata_ipv4_mcast_key_type = SWITCH_MCAST_KEY_TYPE_VRF;
                        match_spec.multicast_metadata_ipv4_mcast_key = handle_to_id(group_key->bd_vrf_handle);
                        match_spec.ipv4_metadata_lkp_ipv4_da = SWITCH_MCAST_GROUP_IPV4_GRP_IP(group_key);
                        match_spec.ipv4_metadata_lkp_ipv4_da_mask = 0xffffffff;

#ifdef OUTER_MULTICAST_TREE_ENABLED
                        action_spec.action_mc_index = mgid_index;
#endif /* OUTER_MULTICAST_TREE_ENABLED */
                        action_spec.action_mcast_rpf_group = rpf_group;

                        status = p4_pd_dc_outer_ipv4_multicast_star_g_table_add_with_outer_multicast_route_sm_star_g_hit(
                            g_sess_hdl, p4_pd_device, &match_spec, 1000,
                            &action_spec, &(group_info->outer_hw_entry));
                    } else {
                        p4_pd_dc_outer_ipv4_multicast_star_g_match_spec_t match_spec;
                        p4_pd_dc_outer_multicast_route_bidir_star_g_hit_action_spec_t action_spec;

                        memset(&match_spec, 0, sizeof(p4_pd_dc_outer_ipv4_multicast_star_g_match_spec_t));
                        memset(&action_spec, 0, sizeof(p4_pd_dc_outer_multicast_route_bidir_star_g_hit_action_spec_t));

                        match_spec.multicast_metadata_ipv4_mcast_key_type = SWITCH_MCAST_KEY_TYPE_VRF;
                        match_spec.multicast_metadata_ipv4_mcast_key = handle_to_id(group_key->bd_vrf_handle);
                        match_spec.ipv4_metadata_lkp_ipv4_da = SWITCH_MCAST_GROUP_IPV4_GRP_IP(group_key);
                        match_spec.ipv4_metadata_lkp_ipv4_da_mask = 0xffffffff;

#ifdef OUTER_MULTICAST_TREE_ENABLED
                        action_spec.action_mc_index = mgid_index;
#endif /* OUTER_MULTICAST_TREE_ENABLED */
                        action_spec.action_mcast_rpf_group = rpf_group;

                        status = p4_pd_dc_outer_ipv4_multicast_star_g_table_add_with_outer_multicast_route_bidir_star_g_hit(
                            g_sess_hdl, p4_pd_device, &match_spec, 1000,
                            &action_spec, &(group_info->outer_hw_entry));
                    }
                } else {
                    p4_pd_dc_outer_ipv4_multicast_star_g_match_spec_t match_spec;
                    p4_pd_dc_outer_multicast_bridge_star_g_hit_action_spec_t action_spec;

                    memset(&match_spec, 0, sizeof(p4_pd_dc_outer_ipv4_multicast_star_g_match_spec_t));
                    memset(&action_spec, 0, sizeof(p4_pd_dc_outer_multicast_bridge_star_g_hit_action_spec_t));

                    match_spec.multicast_metadata_ipv4_mcast_key_type = SWITCH_MCAST_KEY_TYPE_BD;
                    match_spec.multicast_metadata_ipv4_mcast_key = handle_to_id(group_key->bd_vrf_handle);
                    match_spec.ipv4_metadata_lkp_ipv4_da = SWITCH_MCAST_GROUP_IPV4_GRP_IP(group_key);
                    match_spec.ipv4_metadata_lkp_ipv4_da_mask = 0xffffffff;

#ifdef OUTER_MULTICAST_TREE_ENABLED
                    action_spec.action_mc_index = mgid_index;
#endif /* OUTER_MULTICAST_TREE_ENABLED */

                    status = p4_pd_dc_outer_ipv4_multicast_star_g_table_add_with_outer_multicast_bridge_star_g_hit(
                        g_sess_hdl, p4_pd_device, &match_spec, 1000,
                        &action_spec, &(group_info->outer_hw_entry));
                }
#endif /* P4_IPV4_DISABLE */
            } else {
#ifndef P4_IPV6_DISABLE
                if (vrf_entry) {
                    if (mc_mode == SWITCH_API_MCAST_IPMC_PIM_SM) {
                        p4_pd_dc_outer_ipv6_multicast_star_g_match_spec_t match_spec;
                        p4_pd_dc_outer_multicast_route_sm_star_g_hit_action_spec_t action_spec;

                        memset(&match_spec, 0, sizeof(p4_pd_dc_outer_ipv6_multicast_match_spec_t));
                        memset(&action_spec, 0, sizeof(p4_pd_dc_outer_multicast_route_sm_star_g_hit_action_spec_t));

                        match_spec.multicast_metadata_ipv6_mcast_key_type = SWITCH_MCAST_KEY_TYPE_VRF;
                        match_spec.multicast_metadata_ipv6_mcast_key = handle_to_id(group_key->bd_vrf_handle);
                        memcpy(&(match_spec.ipv6_metadata_lkp_ipv6_da),
                               &(SWITCH_MCAST_GROUP_IPV6_GRP_IP(group_key)), 16);
                        memset(&(match_spec.ipv6_metadata_lkp_ipv6_da_mask), 0xff, 16);

#ifdef OUTER_MULTICAST_TREE_ENABLED
                        action_spec.action_mc_index = mgid_index;
#endif /* OUTER_MULTICAST_TREE_ENABLED */
                        action_spec.action_mcast_rpf_group = rpf_group;

                        status = p4_pd_dc_outer_ipv6_multicast_star_g_table_add_with_outer_multicast_route_sm_star_g_hit(
                            g_sess_hdl, p4_pd_device, &match_spec, 1000,
                            &action_spec, &(group_info->outer_hw_entry));
                    } else {
                        p4_pd_dc_outer_ipv6_multicast_star_g_match_spec_t match_spec;
                        p4_pd_dc_outer_multicast_route_bidir_star_g_hit_action_spec_t action_spec;

                        memset(&match_spec, 0, sizeof(p4_pd_dc_outer_ipv6_multicast_star_g_match_spec_t));
                        memset(&action_spec, 0, sizeof(p4_pd_dc_outer_multicast_route_bidir_star_g_hit_action_spec_t));

                        match_spec.multicast_metadata_ipv6_mcast_key_type = SWITCH_MCAST_KEY_TYPE_VRF;
                        match_spec.multicast_metadata_ipv6_mcast_key = handle_to_id(group_key->bd_vrf_handle);
                        memcpy(&(match_spec.ipv6_metadata_lkp_ipv6_da),
                               &(SWITCH_MCAST_GROUP_IPV6_GRP_IP(group_key)), 16);
                        memset(&(match_spec.ipv6_metadata_lkp_ipv6_da_mask), 0xff, 16);

#ifdef OUTER_MULTICAST_TREE_ENABLED
                        action_spec.action_mc_index = mgid_index;
#endif /* OUTER_MULTICAST_TREE_ENABLED */
                        action_spec.action_mcast_rpf_group = rpf_group;

                        status = p4_pd_dc_outer_ipv6_multicast_star_g_table_add_with_outer_multicast_route_bidir_star_g_hit(
                            g_sess_hdl, p4_pd_device, &match_spec, 1000,
                            &action_spec, &(group_info->outer_hw_entry));
                    }
                } else {
                    p4_pd_dc_outer_ipv6_multicast_star_g_match_spec_t match_spec;
                    p4_pd_dc_outer_multicast_bridge_star_g_hit_action_spec_t action_spec;

                    memset(&match_spec, 0, sizeof(p4_pd_dc_outer_ipv6_multicast_star_g_match_spec_t));
                    memset(&action_spec, 0, sizeof(p4_pd_dc_outer_multicast_bridge_star_g_hit_action_spec_t));

                    match_spec.multicast_metadata_ipv6_mcast_key_type = SWITCH_MCAST_KEY_TYPE_BD;
                    match_spec.multicast_metadata_ipv6_mcast_key = handle_to_id(group_key->bd_vrf_handle);
                    memcpy(&(match_spec.ipv6_metadata_lkp_ipv6_da),
                           &(SWITCH_MCAST_GROUP_IPV6_GRP_IP(group_key)), 16);
                    memset(&(match_spec.ipv6_metadata_lkp_ipv6_da_mask), 0xff, 16);

#ifdef OUTER_MULTICAST_TREE_ENABLED
                    action_spec.action_mc_index = mgid_index;
#endif /* OUTER_MULTICAST_TREE_ENABLED */

                    status = p4_pd_dc_outer_ipv6_multicast_star_g_table_add_with_outer_multicast_bridge_star_g_hit(
                        g_sess_hdl, p4_pd_device, &match_spec, 1000,
                        &action_spec, &(group_info->outer_hw_entry));
                }
#endif /* P4_IPV6_DISABLE */
            }
        }
#endif /* P4_TUNNEL_DISABLE */
    }

    if (group_key->sg_entry) {
        if (SWITCH_MCAST_GROUP_IP_TYPE(group_key) == SWITCH_API_IP_ADDR_V4) {
#ifndef P4_IPV4_DISABLE
            if (vrf_entry) {
                p4_pd_dc_ipv4_multicast_route_match_spec_t match_spec;
                p4_pd_dc_multicast_route_s_g_hit_action_spec_t action_spec;

                memset(&match_spec, 0, sizeof(p4_pd_dc_ipv4_multicast_route_match_spec_t));
                match_spec.l3_metadata_vrf = handle_to_id(group_key->bd_vrf_handle);
                match_spec.ipv4_metadata_lkp_ipv4_sa = SWITCH_MCAST_GROUP_IPV4_SRC_IP(group_key);
                match_spec.ipv4_metadata_lkp_ipv4_da = SWITCH_MCAST_GROUP_IPV4_GRP_IP(group_key);

                memset(&action_spec, 0, sizeof(p4_pd_dc_multicast_route_s_g_hit_action_spec_t));
                action_spec.action_mc_index = mgid_index;
                action_spec.action_mcast_rpf_group = rpf_group;

                status = p4_pd_dc_ipv4_multicast_route_table_add_with_multicast_route_s_g_hit(
                    g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                    &(group_info->inner_hw_entry));
            } else {
                p4_pd_dc_ipv4_multicast_bridge_match_spec_t match_spec;
                p4_pd_dc_multicast_bridge_s_g_hit_action_spec_t action_spec;

                memset(&match_spec, 0, sizeof(p4_pd_dc_ipv4_multicast_bridge_match_spec_t));
                match_spec.ingress_metadata_bd = handle_to_id(group_key->bd_vrf_handle);
                match_spec.ipv4_metadata_lkp_ipv4_sa = SWITCH_MCAST_GROUP_IPV4_SRC_IP(group_key);
                match_spec.ipv4_metadata_lkp_ipv4_da = SWITCH_MCAST_GROUP_IPV4_GRP_IP(group_key);

                memset(&action_spec, 0, sizeof(p4_pd_dc_multicast_bridge_s_g_hit_action_spec_t));
                action_spec.action_mc_index = mgid_index;

                status = p4_pd_dc_ipv4_multicast_bridge_table_add_with_multicast_bridge_s_g_hit(
                    g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                    &(group_info->inner_hw_entry));
            }
#endif /* P4_IPV4_DISABLE */
        } else {
#ifndef P4_IPV6_DISABLE
            if (vrf_entry) {
                p4_pd_dc_ipv6_multicast_route_match_spec_t match_spec;
                p4_pd_dc_multicast_route_s_g_hit_action_spec_t action_spec;

                memset(&match_spec, 0, sizeof(p4_pd_dc_ipv6_multicast_route_match_spec_t));
                match_spec.l3_metadata_vrf = handle_to_id(group_key->bd_vrf_handle);
                memcpy(&(match_spec.ipv6_metadata_lkp_ipv6_sa),
                       &(SWITCH_MCAST_GROUP_IPV6_SRC_IP(group_key)), 16);
                memcpy(&(match_spec.ipv6_metadata_lkp_ipv6_da),
                       &(SWITCH_MCAST_GROUP_IPV6_GRP_IP(group_key)), 16);

                memset(&action_spec, 0, sizeof(p4_pd_dc_multicast_route_s_g_hit_action_spec_t));
                action_spec.action_mc_index = mgid_index;
                action_spec.action_mcast_rpf_group = rpf_group;

                status = p4_pd_dc_ipv6_multicast_route_table_add_with_multicast_route_s_g_hit(
                    g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                    &(group_info->inner_hw_entry));
            } else {
                p4_pd_dc_ipv6_multicast_bridge_match_spec_t match_spec;
                p4_pd_dc_multicast_bridge_s_g_hit_action_spec_t action_spec;

                memset(&match_spec, 0, sizeof(p4_pd_dc_ipv6_multicast_bridge_match_spec_t));
                match_spec.ingress_metadata_bd = handle_to_id(group_key->bd_vrf_handle);
                memcpy(&(match_spec.ipv6_metadata_lkp_ipv6_sa),
                       &(SWITCH_MCAST_GROUP_IPV6_SRC_IP(group_key)), 16);
                memcpy(&(match_spec.ipv6_metadata_lkp_ipv6_da),
                       &(SWITCH_MCAST_GROUP_IPV6_GRP_IP(group_key)), 16);

                memset(&action_spec, 0, sizeof(p4_pd_dc_multicast_bridge_s_g_hit_action_spec_t));
                action_spec.action_mc_index = mgid_index;

                status = p4_pd_dc_ipv6_multicast_bridge_table_add_with_multicast_bridge_s_g_hit(
                    g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                    &(group_info->inner_hw_entry));
            }
#endif /* P4_IPV6_DISABLE */
        }
    } else {
        if (SWITCH_MCAST_GROUP_IP_TYPE(group_key) == SWITCH_API_IP_ADDR_V4) {
#ifndef P4_IPV4_DISABLE
            if (vrf_entry) {
                if (mc_mode == SWITCH_API_MCAST_IPMC_PIM_SM) {
                    p4_pd_dc_ipv4_multicast_route_star_g_match_spec_t match_spec;
                    p4_pd_dc_multicast_route_sm_star_g_hit_action_spec_t action_spec;

                    memset(&match_spec, 0, sizeof(p4_pd_dc_ipv4_multicast_route_star_g_match_spec_t));
                    match_spec.l3_metadata_vrf = handle_to_id(group_key->bd_vrf_handle);
                    match_spec.ipv4_metadata_lkp_ipv4_da = SWITCH_MCAST_GROUP_IPV4_GRP_IP(group_key);

                    memset(&action_spec, 0, sizeof(p4_pd_dc_multicast_route_sm_star_g_hit_action_spec_t));
                    action_spec.action_mc_index = mgid_index;
                    action_spec.action_mcast_rpf_group = rpf_group;

                    status = p4_pd_dc_ipv4_multicast_route_star_g_table_add_with_multicast_route_sm_star_g_hit(
                        g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                        &(group_info->inner_hw_entry));
                } else {
                    p4_pd_dc_ipv4_multicast_route_star_g_match_spec_t match_spec;
                    p4_pd_dc_multicast_route_bidir_star_g_hit_action_spec_t action_spec;

                    memset(&match_spec, 0, sizeof(p4_pd_dc_ipv4_multicast_route_star_g_match_spec_t));
                    match_spec.l3_metadata_vrf = handle_to_id(group_key->bd_vrf_handle);
                    match_spec.ipv4_metadata_lkp_ipv4_da = SWITCH_MCAST_GROUP_IPV4_GRP_IP(group_key);

                    memset(&action_spec, 0, sizeof(p4_pd_dc_multicast_route_bidir_star_g_hit_action_spec_t));
                    action_spec.action_mc_index = mgid_index;
                    action_spec.action_mcast_rpf_group = rpf_group;

                    status = p4_pd_dc_ipv4_multicast_route_star_g_table_add_with_multicast_route_bidir_star_g_hit(
                        g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                        &(group_info->inner_hw_entry));
                }
            } else {
                p4_pd_dc_ipv4_multicast_bridge_star_g_match_spec_t match_spec;
                p4_pd_dc_multicast_bridge_star_g_hit_action_spec_t action_spec;

                memset(&match_spec, 0, sizeof(p4_pd_dc_ipv4_multicast_bridge_star_g_match_spec_t));
                match_spec.ingress_metadata_bd = handle_to_id(group_key->bd_vrf_handle);
                match_spec.ipv4_metadata_lkp_ipv4_da = SWITCH_MCAST_GROUP_IPV4_GRP_IP(group_key);

                memset(&action_spec, 0, sizeof(p4_pd_dc_multicast_bridge_star_g_hit_action_spec_t));
                action_spec.action_mc_index = mgid_index;

                status = p4_pd_dc_ipv4_multicast_bridge_star_g_table_add_with_multicast_bridge_star_g_hit(
                    g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                    &(group_info->inner_hw_entry));
            }
#endif /* P4_IPV4_DISABLE */
        } else {
#ifndef P4_IPV6_DISABLE
            if (vrf_entry) {
                if (mc_mode == SWITCH_API_MCAST_IPMC_PIM_SM) {
                    p4_pd_dc_ipv6_multicast_route_star_g_match_spec_t match_spec;
                    p4_pd_dc_multicast_route_sm_star_g_hit_action_spec_t action_spec;

                    memset(&match_spec, 0, sizeof(p4_pd_dc_ipv6_multicast_route_star_g_match_spec_t));
                    match_spec.l3_metadata_vrf = handle_to_id(group_key->bd_vrf_handle);
                    memcpy(&(match_spec.ipv6_metadata_lkp_ipv6_da),
                           &(SWITCH_MCAST_GROUP_IPV6_GRP_IP(group_key)), 16);

                    memset(&action_spec, 0, sizeof(p4_pd_dc_multicast_route_sm_star_g_hit_action_spec_t));
                    action_spec.action_mc_index = mgid_index;
                    action_spec.action_mcast_rpf_group = rpf_group;

                    status = p4_pd_dc_ipv6_multicast_route_star_g_table_add_with_multicast_route_sm_star_g_hit(
                        g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                        &(group_info->inner_hw_entry));
                } else {
                    p4_pd_dc_ipv6_multicast_route_star_g_match_spec_t match_spec;
                    p4_pd_dc_multicast_route_bidir_star_g_hit_action_spec_t action_spec;

                    memset(&match_spec, 0, sizeof(p4_pd_dc_ipv6_multicast_route_star_g_match_spec_t));
                    match_spec.l3_metadata_vrf = handle_to_id(group_key->bd_vrf_handle);
                    memcpy(&(match_spec.ipv6_metadata_lkp_ipv6_da),
                           &(SWITCH_MCAST_GROUP_IPV6_GRP_IP(group_key)), 16);

                    memset(&action_spec, 0, sizeof(p4_pd_dc_multicast_route_bidir_star_g_hit_action_spec_t));
                    action_spec.action_mc_index = mgid_index;
                    action_spec.action_mcast_rpf_group = rpf_group;

                    status = p4_pd_dc_ipv6_multicast_route_star_g_table_add_with_multicast_route_bidir_star_g_hit(
                        g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                        &(group_info->inner_hw_entry));
                }
            } else {
                p4_pd_dc_ipv6_multicast_bridge_star_g_match_spec_t match_spec;
                p4_pd_dc_multicast_bridge_star_g_hit_action_spec_t action_spec;

                memset(&match_spec, 0, sizeof(p4_pd_dc_ipv6_multicast_bridge_star_g_match_spec_t));
                match_spec.ingress_metadata_bd = handle_to_id(group_key->bd_vrf_handle);
                memcpy(&(match_spec.ipv6_metadata_lkp_ipv6_da),
                       &(SWITCH_MCAST_GROUP_IPV6_GRP_IP(group_key)), 16);

                memset(&action_spec, 0, sizeof(p4_pd_dc_multicast_bridge_star_g_hit_action_spec_t));
                action_spec.action_mc_index = mgid_index;

                status = p4_pd_dc_ipv6_multicast_bridge_star_g_table_add_with_multicast_bridge_star_g_hit(
                    g_sess_hdl, p4_pd_device, &match_spec, &action_spec,
                    &(group_info->inner_hw_entry));
            }
#endif /* P4_IPV6_DISABLE */
        }
    }

#endif /* P4_MULTICAST_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}

p4_pd_status_t
switch_pd_mcast_table_delete_entry(switch_device_t device,
                                   switch_mcast_group_info_t *group_info,
                                   bool core_entry, bool vrf_entry)

{
    p4_pd_status_t status = 0;
#ifndef P4_MULTICAST_DISABLE

    switch_mcast_group_key_t               *group_key;
    group_key = &(group_info->group_key);

    if (core_entry) {
#ifndef P4_TUNNEL_DISABLE
        if (group_key->sg_entry) {
            if (SWITCH_MCAST_GROUP_IP_TYPE(group_key) == SWITCH_API_IP_ADDR_V4) {
#ifndef P4_IPV4_DISABLE
                status = p4_pd_dc_outer_ipv4_multicast_table_delete(
                    g_sess_hdl, device, group_info->outer_hw_entry);
#endif /* P4_IPV4_DISABLE */
            } else {
#ifndef P4_IPV6_DISABLE
                status = p4_pd_dc_outer_ipv6_multicast_table_delete(
                    g_sess_hdl, device, group_info->outer_hw_entry);
#endif /* P4_IPV6_DISABLE */
            }
        } else {
            if (SWITCH_MCAST_GROUP_IP_TYPE(group_key) == SWITCH_API_IP_ADDR_V4) {
#ifndef P4_IPV4_DISABLE
                status = p4_pd_dc_outer_ipv4_multicast_star_g_table_delete(
                    g_sess_hdl, device, group_info->outer_hw_entry);
#endif /* P4_IPV4_DISABLE */
            } else {
#ifndef P4_IPV6_DISABLE
                status = p4_pd_dc_outer_ipv6_multicast_star_g_table_delete(
                    g_sess_hdl, device, group_info->outer_hw_entry);
#endif /* P4_IPV6_DISABLE */
            }
        }
#endif /* P4_TUNNEL_DISABLE */
    }

    if (group_key->sg_entry) {
        if (SWITCH_MCAST_GROUP_IP_TYPE(group_key) == SWITCH_API_IP_ADDR_V4) {
#ifndef P4_IPV4_DISABLE
            if (vrf_entry) {
                status = p4_pd_dc_ipv4_multicast_route_table_delete(
                    g_sess_hdl, device, group_info->inner_hw_entry);
            } else {
                status = p4_pd_dc_ipv4_multicast_bridge_table_delete(
                    g_sess_hdl, device, group_info->inner_hw_entry);
            }
#endif /* P4_IPV4_DISABLE */
        } else {
#ifndef P4_IPV6_DISABLE
            if (vrf_entry) {
                status = p4_pd_dc_ipv6_multicast_route_table_delete(
                    g_sess_hdl, device, group_info->inner_hw_entry);
            } else {
                status = p4_pd_dc_ipv6_multicast_bridge_table_delete(
                    g_sess_hdl, device, group_info->inner_hw_entry);
            }
#endif /* P4_IPV6_DISABLE */
        }
    } else {
        if (SWITCH_MCAST_GROUP_IP_TYPE(group_key) == SWITCH_API_IP_ADDR_V4) {
#ifndef P4_IPV4_DISABLE
            if (vrf_entry) {
                status = p4_pd_dc_ipv4_multicast_route_star_g_table_delete(
                    g_sess_hdl, device, group_info->inner_hw_entry);
            } else {
                status = p4_pd_dc_ipv4_multicast_bridge_star_g_table_delete(
                    g_sess_hdl, device, group_info->inner_hw_entry);
            }
#endif /* P4_IPV4_DISABLE */
        } else {
#ifndef P4_IPV6_DISABLE
            if (vrf_entry) {
                status = p4_pd_dc_ipv6_multicast_route_star_g_table_delete(
                    g_sess_hdl, device, group_info->inner_hw_entry);
            } else {
                status = p4_pd_dc_ipv6_multicast_bridge_star_g_table_delete(
                    g_sess_hdl, device, group_info->inner_hw_entry);
            }
#endif /* P4_IPV6_DISABLE */
        }
    }

#endif /* P4_MULTICAST_DISABLE */

    p4_pd_complete_operations(g_sess_hdl);
    return status;
}
