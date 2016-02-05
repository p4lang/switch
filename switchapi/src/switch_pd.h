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

#ifndef _switch_pd_api_
#define _switch_pd_api_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <switchapi/switch_base_types.h>
#include <switchapi/switch_handle.h>
#include <switchapi/switch_status.h>
#include <switchapi/switch_tunnel.h>
#include <switchapi/switch_stp.h>
#include <switchapi/switch_vrf.h>
#include <switchapi/switch_hostif.h>
#include <switchapi/switch_protocol.h>
#include <switchapi/switch_acl.h>
#include <switchapi/switch_neighbor.h>
#include <switchapi/switch_mirror.h>
#include <switchapi/switch_meter.h>
#include "switch_interface_int.h"
#include "switch_hostif_int.h"
#include "switch_vlan_int.h"
#include "switch_l2_int.h"
#include "switch_l3_int.h"
#include "switch_mcast_int.h"
#include "switch_port_int.h"
#include "switch_rmac_int.h"
#include "switch_defines.h"
#include "switch_mirror_int.h"
#include "switch_meter_int.h"

#define SWITCH_MAX_DEVICE 32

p4_pd_status_t
switch_pd_client_init(switch_device_t device);

/* Dmac table PD API's */
p4_pd_status_t
switch_pd_dmac_table_add_entry(switch_device_t device,
                           switch_api_mac_entry_t *mac_entry,
                           uint16_t nhop_index,
                           uint16_t mgid_index,
                           uint32_t aging_time,
                           switch_interface_info_t *intf_info,
                           p4_pd_entry_hdl_t *entry_hdl);
p4_pd_status_t
switch_pd_dmac_table_update_entry(switch_device_t device,
                           switch_api_mac_entry_t *mac_entry,
                           uint16_t nhop_index,
                           uint16_t mgid_index,
                           switch_interface_info_t *intf_info,
                           p4_pd_entry_hdl_t entry_hdl);
p4_pd_status_t
switch_pd_dmac_table_delete_entry(switch_device_t device,
                              p4_pd_entry_hdl_t entry_hdl);

/* Smac table PD API's */
p4_pd_status_t
switch_pd_smac_table_add_entry(switch_device_t device,
                           switch_api_mac_entry_t *mac_entry,
                           switch_interface_info_t *intf_info,
                           p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_smac_table_update_entry(switch_device_t device,
                           switch_api_mac_entry_t *mac_entry,
                           switch_interface_info_t *intf_info,
                           p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_smac_table_delete_entry(switch_device_t device,
                              p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_mac_table_set_learning_timeout(switch_device_t device, uint32_t timeout);

p4_pd_status_t
switch_pd_nexthop_table_add_entry(switch_device_t device,
                                  uint16_t nhop,
                                  uint16_t bd,
                                  switch_ifindex_t ifindex,
                                  bool flood,
                                  uint32_t mc_index,
                                  bool tunnel,
                                  p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_nexthop_table_update_entry(switch_device_t device,
                                     uint16_t nhop_index,
                                     uint16_t bd,
                                     switch_ifindex_t ifindex,
                                     bool flood,
                                     uint32_t mc_index,
                                     bool tunnel,
                                     p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_nexthop_table_delete_entry(switch_device_t device,
                                     p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_ecmp_group_create(switch_device_t device,
                            p4_pd_grp_hdl_t *p4_pd_group_hdl);

p4_pd_status_t
switch_pd_ecmp_group_delete(switch_device_t device,
                            p4_pd_grp_hdl_t p4_pd_group_hdl);
p4_pd_status_t
switch_pd_ecmp_member_add(switch_device_t device,
                          p4_pd_grp_hdl_t p4_pd_group_hdl,
                          uint16_t nhop_index,
                          switch_interface_info_t *intf_info,
                          p4_pd_mbr_hdl_t *mbr_hdl);

p4_pd_status_t
switch_pd_ecmp_member_delete(switch_device_t device,
                             p4_pd_grp_hdl_t p4_pd_group_hdl,
                             p4_pd_mbr_hdl_t mbr_hdl);

p4_pd_status_t
switch_pd_ecmp_group_table_add_entry_with_selector(
    switch_device_t device, uint16_t ecmp_index,
    p4_pd_grp_hdl_t p4_pd_group_hdl,
    p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_ecmp_group_table_delete_entry(switch_device_t device,
                                        p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_ip_fib_add_entry(switch_device_t device,
                           switch_handle_t vrf,
                           switch_ip_addr_t *ipaddr,
                           bool ecmp,
                           switch_handle_t nexthop,
                           p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_ip_fib_update_entry(switch_device_t device,
                           switch_handle_t vrf,
                           switch_ip_addr_t *ipaddr,
                           bool ecmp,
                           switch_handle_t nexthop,
                           p4_pd_entry_hdl_t entry_hdl);
p4_pd_status_t
switch_pd_ip_fib_delete_entry(switch_device_t device,
                               switch_ip_addr_t *ip_addr,
                               p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_inner_rmac_table_add_entry(switch_device_t device,
                                switch_handle_t rmac_group,
                                switch_mac_addr_t *mac,
                                p4_pd_entry_hdl_t *entry_hdl);
p4_pd_status_t
switch_pd_inner_rmac_table_delete_entry(switch_device_t device,
                                    p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_outer_rmac_table_add_entry(switch_device_t device,
                                switch_handle_t rmac_group,
                                switch_mac_addr_t *mac,
                                p4_pd_entry_hdl_t *entry_hdl);
p4_pd_status_t
switch_pd_outer_rmac_table_delete_entry(switch_device_t device,
                                    p4_pd_entry_hdl_t entry_hdl);
p4_pd_status_t
switch_pd_src_vtep_table_add_entry(switch_device_t device,
                              switch_ip_encap_t *ip_encap,
                              switch_ifindex_t ifindex,
                              p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_src_vtep_table_delete_entry(switch_device_t device,
                                 switch_ip_encap_t *ip_encap,
                                 p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_dest_vtep_table_add_entry(switch_device_t device,
                               switch_ip_encap_t *ip_encap,
                               p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_dest_vtep_table_delete_entry(switch_device_t device,
                                  switch_ip_encap_t *ip_encap,
                                  p4_pd_entry_hdl_t entry_hdl);
p4_pd_status_t
switch_pd_tunnel_rewrite_table_add_entry(switch_device_t device,
                                         uint16_t tunnel_index,
                                         uint16_t sip_index, uint16_t dip_index,
                                         uint16_t smac_index,
                                         uint16_t dmac_index,
                                         p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_rewrite_table_fabric_add_entry(switch_device_t device,
                                         switch_tunnel_type_egress_t tunnel_type,
                                         uint16_t tunnel_index,
                                         p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_tunnel_rewrite_cpu_add_entry(switch_device_t device,
                                       uint16_t tunnel_index,
                                       p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_tunnel_rewrite_table_delete_entry(switch_device_t device, p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_tunnel_table_add_entry(switch_device_t device,
                             switch_encap_type_t encap_type,
                             uint16_t tunnel_vni,
                             switch_rid_t rid,
                             switch_bd_info_t *bd_info,
                             switch_ip_encap_t *ip_encap,
                             switch_handle_t bd_handle,
                             p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_tunnel_table_delete_entry(switch_device_t device,
                               p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_egress_vni_table_add_entry(switch_device_t device,
                                    switch_handle_t egress_bd,
                                    uint16_t tunnel_vni,
                                    uint8_t tunnel_type,
                                    p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_egress_vni_table_delete_entry(switch_device_t device_id,
                                       p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_tunnel_src_rewrite_table_add_entry(switch_device_t device,
                                        uint16_t tunnel_src_index,
                                        switch_ip_encap_t *ip_encap,
                                        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_tunnel_src_rewrite_table_delete_entry(switch_device_t device,
                                           p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_tunnel_dst_rewrite_table_add_entry(switch_device_t device,
                                        uint16_t tunnel_dst_index,
                                        switch_ip_encap_t *ip_encap,
                                        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_tunnel_dst_rewrite_table_delete_entry(switch_device_t device,
                                           p4_pd_entry_hdl_t entry_hdl);
p4_pd_status_t
switch_pd_tunnel_smac_rewrite_table_add_entry(switch_device_t device,
                                         uint16_t smac_index,
                                         switch_mac_addr_t *mac,
                                         p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_tunnel_smac_rewrite_table_delete_entry(switch_device_t device,
                                            p4_pd_entry_hdl_t entry_hdl);
p4_pd_status_t
switch_pd_tunnel_dmac_rewrite_table_add_entry(switch_device_t device,
                                         uint16_t dmac_index,
                                         switch_mac_addr_t *mac,
                                         p4_pd_entry_hdl_t *entry_hdl);
p4_pd_status_t
switch_pd_tunnel_dmac_rewrite_table_delete_entry(switch_device_t device,
                                            p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_bd_table_add_entry(switch_device_t device,
                             uint16_t bd,
                             switch_bd_info_t *bd_info,
                             p4_pd_mbr_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_bd_table_update_entry(switch_device_t device,
                                uint16_t outer_bd,
                                switch_bd_info_t *bd_info,
                                p4_pd_mbr_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_bd_table_delete_entry(switch_device_t device,
                                switch_bd_info_t *bd_info);

p4_pd_status_t
switch_pd_egress_bd_map_table_add_entry(switch_device_t device,
                                        switch_handle_t bd_handle,
                                        switch_bd_info_t *bd_info);

p4_pd_status_t
switch_pd_egress_bd_map_table_update_entry(switch_device_t device,
                                           switch_handle_t bd_handle,
                                           switch_bd_info_t *bd_info);

p4_pd_status_t
switch_pd_egress_bd_map_table_delete_entry(switch_device_t device,
                                           switch_bd_info_t *bd_info);

p4_pd_status_t
switch_pd_port_vlan_mapping_table_add_entry(switch_device_t device,
                                        switch_vlan_t vlan_id0,
                                        switch_vlan_t vlan_id1,
                                        switch_interface_info_t *info,
                                        p4_pd_mbr_hdl_t bd_hdl,
                                        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_port_vlan_mapping_table_delete_entry(switch_device_t device,
                                           p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_egress_vlan_xlate_table_add_entry(switch_device_t device, switch_port_t port,
                                       uint16_t egress_bd, switch_vlan_t vlan_id,
                                       p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_egress_vlan_xlate_table_delete_entry(switch_device_t device, p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_port_mapping_table_add_entry(switch_device_t device,
                                   switch_port_t port_id,
                                   switch_ifindex_t ifindex,
                                   switch_port_type_t port_type,
                                   p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_port_mapping_table_delete_entry(switch_device_t device,
                                      p4_pd_entry_hdl_t entry_hdl);

/*
 * Rewrite table
 */
p4_pd_status_t
switch_pd_rewrite_table_unicast_rewrite_add_entry(switch_device_t device,
                                                  uint16_t bd,
                                                  uint16_t nhop_index,
                                                  switch_mac_addr_t dmac,
                                                  switch_neighbor_rw_type_t rw_type,
                                                  p4_pd_entry_hdl_t *entry_hdl);
p4_pd_status_t
switch_pd_rewrite_table_unicast_rewrite_update_entry(switch_device_t device,
                                                     uint16_t bd,
                                                     uint16_t nhop_index,
                                                     switch_mac_addr_t dmac,
                                                     switch_neighbor_rw_type_t rw_type,
                                                     p4_pd_entry_hdl_t entry_hdl);
p4_pd_status_t
switch_pd_rewrite_table_tunnel_rewrite_add_entry(switch_device_t device,
                                                 uint16_t bd,
                                                 uint16_t nhop_index,
                                                 switch_mac_addr_t dmac,
                                                 switch_neighbor_type_t neigh_type,
                                                 switch_neighbor_rw_type_t rw_type,
                                                 uint16_t tunnel_index,
                                                 switch_encap_type_t encap_type,
                                                 p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_rewrite_table_tunnel_rewrite_update_entry(switch_device_t device,
                                                    uint16_t bd,
                                                    uint16_t nhop_index,
                                                    switch_mac_addr_t dmac,
                                                    switch_neighbor_type_t neigh_type,
                                                    switch_neighbor_rw_type_t rw_type,
                                                    uint16_t tunnel_index,
                                                    switch_encap_type_t encap_type,
                                                    p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_rewrite_table_delete_entry(switch_device_t device,
                                     p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t switch_pd_lag_group_create(switch_device_t device, p4_pd_grp_hdl_t *p4_pd_group_hdl);
p4_pd_status_t switch_pd_lag_group_delete(switch_device_t device, p4_pd_grp_hdl_t p4_pd_group_hdl);
p4_pd_status_t switch_pd_lag_member_add(switch_device_t device, p4_pd_grp_hdl_t p4_pd_group_hdl, 
            unsigned int port, p4_pd_mbr_hdl_t *mbr_hdl);
p4_pd_status_t switch_pd_lag_member_delete(switch_device_t device, p4_pd_grp_hdl_t p4_pd_group_hdl, 
            p4_pd_mbr_hdl_t mbr_hdl);
p4_pd_status_t
switch_pd_lag_group_table_add_entry(switch_device_t device,
                                switch_ifindex_t ifindex,
                                unsigned int port,
                                p4_pd_mbr_hdl_t *mbr_hdl,
                                p4_pd_entry_hdl_t *entry_hdl);
p4_pd_status_t
switch_pd_lag_group_table_add_entry_with_selector(switch_device_t device,
                                switch_ifindex_t ifindex,
                                p4_pd_grp_hdl_t p4_pd_group_hdl,
                                p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_lag_group_table_delete_entry(switch_device_t device,
                             p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_smac_rewrite_table_add_entry(switch_device_t device,
                                       switch_smac_entry_t *smac_entry);

p4_pd_status_t
switch_pd_smac_rewrite_table_delete_entry(switch_device_t device,
                                          switch_smac_entry_t *smac_entry);

p4_pd_status_t
switch_pd_cpu_rewrite_add_entry(switch_device_t device,
                            switch_port_t port_id);
p4_pd_status_t
switch_pd_rid_table_add_entry(switch_device_t device,
                              uint16_t rid,
                              uint32_t bd,
                              bool inner_replica,
                              uint8_t tunnel_type, uint16_t tunnel_index,
                              p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_rid_table_delete_entry(switch_device_t device,
                             p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_mcast_table_add_entry(switch_device_t device,
                                uint16_t mgid_index,
                                switch_mcast_mode_t mc_mode,
                                switch_mcast_group_info_t *group_info,
                                bool core_entry, bool vrf_entry,
                                uint16_t rpf_group);

p4_pd_status_t
switch_pd_mcast_table_delete_entry(switch_device_t device,
                                   switch_mcast_group_info_t *group_info,
                                   bool core_entry, bool vrf_entry);

p4_pd_status_t
switch_pd_spanning_tree_table_add_entry(switch_device_t device,
                                    uint16_t stp_group,
                                    switch_ifindex_t ifindex,
                                    switch_stp_state_t stp_state,
                                    p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_spanning_tree_table_update_entry(switch_device_t device,
                                      uint16_t stp_group,
                                      switch_ifindex_t ifindex,
                                      switch_stp_state_t stp_state,
                                      p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_spanning_tree_table_delete_entry(switch_device_t device,
                                       p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_urpf_bd_table_add_entry(switch_device_t device,
                              uint16_t urpf_group,
                              uint16_t bd_index,
                              p4_pd_entry_hdl_t *entry_hdl);
p4_pd_status_t
switch_pd_urpf_bd_table_delete_entry(switch_device_t device,
                                 p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_urpf_add_entry(switch_device_t device,
                    switch_vrf_id_t vrf_id,
                    switch_ip_addr_t *ip_addr,
                    uint16_t urpf_group,
                    p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_urpf_update_entry(switch_device_t device,
                       switch_vrf_id_t vrf_id,
                       switch_ip_addr_t *ip_addr,
                       uint16_t urpf_group,
                       p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_urpf_delete_entry(switch_device_t device,
                       switch_vrf_id_t vrf_id,
                       switch_ip_addr_t *ip_addr,
                       p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_mcast_mgrp_tree_create(switch_device_t device, uint16_t mgid_index,
                            switch_mcast_info_t *mcast_info);
p4_pd_status_t
switch_pd_mcast_mgrp_tree_delete(switch_device_t device,
                             switch_mcast_info_t *mcast_info);

p4_pd_status_t
switch_pd_mcast_add_entry(switch_device_t device, switch_mcast_node_t *node);

p4_pd_status_t
switch_pd_mcast_update_entry(switch_device_t device, switch_mcast_node_t *node);

p4_pd_status_t
switch_pd_mcast_delete_entry(switch_device_t device, switch_mcast_node_t *node);

p4_pd_status_t
switch_pd_mcast_mgid_table_add_entry(switch_device_t device,
                                     mc_mgrp_hdl_t mgid,
                                     switch_mcast_node_t *node);

p4_pd_status_t
switch_pd_mcast_mgid_table_delete_entry(switch_device_t device,
                                        mc_mgrp_hdl_t mgid_hdl,
                                        switch_mcast_node_t *node);

p4_pd_status_t
switch_pd_mcast_lag_port_map_update(switch_device_t device, uint16_t lag_index,
                                    switch_mc_port_map_t port_map);

p4_pd_status_t
switch_pd_mpls_table_add_entry(switch_device_t device, switch_mpls_encap_t *mpls_encap,
                          uint32_t bd_index, uint32_t label,
                          switch_bd_info_t *bd_info,
                          uint16_t egress_ifindex, p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_mpls_table_delete_entry(switch_device_t device, p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_tunnel_rewrite_table_mpls_add_entry(switch_device_t device, uint32_t tunnel_index,
                                       uint16_t smac_index, uint16_t dmac_index,
                                       switch_mpls_encap_t *mpls_encap,
                                       p4_pd_entry_hdl_t *entry_hdl);
p4_pd_status_t
switch_pd_rewrite_table_mpls_rewrite_add_entry(switch_device_t device,
                                               uint16_t bd,
                                               uint16_t nhop_index,
                                               uint16_t tunnel_index,
                                               switch_neighbor_type_t neigh_type,
                                               switch_mac_addr_t dmac,
                                               uint32_t label,
                                               uint8_t header_count,
                                               p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_ipv4_acl_table_add_entry(
        switch_device_t device,
        uint16_t if_label,
        uint16_t bd_label,
        uint16_t priority,
        unsigned int count,
        switch_acl_ip_key_value_pair_t *ip_acl,
        switch_acl_ip_action_t action,
        switch_acl_action_params_t *action_params,
        switch_acl_opt_action_params_t *opt_action_params,
        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_ipv4_acl_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_ipv6_acl_table_add_entry(
        switch_device_t device,
        uint16_t if_label,
        uint16_t bd_label,
        uint16_t priority,
        unsigned int count,
        switch_acl_ipv6_key_value_pair_t *ipv6_acl,
        switch_acl_ipv6_action_t action,
        switch_acl_action_params_t *action_params,
        switch_acl_opt_action_params_t *opt_action_params,
        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_ipv6_acl_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_ipv4_racl_table_add_entry(
        switch_device_t device,
        uint16_t if_label,
        uint16_t bd_label,
        uint16_t priority,
        unsigned int count,
        switch_acl_ip_racl_key_value_pair_t *ip_racl,
        switch_acl_ip_action_t action,
        switch_acl_action_params_t *action_params,
        switch_acl_opt_action_params_t *opt_action_params,
        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_ipv4_racl_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_ipv6_racl_table_add_entry(
        switch_device_t device,
        uint16_t if_label,
        uint16_t bd_label,
        uint16_t priority,
        unsigned int count,
        switch_acl_ipv6_racl_key_value_pair_t *ip_racl,
        switch_acl_ipv6_action_t action,
        switch_acl_action_params_t *action_params,
        switch_acl_opt_action_params_t *opt_action_params,
        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_ipv6_racl_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_mac_acl_table_add_entry(
        switch_device_t device,
        uint16_t if_label,
        uint16_t bd_label,
        uint16_t priority,
        unsigned int count,
        switch_acl_mac_key_value_pair_t *mac_acl,
        switch_acl_mac_action_t action,
        switch_acl_action_params_t *action_params,
        switch_acl_opt_action_params_t *opt_action_params,
        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_mac_acl_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_qos_acl_table_add_entry(
        switch_device_t device,
        uint16_t if_label,
        uint16_t bd_label,
        uint16_t priority,
        unsigned int count,
        switch_acl_qos_key_value_pair_t *qos_acl,
        switch_acl_mac_action_t action,
        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_qos_acl_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_system_acl_table_add_entry(
        switch_device_t device,
        uint16_t if_label,
        uint16_t bd_label,
        uint16_t priority,
        unsigned int count,
        switch_acl_system_key_value_pair_t *system_acl,
        switch_acl_system_action_t action_type,
        switch_acl_action_params_t *action_params,
        switch_acl_opt_action_params_t *opt_action_params,
        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_system_acl_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_egr_acl_table_add_entry(
        switch_device_t device,
        uint16_t if_label,
        uint16_t bd_label,
        uint16_t priority,
        unsigned int count,
        switch_acl_egr_key_value_pair_t *egr_acl,
        switch_acl_egr_action_t action,
        switch_acl_action_params_t *action_params,
        switch_acl_opt_action_params_t *opt_action_params,
        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_egr_acl_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_vlan_ingress_stats_get(switch_device_t device, switch_bd_stats_t *bd_stats);

p4_pd_status_t
switch_pd_vlan_egress_stats_get(switch_device_t device, switch_bd_stats_t *bd_stats);;

p4_pd_status_t
switch_pd_drop_stats_get(switch_device_t device, int num_counters,
                         uint64_t *counters);

p4_pd_status_t
switch_pd_egress_lag_table_add_entry(switch_device_t device,
                                     switch_port_t port_id,
                                     switch_ifindex_t ifindex,
                                     p4_pd_entry_hdl_t *entry_hdl);
p4_pd_status_t
switch_pd_egress_lag_table_delete_entry(switch_device_t device,
                                        p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_ingress_fabric_table_add_entry(switch_device_t device);
//TODO: Add delete entry for outer_mac table

// Default Entries
p4_pd_status_t
switch_pd_ip_mcast_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_validate_outer_ethernet_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_validate_outer_ip_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_storm_control_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_outer_rmac_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_src_vtep_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_dest_vtep_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_validate_packet_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_port_vlan_mapping_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_acl_table_add_default_entry(switch_device_t device);

switch_status_t
switch_pd_inner_rmac_table_add_default_entry(switch_device_t device);

switch_status_t
switch_pd_fwd_result_table_add_default_entry(switch_device_t device);

switch_status_t
switch_pd_nexthop_table_add_default_entry(switch_device_t device);

switch_status_t
switch_pd_lag_table_add_default_entry(switch_device_t device);

switch_status_t
switch_pd_rid_table_add_default_entry(switch_device_t device);

switch_status_t
switch_pd_replica_type_table_add_default_entry(switch_device_t device);

switch_status_t
switch_pd_mac_table_add_default_entry(switch_device_t device);

switch_status_t
switch_pd_egress_bd_map_table_add_default_entry(switch_device_t device);

switch_status_t
switch_pd_egress_vni_table_add_default_entry(switch_device_t device);

switch_status_t
switch_pd_ip_fib_add_default_entry(switch_device_t device);

switch_status_t
switch_pd_ip_urpf_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_tunnel_smac_rewrite_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_tunnel_dmac_rewrite_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_tunnel_rewrite_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_fwd_result_table_add_init_entry(switch_device_t device);

p4_pd_status_t
switch_pd_rewrite_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_rewrite_multicast_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_egress_vlan_xlate_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_cpu_rewrite_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_egress_acl_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_vlan_decap_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_tunnel_src_rewrite_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_tunnel_dst_rewrite_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_tunnel_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_bd_stats_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_bd_flood_table_add_default_entry(switch_device_t device);

switch_status_t
switch_pd_mtu_table_add_default_entry(switch_device_t device);

switch_status_t
switch_pd_l3_rewrite_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_learn_notify_table_add_init_entry(switch_device_t device);

p4_pd_status_t
switch_pd_tunnel_encap_tables_init_entry(switch_device_t device);

p4_pd_status_t
switch_pd_tunnel_decap_tables_init_entry(switch_device_t device);

p4_pd_status_t
switch_pd_validate_outer_ethernet_table_init_entry(switch_device_t device);

p4_pd_status_t
switch_pd_vlan_decap_table_init_entry(switch_device_t device);

p4_pd_status_t
switch_pd_validate_mpls_packet_table_init_entry(switch_device_t device);

switch_status_t
switch_pd_egress_lag_table_add_default_entry(switch_device_t device);

p4_pd_status_t
switch_pd_fabric_header_table_init_entry(switch_device_t device);

p4_pd_status_t
switch_pd_egress_port_mapping_table_init_entry(switch_device_t device);

p4_pd_status_t
switch_pd_compute_hashes_init_entry(switch_device_t device);

switch_status_t
switch_pd_switch_config_params_update(switch_device_t device);

switch_status_t
switch_pd_switch_config_params_table_init(switch_device_t device);

switch_status_t
switch_pd_replica_type_table_init_entry(switch_device_t device);

switch_status_t
switch_pd_rewrite_multicast_table_init_entry(switch_device_t device);

switch_status_t
switch_pd_l3_rewrite_table_init_entry(switch_device_t device);

// mirroring apis
p4_pd_status_t
switch_pd_mirror_session_update(switch_device_t device,
                                switch_handle_t mirror_handle,
                                switch_mirror_info_t *mirror_info);

p4_pd_status_t
switch_pd_mirror_session_delete(switch_device_t device,
                                switch_handle_t mirror_handle);

p4_pd_status_t
switch_pd_mirror_table_entry_add(switch_device_t device,
                             switch_handle_t mirror_handle,
                             switch_mirror_info_t *mirror_info);

p4_pd_status_t
switch_pd_mirror_table_entry_delete(switch_device_t device,
                             switch_mirror_info_t *mirror_info);

switch_status_t
switch_pd_mirror_table_add_default_entry(switch_device_t device);

switch_status_t
switch_pd_neg_mirror_add_entry(switch_device_t device);

p4_pd_status_t
p4_pd_complete_operations(p4_pd_sess_hdl_t shdl);

p4_pd_status_t
p4_pd_client_init(p4_pd_sess_hdl_t *sess_hdl, uint32_t max_txn_size);

#ifdef P4_INT_TRANSIT_ENABLE
// INT APIs
p4_pd_status_t
switch_pd_int_tables_init(switch_device_t device);

p4_pd_status_t
switch_pd_int_transit_enable(switch_device_t device, int32_t swid,
                             int32_t idx, p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_int_transit_disable(switch_device_t device,
                              p4_pd_entry_hdl_t entry_hdl);

#endif
#ifdef P4_INT_EP_ENABLE
p4_pd_status_t
switch_pd_int_src_enable(switch_device_t device, int32_t switch_id,
                         switch_ip_addr_t *src,
                         switch_ip_addr_t *dst,
                         uint8_t hop_cnt, uint16_t ins_mask,
                         int32_t idx, p4_pd_entry_hdl_t *entry_hdl,
                         bool vtep_src);

#endif
#ifdef P4_INT_EP_ENABLE
p4_pd_status_t
switch_pd_int_sink_enable(switch_device_t device,
                          switch_ip_addr_t *dst,
                          uint32_t mirror_id,
                          int32_t prio, p4_pd_entry_hdl_t *entry_hdl,
                          bool use_client_ip);
#endif

p4_pd_status_t
switch_pd_storm_control_table_add_default_entry(
        switch_device_t device);

p4_pd_status_t
switch_pd_storm_control_meter_add_entry(
        switch_device_t device,
        switch_meter_idx_t meter_idx,
        switch_meter_info_t *meter_info);

p4_pd_status_t
switch_pd_storm_control_table_add_entry(
        switch_device_t device,
        switch_port_t port,
        uint16_t priority,
        switch_packet_type_t pkt_type,
        switch_meter_idx_t meter_idx,
        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_storm_control_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_meter_index_table_add_default_entry(
        switch_device_t device);

p4_pd_status_t
switch_pd_meter_index_table_add_entry(
        switch_device_t device,
        switch_meter_idx_t meter_idx,
        switch_meter_info_t *meter_info,
        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_meter_index_table_update_entry(
        switch_device_t device,
        switch_meter_idx_t meter_idx,
        switch_meter_info_t *meter_info,
        p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_meter_index_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t entry_hdl);

p4_pd_status_t
switch_pd_meter_action_table_add_default_entry(
        switch_device_t device);

p4_pd_status_t
switch_pd_meter_action_table_add_entry(
        switch_device_t device,
        switch_meter_idx_t meter_idx,
        switch_meter_info_t *meter_info,
        p4_pd_entry_hdl_t *entry_hdl);


p4_pd_status_t
switch_pd_meter_action_table_update_entry(
        switch_device_t device,
        switch_meter_idx_t meter_idx,
        switch_meter_info_t *meter_info,
        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_meter_action_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_stats_update(switch_device_t device);

p4_pd_status_t
switch_pd_meter_stats_get(switch_device_t device, switch_meter_info_t *meter_info);

p4_pd_status_t
switch_pd_storm_control_stats_get(switch_device_t device, switch_meter_info_t *meter_info);

p4_pd_status_t
switch_pd_egress_bd_stats_table_add_entry(
        switch_device_t device,
        uint16_t bd,
        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_egress_bd_stats_table_delete_entry(
        switch_device_t device,
        p4_pd_entry_hdl_t *entry_hdl);

p4_pd_status_t
switch_pd_acl_stats_get(
        switch_device_t device,
        uint16_t acl_stats_index,
        switch_counter_t *acl_counter);

#ifdef __cplusplus
}
#endif

#endif
