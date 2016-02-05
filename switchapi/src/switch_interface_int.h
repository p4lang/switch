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

#ifndef _switch_interface_int_h_
#define _switch_interface_int_h_

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_interface.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct switch_ip_encap_pd_hdl_ {
#ifdef SWITCH_PD
    // ingress
    p4_pd_entry_hdl_t src_hw_entry;
    p4_pd_entry_hdl_t dst_hw_entry;
    // egress
    p4_pd_entry_hdl_t src_rw_hw_entry;
    p4_pd_entry_hdl_t dst_rw_hw_entry;
#endif
} switch_ip_encap_pd_hdl_t;

/** Interface information */
typedef struct switch_interface_info_ {
    switch_device_t device;                          /**< For now, just one device */
    switch_ifindex_t ifindex;
    switch_api_interface_info_t api_intf_info;
    switch_ip_encap_pd_hdl_t ip_encap_hdl;
    unsigned int ip_addr_count;                      /**< number of IP addresses on interface */
    tommy_list ip_addr;                              /**< List of IP addresses */
    unsigned int acl_label;                          /**< ACL label */
    switch_handle_t bd_handle;                       /**< L3 Port Implicit BD Handle */
    switch_handle_t ln_bd_handle;                    /**< Logical network BD Handle */
    switch_handle_t nhop_handle;
    switch_handle_t hostif_handle;
#ifdef SWITCH_PD
    p4_pd_entry_hdl_t nhop_type_entry;
    p4_pd_entry_hdl_t lag_group_entry;
    p4_pd_entry_hdl_t pv_entry;
    p4_pd_entry_hdl_t xlate_entry;
#endif
} switch_interface_info_t;

#define SWITCH_INTF_TYPE(info) \
    info->api_intf_info.type

#define SWITCH_INTF_TUNNEL_ENCAP_TYPE(info) \
    info->api_intf_info.u.tunnel_info.encap_info.encap_type

#define SWITCH_INTF_TUNNEL_IP_ENCAP(info) \
    info->api_intf_info.u.tunnel_info.u.ip_encap

#define SWITCH_INTF_TUNNEL_MPLS_ENCAP(info) \
    info->api_intf_info.u.tunnel_info.u.mpls_encap

#define SWITCH_INTF_TUNNEL_ENCAP_OUT_IF(info) \
    info->api_intf_info.u.tunnel_info.out_if

#define SWITCH_INTF_PORT_HANDLE(info) \
    info->api_intf_info.u.port_lag_handle

#define SWITCH_INTF_VLAN_ID(info) \
    info->api_intf_info.u.vlan_id

#define SWITCH_INTF_PV_PORT_HANDLE(info) \
    info->api_intf_info.u.port_vlan.port_lag_handle

#define SWITCH_INTF_PV_VLAN_ID(info) \
    info->api_intf_info.u.port_vlan.vlan_id

#define SWITCH_INTF_L2_LAG_INDEX(info) \
    handle_to_id(SWITCH_INTF_PORT_HANDLE(info))

#define SWITCH_INTF_L2_PORT(info) \
    handle_to_id(SWITCH_INTF_PORT_HANDLE(info))

#define SWITCH_INTF_L3_LAG_INDEX(info) \
    handle_to_id(SWITCH_INTF_PORT_HANDLE(info))

#define SWITCH_INTF_L3_PORT(info) \
    handle_to_id(SWITCH_INTF_PORT_HANDLE(info))

#define SWITCH_INTF_IS_PORT_L3(info) \
    ((info->api_intf_info.type == SWITCH_API_INTERFACE_L3) || \
    (info->api_intf_info.type == SWITCH_API_INTERFACE_L3_PORT_VLAN) || \
    (info->api_intf_info.type == SWITCH_API_INTERFACE_TUNNEL))

#define SWITCH_INTF_IS_PORT_L2(info) \
    (info->api_intf_info.type == SWITCH_API_INTERFACE_L2_VLAN_ACCESS) || \
    (info->api_intf_info.type == SWITCH_API_INTERFACE_L2_VLAN_TRUNK)

#define SWITCH_INTF_NATIVE_VLAN_HANDLE(info) \
    info->api_intf_info.native_vlan

#define SWITCH_INTF_IS_PORT_L2_ACCESS(info) \
    (info->api_intf_info.type == SWITCH_API_INTERFACE_L2_VLAN_ACCESS)

#define SWITCH_INTF_IS_PORT_L2_TRUNK(info) \
    (info->api_intf_info.type == SWITCH_API_INTERFACE_L2_VLAN_TRUNK)

#define SWITCH_INTF_IS_CORE(info) \
    info->api_intf_info.flags.core_intf

#define SWITCH_INTF_FLOOD_ENABLED(info) \
    info->api_intf_info.flags.flood_enabled

#define SWITCH_INTF_COMPUTE_TUNNEL_IFINDEX(handle)                       \
    handle_to_id(handle) |                                               \
    (SWITCH_INTF_TUNNEL_IFINDEX << SWITCH_LOGICAL_IFINDEX_SHIFT)

#define SWITCH_INTF_IS_TUNNEL_IFINDEX(ifindex) \
    ifindex & (SWITCH_INTF_TUNNEL_IFINDEX << SWITCH_LOGICAL_IFINDEX_SHIFT)

#define SWITCH_INTF_TUNNEL_ID(ifindex) \
    ifindex & ~(SWITCH_INTF_TUNNEL_IFINDEX << SWITCH_LOGICAL_IFINDEX_SHIFT)

#define SWITCH_VLAN_INTERFACE_COMPUTE_IFINDEX(handle)                      \
    (handle_to_id(handle) |                                                \
    (SWITCH_IFINDEX_TYPE_VLAN_INTERFACE << SWITCH_IFINDEX_PORT_WIDTH))

// Internal Interface API's
switch_interface_info_t *switch_api_interface_get(switch_handle_t handle);
switch_handle_t switch_api_interface_get_from_ifindex(switch_ifindex_t ifindex);
switch_status_t switch_interface_init(switch_device_t device);
switch_status_t switch_interface_free(switch_device_t device);
switch_status_t switch_api_interface_create_l2(switch_device_t device, switch_handle_t intf_handle,
                                               switch_interface_info_t *intf_info);
switch_status_t switch_api_interface_create_l3(switch_device_t device, switch_handle_t intf_handle,
                                               switch_interface_info_t *intf_info);

#ifdef __cplusplus
}
#endif

#endif
