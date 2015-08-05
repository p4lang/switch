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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SWITCH_DEV_ID          0x0
#define SWITCH_DEV_PIPE_ID     0xFFFF

#define SWITCH_LOGICAL_IFINDEX_SHIFT      12 
#define SWITCH_INTF_TUNNEL_IFINDEX        1

//IP Encap defines
#define SWITCH_IP_ENCAP_SRC_IP_TYPE(ip_encap) \
    ip_encap->src_ip.type

#define SWITCH_IP_ENCAP_DST_IP_TYPE(ip_encap) \
    ip_encap->dst_ip.type

#define SWITCH_IP_ENCAP_IPV4_SRC_IP(ip_encap) \
    ip_encap->src_ip.ip.v4addr

#define SWITCH_IP_ENCAP_IPV4_DST_IP(ip_encap) \
    ip_encap->dst_ip.ip.v4addr

#define SWITCH_IP_ENCAP_IPV6_SRC_IP(ip_encap) \
    ip_encap->src_ip.ip.v6addr

#define SWITCH_IP_ENCAP_IPV6_DST_IP(ip_encap) \
    ip_encap->dst_ip.ip.v6addr

#define SWITCH_IP_ENCAP_UDP_DST_PORT(ip_encap) \
    ip_encap->u.udp.dst_port

//Encap Info defines
#define SWITCH_ENCAP_VXLAN_VNI(encap_info) \
    encap_info->u.vxlan_info.vnid

#define SWITCH_ENCAP_NVGRE_VNI(encap_info) \
    encap_info->u.nvgre_info.tnid

#define SWITCH_ENCAP_GENEVE_VNI(encap_info) \
    encap_info->u.geneve_info.vni

#define SWITCH_ENCAP_VLAN_ID(encap_info) \
    encap_info->u.vlan_id

// Tunnel defines
#define SWITCH_INTF_TUNNEL_INFO(intf_info) \
    intf_info->api_intf_info.u.tunnel_info

#define SWITCH_INTF_TUNNEL_ENCAP_INFO(intf_info) \
    intf_info->api_intf_info.u.tunnel_info.encap_info

// MPLS defines
#define SWITCH_MPLS_POP_HEADER_COUNT(mpls_encap) \
    mpls_encap->u.pop_info.count

#define SWITCH_MPLS_PUSH_HEADER_COUNT(mpls_encap) \
    mpls_encap->u.push_info.count

#define SWITCH_MPLS_SWAP_HEADER_COUNT(mpls_encap) 1

#define SWITCH_MPLS_SWAP_PUSH_HEADER_COUNT(mpls_encap) \
    mpls_encap->u.swap_push_info.count

#define SWITCH_MPLS_PUSH_HEADER(mpls_encap) \
    mpls_encap->u.push_info.tag

#define SWITCH_MPLS_SWAP_NEW_LABEL(mpls_encap) \
    mpls_encap->u.swap_info.new_tag.label

#define SWITCH_MPLS_SWAP_PUSH_HEADER(mpls_encap) \
    mpls_encap->u.swap_push_info.new_tag

#define SWITCH_MPLS_SWAP_OLD_LABEL(mpls_encap) \
    mpls_encap->u.swap_info.old_tag.label

#define SWITCH_MPLS_SWAP_PUSH_OLD_LABEL(mpls_encap) \
    mpls_encap->u.swap_push_info.old_tag.label

// LN defines
#define SWITCH_LN_ENCAP_INFO(bd_info) \
    bd_info->ln_info.encap_info

#define SWITCH_LN_TUNNEL_VNI(bd_info) \
    bd_info->ln_info.encap_info.u.tunnel_vni

#ifdef __cplusplus
}
#endif
