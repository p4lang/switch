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
/*
        switcht API thrift file
*/

namespace py switch_api
namespace cpp switch_api

/*
enum switcht_status_t {
    SWITCHT_API_STATUS_SUCCESS = 0,
    SWITCHT_API_STATUS_PARAM_INVALID,
    SWITCHT_API_STATUS_INVALID_OPERATION,
    SWITCHT_API_STATUS_NOT_SUPPORTED,
    SWITCHT_API_STATUS_DUPLICATE,
    SWITCHT_API_STATUS_UNKNOWN_ERROR
}

enum switcht_handle_type_t {
    SWITCHT_HANDLE_TYPE_NONE,
    SWITCHT_HANDLE_TYPE_PORT,
    SWITCHT_HANDLE_TYPE_LAG,
    SWITCHT_HANDLE_TYPE_INTERFACE,
    SWITCHT_HANDLE_TYPE_VRF,
    SWITCHT_HANDLE_TYPE_BD,
    SWITCHT_HANDLE_TYPE_TUNNEL,
    SWITCHT_HANDLE_TYPE_NHOP,
    SWITCHT_HANDLE_TYPE_ECMP,
    SWITCHT_HANDLE_TYPE_ARP,
    SWITCHT_HANDLE_TYPE_MY_MAC,
    SWITCHT_HANDLE_TYPE_MAX=15
}

enum switcht_interface_type_t {
    SWITCHT_API_INTERFACE_NONE,
    SWITCHT_API_INTERFACE_LOOPBACK,
    SWITCHT_API_INTERFACE_L2_VLAN_ACCESS,
    SWITCHT_API_INTERFACE_L2_VLAN_TRUNK,
    SWITCHT_API_INTERFACE_L3,
    SWITCHT_API_INTERFACE_L3_VLAN,
    SWITCHT_API_INTERFACE_L3_PORT_VLAN,
    SWITCHT_API_INTERFACE_LAG,
    SWITCHT_API_INTERFACE_L3_TUNNEL,
    SWITCHT_API_INTERFACE_L2_PORT_VLAN
}

enum switcht_direction_t {
    SWITCHT_API_DIRECTION_BOTH,
    SWITCHT_API_DIRECTION_INGRESS,
    SWITCHT_API_DIRECTION_EGRESS
}

enum switcht_sflow_collector_type_t {
    SWITCHT_API_SFLOW_COLLECTOR_TYPE_CPU = 0;
    SWITCHT_API_SFLOW_COLLECTOR_TYPE_REMOTE;
}

*/

typedef i32 switcht_status_t
typedef i32 switcht_direction_t
typedef i32 switcht_interface_type_t
typedef i32 switcht_handle_type_t

typedef byte switcht_device_t
typedef i32 switcht_vrf_id_t
typedef i64 switcht_handle_t
typedef string switcht_mac_addr_t
typedef i32 switcht_port_t
typedef i16 switcht_vlan_t
typedef i32 switcht_interface_handle_t
typedef i32 switcht_tunnel_handle_t

typedef i32 switcht_stp_mode_t
typedef i32 switcht_stp_state_t
typedef i32 switcht_intf_attr_t

typedef i16 switcht_nat_mode_t
typedef i16 switcht_nat_rw_type_t
typedef i16 switcht_mcast_mode_t

typedef i32 switcht_urpf_group_t

typedef i32 switcht_sflow_collector_type_t
typedef i32 switcht_sflow_sample_mode_t

typedef byte switcht_packet_type_t

struct switcht_port_info_t {
        1: required i32 port_number;
        2: optional i32 l2mtu;
        3: optional i32 l3mtu;
        4: optional i32 vrf;
        5: optional bool tunnel_term;
        6: optional bool ipv4_term=true;
        7: optional i32 v6_vrf;
        8: optional bool ipv6_term;
        9: optional bool igmp_snoop;
        10: optional byte urpf_mode=0;
}

struct switcht_ip_addr_t {
        1: byte addr_type;
        2: string ipaddr;
        3: i32 prefix_length;
}

struct switcht_flow_t {
        1: switcht_ip_addr_t src_ip;
        2: switcht_ip_addr_t dst_ip;
        3: bool is_local_flow;
}

typedef list<switcht_flow_t> switcht_flow_list_t

struct switcht_port_vlan_t {
        2: switcht_handle_t port_lag_handle;
        3: i16 vlan_id;                        /**< VLAN id on port */
}

struct switcht_vlan_interface_t {
        1: switcht_handle_t vlan_handle;
        2: switcht_handle_t intf_handle;
}

typedef i32 switcht_protocol_t

struct switcht_udp_t {
    1: i16 src_port;
    2: i16 dst_port;
}

struct switcht_tcp_t {
    1: i16 src_port;
    2: i16 dst_port;
}


union switcht_udp_tcp_t {
    1: switcht_udp_t udp;
    2: switcht_tcp_t tcp;
}

struct switcht_ip_encap_t {
    1: switcht_vrf_id_t vrf;
    2: switcht_ip_addr_t src_ip;
    3: switcht_ip_addr_t dst_ip;
    4: byte ttl;
    5: switcht_protocol_t proto;
    6: optional switcht_udp_tcp_t u;
    7: optional i16 gre_proto;
}

union interface_union {
    1: switcht_handle_t port_lag_handle;       /**< LAG handle */
    2: switcht_vlan_t vlan_id;                 /**< VLAN */
    3: switcht_port_vlan_t port_vlan;          /**< Port-VLAN */
    4: switcht_ip_encap_t ip_encap;            /**< Tunnel info */
}

struct switcht_interface_flags {
    1: bool core_intf;
    2: bool flood_enabled;
    3: bool learn_enabled;
}

struct switcht_interface_info_t {
        1: switcht_device_t device
        2: switcht_interface_type_t type;      /**< type of interface */
        3: interface_union u;
        4: switcht_mac_addr_t mac;             /**< Mac address associated with interface */
        5: i32 label                           /**< ACL label */
        6: switcht_handle_t vrf_handle;
        7: switcht_nat_mode_t nat_mode;        /**< Nat mode for L3 interface */
        8: switcht_handle_t rmac_handle;
        9: switcht_interface_flags flags;
        10: i16 v4_urpf_mode;
        11: i16 v6_urpf_mode;
        12: bool v4_unicast_enabled;
        13: bool v6_unicast_enabled;
        14: bool v4_multicast_enabled;
        15: bool v6_multicast_enabled;
}

enum switcht_neighbor_type_t {
    SWITCHT_API_NEIGHBOR_L3_UNICAST,
    SWITCHT_API_NEIGHBOR_MPLS_L2VPN,
    SWITCHT_API_NEIGHBOR_MPLS_L3VPN
}

enum switcht_neighbor_rw_type_t {
    SWITCH_API_NEIGHBOR_RW_TYPE_L2,
    SWITCH_API_NEIGHBOR_RW_TYPE_L3
}

struct switcht_neighbor_info_t {
        1: switcht_neighbor_type_t neigh_type;
        2: switcht_handle_t nhop_handle;
        3: switcht_interface_handle_t interface_handle;
        4: switcht_vlan_t vlan;
        5: switcht_mac_addr_t mac_addr;
        6: switcht_ip_addr_t ip_addr;
        7: i32 mpls_label;
        8: byte header_count;
        9: switcht_neighbor_rw_type_t rw_type;
}

struct switcht_nat_info_t {
    1: switcht_nat_rw_type_t nat_rw_type;
    2: switcht_ip_addr_t src_ip;
    3: switcht_ip_addr_t dst_ip;
    4: i32 src_port;
    5: i32 dst_port;
    6: i16 protocol;
    7: switcht_handle_t vrf_handle;
    9: switcht_handle_t nhop_handle;
    10: switcht_ip_addr_t rw_src_ip;
    11: switcht_ip_addr_t rw_dst_ip;
    12: i32 rw_src_port;
    13: i32 rw_dst_port;
}

struct switcht_vxlan_id_t {
    1: i32 vnid;
}

struct switcht_geneve_id_t {
    1: i32 vni;
}

struct switcht_nvgre_id_t {
    1: i32 tnid;
}

struct switcht_ln_flags {
    1: bool flood_enabled;
    2: bool learn_enabled;
    3: bool core_bd;
    4: bool ipv4_unicast_enabled;
    5: bool ipv6_unicast_enabled;
    6: bool ipv4_multicast_enabled;
    7: bool ipv6_multicast_enabled;
}

union switcht_bridge_type  {
    1: switcht_vlan_t vlan_id;
    2: switcht_vxlan_id_t vxlan_info;
    3: switcht_geneve_id_t geneve_info;
    4: switcht_nvgre_id_t  nvgre_info;
    5: i32 tunnel_vni;
}

struct switcht_encap_info_t {
    1: i32 encap_type;
    2: switcht_bridge_type u;
}

struct switcht_mpls_t {
    1: i32 label;
    2: byte exp;
    3: byte bos;
    4: byte ttl;
}

enum switcht_mpls_type_t {
    SWITCHT_API_MPLS_TYPE_EOMPLS,
    SWITCHT_API_MPLS_TYPE_IPV4_MPLS,
    SWITCHT_API_MPLS_TYPE_IPV6_MPLS,
    SWITCHT_API_MPLS_TYPE_VPLS,
    SWITCHT_API_MPLS_TYPE_PW
}

enum switcht_mpls_mode_t {
    SWITCHT_API_MPLS_INITIATE,
    SWITCHT_API_MPLS_TRANSIT,
    SWITCHT_API_MPLS_TERMINATE
}

enum switcht_mpls_action_t {
    SWITCHT_API_MPLS_ACTION_POP,
    SWITCHT_API_MPLS_ACTION_PUSH,
    SWITCHT_API_MPLS_ACTION_SWAP,
    SWITCHT_API_MPLS_ACTION_SWAP_PUSH
}

struct switcht_mpls_swap_t {
    1: switcht_mpls_t old_tag;
    2: switcht_mpls_t new_tag;
}

struct switcht_mpls_pop_t {
    1: list<switcht_mpls_t> tag;
    2: byte count;
}

struct switcht_mpls_push_t {
    1: list<switcht_mpls_t> tag;
    2: byte count;
}

struct switcht_mpls_swap_push_t {
    1: switcht_mpls_t old_tag;
    2: list<switcht_mpls_t> new_tag;
    3: byte count;
}

union switcht_mpls_info_t {
    1: switcht_mpls_swap_t swap_info;
    2: switcht_mpls_push_t push_info;
    3: switcht_mpls_pop_t pop_info;
    4: switcht_mpls_swap_push_t swap_push_info;
}

struct switcht_mpls_encap_t {
    1: switcht_mpls_type_t mpls_type;
    2: switcht_mpls_action_t mpls_action;
    3: switcht_mpls_mode_t mpls_mode;
    4: switcht_mpls_info_t u;
    5: switcht_handle_t bd_handle;
    6: switcht_handle_t vrf_handle;
    7: switcht_handle_t nhop_handle;
    8: switcht_handle_t egress_if;
}

union switcht_tunnel_encap_t {
    1: switcht_ip_encap_t ip_encap;
    2: switcht_mpls_encap_t mpls_encap;
}

enum switcht_encap_mode_t {
    SWITCHT_API_TUNNEL_ENCAP_MODE_IP,
    SWITCHT_API_TUNNEL_ENCAP_MODE_MPLS
}

struct switcht_tunnel_info_t {
    1: switcht_encap_mode_t encap_mode;
    2: switcht_tunnel_encap_t tunnel_encap;
    3: switcht_encap_info_t encap_info;
    4: switcht_handle_t out_if;
    5: switcht_interface_flags flags;
}

struct switcht_logical_network_t  {
    1: i32 type;
    2: switcht_encap_info_t encap_info;
    3: i32 age_interval;
    4: switcht_handle_t vrf;
    5: switcht_ln_flags flags;
    6: switcht_handle_t rmac_handle;
}

typedef i32 switcht_acl_type_t

union switcht_acl_value_t {
    1: string value_str;
    2: i64 value_num;
}

struct switcht_acl_key_value_pair_t {
    1: i32 field;
    2: switcht_acl_value_t value;
    3: switcht_acl_value_t mask;
}

typedef switcht_acl_key_value_pair_t switcht_acl_system_key_value_pair_t
typedef switcht_acl_key_value_pair_t switcht_acl_ip_key_value_pair_t
typedef switcht_acl_key_value_pair_t switcht_acl_mirror_key_value_pair_t
typedef switcht_acl_key_value_pair_t switcht_acl_qos_key_value_pair_t
typedef switcht_acl_key_value_pair_t switcht_acl_mac_key_value_pair_t
typedef switcht_acl_key_value_pair_t switcht_acl_ipv6_key_value_pair_t
typedef switcht_acl_key_value_pair_t switcht_acl_ipracl_key_value_pair_t
typedef switcht_acl_key_value_pair_t switcht_acl_ipv6racl_key_value_pair_t
typedef switcht_acl_key_value_pair_t switcht_acl_egr_key_value_pair_t
typedef switcht_acl_key_value_pair_t switcht_sflow_key_value_pair_t

struct switcht_vlan_port_t {
    1: switcht_handle_t handle;
    2: i16 tagging_mode;
}

struct switcht_nhop_key_t {
    1: switcht_handle_t intf_handle;
    2: switcht_ip_addr_t ip_addr;
    3: bool ip_addr_valid;
}

struct switcht_hostif_group_t {
    1: i32 queue_id;
    2: i32 priority;
    3: i32 policer_handle;
}

struct switcht_counter_t {
    1: i64 num_packets;
    2: i64 num_bytes;
}

typedef i32 switcht_acl_action_t
typedef i32 switcht_hostif_reason_code_t
typedef byte switcht_hostif_channel_t

struct switcht_api_hostif_rcode_info_t {
    1: switcht_hostif_reason_code_t reason_code;
    2: switcht_acl_action_t action;
    3: i32 priority;
    4: switcht_hostif_channel_t channel;
    5: switcht_handle_t hostif_group_id;
}

struct switcht_hostif_t {
    1: string intf_name;
}

struct switcht_acl_action_cpu_redirect {
    1: i32 reason_code;
}

struct switcht_acl_action_redirect {
    1: switcht_handle_t handle;
}

union switcht_acl_action_params_t {
    1: switcht_acl_action_cpu_redirect cpu_redirect;
    2: switcht_acl_action_redirect redirect;
}

struct switcht_acl_opt_action_params_t {
    1: switcht_handle_t mirror_handle;
    2: switcht_handle_t meter_handle;
    3: switcht_handle_t counter_handle;
}

struct switcht_mirror_info_t {
    1: i32 session_id;
    2: switcht_direction_t direction;
    3: i32 egress_port;
    4: i32 mirror_type;
    5: byte cos;
    6: i32 max_pkt_len;
    7: i32 ttl;
    8: bool enable;
    9: switcht_handle_t nhop_handle;
    10: i32 session_type;
    11: switcht_vlan_t vlan_id;
    12: switcht_tunnel_info_t tun_info;
    13: i32 extract_len;
    14: i32 timeout_usec;
}

struct switcht_sflow_info_t {
    1: i32    timeout_usec;
    2: i32    sample_rate;
    3: i32    extract_len;
    4: switcht_sflow_collector_type_t  collector_type;
    5: switcht_handle_t         egress_port_hdl;
    6: switcht_sflow_sample_mode_t  sample_mode;
}

typedef i64 switcht_cbs_t
typedef i64 switcht_pbs_t
typedef i64 switcht_cir_t
typedef i64 switcht_pir_t
typedef byte switcht_meter_mode_t
typedef byte switcht_meter_color_source_t
typedef byte switcht_meter_type_t

struct switcht_api_meter_info_t {
    1: switcht_meter_mode_t meter_mode;
    2: switcht_meter_color_source_t color_source;
    3: switcht_meter_type_t meter_type;
    4: switcht_cbs_t cbs;
    5: switcht_pbs_t pbs;
    6: switcht_cir_t cir;
    7: switcht_pir_t pir;
    8: switcht_acl_action_t green_action;
    9: switcht_acl_action_t yellow_action;
   10: switcht_acl_action_t red_action;
}

struct switcht_api_buffer_profile_t {
    1: byte threshold_mode;
    2: i32 threshold;
    3: switcht_handle_t pool_handle;
    4: i32 buffer_size;
    5: i32 xoff_threshold;
    6: i32 xon_threshold;
}

typedef i16 switcht_qos_map_type_t
typedef byte switcht_color_t

struct switcht_qos_map_t {
    1: byte dscp;
    2: byte pcp;
    3: i16 tc;
    4: switcht_color_t color;
    5: byte icos;
    6: byte qid;
}

typedef byte switcht_scheduler_type_t
typedef byte switcht_shaper_type_t

struct switcht_scheduler_info_t {
    1: switcht_scheduler_type_t scheduler_type;
    2: switcht_shaper_type_t shaper_type;
    3: i32 priority;
    4: i32 rem_bw_priority;
    5: i32 weight;
    6: i32 min_burst_size;
    7: i32 min_rate;
    8: i32 max_burst_size;
    9: i32 max_rate;
}

struct switcht_range_t {
    1: i32 start_value;
    2: i32 end_value;
}

service switch_api_rpc {
    /* init */
    switcht_status_t switcht_api_init(1:switcht_device_t device);

    /* drop stats */
    list<i64> switcht_api_drop_stats_get(1:switcht_device_t device);

    /* Port */
    switcht_status_t switcht_api_port_set(1:switcht_device_t device, 2:switcht_port_info_t port_info);
    switcht_status_t switcht_api_port_print_all();
    switcht_status_t switcht_api_port_storm_control_set(
                             1: switcht_device_t device,
                             2: switcht_port_t port_id,
                             3: switcht_packet_type_t pkt_type,
                             4: switcht_handle_t meter_handle);
    list<switcht_counter_t> switcht_api_storm_control_stats_get(
                             1: switcht_device_t device,
                             2: switcht_handle_t meter_handle,
                             3: list<i16> counter_ids);
    switcht_status_t switcht_api_port_trust_dscp_set(
                             1: switcht_device_t device,
                             2: switcht_handle_t port_handle,
                             3: bool trust_dscp);
    switcht_status_t switcht_api_port_trust_pcp_set(
                             1: switcht_device_t device,
                             2: switcht_handle_t port_handle,
                             3: bool trust_pcp);
    switcht_status_t switcht_api_port_drop_limit_set(
                             1: switcht_device_t device,
                             2: switcht_handle_t port_handle,
                             3: i32 num_bytes);
    switcht_status_t switcht_api_port_drop_hysteresis_set(
                             1: switcht_device_t device,
                             2: switcht_handle_t port_handle,
                             3: i32 num_bytes);
    switcht_status_t switcht_api_port_pfc_cos_mapping(
                             1: switcht_device_t device,
                             2: switcht_handle_t port_handle,
                             3: list<byte> cos_to_icos);
    switcht_status_t switcht_api_port_tc_default_set(
                             1: switcht_device_t device,
                             2: switcht_handle_t port_handle,
                             3: i16 tc);
    switcht_status_t switcht_api_port_color_default_set(
                             1: switcht_device_t device,
                             2: switcht_handle_t port_handle,
                             3: switcht_color_t color);
    switcht_status_t switcht_api_port_qos_group_ingress_set(
                             1: switcht_device_t device,
                             2: switcht_handle_t port_handle,
                             3: switcht_handle_t qos_handle);
    switcht_status_t switcht_api_port_qos_group_tc_set(
                             1: switcht_device_t device,
                             2: switcht_handle_t port_handle,
                             3: switcht_handle_t qos_handle);
    switcht_status_t switcht_api_port_qos_group_egress_set(
                             1: switcht_device_t device,
                             2: switcht_handle_t port_handle,
                             3: switcht_handle_t qos_handle);

    /* vpn */
    switcht_handle_t switcht_api_vrf_create(1:switcht_device_t device, 2:switcht_vrf_id_t vrf);
    switcht_status_t switcht_api_vrf_delete(1:switcht_device_t device, 2:switcht_handle_t vrf_handle);
    switcht_handle_t switcht_api_default_vrf_get();

    /* router mac */
    switcht_handle_t switcht_api_router_mac_group_create(1:switcht_device_t device);
    switcht_status_t switcht_api_router_mac_group_delete(1:switcht_device_t device, 2:switcht_handle_t rmac_handle);
    switcht_status_t switcht_api_router_mac_add(1:switcht_device_t device, 2:switcht_handle_t rmac_handle, 3:switcht_mac_addr_t mac);
    switcht_status_t switcht_api_router_mac_delete(1:switcht_device_t device, 2:switcht_handle_t rmac_handle, 3:switcht_mac_addr_t mac);
    switcht_status_t switcht_api_router_mac_group_print_all();

    /* interface */
    switcht_interface_handle_t switcht_api_interface_create(1:switcht_device_t device, 2:switcht_interface_info_t interface_info);
    switcht_status_t switcht_api_interface_delete(1:switcht_device_t device, 2:switcht_interface_handle_t interface_handle);
    switcht_status_t switcht_api_interface_print_all();
    switcht_status_t switcht_api_interface_attribute_set(1: switcht_handle_t interface_handle, 2: switcht_intf_attr_t attr_type, 3:i64 value);
    switcht_status_t switcht_api_interface_ipv4_unicast_enabled_set(1: switcht_handle_t intf_handle, 2: i64 value);
    switcht_status_t switcht_api_interface_ipv6_unicast_enabled_set(1: switcht_handle_t intf_handle, 2: i64 value);
    switcht_status_t switcht_api_interface_ipv4_urpf_mode_set(1: switcht_handle_t intf_handle, 2: i64 value);
    switcht_status_t switcht_api_interface_ipv6_urpf_mode_set(1: switcht_handle_t intf_handle, 2: i64 value);

    /* get interface handle by vrf + ip */
    switcht_handle_t switcht_api_l3_route_nhop_intf_get(1:switcht_device_t device, 2:switcht_handle_t vrf, 3:switcht_ip_addr_t ip_addr);

    /* ip address */
    switcht_status_t switcht_api_l3_interface_address_add(1:switcht_device_t device, 2:switcht_interface_handle_t interface_handle, 3:switcht_handle_t vrf, 4:switcht_ip_addr_t ip_addr);
    switcht_status_t switcht_api_l3_interface_address_delete(1:switcht_device_t device, 2:switcht_interface_handle_t interface_handle, 3:switcht_handle_t vrf, 4:switcht_ip_addr_t ip_addr);

    /* next hop */
    switcht_handle_t switcht_api_nhop_create(1:switcht_device_t device, 2:switcht_nhop_key_t nhop_key);
    switcht_status_t switcht_api_nhop_delete(1:switcht_device_t device, 2:switcht_handle_t handle);
    switcht_status_t switcht_api_nhop_print_all();

    /* ARP */
    switcht_handle_t switcht_api_neighbor_entry_add(1:switcht_device_t device, 2:switcht_neighbor_info_t neighbor);
    switcht_status_t switcht_api_neighbor_entry_remove(1:switcht_device_t device, 2:switcht_handle_t neighbor_handle);
    switcht_status_t switcht_api_neighbor_print_all();

    /* L3 */
    switcht_status_t switcht_api_l3_route_add(1:switcht_device_t device, 2:switcht_handle_t vrf, 3:switcht_ip_addr_t ip_addr, 4: switcht_handle_t nhop_handle);
    switcht_status_t switcht_api_l3_route_delete(1:switcht_device_t device, 2:switcht_handle_t vrf, 3:switcht_ip_addr_t ip_addr, 4: switcht_handle_t nhop_handle);
    switcht_handle_t switcht_api_l3_route_lookup(1:switcht_device_t device, 2:switcht_handle_t vrf, 3:switcht_ip_addr_t ip_addr);
    switcht_status_t switcht_api_l3_routes_print_all()

    /* VLAN */
    switcht_handle_t switcht_api_vlan_create(1:switcht_device_t device, 2:switcht_vlan_t vlan_id);
    switcht_status_t switcht_api_vlan_delete(1:switcht_device_t device, 2:switcht_handle_t vlan_handle);
    switcht_status_t switcht_api_vlan_ports_add(1:switcht_device_t device, 2:switcht_handle_t vlan_handle, 3:switcht_vlan_port_t port_vlan);
    switcht_status_t switcht_api_vlan_ports_remove(1:switcht_device_t device, 2:switcht_handle_t vlan_handle, 3:switcht_vlan_port_t port_vlan);
    switcht_status_t switcht_api_vlan_print_all();

    /* VLAN attribute */
    switcht_status_t switcht_api_vlan_learning_enabled_set(1: switcht_handle_t vlan_handle, 2: i64 value);
    switcht_status_t switcht_api_vlan_learning_enabled_get(1: switcht_handle_t vlan_handle, 2: i64 value);
    switcht_status_t switcht_api_vlan_aging_interval_set(1: switcht_handle_t vlan_handle, 2: i64 value);
    switcht_status_t switcht_api_vlan_stats_enable(1: switcht_device_t device, 2: switcht_handle_t vlan_handle);
    switcht_status_t switcht_api_vlan_stats_disable(1: switcht_device_t device, 2: switcht_handle_t vlan_handle);
    list<switcht_counter_t> switcht_api_vlan_stats_get(1: switcht_device_t device, 2: switcht_handle_t vlan_handle, 3: list<i16> counter_ids);
    switcht_status_t switcht_api_vlan_igmp_snooping_enabled_set(1: switcht_handle_t vlan_handle, 2: i64 value);
    switcht_status_t switcht_api_vlan_mld_snooping_enabled_set(1: switcht_handle_t vlan_handle, 2: i64 value);
    switcht_status_t switcht_api_vlan_mrpf_group_set(1: switcht_handle_t vlan_handle, 2: i64 value);

    /* L2 */
    switcht_status_t switcht_api_mac_table_entry_create(1:switcht_device_t device, 2:switcht_handle_t vlan_handle, 3:switcht_mac_addr_t mac, 4:byte entry_type, 5:switcht_handle_t handle);
    switcht_status_t switcht_api_mac_table_entry_update(1:switcht_device_t device, 2:switcht_handle_t vlan_handle, 3:switcht_mac_addr_t mac, 4:byte entry_type, 5:switcht_handle_t handle);
    switcht_status_t switcht_api_mac_table_entry_delete(1:switcht_device_t device, 2:switcht_handle_t vlan_handle, 3:switcht_mac_addr_t mac);
    switcht_status_t switcht_api_mac_table_entries_delete_by_vlan(1:switcht_device_t device, 2: switcht_handle_t vlan_handle);
    switcht_status_t switcht_api_mac_table_entries_delete_by_interface(1:switcht_device_t device, 2: switcht_handle_t intf_handle);
    switcht_status_t switcht_api_mac_table_entries_delete_all(1:switcht_device_t device);
    switcht_status_t switcht_api_mac_table_set_learning_timeout(1: switcht_device_t device, 2:i32 timeout);
    switcht_status_t switcht_api_mac_table_aging_time_set(1: i64 value);
    switcht_status_t switcht_api_mac_table_print_all();

    /* ECMP */
    switcht_handle_t switcht_api_l3_ecmp_create(1:switcht_device_t device);
    switcht_status_t switcht_api_l3_ecmp_delete(1:switcht_device_t device, 2:switcht_handle_t handle);
    switcht_status_t switcht_api_l3_ecmp_member_add(1: switcht_device_t device, 2:switcht_handle_t handle, 3: i16 nhop_count, 4:list<switcht_handle_t> nhop_handle);
    switcht_status_t switcht_api_l3_ecmp_member_delete(1: switcht_device_t device, 2:switcht_handle_t handle, 3: i16 nhop_count, 4: list<switcht_handle_t> nhop_handle);

    /* LAG */
    switcht_handle_t switcht_api_lag_create(1:switcht_device_t device);
    switcht_status_t switcht_api_lag_delete(1:switcht_device_t device, 2:switcht_handle_t lag_handle);
    switcht_status_t switcht_api_lag_member_add(1: switcht_device_t device, 2:switcht_handle_t lag_handle, 3:switcht_direction_t side, 4:switcht_port_t port);
    switcht_status_t switcht_api_lag_member_delete(1: switcht_device_t device, 2:switcht_handle_t lag_handle, 3:switcht_direction_t side, 4:switcht_port_t port);
    switcht_status_t switcht_api_lag_print_all();

    /* Logical Network */
    switcht_handle_t switcht_api_logical_network_create(1:switcht_device_t device, 2:switcht_logical_network_t info);
    switcht_status_t switcht_api_logical_network_delete(1:switcht_device_t device, 2:switcht_handle_t network_handle);

    /* Tunnel API */
    switcht_tunnel_handle_t switcht_api_tunnel_interface_create(1:switcht_device_t device, 2:switcht_direction_t direction, 3:switcht_tunnel_info_t tun_info);
    switcht_status_t switcht_api_tunnel_interface_delete(1:switcht_device_t device, 2:switcht_tunnel_handle_t tun_handle);
    switcht_status_t switcht_api_logical_network_member_add(1:switcht_device_t device, 2:switcht_handle_t network_handle, 3:switcht_interface_handle_t interface_handle);
    switcht_status_t switcht_api_logical_network_member_remove(1:switcht_device_t device, 2:switcht_handle_t network_handle, 3:switcht_interface_handle_t interface_handle);
    switcht_status_t switcht_api_mpls_tunnel_transit_create(1: switcht_device_t device, 2: switcht_mpls_encap_t mpls_encap);
    switcht_status_t switcht_api_mpls_tunnel_transit_delete(1: switcht_device_t device, 2: switcht_mpls_encap_t mpls_encap);

    /* STP API */
    switcht_handle_t switcht_api_stp_group_create(1:switcht_device_t device, 2:switcht_stp_mode_t stp_mode);
    switcht_status_t switcht_api_stp_group_delete(1:switcht_device_t device, 2:switcht_handle_t stp_handle);
    switcht_status_t switcht_api_stp_group_vlans_add(1:switcht_device_t device, 2:switcht_handle_t stp_handle, 3:i16 vlan_count, 4:list<switcht_handle_t> vlan_handle);
    switcht_status_t switcht_api_stp_group_vlans_remove(1:switcht_device_t device, 2:switcht_handle_t stp_handle, 3:i16 vlan_count, 4:list<switcht_handle_t> vlan_handle);
    switcht_status_t switcht_api_stp_port_state_set(1:switcht_device_t device, 2:switcht_handle_t stp_handle,
                                            3:switcht_handle_t intf_handle, 4:switcht_stp_state_t stp_state);
    switcht_status_t switcht_api_stp_port_state_clear(1:switcht_device_t device, 2:switcht_handle_t stp_handle,
                                              3:switcht_handle_t intf_handle);
    switcht_status_t switcht_api_stp_group_print_all();

    /* NAT API */
    switcht_status_t switcht_api_nat_create(1:switcht_device_t device, 2:switcht_nat_info_t nat_info);
    switcht_status_t switcht_api_nat_delete(1:switcht_device_t device, 2:switcht_nat_info_t nat_info);

    /* ACL API */
    switcht_handle_t switcht_api_acl_list_create(
                             1:switcht_device_t device,
                             2:switcht_direction_t direction,
                             3:switcht_acl_type_t type);
    switcht_status_t switcht_api_acl_list_delete(1:switcht_device_t device, 2:switcht_handle_t handle);
    switcht_handle_t switcht_api_acl_mac_rule_create(
                             1:switcht_device_t device,
                             2:switcht_handle_t acl_handle,
                             3:i32 priority,
                             4:i32 key_value_count,
                             5:list<switcht_acl_mac_key_value_pair_t> acl_kvp,
                             6:switcht_acl_action_t action,
                             7:switcht_acl_action_params_t action_params,
                             8:switcht_acl_opt_action_params_t opt_action_params);
    switcht_handle_t switcht_api_acl_ip_rule_create(
                             1:switcht_device_t device,
                             2:switcht_handle_t acl_handle,
                             3:i32 priority,
                             4:i32 key_value_count,
                             5:list<switcht_acl_ip_key_value_pair_t> acl_kvp,
                             6:switcht_acl_action_t action,
                             7:switcht_acl_action_params_t action_params,
                             8:switcht_acl_opt_action_params_t opt_action_params);
    switcht_handle_t switcht_api_acl_ipv6_rule_create(
                             1:switcht_device_t device,
                             2:switcht_handle_t acl_handle,
                             3:i32 priority,
                             4:i32 key_value_count,
                             5:list<switcht_acl_ipv6_key_value_pair_t> acl_kvp,
                             6:switcht_acl_action_t action,
                             7:switcht_acl_action_params_t action_params,
                             8:switcht_acl_opt_action_params_t opt_action_params);
    switcht_handle_t switcht_api_acl_ipracl_rule_create(
                             1:switcht_device_t device,
                             2:switcht_handle_t acl_handle,
                             3:i32 priority,
                             4:i32 key_value_count,
                             5:list<switcht_acl_ipracl_key_value_pair_t> acl_kvp,
                             6:switcht_acl_action_t action,
                             7:switcht_acl_action_params_t action_params,
                             8:switcht_acl_opt_action_params_t opt_action_params);
    switcht_handle_t switcht_api_acl_ipv6racl_rule_create(
                             1:switcht_device_t device,
                             2:switcht_handle_t acl_handle,
                             3:i32 priority,
                             4:i32 key_value_count,
                             5:list<switcht_acl_ipv6racl_key_value_pair_t> acl_kvp,
                             6:switcht_acl_action_t action,
                             7:switcht_acl_action_params_t action_params,
                             8:switcht_acl_opt_action_params_t opt_action_params);
    switcht_handle_t switcht_api_acl_mirror_rule_create(
                             1:switcht_device_t device,
                             2:switcht_handle_t acl_handle,
                             3:i32 priority,
                             4:i32 key_value_count,
                             5:list<switcht_acl_mirror_key_value_pair_t> acl_kvp,
                             6:switcht_acl_action_t action,
                             7:switcht_acl_action_params_t action_params,
                             8:switcht_acl_opt_action_params_t opt_action_params);
    switcht_handle_t switcht_api_acl_system_rule_create(
                             1:switcht_device_t device,
                             2:switcht_handle_t acl_handle,
                             3:i32 priority,
                             4:i32 key_value_count,
                             5:list<switcht_acl_system_key_value_pair_t> acl_kvp,
                             6:switcht_acl_action_t action,
                             7:switcht_acl_action_params_t action_params,
                             8:switcht_acl_opt_action_params_t opt_action_params);
    switcht_handle_t switcht_api_acl_egr_rule_create(
                             1:switcht_device_t device,
                             2:switcht_handle_t acl_handle,
                             3:i32 priority,
                             4:i32 key_value_count,
                             5:list<switcht_acl_egr_key_value_pair_t> acl_kvp,
                             6:switcht_acl_action_t action,
                             7:switcht_acl_action_params_t action_params,
                             8:switcht_acl_opt_action_params_t opt_action_params);
    switcht_status_t switcht_api_acl_rule_delete(
                             1:switcht_device_t device,
                             2:switcht_handle_t acl_handle,
                             3:switcht_handle_t handle);
    switcht_status_t switcht_api_acl_reference(
                             1:switcht_device_t device,
                             2:switcht_handle_t acl_handle,
                             3:switcht_handle_t interface_handle);
    switcht_status_t switcht_api_acl_remove(
                             1:switcht_device_t device,
                             2:switcht_handle_t acl_handle,
                             3:switcht_handle_t interface_handle);
    switcht_handle_t switcht_api_acl_counter_create(
                             1: switcht_device_t device);
    switcht_status_t switcht_api_acl_counter_delete(
                             1: switcht_device_t device,
                             2: switcht_handle_t counter_handle);
    switcht_counter_t switcht_api_acl_stats_get(
                             1: switcht_device_t device,
                             2: switcht_handle_t counter_handle);
    switcht_handle_t switcht_api_acl_range_create(
                             1: switcht_device_t device,
                             2: switcht_direction_t direction,
                             3: byte range_type,
                             4: switcht_range_t range);
    switcht_status_t switcht_api_acl_range_update(
                             1: switcht_device_t device,
                             2: switcht_handle_t range_handle,
                             3: switcht_range_t range);
    switcht_status_t switcht_api_acl_range_delete(
                             1: switcht_device_t device,
                             2: switcht_handle_t range_handle);

    /* HOSTIF API */
    switcht_handle_t switcht_api_hostif_group_create(1:switcht_device_t device, 2:switcht_hostif_group_t hostif_group);
    switcht_status_t switcht_api_hostif_group_delete(1:switcht_device_t device, 2:switcht_handle_t hostif_group_handle);
    switcht_status_t switcht_api_hostif_reason_code_create(1:switcht_device_t device, 2:switcht_api_hostif_rcode_info_t rcode_api_info);
    switcht_status_t switcht_api_hostif_reason_code_delete(1:switcht_device_t device, 2:switcht_hostif_reason_code_t reason_code);
    switcht_handle_t switcht_api_hostif_create(1:switcht_device_t device, 2:switcht_hostif_t hostif);
    switcht_status_t switcht_api_hostif_delete(1:switcht_device_t device, 2:switcht_handle_t hostif_handle);

    switcht_handle_t switcht_api_hostif_meter_create(
                             1: switcht_device_t device,
                             2: switcht_api_meter_info_t api_meter_info);

    switcht_status_t switcht_api_hostif_meter_delete(
                             1: switcht_device_t device,
                             2: switcht_handle_t meter_handle);

    /* Multicast API */
    switcht_handle_t switcht_api_multicast_tree_create(1:switcht_device_t device);
    switcht_status_t switcht_api_multicast_tree_delete(1:switcht_device_t device, 2:switcht_handle_t mgid_handle);

    switcht_status_t switcht_api_multicast_member_add(1:switcht_device_t device, 2:switcht_handle_t mgid_handle,
                                              3:list<switcht_vlan_interface_t> mbrs);

    switcht_status_t switcht_api_multicast_member_delete(1:switcht_device_t device, 2:switcht_handle_t mgid_handle,
                                              3:list<switcht_vlan_interface_t> mbrs);

    switcht_status_t switcht_api_multicast_mroute_add(1:switcht_device_t device, 2:switcht_handle_t mgid_handle,
                                              3:switcht_handle_t vrf_handle,
                                              4:switcht_ip_addr_t src_ip, 5:switcht_ip_addr_t grp_ip,
                                              6:switcht_mcast_mode_t mc_mode, 7:list<switcht_handle_t> rpf_bd_list,
                                              8:i32 rpf_bd_count);

    switcht_status_t switcht_api_multicast_mroute_delete(1:switcht_device_t device,
                                              2:switcht_handle_t vrf_handle,
                                              3:switcht_ip_addr_t src_ip, 4:switcht_ip_addr_t grp_ip)

    switcht_status_t switcht_api_multicast_l2route_add(1: switcht_device_t device, 2:switcht_handle_t mgid_handle,
                                               3:switcht_handle_t bd_handle,
                                               4:switcht_ip_addr_t src_ip, 5: switcht_ip_addr_t grp_ip);

    switcht_status_t switcht_api_multicast_l2route_delete(1: switcht_device_t device,
                                               2:switcht_handle_t bd_handle,
                                               3:switcht_ip_addr_t src_ip, 4:switcht_ip_addr_t grp_ip);

    /* MIRROR API */

    switcht_handle_t switcht_api_mirror_session_create(1:switcht_device_t device, 2:switcht_mirror_info_t api_mirror_info);

    switcht_status_t switcht_api_mirror_session_update(1:switcht_device_t device, 2:switcht_handle_t mirror_handle, 3:switcht_mirror_info_t api_mirror_info);

    switcht_status_t switcht_api_mirror_session_delete(1:switcht_device_t device, 2:switcht_handle_t mirror_handle);

    /* INT APIs */
    switcht_status_t switcht_int_transit_enable(1:switcht_device_t device, 2:i32 switch_id, 3:i32 enable);
    switcht_status_t switcht_int_src_enable(1:switcht_device_t device, 2:i32 switch_id, 3:switcht_ip_addr_t src_ip, 4:switcht_ip_addr_t dst_ip, 5:i16 max_hop, 6:i16 ins_mask);
    switcht_status_t switcht_int_src_disable(1:switcht_device_t device, 2:switcht_ip_addr_t src_ip, 3:switcht_ip_addr_t dst_ip);
    switcht_status_t switcht_int_sink_enable(1:switcht_device_t device, 2:switcht_ip_addr_t dst_ip, 3:i32 mirror_id);
    switcht_status_t switcht_int_sink_disable(1:switcht_device_t device, 2:switcht_ip_addr_t dst_ip);

    /* Meter APS */
    switcht_handle_t switcht_api_meter_create(
                             1: switcht_device_t device,
                             2: switcht_api_meter_info_t api_meter_info);

    switcht_status_t switcht_api_meter_update(
                             1: switcht_device_t device,
                             2: switcht_handle_t meter_handle,
                             3: switcht_api_meter_info_t api_meter_info);

    switcht_status_t switcht_api_meter_delete(
                             1: switcht_device_t device,
                             2: switcht_handle_t meter_handle);

    list<switcht_counter_t> switcht_api_meter_stats_get(
                             1: switcht_device_t device,
                             2: switcht_handle_t meter_handle,
                             3: list<i16> counter_ids);

    /* Global config */
    switcht_status_t switcht_api_set_deflect_on_drop (1:switcht_device_t device, 2:bool enable_dod);

    /* SFLOW APIs */
    switcht_handle_t switcht_api_sflow_session_create(1:switcht_device_t device, 2:switcht_sflow_info_t api_sflow_info);

    switcht_status_t switcht_api_sflow_session_delete(1:switcht_device_t device, 2:switcht_handle_t sflow_hdl, 3:bool all_cleanup);

    switcht_handle_t switcht_api_sflow_session_attach(
                             1:switcht_device_t device,
                             2:switcht_handle_t sflow_handle,
                             3:switcht_direction_t direction,
                             4:i32 priority,
                             5:i32 sample_rate,
                             6:list<switcht_sflow_key_value_pair_t> sflow_kvp);

    switcht_status_t switcht_api_sflow_session_detach(
                             1:switcht_device_t device,
                             2:switcht_handle_t sflow_handle
                             3:switcht_handle_t entry_hdl);

    switcht_status_t switcht_api_sflow_session_sample_count_reset(
                             1:switcht_device_t device,
                             2:switcht_handle_t sflow_handle,
                             3:switcht_handle_t entry_handle);

    switcht_counter_t switcht_api_sflow_session_sample_count_get(
                             1:switcht_device_t device,
                             2:switcht_handle_t sflow_handle,
                             3:switcht_handle_t entry_handle);


    /* PPG */
    switcht_status_t switcht_api_port_cos_mapping(
                             1: switcht_device_t device,
                             2: switcht_handle_t port_handle,
                             3: switcht_handle_t ppg_handle,
                             4: byte cos_bmp);
    switcht_status_t switcht_api_ppg_lossless_enable(
                             1: switcht_device_t device,
                             2: switcht_handle_t ppg_handle,
                             3: bool enabled);
    list<switcht_handle_t> switcht_api_ppg_get(
                             1: switcht_device_t device,
                             2: switcht_handle_t port_handle);
    switcht_status_t switcht_api_ppg_guaranteed_limit_set(
                             1: switcht_device_t device,
                             2: switcht_handle_t ppg_handle,
                             3: i32 num_bytes);
    switcht_status_t switcht_api_ppg_skid_limit_set(
                             1: switcht_device_t device,
                             2: switcht_handle_t ppg_handle,
                             3: i32 num_bytes);
    switcht_status_t switcht_api_ppg_skid_hysteresis_set(
                             1: switcht_device_t device,
                             2: switcht_handle_t ppg_handle,
                             3: i32 num_bytes);

    /* Buffer */
    switcht_handle_t switcht_api_buffer_pool_create(
                             1: switcht_device_t device,
                             2: switcht_direction_t direction,
                             3: i16 pool_size);
    switcht_status_t switcht_api_buffer_pool_delete(
                             1: switcht_device_t device,
                             2: switcht_handle_t buffer_pool_handle);
    switcht_handle_t switcht_api_buffer_profile_create(
                             1: switcht_device_t device,
                             2: switcht_api_buffer_profile_t api_buffer_info);
    switcht_status_t switcht_api_buffer_profile_delete(
                             1: switcht_device_t device,
                             2: switcht_handle_t buffer_profile_handle);
    switcht_status_t switcht_api_ppg_buffer_profile_set(
                             1: switcht_device_t device,
                             2: switcht_handle_t ppg_handle,
                             3: switcht_handle_t buffer_profile_handle);
    switcht_status_t switcht_api_queue_buffer_profile_set(
                             1: switcht_device_t device,
                             2: switcht_handle_t queue_handle,
                             3: switcht_handle_t buffer_profile_handle);
    switcht_status_t switcht_api_buffer_skid_limit_set(
                             1: switcht_device_t device,
                             2: i32 num_bytes);
    switcht_status_t switcht_api_buffer_skid_hysteresis_set(
                             1: switcht_device_t device,
                             2: i32 num_bytes);
    switcht_status_t switcht_api_buffer_pool_pfc_limit(
                             1: switcht_device_t device,
                             2: switcht_handle_t pool_handle,
                             3: byte icos,
                             4: i32 num_bytes);
    switcht_status_t switcht_api_buffer_pool_color_drop_enable(
                             1: switcht_device_t device,
                             2: switcht_handle_t pool_handle,
                             3: bool enable);
    switcht_status_t switcht_api_buffer_pool_color_limit_set(
                             1: switcht_device_t device,
                             2: switcht_handle_t pool_handle,
                             3: switcht_color_t color,
                             4: i32 num_bytes);
    switcht_status_t switcht_api_buffer_pool_color_hysteresis_set(
                             1: switcht_device_t device,
                             2: switcht_color_t color,
                             3: i32 num_bytes);


    /* Qos */
    switcht_handle_t switcht_api_qos_map_ingress_create(
                             1: switcht_device_t device,
                             2: switcht_qos_map_type_t qos_map_type,
                             3: list<switcht_qos_map_t> qos_map);
    switcht_status_t switcht_api_qos_map_ingress_delete(
                             1: switcht_device_t device,
                             2: switcht_handle_t qos_map_handle);
    switcht_handle_t switcht_api_qos_map_egress_create(
                             1: switcht_device_t device,
                             2: switcht_qos_map_type_t qos_map_type,
                             3: list<switcht_qos_map_t> qos_map);
    switcht_status_t switcht_api_qos_map_egress_delete(
                             1: switcht_device_t device,
                             2: switcht_handle_t qos_map_handle);

    /* Scheduler */
    switcht_handle_t switcht_api_scheduler_create(
                             1: switcht_device_t device,
                             2: switcht_scheduler_info_t api_scheduler_info);
    switcht_status_t switcht_api_scheduler_delete(
                             1: switcht_device_t device,
                             2: switcht_handle_t scheduler_handle);

    /* Queues */
    list<switcht_handle_t> switcht_api_queues_get(
                            1: switcht_device_t device,
                            2: switcht_handle_t port_handle);
    switcht_status_t switcht_api_queue_color_drop_enable(
                            1: switcht_device_t device,
                            2: switcht_handle_t port_handle,
                            3: switcht_handle_t queue_handle,
                            4: bool enable);
    switcht_status_t switcht_api_queue_color_limit_set(
                            1: switcht_device_t device,
                            2: switcht_handle_t port_handle,
                            3: switcht_handle_t queue_handle,
                            4: switcht_color_t color,
                            5: i32 limit);
    switcht_status_t switcht_api_queue_color_hysteresis_set(
                            1: switcht_device_t device,
                            2: switcht_handle_t port_handle,
                            3: switcht_handle_t queue_handle,
                            4: switcht_color_t color,
                            5: i32 limit);
    switcht_status_t switcht_api_queue_pfc_cos_mapping(
                            1: switcht_device_t device,
                            2: switcht_handle_t port_handle,
                            3: switcht_handle_t queue_handle,
                            4: byte cos);
    /* MTU */
    switcht_status_t switcht_api_mtu_entry_create(
                            1: switcht_device_t device,
                            2: i16 mtu_index,
                            3: i32 mtu);
}
