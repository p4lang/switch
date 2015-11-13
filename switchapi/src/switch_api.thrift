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

*/

typedef i32 switcht_status_t
typedef i32 switcht_direction_t
typedef i32 switcht_interface_type_t
typedef i32 switcht_handle_type_t 

typedef byte switcht_device_t
typedef i32 switcht_vrf_id_t
typedef i32 switcht_handle_t
typedef string switcht_mac_addr_t
typedef i32 switcht_port_t
typedef i16 switcht_vlan_t
typedef i32 switcht_interface_handle_t
typedef i32 switcht_tunnel_handle_t

typedef i32 switcht_stp_mode_t
typedef i32 switcht_stp_state_t
typedef i32 switcht_intf_attr_t

typedef i16 switcht_nat_mode_t
typedef i16 switcht_mcast_mode_t

typedef i32 switcht_urpf_group_t

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

struct switcht_port_vlan_t {
        2: switcht_handle_t port_lag_handle;
        3: i16 vlan_id;             /**< VLAN id on port */
}

typedef i32 switcht_protocol_t

struct switcht_udp_t {
    1: i16  src_port;
    2: i16 dst_port;
}

struct switcht_tcp_t {
    1: i16  src_port;
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
    1: switcht_handle_t port_lag_handle;         /**< LAG handle */
    2: switcht_vlan_t vlan_id;              /**< VLAN */
    3: switcht_port_vlan_t port_vlan;       /**< Port-VLAN */
    4: switcht_ip_encap_t ip_encap;      /**< Tunnel info */
}

struct switcht_interface_flags {
    1: bool core_intf;
    2: bool flood_enabled;
    3: bool learn_enabled;
}

struct switcht_interface_info_t {
        1: switcht_device_t device
        2: switcht_interface_type_t type;           /**< type of interface */
        3: interface_union u;
        4: switcht_mac_addr_t mac;                  /**< Mac address associated with interface */
        5: i32 label                            /**< ACL label */
        6: switcht_handle_t vrf_handle;
        7: switcht_nat_mode_t nat_mode;             /**< Nat mode for L3 interface */
        8: switcht_handle_t rmac_handle;
        9: switcht_interface_flags flags;
        10: i16 v4_urpf_mode;
        11: i16 v6_urpf_mode;
        12: bool v4_unicast_enabled;
        13: bool v6_unicast_enabled;
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

struct switcht_acl_system_key_value_pair_t {
    1: i32 field;
    2: i64 value;
    3: i64 mask;
}

struct switcht_acl_ip_key_value_pair_t {
    1: i32 field;
    2: i64 value;
    3: i64 mask;
}

struct switcht_acl_mirror_key_value_pair_t {
    1: i32 field;
    2: i64 value;
    3: i64 mask;
}

struct switcht_acl_qos_key_value_pair_t {
    1: i32 field;
    2: i32 value;
    3: i32 mask;
}

struct switcht_acl_mac_key_value_pair_t {
    1: i32 field;
    2: i64 value;
    3: i64 mask;
}

struct switcht_acl_ipv6_key_value_pair_t {
    1: i32 field;
    2: i64 value;
    3: i64 mask;
}

struct switcht_acl_ipracl_key_value_pair_t {
    1: i32 field;
    2: i64 value;
    3: i64 mask;
}

struct switcht_acl_ipv6racl_key_value_pair_t {
    1: i32 field;
    2: i64 value;
    3: i64 mask;
}

struct switcht_acl_egr_key_value_pair_t {
    1: i32 field;
    2: i16 value;
    3: i16 mask;
}

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
    1: i32 egress_queue;
    2: i32 priority;
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
    1: switcht_handle_t handle;
    2: string intf_name;
}

struct switcht_acl_action_mirror {
    1: switcht_handle_t mirror_handle;
    2: i32 drop_reason;
}

struct switcht_acl_action_cpu_redirect {
    1: i32 reason_code;
}

struct switcht_acl_action_redirect {
    1: switcht_handle_t handle;
}

union switcht_acl_action_params_t {
    1: switcht_acl_action_mirror mirror;
    2: switcht_acl_action_cpu_redirect cpu_redirect;
    3: switcht_acl_action_redirect redirect;
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
}

service switch_api_rpc {
    /* init */
    switcht_status_t switcht_api_init(1:switcht_device_t device);

    /* drop stats */
    list<i64> switcht_api_drop_stats_get(1:switcht_device_t device);

    /* Port */
    switcht_status_t switcht_api_port_set(1:switcht_device_t device, 2:switcht_port_info_t port_info);
    switcht_status_t switcht_api_port_print_all();

    /* vpn */
    switcht_handle_t switcht_api_vrf_create(1:switcht_device_t device, 2:switcht_vrf_id_t vrf);
    switcht_status_t switcht_api_vrf_delete(1:switcht_device_t device, 2:switcht_handle_t vrf_handle);

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
    list<switcht_counter_t> switcht_api_vlan_stats_get(1: switcht_handle_t vlan_handle, 2: list<i16> counter_ids);

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

    /* ACL API */
    switcht_handle_t switcht_api_acl_list_create(1:switcht_device_t device, 2:switcht_acl_type_t type);
    switcht_status_t switcht_api_acl_list_delete(1:switcht_device_t device, 2:switcht_handle_t handle);
    switcht_handle_t switcht_api_acl_ip_rule_create(1:switcht_device_t device, 2:switcht_handle_t acl_handle, 3:i32 priority, 4:i32 key_value_count, 5:list<switcht_acl_ip_key_value_pair_t> acl_kvp, 6:switcht_acl_action_t action, 7:switcht_acl_action_params_t action_params);
    switcht_handle_t switcht_api_acl_mirror_rule_create(1:switcht_device_t device, 2:switcht_handle_t acl_handle, 3:i32 priority, 4:i32 key_value_count, 5:list<switcht_acl_mirror_key_value_pair_t> acl_kvp, 6:switcht_acl_action_t action, 7:switcht_acl_action_params_t action_params);
    switcht_handle_t switcht_api_acl_system_rule_create(1:switcht_device_t device, 2:switcht_handle_t acl_handle, 3:i32 priority, 4:i32 key_value_count, 5:list<switcht_acl_system_key_value_pair_t> acl_kvp, 6:switcht_acl_action_t action, 7:switcht_acl_action_params_t action_params);
    switcht_handle_t switcht_api_acl_egr_rule_create(1:switcht_device_t device, 2:switcht_handle_t acl_handle, 3:i32 priority, 4:i32 key_value_count, 5:list<switcht_acl_egr_key_value_pair_t> acl_kvp, 6:switcht_acl_action_t action, 7:switcht_acl_action_params_t action_params);
    switcht_status_t switcht_api_acl_rule_delete(1:switcht_device_t device, 2:switcht_handle_t acl_handle, 3:switcht_handle_t handle);
    switcht_status_t switcht_api_acl_reference(1:switcht_device_t device, 2:switcht_handle_t acl_handle, 3:switcht_handle_t interface_handle);
    switcht_status_t switcht_api_acl_remove(1:switcht_device_t device, 2:switcht_handle_t acl_handle, 3:switcht_handle_t interface_handle);

    /* HOSTIF API */
    switcht_handle_t switcht_api_hostif_group_create(1:switcht_device_t device, 2:switcht_hostif_group_t hostif_group);
    switcht_status_t switcht_api_hostif_group_delete(1:switcht_device_t device, 2:switcht_handle_t hostif_group_handle);
    switcht_status_t switcht_api_hostif_reason_code_create(1:switcht_device_t device, 2:switcht_api_hostif_rcode_info_t rcode_api_info);
    switcht_status_t switcht_api_hostif_reason_code_delete(1:switcht_device_t device, 2:switcht_hostif_reason_code_t reason_code);
    switcht_handle_t switcht_api_hostif_create(1:switcht_device_t device, 2:switcht_hostif_t hostif);
    switcht_status_t switcht_api_hostif_delete(1:switcht_device_t device, 2:switcht_handle_t hostif_handle);


    /* MIRROR API */

    switcht_handle_t switcht_api_mirror_session_create(1:switcht_device_t device, 2:switcht_mirror_info_t api_mirror_info);

    switcht_status_t switcht_api_mirror_session_update(1:switcht_device_t device, 2:switcht_handle_t mirror_handle, 3:switcht_mirror_info_t api_mirror_info);

    switcht_status_t switcht_api_mirror_session_delete(1:switcht_device_t device, 2:switcht_handle_t mirror_handle);

    /* INT APIs */
    switcht_status_t switcht_int_transit_enable(1:switcht_device_t device, 2:i32 switch_id, 3:i32 enable);
}
