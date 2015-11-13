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
#include <iostream>

#include "switch_api_rpc.h"
#include "thrift_cache.h"

#include "switchapi/switch_port.h"
#include "switchapi/switch_vlan.h"
#include "switchapi/switch_l2.h"
#include "switchapi/switch_l3.h"
#include "switchapi/switch_neighbor.h"
#include "switchapi/switch_rmac.h"
#include "switchapi/switch_lag.h"
#include "switchapi/switch_tunnel.h"
#include "switchapi/switch_vrf.h"
#include "switchapi/switch_nhop.h"
#include "switchapi/switch_hostif.h"
#include "switchapi/switch_acl.h"
#include "switchapi/switch_mcast.h"
#include "switchapi/switch_stp.h"
#include "switchapi/switch_mirror.h"
#include "switchapi/switch_INT.h"
#include "switchapi/switch_protocol.h"
#include "arpa/inet.h"

#define SWITCH_API_RPC_SERVER_PORT (9091)

using namespace ::apache::thrift;
using namespace ::apache::thrift::protocol;
using namespace ::apache::thrift::transport;
using namespace ::apache::thrift::server;

using boost::shared_ptr;

using namespace  ::switch_api;

unsigned int switch_string_to_mac(const std::string s, unsigned char *m) {
    unsigned int i, j=0;
      memset(m, 0, 6);
      for(i=0;i<s.size();i++) {
        char let = s.c_str()[i];
        if (let >= '0' && let <= '9') {
            m[j/2] = (m[j/2] << 4) + (let - '0'); j++;
        } else if (let >= 'a' && let <= 'f') {
            m[j/2] = (m[j/2] << 4) + (let - 'a'+10); j++;
        } else if (let >= 'A' && let <= 'F') {
            m[j/2] = (m[j/2] << 4) + (let - 'A'+10); j++;
        }
    }
    return (j == 12);
}

unsigned int switch_string_to_v4_ip(const std::string s, unsigned int *m) {
    unsigned char r=0;
    unsigned int i;
    *m = 0;
      for(i=0;i<s.size();i++) {
        char let = s.c_str()[i];
        if (let >= '0' && let <= '9') {
            r = (r * 10) + (let - '0');
        }
        else {
            *m = (*m << 8) | r;
            r=0;
        }
    }
    *m = (*m << 8) | (r & 0xFF);
    return (*m);
}

void switch_string_to_v6_ip(const std::string s, unsigned char *v6_ip)
{
    const char *v6_str = s.c_str();
    inet_pton(AF_INET6, v6_str, v6_ip);
    return;
}

void switch_parse_ip_address(const switcht_ip_addr_t ip_addr, switch_ip_addr_t *lip_addr)
{
    lip_addr->type = (switch_ip_addr_type_t)ip_addr.addr_type;
    lip_addr->prefix_len = ip_addr.prefix_length;
    if (lip_addr->type == SWITCH_API_IP_ADDR_V4) {
        switch_string_to_v4_ip(ip_addr.ipaddr, &(lip_addr->ip.v4addr));
    } else {
        switch_string_to_v6_ip(ip_addr.ipaddr, lip_addr->ip.v6addr);
    }
}

class switch_api_rpcHandler : virtual public switch_api_rpcIf {
 public:
  switch_api_rpcHandler() {
    // Your initialization goes here
    printf("RPC Initialization\n");
  switch_api_init(0, 256);
  }

  switcht_status_t switcht_api_init(const switcht_device_t device) {
    // Your implementation goes here
    printf("switcht_api_init\n");
    return 0;
  }

  void switcht_api_drop_stats_get(std::vector<int64_t> & _return, const switcht_device_t device) {
    printf("switcht_api_drop_stats_get\n");
    uint64_t *counters = NULL;
    int num_counters = 0;

    switch_api_drop_stats_get(device, &num_counters, &counters);
    if (num_counters <= 0) {
        return;
    }

    for (uint32_t i = 0; i < num_counters; i++) {
        _return.push_back(counters[i]);
    }

    free(counters);
    return;
  }

  switcht_status_t switcht_api_port_set(const switcht_device_t device, const switcht_port_info_t& port_info) {
    // Your implementation goes here
    switch_api_port_info_t port;
    port.port_number = port_info.port_number;
    port.ipv4_term = port_info.ipv4_term;
    port.l2mtu = port_info.l2mtu;
    port.l3mtu= port_info.l3mtu;
    port.tunnel_term = port_info.tunnel_term;
    port.ipv4_term=port_info.ipv4_term;
    port.ipv6_term = port_info.ipv6_term;
    port.igmp_snoop = port_info.igmp_snoop;
    port.urpf_mode = port_info.urpf_mode;
    printf("switcht_api_port_set\n");
    return switch_api_port_set(device, &port);
  }

  switcht_status_t switcht_api_port_print_all() {
    // Your implementation goes here
    printf("switcht_api_port_print_all\n");
    return switch_api_port_print_all();
  }

  switcht_status_t switcht_api_vrf_create(const switcht_device_t device, const switcht_vrf_id_t vrf) {
    // Your implementation goes here
    printf("switcht_api_l3_vrf_create\n");
    return switch_api_vrf_create(device, vrf);
  }

  switcht_status_t switcht_api_vrf_delete(const switcht_device_t device, const switcht_handle_t vrf_handle) {
    // Your implementation goes here
    printf("switcht_api_l3_vrf_delete\n");
    return switch_api_vrf_delete(device, vrf_handle);
  }

  switcht_handle_t switcht_api_router_mac_group_create(const switcht_device_t device) {
    // Your implementation goes here
    printf("switcht_api_router_mac_group_create\n");
    return switch_api_router_mac_group_create(device);
  }

  switcht_status_t switcht_api_router_mac_group_delete(const switcht_device_t device, const switcht_handle_t rmac_handle) {
    // Your implementation goes here
    printf("switcht_api_router_mac_group_delete\n");
    return switch_api_router_mac_group_delete(device, rmac_handle);
  }

  switcht_status_t switcht_api_router_mac_add(const switcht_device_t device, const switcht_handle_t rmac_handle, const switcht_mac_addr_t& mac) {
    // Your implementation goes here
    switch_mac_addr_t lmac;
    switch_string_to_mac(mac, lmac.mac_addr);
    printf("switcht_api_router_mac_add\n");
    return switch_api_router_mac_add(device, rmac_handle, &lmac);
  }

  switcht_status_t switcht_api_router_mac_delete(const switcht_device_t device, const switcht_handle_t rmac_handle, const switcht_mac_addr_t& mac) {
    // Your implementation goes here
    switch_mac_addr_t lmac;
    switch_string_to_mac(mac, lmac.mac_addr);
    printf("switcht_api_router_mac_delete\n");
    return switch_api_router_mac_delete(device, rmac_handle, &lmac);
  }

  switcht_status_t switcht_api_router_mac_group_print_all() {
    // Your implementation goes here
    printf("switcht_api_router_mac_group_print_all\n");
    return switch_api_router_mac_group_print_all();
  }

  switcht_interface_handle_t switcht_api_interface_create(const switcht_device_t device, const switcht_interface_info_t& interface_info) {
    // Your implementation goes here
    switch_api_interface_info_t i_info;
    memset(&i_info, 0, sizeof(switch_api_interface_info_t));
    i_info.type = (switch_interface_type_t)interface_info.type;
    i_info.vrf_handle = interface_info.vrf_handle;
    i_info.rmac_handle = interface_info.rmac_handle;
    i_info.flags.core_intf = interface_info.flags.core_intf;
    i_info.ipv4_urpf_mode = (switch_urpf_mode_t) interface_info.v4_urpf_mode;

    if (i_info.type == SWITCH_API_INTERFACE_L3_PORT_VLAN || i_info.type == SWITCH_API_INTERFACE_L2_PORT_VLAN) {
        i_info.u.port_vlan.port_lag_handle = interface_info.u.port_vlan.port_lag_handle;
        i_info.u.port_vlan.vlan_id = interface_info.u.port_vlan.vlan_id;
    } else if (i_info.type == SWITCH_API_INTERFACE_L3_VLAN) {
        i_info.u.vlan_id = interface_info.u.vlan_id;
        i_info.ipv4_unicast_enabled = interface_info.v4_unicast_enabled;
        i_info.ipv6_unicast_enabled = interface_info.v6_unicast_enabled;
    } else {
        i_info.u.port_lag_handle = interface_info.u.port_lag_handle;
    }
    printf("switcht_api_interface_create\n");
    return switch_api_interface_create(device, &i_info);
  }

  switcht_status_t switcht_api_interface_delete(const switcht_device_t device, const switcht_interface_handle_t interface_handle) {
    // Your implementation goes here
    printf("switcht_api_interface_delete\n");
    return switch_api_interface_delete(device, interface_handle);
  }

  switcht_status_t switcht_api_interface_print_all() {
    // Your implementation goes here
    printf("switcht_api_interface_print_all\n");
    return switch_api_interface_print_all();
  }

  switcht_status_t switcht_api_interface_attribute_set(const switcht_handle_t interface_handle, const switcht_intf_attr_t attr_type, const int64_t value) {
    // Your implementation goes here
    printf("switcht_api_set_interface_attribute\n");
    return switch_api_interface_attribute_set(interface_handle, (switch_intf_attr_t)attr_type, (uint64_t) value);
  }

  switcht_status_t switcht_api_interface_ipv4_unicast_enabled_set(const switcht_handle_t interface_handle, const int64_t value) {
    // Your implementation goes here
    printf("switcht_api_set_interface_attribute\n");
    return switch_api_interface_ipv4_unicast_enabled_set(interface_handle, (uint64_t) value);
  }

  switcht_status_t switcht_api_interface_ipv6_unicast_enabled_set(const switcht_handle_t interface_handle, const int64_t value) {
    // Your implementation goes here
    printf("switcht_api_set_interface_attribute\n");
    return switch_api_interface_ipv6_unicast_enabled_set(interface_handle, (uint64_t) value);
  }

  switcht_status_t switcht_api_interface_ipv4_urpf_mode_set(const switcht_handle_t interface_handle, const int64_t value) {
    // Your implementation goes here
    printf("switcht_api_set_interface_attribute\n");
    return switch_api_interface_ipv4_urpf_mode_set(interface_handle, (uint64_t) value);
  }

  switcht_status_t switcht_api_interface_ipv6_urpf_mode_set(const switcht_handle_t interface_handle, const int64_t value) {
    // Your implementation goes here
    printf("switcht_api_set_interface_attribute\n");
    return switch_api_interface_ipv6_urpf_mode_set(interface_handle, (uint64_t) value);
  }

  switcht_status_t switcht_api_l3_interface_address_add(const switcht_device_t device, const switcht_interface_handle_t interface_handle, const switcht_handle_t vrf, const switcht_ip_addr_t& ip_addr) {
    // Your implementation goes here
    printf("switcht_api_l3_interface_address_add\n");
    switch_ip_addr_t lip_addr;
    switch_parse_ip_address(ip_addr, &lip_addr);
    return switch_api_l3_interface_address_add(device, interface_handle, vrf, &lip_addr);
  }

  switcht_status_t switcht_api_l3_interface_address_delete(const switcht_device_t device, const switcht_interface_handle_t interface_handle, const switcht_handle_t vrf, const switcht_ip_addr_t& ip_addr) {
    // Your implementation goes here
    printf("switcht_api_l3_interface_address_delete\n");
    switch_ip_addr_t lip_addr;
    switch_parse_ip_address(ip_addr, &lip_addr);
    return switch_api_l3_interface_address_delete(device, interface_handle, vrf, &lip_addr);
  }

  switcht_handle_t switcht_api_nhop_create(const switcht_device_t device, const switcht_nhop_key_t& nhop_key) {
    // Your implementation goes here
    printf("switcht_api_nhop_create\n");
    switch_nhop_key_t lnhop_key;
    memset(&lnhop_key, 0, sizeof(switch_nhop_key_t));
    lnhop_key.intf_handle = nhop_key.intf_handle;
    if (nhop_key.ip_addr_valid) {
        switch_parse_ip_address(nhop_key.ip_addr, &lnhop_key.ip_addr);
    }
    return switch_api_nhop_create(device, &lnhop_key);
  }

  switcht_status_t switcht_api_nhop_delete(const switcht_device_t device, const switcht_handle_t handle) {
    // Your implementation goes here
    printf("switcht_api_nhop_delete\n");
    return switch_api_nhop_delete(device, handle);
  }

  switcht_status_t switcht_api_nhop_print_all(void) {
    // Your implementation goes here
    printf("switcht_api_nhop_print_all\n");
    return switch_api_nhop_print_all();
  }

  switcht_handle_t switcht_api_neighbor_entry_add(const switcht_device_t device, const switcht_neighbor_info_t& neighbor) {
    switch_api_neighbor_t lneighbor;
    lneighbor.neigh_type = (switch_neighbor_type_t) neighbor.neigh_type;
    lneighbor.rw_type = (switch_neighbor_rw_type_t) neighbor.rw_type;
    lneighbor.nhop_handle = neighbor.nhop_handle;
    lneighbor.vlan = neighbor.vlan;
    lneighbor.interface = neighbor.interface_handle;
    switch_string_to_mac(neighbor.mac_addr, lneighbor.mac_addr.mac_addr);
    lneighbor.mpls_label = neighbor.mpls_label;
    lneighbor.header_count = neighbor.header_count;
    printf("switcht_api_neighbor_entry_add\n");
    return switch_api_neighbor_entry_add(device, &lneighbor);
  }

  switcht_status_t switcht_api_neighbor_entry_remove(const switcht_device_t device, const switcht_handle_t neighbor_handle) {
    printf("switcht_api_neighbor_entry_delete\n");
    return switch_api_neighbor_entry_remove(device, neighbor_handle);
  }

  switcht_status_t switcht_api_neighbor_print_all() {
    // Your implementation goes here
    printf("switcht_api_neighbor_print_all\n");
    return switch_api_neighbor_print_all();
  }

  switcht_status_t switcht_api_l3_route_add(const switcht_device_t device, const switcht_handle_t vrf, const switcht_ip_addr_t& ip_addr, const switcht_handle_t nhop_handle) {
    switch_ip_addr_t lip_addr;
    printf("switcht_api_l3_route_add\n");
    switch_parse_ip_address(ip_addr, &lip_addr);
    return switch_api_l3_route_add(device, vrf, &lip_addr, nhop_handle);
  }

  switcht_status_t switcht_api_l3_route_delete(const switcht_device_t device, const switcht_handle_t vrf, const switcht_ip_addr_t& ip_addr, const switcht_handle_t nhop_handle) {
    switch_ip_addr_t lip_addr;
    printf("switcht_api_l3_route_delete\n");
    switch_parse_ip_address(ip_addr, &lip_addr);
    return switch_api_l3_route_delete(device, vrf, &lip_addr, nhop_handle);
  }

  switcht_status_t switcht_api_l3_routes_print_all() {
    // Your implementation goes here
    printf("switcht_api_l3_routes_print_all\n");
    return switch_api_l3_routes_print_all();
  }

  switcht_handle_t switcht_api_vlan_create(const switcht_device_t device, const switcht_vlan_t vlan_id) {
    // Your implementation goes here
    printf("switcht_api_vlan_create\n");
    return switch_api_vlan_create(device, vlan_id);
  }

  switcht_status_t switcht_api_vlan_delete(const switcht_device_t device, const switcht_handle_t vlan_handle) {
    // Your implementation goes here
    printf("switcht_api_vlan_delete\n");
    return switch_api_vlan_delete(device, vlan_handle);
  }

  switcht_status_t switcht_api_vlan_print_all() {
    // Your implementation goes here
    printf("switcht_api_vlan_print_all\n");
    return switch_api_vlan_print_all();
  }

  switcht_status_t switcht_api_vlan_stats_enable(const switcht_device_t device, const switcht_handle_t vlan_handle) {
    // Your implementation goes here
    printf("switcht_api_vlan_stats_enable\n");
    return switch_api_vlan_stats_enable(device, vlan_handle);
  }

  switcht_status_t switcht_api_vlan_stats_disable(const switcht_device_t device, const switcht_handle_t vlan_handle) {
    // Your implementation goes here
    printf("switcht_api_vlan_stats_disable\n");
    return switch_api_vlan_stats_disable(device, vlan_handle);
  }

  void switcht_api_vlan_stats_get(std::vector<switcht_counter_t> & _counters, const switcht_handle_t vlan_handle, const std::vector<int16_t> & counter_ids) {
    // Your implementation goes here
    printf("switcht_api_vlan_stats_get\n");
    std::vector<int16_t>::const_iterator it = counter_ids.begin();
    switcht_counter_t _counter;
    switch_vlan_stat_counter_t *counter_id_list = (switch_vlan_stat_counter_t *) malloc(sizeof(switch_vlan_stat_counter_t) * counter_ids.size());
    switch_counter_t *counters = (switch_counter_t *) malloc(sizeof(switch_counter_t) * counter_ids.size());
    for(uint32_t i = 0; i < counter_ids.size(); i++, it++) {
        counter_id_list[i] = (switch_vlan_stat_counter_t) *it;
    }
    printf("\nnumber of counterids %d\n", (int)(counter_ids.size()));
    switch_api_vlan_stats_get(vlan_handle, counter_ids.size(), counter_id_list, counters);
    for (uint32_t i = 0; i < counter_ids.size(); i++) {
        _counter.num_packets = counters[i].num_packets;
        _counter.num_bytes = counters[i].num_bytes;
        _counters.push_back(_counter);
    }
    free(counter_id_list);
    free(counters);
    return;
  }

  switcht_status_t switcht_api_mac_table_entry_create(const switcht_device_t device, const switcht_handle_t vlan_handle, const switcht_mac_addr_t& mac, const int8_t entry_type, const switcht_interface_handle_t interface_handle) {
    // Your implementation goes here
    switch_api_mac_entry_t mac_entry;
    switch_string_to_mac(mac, mac_entry.mac.mac_addr);
    printf("switcht_api_l2_mac_add\n");
    mac_entry.vlan_handle = vlan_handle;
    mac_entry.handle = interface_handle;
    mac_entry.entry_type = (switch_mac_entry_type_t) entry_type;
    return switch_api_mac_table_entry_add(device, &mac_entry);
  }

  switcht_status_t switcht_api_mac_table_entry_update(const switcht_device_t device, const switcht_handle_t vlan_handle, const switcht_mac_addr_t& mac, const int8_t entry_type, const switcht_interface_handle_t interface_handle) {
    // Your implementation goes here
    switch_api_mac_entry_t mac_entry;
    switch_string_to_mac(mac, mac_entry.mac.mac_addr);
    printf("switcht_api_l2_mac_update\n");
    mac_entry.vlan_handle = vlan_handle;
    mac_entry.handle = interface_handle;
    mac_entry.entry_type = (switch_mac_entry_type_t) entry_type;
    return switch_api_mac_table_entry_update(device, &mac_entry);
  }

  switcht_status_t switcht_api_mac_table_entry_delete(const switcht_device_t device, const switcht_handle_t vlan_handle, const switcht_mac_addr_t& mac) {
    // Your implementation goes here
    switch_api_mac_entry_t mac_entry;
    switch_string_to_mac(mac, mac_entry.mac.mac_addr);
    mac_entry.vlan_handle = vlan_handle;
    printf("switcht_api_l2_mac_delete\n");
    return switch_api_mac_table_entry_delete(device, &mac_entry);
  }

  switcht_status_t switcht_api_mac_table_print_all() {
    // Your implementation goes here
    printf("switcht_api_interface_print_all\n");
    return switch_api_mac_table_print_all();
  }

  switcht_status_t switcht_api_mac_table_entries_delete_by_vlan(const switcht_device_t device, const switcht_handle_t vlan_handle) {
    // Your implementation goes here
    printf("switcht_api_mac_table_entries_delete_by_vlan\n");
    return switch_api_mac_table_entries_delete_by_vlan(device, vlan_handle);
  }

  switcht_status_t switcht_api_mac_table_entries_delete_by_interface(const switcht_device_t device, const switcht_handle_t intf_handle) {
    // Your implementation goes here
    printf("switcht_api_mac_table_entries_delete_by_interface\n");
    return switch_api_mac_table_entries_delete_by_interface(device, intf_handle);
  }

  switcht_status_t switcht_api_mac_table_entries_delete_all(const switcht_device_t device) {
    // Your implementation goes here
    printf("switcht_api_mac_table_entries_delete_all\n");
    return switch_api_mac_table_entries_delete_all(device);
  }

  switcht_handle_t switcht_api_l3_ecmp_create(const switcht_device_t device) {
    // Your implementation goes here
    printf("switcht_api_l3_ecmp_create\n");
    return switch_api_ecmp_create(device);
  }

  switcht_status_t switcht_api_l3_ecmp_delete(const switcht_device_t device, const switcht_handle_t handle) {
    // Your implementation goes here
    printf("switcht_api_l3_ecmp_delete\n");
    return switch_api_ecmp_delete(device, handle);
  }

  switcht_status_t switcht_api_l3_ecmp_member_add(const switcht_device_t device, const switcht_handle_t handle, const int16_t nhop_count, const std::vector<switcht_handle_t> & nhop_handle) {
    // Your implementation goes here
    printf("switcht_api_l3_ecmp_member_add\n");
    switch_status_t status=0;
    std::vector<switcht_handle_t>::const_iterator it = nhop_handle.begin();

    switch_handle_t *nhop_handle_list = (switch_handle_t *) malloc(sizeof(switch_handle_t) * nhop_handle.size());
    for(uint32_t i = 0; i < nhop_handle.size(); i++, it++) {
        nhop_handle_list[i] = (switch_handle_t) *it;
    }
    status = switch_api_ecmp_member_add(device, handle, nhop_count, nhop_handle_list);
    free(nhop_handle_list);
    return status;
  }

  switcht_status_t switcht_api_l3_ecmp_member_delete(const switcht_device_t device, const switcht_handle_t handle, const int16_t nhop_count, const std::vector<switcht_handle_t> & nhop_handle) {
    // Your implementation goes here
    printf("switcht_api_l3_ecmp_member_delete\n");
    switch_status_t status=0;
    std::vector<switcht_handle_t>::const_iterator it = nhop_handle.begin();

    switch_handle_t *nhop_handle_list = (switch_handle_t *) malloc(sizeof(switch_handle_t) * nhop_handle.size());
    for(uint32_t i = 0; i < nhop_handle.size(); i++, it++) {
        nhop_handle_list[i] = (switch_handle_t) *it;
    }
    status = switch_api_ecmp_member_delete(device, handle, nhop_count, nhop_handle_list);
    free(nhop_handle_list);
    return status;
  }

  switcht_handle_t switcht_api_lag_create(const switcht_device_t device) {
    // Your implementation goes here
    printf("switcht_api_lag_create\n");
    return switch_api_lag_create(device);
  }

  switcht_status_t switcht_api_lag_delete(const switcht_device_t device, const switcht_handle_t lag_handle) {
    // Your implementation goes here
    printf("switcht_api_lag_delete\n");
    return switch_api_lag_delete(device, lag_handle);
  }

  switcht_status_t switcht_api_lag_member_add(const switcht_device_t device, const switcht_handle_t lag_handle, const switcht_direction_t side, const switcht_port_t port) {
    // Your implementation goes here
    printf("switcht_api_lag_member_add\n");
    return switch_api_lag_member_add(device, lag_handle, (switch_direction_t)side, port);
  }

  switcht_status_t switcht_api_lag_member_delete(const switcht_device_t device, const switcht_handle_t lag_handle, const switcht_direction_t side, const switcht_port_t port) {
    // Your implementation goes here
    printf("switcht_api_lag_member_delete\n");
    return switch_api_lag_member_delete(device, lag_handle, (switch_direction_t)side, port);
  }

  switcht_status_t switcht_api_lag_print_all() {
    printf("switcht_api_lag_print_all\n");
    return switch_api_lag_print_all();
  }

  switcht_handle_t switcht_api_logical_network_create(const switcht_device_t device, const switcht_logical_network_t& info) {
    // Your implementation goes here
    switch_logical_network_t linfo;
    memset(&linfo, 0, sizeof(switch_logical_network_t));
    linfo.type = (switch_logical_network_type_t)info.type;
    linfo.encap_info.encap_type = (switch_encap_type_t) info.encap_info.encap_type;
    switch(info.type) {
        case SWITCH_LOGICAL_NETWORK_TYPE_VLAN:
        linfo.encap_info.u.vlan_id = info.encap_info.u.vlan_id;
        break;
        case SWITCH_LOGICAL_NETWORK_TYPE_ENCAP_BASIC:
        linfo.encap_info.u.tunnel_vni = info.encap_info.u.tunnel_vni;
        break;
    }
    linfo.age_interval = info.age_interval;
    linfo.flags.flood_enabled = info.flags.flood_enabled;
    linfo.flags.learn_enabled = info.flags.learn_enabled;
    linfo.flags.core_bd = info.flags.core_bd;
    linfo.flags.ipv4_unicast_enabled = info.flags.ipv4_unicast_enabled;
    linfo.flags.ipv6_unicast_enabled = info.flags.ipv6_unicast_enabled;
    linfo.vrf_handle = info.vrf;
    linfo.rmac_handle = info.rmac_handle;
    printf("switcht_api_logical_network_create\n");
    return switch_api_logical_network_create(device, &linfo);
  }

  switcht_status_t switcht_api_logical_network_delete(const switcht_device_t device, const switcht_handle_t network_handle) {
    // Your implementation goes here
    printf("switcht_api_logical_network_delete\n");
    return switch_api_logical_network_delete(device, network_handle);
  }

  switcht_tunnel_handle_t switcht_api_tunnel_interface_create(const switcht_device_t device, const switcht_direction_t direction, const switcht_tunnel_info_t& tun_info) {
    // Your implementation goes here
    switch_tunnel_info_t ltun_info;
    memset(&ltun_info, 0, sizeof(switch_tunnel_info_t));
    ltun_info.encap_mode = (switch_encap_mode_t) tun_info.encap_mode;
    if (ltun_info.encap_mode == SWITCH_API_TUNNEL_ENCAP_MODE_IP) {
        ltun_info.encap_info.encap_type = (switch_encap_type_t)tun_info.encap_info.encap_type;
        ltun_info.u.ip_encap.vrf_handle = tun_info.tunnel_encap.ip_encap.vrf;
        ltun_info.u.ip_encap.ttl = tun_info.tunnel_encap.ip_encap.ttl;
        switch(tun_info.encap_info.encap_type) {
            case SWITCH_API_ENCAP_TYPE_VLAN:
            ltun_info.encap_info.u.vlan_id = tun_info.encap_info.u.vlan_id;
            break;
            case SWITCH_API_ENCAP_TYPE_VXLAN:
            ltun_info.encap_info.u.vxlan_info.vnid = tun_info.encap_info.u.vxlan_info.vnid;
            break;
            case SWITCH_API_ENCAP_TYPE_GENEVE:
            ltun_info.encap_info.u.geneve_info.vni = tun_info.encap_info.u.geneve_info.vni;
            break;
            case SWITCH_API_ENCAP_TYPE_NVGRE:
            ltun_info.encap_info.u.nvgre_info.tnid = tun_info.encap_info.u.nvgre_info.tnid;
            break;
        }
        switch_parse_ip_address(tun_info.tunnel_encap.ip_encap.src_ip, &ltun_info.u.ip_encap.src_ip);
        switch_parse_ip_address(tun_info.tunnel_encap.ip_encap.dst_ip, &ltun_info.u.ip_encap.dst_ip);
        ltun_info.u.ip_encap.proto = tun_info.tunnel_encap.ip_encap.proto;
        if (ltun_info.u.ip_encap.proto == 17) {
            ltun_info.u.ip_encap.u.udp.src_port = tun_info.tunnel_encap.ip_encap.u.udp.src_port;
            ltun_info.u.ip_encap.u.udp.dst_port = tun_info.tunnel_encap.ip_encap.u.udp.dst_port;
        } else if (ltun_info.u.ip_encap.proto == 47) {
            ltun_info.u.ip_encap.u.gre.protocol = tun_info.tunnel_encap.ip_encap.gre_proto;
        }
    } else {
        ltun_info.u.mpls_encap.bd_handle = tun_info.tunnel_encap.mpls_encap.bd_handle;
        ltun_info.u.mpls_encap.vrf_handle = tun_info.tunnel_encap.mpls_encap.vrf_handle;
        ltun_info.u.mpls_encap.nhop_handle = tun_info.tunnel_encap.mpls_encap.nhop_handle;
        ltun_info.u.mpls_encap.egress_if = tun_info.tunnel_encap.mpls_encap.egress_if;
        ltun_info.u.mpls_encap.mpls_type = (switch_mpls_type_t) tun_info.tunnel_encap.mpls_encap.mpls_type;
        ltun_info.u.mpls_encap.mpls_action = (switch_mpls_action_t) tun_info.tunnel_encap.mpls_encap.mpls_action;
        ltun_info.u.mpls_encap.mpls_mode = (switch_mpls_mode_t) tun_info.tunnel_encap.mpls_encap.mpls_mode;
        switch (ltun_info.u.mpls_encap.mpls_action) {
            case SWITCH_API_MPLS_ACTION_POP:
            {
                int count = tun_info.tunnel_encap.mpls_encap.u.pop_info.tag.size();
                ltun_info.u.mpls_encap.u.pop_info.count = count;
                std::vector<switcht_mpls_t>::const_iterator it = tun_info.tunnel_encap.mpls_encap.u.pop_info.tag.begin();
                for(int i = 0; i < count; i++, it++) {
                    ltun_info.u.mpls_encap.u.pop_info.tag[i].label = it->label;
                    ltun_info.u.mpls_encap.u.pop_info.tag[i].exp = it->exp;
                    ltun_info.u.mpls_encap.u.pop_info.tag[i].ttl = it->ttl;
                    ltun_info.u.mpls_encap.u.pop_info.tag[i].bos = it->bos;
                }
            }
            break;
            case SWITCH_API_MPLS_ACTION_PUSH:
            {
                int count = tun_info.tunnel_encap.mpls_encap.u.push_info.tag.size();
                ltun_info.u.mpls_encap.u.push_info.count = count;
                std::vector<switcht_mpls_t>::const_iterator it = tun_info.tunnel_encap.mpls_encap.u.push_info.tag.begin();
                for(int i = 0; i < count; i++, it++) {
                    ltun_info.u.mpls_encap.u.push_info.tag[i].label = it->label;
                    ltun_info.u.mpls_encap.u.push_info.tag[i].exp = it->exp;
                    ltun_info.u.mpls_encap.u.push_info.tag[i].ttl = it->ttl;
                    ltun_info.u.mpls_encap.u.push_info.tag[i].bos = it->bos;
                }
            }
            break;
            case SWITCH_API_MPLS_ACTION_SWAP:
            {
                ltun_info.u.mpls_encap.u.swap_info.old_tag.label = tun_info.tunnel_encap.mpls_encap.u.swap_info.old_tag.label;
                ltun_info.u.mpls_encap.u.swap_info.old_tag.exp = tun_info.tunnel_encap.mpls_encap.u.swap_info.old_tag.exp;
                ltun_info.u.mpls_encap.u.swap_info.old_tag.ttl = tun_info.tunnel_encap.mpls_encap.u.swap_info.old_tag.ttl;
                ltun_info.u.mpls_encap.u.swap_info.old_tag.bos = tun_info.tunnel_encap.mpls_encap.u.swap_info.old_tag.bos;
                ltun_info.u.mpls_encap.u.swap_info.new_tag.label = tun_info.tunnel_encap.mpls_encap.u.swap_info.new_tag.label;
                ltun_info.u.mpls_encap.u.swap_info.new_tag.exp = tun_info.tunnel_encap.mpls_encap.u.swap_info.new_tag.exp;
                ltun_info.u.mpls_encap.u.swap_info.new_tag.ttl = tun_info.tunnel_encap.mpls_encap.u.swap_info.new_tag.ttl;
                ltun_info.u.mpls_encap.u.swap_info.new_tag.bos = tun_info.tunnel_encap.mpls_encap.u.swap_info.new_tag.bos;
            }
            break;
            case SWITCH_API_MPLS_ACTION_SWAP_PUSH:
            {
                ltun_info.u.mpls_encap.u.swap_push_info.old_tag.label = tun_info.tunnel_encap.mpls_encap.u.swap_push_info.old_tag.label;
                ltun_info.u.mpls_encap.u.swap_push_info.old_tag.exp = tun_info.tunnel_encap.mpls_encap.u.swap_push_info.old_tag.exp;
                ltun_info.u.mpls_encap.u.swap_push_info.old_tag.ttl = tun_info.tunnel_encap.mpls_encap.u.swap_push_info.old_tag.ttl;
                ltun_info.u.mpls_encap.u.swap_push_info.old_tag.bos = tun_info.tunnel_encap.mpls_encap.u.swap_push_info.old_tag.bos;

                int count = tun_info.tunnel_encap.mpls_encap.u.swap_push_info.new_tag.size();
                ltun_info.u.mpls_encap.u.swap_push_info.count = count;
                std::vector<switcht_mpls_t>::const_iterator it = tun_info.tunnel_encap.mpls_encap.u.swap_push_info.new_tag.begin();
                for(int i = 0; i < count; i++, it++) {
                    ltun_info.u.mpls_encap.u.swap_push_info.new_tag[i].label = it->label;
                    ltun_info.u.mpls_encap.u.swap_push_info.new_tag[i].exp = it->exp;
                    ltun_info.u.mpls_encap.u.swap_push_info.new_tag[i].ttl = it->ttl;
                    ltun_info.u.mpls_encap.u.swap_push_info.new_tag[i].bos = it->bos;
                }
                break;
            }
        }
    }
    printf("switcht_api_tunnel_interface_create\n");
    ltun_info.flags.core_intf = tun_info.flags.core_intf;
    ltun_info.flags.flood_enabled = tun_info.flags.flood_enabled;
    ltun_info.out_if = tun_info.out_if;
    return switch_api_tunnel_interface_create(device, (switch_direction_t)direction, &ltun_info);
  }

  switcht_status_t switcht_api_tunnel_interface_delete(const switcht_device_t device, const switcht_tunnel_handle_t tun_handle) {
    // Your implementation goes here
    printf("switcht_api_tunnel_interface_delete\n");
    return switch_api_tunnel_interface_delete(device, tun_handle);
  }

  switcht_status_t switcht_api_logical_network_member_add(const switcht_device_t device, const switcht_handle_t network_handle, const switcht_interface_handle_t interface_handle) {
    // Your implementation goes here
    printf("switcht_api_logical_network_add_member\n");
    return switch_api_logical_network_member_add(device, network_handle, interface_handle);
  }

  switcht_status_t switcht_api_logical_network_member_remove(const switcht_device_t device, const switcht_handle_t network_handle, const switcht_interface_handle_t interface_handle) {
    // Your implementation goes here
    printf("switcht_api_logical_network_delete_member\n");
    return switch_api_logical_network_member_remove(device, network_handle, interface_handle);
  }

  switcht_status_t switcht_api_vlan_ports_add(const switcht_device_t device, const switcht_handle_t vlan_handle, const switcht_vlan_port_t& vlan_port) {
    printf("switcht_api_add_ports_to_vlan\n");
    switch_vlan_port_t lvlan_port;
    lvlan_port.handle = vlan_port.handle;
    lvlan_port.tagging_mode = (switch_vlan_tagging_mode_t)vlan_port.tagging_mode;
    return (switch_api_vlan_ports_add(device, vlan_handle, 1, &lvlan_port));
  }

  switcht_status_t switcht_api_vlan_ports_remove(const switcht_device_t device, const switcht_handle_t vlan_handle, const switcht_vlan_port_t& vlan_port) {
    printf("switcht_api_remove_ports_from_vlan\n");
    switch_vlan_port_t lvlan_port;
    lvlan_port.handle = vlan_port.handle;
    lvlan_port.tagging_mode = (switch_vlan_tagging_mode_t) vlan_port.tagging_mode;
    return (switch_api_vlan_ports_remove(device, vlan_handle, 1, &lvlan_port));
  }

  switcht_handle_t switcht_api_stp_group_create(const switcht_device_t device, const switcht_stp_mode_t stp_mode) {
    printf("switcht_api_stp_group_create\n");
    return switch_api_stp_group_create(device, (switch_stp_mode_t)stp_mode);
  }

  switcht_status_t switcht_api_stp_group_delete(const switcht_device_t device, const switcht_handle_t stg_handle) {
    printf("switcht_api_stp_group_delete\n");
    return switch_api_stp_group_delete(device, stg_handle);
  }

  switcht_status_t switcht_api_stp_group_vlans_add(const switcht_device_t device, const switcht_handle_t stg_handle, const int16_t vlan_count, const std::vector<switcht_handle_t> & vlan_handle) {
    printf("switcht_api_stp_group_vlan_add\n");
    switch_status_t status=0;
    std::vector<switcht_handle_t>::const_iterator it = vlan_handle.begin();

    switch_handle_t *vlan_list = (switch_handle_t *) malloc(sizeof(switch_handle_t) * vlan_handle.size());
    for(uint32_t i = 0; i < vlan_handle.size(); i++, it++) {
        vlan_list[i] = (switch_handle_t) *it;
    }
    status = switch_api_stp_group_vlans_add(device, stg_handle, vlan_count, vlan_list);
    free(vlan_list);
    return status;
  }

  switcht_status_t switcht_api_stp_group_vlans_remove(const switcht_device_t device, const switcht_handle_t stg_handle, const int16_t vlan_count, const std::vector<switcht_handle_t> & vlan_handle) {
    printf("switcht_api_stp_group_vlan_delete\n");
    switch_status_t status=0;
    std::vector<switcht_handle_t>::const_iterator it = vlan_handle.begin();

    switch_handle_t *vlan_list = (switch_handle_t *) malloc(sizeof(switch_handle_t) * vlan_handle.size());
    for(uint32_t i = 0; i < vlan_handle.size(); i++, it++) {
        vlan_list[i] = (switch_handle_t) *it;
    }
    status = switch_api_stp_group_vlans_remove(device, stg_handle, vlan_count, vlan_list);
    free(vlan_list);
    return status;
  }

  switcht_status_t switcht_api_stp_group_print_all() {
    printf("switcht_api_stp_group_print_all\n");
    return switch_api_stp_group_print_all();
  }

  switcht_status_t switcht_api_stp_port_state_set(const switcht_device_t device, const switcht_handle_t stg_handle, const switcht_handle_t intf_handle, const switcht_stp_state_t stp_state) {
    printf("switcht_api_stp_port_state_set\n");
    return switch_api_stp_port_state_set(device, stg_handle, intf_handle, (switch_stp_state_t) stp_state);
  }

  switcht_status_t switcht_api_stp_port_state_clear(const switcht_device_t device, const switcht_handle_t stg_handle, const switcht_handle_t intf_handle) {
    printf("switcht_api_stp_port_state_clear\n");
    return switch_api_stp_port_state_clear(device, stg_handle, intf_handle);
  }

  // ACL

  switcht_handle_t switcht_api_acl_list_create(const switcht_device_t device, const switcht_acl_type_t type) {
    printf("switcht_api_acl_list_create\n");
    return switch_api_acl_list_create(device, (switch_acl_type_t)type);
  }

  switcht_status_t switcht_api_acl_list_delete(const switcht_device_t device, const switcht_handle_t handle) {
    printf("switcht_api_acl_list_delete\n");
    return switch_api_acl_list_delete(device, handle);
  }

  switcht_handle_t switcht_api_acl_ip_rule_create(const switcht_device_t device, const switcht_handle_t acl_handle, const int32_t priority, const int32_t key_value_count, const std::vector<switcht_acl_ip_key_value_pair_t> & acl_kvp, const switcht_acl_action_t action, const switcht_acl_action_params_t& action_params) {
    printf("switcht_api_acl_ip_rule_create\n");
//    switch_status_t status=0;
    switch_handle_t handle;
    switch_acl_action_params_t ap;

    std::vector<switcht_acl_ip_key_value_pair_t>::const_iterator f=acl_kvp.begin();

    void *fields = calloc(sizeof(switch_acl_ip_key_value_pair_t)*acl_kvp.size(), 1);
    for(uint32_t i=0;i<acl_kvp.size();i++,f++) {
        unsigned long long v = (unsigned long long)((switch_acl_ip_field_t)f->value);
        ((switch_acl_ip_key_value_pair_t *)fields+i)->field = (switch_acl_ip_field_t)f->field;
        memcpy(&(((switch_acl_ip_key_value_pair_t *)fields+i)->value.ipv4_source), &v, sizeof(switch_acl_ip_value));
        ((switch_acl_ip_key_value_pair_t *)fields+i)->mask.u.mask = (switch_acl_ip_field_t)f->mask;
    }
    memset(&ap, 0, sizeof(switch_acl_action_params_t));
    switch((switch_acl_action_t)action) {
        case SWITCH_ACL_ACTION_REDIRECT:
            ap.redirect.handle = action_params.redirect.handle;
            break;
        case SWITCH_ACL_ACTION_REDIRECT_TO_CPU:
            ap.cpu_redirect.reason_code = action_params.cpu_redirect.reason_code;
            break;
        case SWITCH_ACL_ACTION_SET_MIRROR:
            ap.mirror.mirror_handle = action_params.mirror.mirror_handle;
            break;
        default:
            break;
    }
    /*status =*/ switch_api_acl_rule_create(device, acl_handle, priority, key_value_count, fields, (switch_acl_action_t)action, &ap, &handle);
    free(fields);
    return handle;
  }

 switcht_handle_t switcht_api_acl_mirror_rule_create(const switcht_device_t device, const switcht_handle_t acl_handle, const int32_t priority, const int32_t key_value_count, const std::vector<switcht_acl_mirror_key_value_pair_t> & acl_kvp, const switcht_acl_action_t action, const switcht_acl_action_params_t& action_params) {
    printf("switcht_api_acl_mirror_rule_create\n");
//    switch_status_t status=0;
    std::vector<switcht_acl_mirror_key_value_pair_t>::const_iterator f=acl_kvp.begin();
    switch_acl_action_params_t ap;
    switch_handle_t handle;

    void *fields = calloc(sizeof(switch_acl_mirror_key_value_pair_t)*acl_kvp.size(), 1);
    for(uint32_t i=0;i<acl_kvp.size();i++,f++) {
        unsigned long long v = (unsigned long long)((switch_acl_mirror_field_t)f->value);
        ((switch_acl_mirror_key_value_pair_t *)fields+i)->field = (switch_acl_mirror_field_t)f->field;
        memcpy(&(((switch_acl_mirror_key_value_pair_t *)fields+i)->value.ipv4_source), &v, sizeof(switch_acl_mirror_value));
        ((switch_acl_mirror_key_value_pair_t *)fields+i)->mask.u.mask = (switch_acl_mirror_field_t)f->mask;
    }
    memset(&ap, 0, sizeof(switch_acl_action_params_t));
    ap.mirror.mirror_handle = action_params.mirror.mirror_handle;
    /*status =*/ switch_api_acl_rule_create(device, acl_handle, priority, key_value_count, fields, (switch_acl_action_t)action, &ap, &handle);
    free(fields);
    return handle;
  }

  switcht_handle_t switcht_api_acl_system_rule_create(const switcht_device_t device, const switcht_handle_t acl_handle, const int32_t priority, const int32_t key_value_count, const std::vector<switcht_acl_system_key_value_pair_t> & acl_kvp, const switcht_acl_action_t action, const switcht_acl_action_params_t& action_params) {
    printf("switcht_api_system_acl_rule_create\n");
//    switch_status_t status=0;
    switch_handle_t handle;
    std::vector<switcht_acl_system_key_value_pair_t>::const_iterator f=acl_kvp.begin();
    switch_acl_action_params_t ap;

    void *fields = calloc(sizeof(switch_acl_system_key_value_pair_t)*acl_kvp.size(), 1);
    for(uint32_t i=0;i<acl_kvp.size();i++,f++) {
        unsigned long long v = (unsigned long long)((switch_acl_mirror_field_t)f->value);
        ((switch_acl_system_key_value_pair_t *)fields+i)->field = (switch_acl_system_field_t)f->field;
        memcpy(&(((switch_acl_system_key_value_pair_t *)fields+i)->value.ipv4_source), &v, sizeof(switch_acl_system_value));
        ((switch_acl_system_key_value_pair_t *)fields+i)->mask.u.mask = (switch_acl_system_field_t)f->mask;
    }
    memset(&ap, 0, sizeof(switch_acl_action_params_t));
    ap.cpu_redirect.reason_code = action_params.cpu_redirect.reason_code;
    /*status =*/ switch_api_acl_rule_create(device, acl_handle, priority, key_value_count, fields, (switch_acl_action_t)action, &ap, &handle);
    free(fields);
    return handle;
  }

   switcht_handle_t switcht_api_acl_egr_rule_create(const switcht_device_t device, const switcht_handle_t acl_handle, const int32_t priority, const int32_t key_value_count, const std::vector<switcht_acl_egr_key_value_pair_t> & acl_kvp, const switcht_acl_action_t action, const switcht_acl_action_params_t& action_params) {
    printf("switcht_api_acl_egr_rule_create\n");
    switch_handle_t handle;
    std::vector<switcht_acl_egr_key_value_pair_t>::const_iterator f = acl_kvp.begin();
    switch_acl_action_params_t ap;

    void *fields = calloc(sizeof(switch_acl_egr_key_value_pair_t)*acl_kvp.size(), 1);
    for (uint32_t i=0;i<acl_kvp.size();i++,f++) {
        unsigned long long v = (unsigned long long)((switch_acl_mirror_field_t)f->value);
        ((switch_acl_egr_key_value_pair_t *)fields+i)->field =
            (switch_acl_egr_field_t)f->field;
        memcpy(&(((switch_acl_egr_key_value_pair_t *)fields+i)->value.egr_port), &v, sizeof(switch_acl_egr_value_t));
        ((switch_acl_egr_key_value_pair_t *)fields+i)->mask.u.mask = (switch_acl_egr_field_t)f->mask;
    }
    memset(&ap, 0, sizeof(switch_acl_action_params_t));
    ap.mirror.mirror_handle = action_params.mirror.mirror_handle;
    switch_api_acl_rule_create(device, acl_handle, priority, key_value_count, fields, (switch_acl_action_t)action, &ap, &handle);
    free(fields);
    return handle;
    }

  switcht_status_t switcht_api_acl_rule_delete(const switcht_device_t device, const switcht_handle_t acl_handle, const switcht_handle_t ace) {
    printf("switcht_api_acl_rule_delete\n");
    return switch_api_acl_rule_delete(device, acl_handle, ace);
  }

  switcht_status_t switcht_api_acl_reference(const switcht_device_t device, const switcht_handle_t acl_handle, const switcht_handle_t interface_handle) {
    printf("switcht_api_acl_reference\n");
    return switch_api_acl_reference(device, acl_handle, interface_handle);
  }

  switcht_status_t switcht_api_acl_remove(const switcht_device_t device, const switcht_handle_t acl_handle, const switcht_handle_t interface_handle) {
    // Your implementation goes here
    printf("switcht_api_acl_remove\n");
    return switch_api_acl_remove(device, acl_handle, interface_handle);
  }

  switcht_handle_t switcht_api_multicast_tree_create(const switcht_device_t device) {
    // Your implementation goes here
    printf("switcht_api_multicast_tree_create\n");
    return switch_api_multicast_tree_create(device);
  }

  switcht_status_t switcht_api_multicast_tree_delete(const switcht_device_t device, const switcht_handle_t mgid_handle) {
    // Your implementation goes here
    printf("switcht_api_multicast_tree_delete\n");
    return switch_api_multicast_tree_delete(device, mgid_handle);
  }

  switcht_status_t switcht_api_multicast_member_add(const switcht_device_t device, const switcht_handle_t mgid_handle, const switcht_handle_t tenant_bd_handle, const int32_t intf_handle_count, const std::vector<switcht_handle_t> & interface_handle) {
    // Your implementation goes here
    printf("switcht_api_multicast_member_add\n");
    switch_status_t status=0;
    std::vector<switcht_handle_t>::const_iterator it = interface_handle.begin();

    switch_handle_t *interface_list = (switch_handle_t *) malloc(sizeof(switch_handle_t) * interface_handle.size());
    for(uint32_t i = 0; i < interface_handle.size(); i++, it++) {
        interface_list[i] = (switch_handle_t) *it;
    }
    status = switch_api_multicast_member_add(device, mgid_handle, tenant_bd_handle,
                                         intf_handle_count, interface_list);
    free(interface_list);
    return status;
  }

  switcht_status_t switcht_api_multicast_member_delete(const switcht_device_t device, const switcht_handle_t mgid_handle, const switcht_handle_t tenant_bd_handle, const int32_t intf_handle_count, const std::vector<switcht_handle_t> & interface_handle) {
    // Your implementation goes here
    printf("switcht_api_multicast_member_delete\n");
    switch_status_t status=0;
    std::vector<switcht_handle_t>::const_iterator it = interface_handle.begin();

    switch_handle_t *interface_list = (switch_handle_t *) malloc(sizeof(switch_handle_t) * interface_handle.size());
    for(uint32_t i = 0; i < interface_handle.size(); i++, it++) {
        interface_list[i] = (switch_handle_t) *it;
    }
    status = switch_api_multicast_member_delete(device, mgid_handle, tenant_bd_handle,
                                         intf_handle_count, interface_list);
    free(interface_list);
    return status;
  }

  switcht_status_t switcht_api_vlan_learning_enabled_set(const switcht_handle_t vlan_handle, const int64_t value) {
    printf("switcht_api_set_vlan_learning_enabled\n");
    return (switch_api_vlan_learning_enabled_set(vlan_handle, value));
  }

  switcht_status_t switcht_api_vlan_learning_enabled_get(const switcht_handle_t vlan_handle, const int64_t value) {
    printf("switcht_api_get_vlan_learning_enabled\n");
    return (switch_api_vlan_learning_enabled_get(vlan_handle, (uint64_t *)&value));
  }

 switcht_handle_t switcht_api_mirror_session_create(const switcht_device_t device, const switcht_mirror_info_t& api_mirror_info) {
    // Your implementation goes here
    printf("switcht_api_mirror_session_create\n");
    switch_api_mirror_info_t lapi_mirror_info;
    memset(&lapi_mirror_info, 0, sizeof(switch_api_mirror_info_t));
    lapi_mirror_info.mirror_type = (switch_mirror_type_t) api_mirror_info.mirror_type;
    lapi_mirror_info.session_type = (switch_mirror_session_type_t) api_mirror_info.session_type;
    lapi_mirror_info.cos = api_mirror_info.cos;
    lapi_mirror_info.max_pkt_len = api_mirror_info.max_pkt_len;
    lapi_mirror_info.egress_port = api_mirror_info.egress_port;
    lapi_mirror_info.direction = (switch_direction_t) api_mirror_info.direction;
    lapi_mirror_info.session_id = api_mirror_info.session_id;
    lapi_mirror_info.nhop_handle = api_mirror_info.nhop_handle;
    return switch_api_mirror_session_create(device, &lapi_mirror_info);
  }

 switcht_status_t switcht_api_mirror_session_update(const switcht_device_t device, const switcht_handle_t mirror_handle, const switcht_mirror_info_t& api_mirror_info) {
    // Your implementation goes here
    printf("switcht_api_mirror_session_update\n");
    switch_api_mirror_info_t lapi_mirror_info;
    memset(&lapi_mirror_info, 0, sizeof(switch_api_mirror_info_t));
    lapi_mirror_info.mirror_type = (switch_mirror_type_t) api_mirror_info.mirror_type;
    lapi_mirror_info.session_type = (switch_mirror_session_type_t) api_mirror_info.session_type;
    lapi_mirror_info.cos = api_mirror_info.cos;
    lapi_mirror_info.max_pkt_len = api_mirror_info.max_pkt_len;
    lapi_mirror_info.egress_port = api_mirror_info.egress_port;
    lapi_mirror_info.direction = (switch_direction_t) api_mirror_info.direction;
    lapi_mirror_info.session_id = api_mirror_info.session_id;
    lapi_mirror_info.nhop_handle = api_mirror_info.nhop_handle;
    lapi_mirror_info.enable = api_mirror_info.enable;
    return switch_api_mirror_session_update(device, mirror_handle, &lapi_mirror_info);
  }

  switcht_status_t switcht_api_mirror_session_delete(const switcht_device_t device, const switcht_handle_t mirror_handle) {
    // Your implementation goes here
    printf("switcht_mirror_session_delete\n");
    return switch_api_mirror_session_delete(device, mirror_handle);
  }

  switcht_status_t switcht_int_transit_enable(const switcht_device_t device, const int32_t switch_id, const int32_t enable) {
    // Your implementation goes here
    printf("switcht_api_int_transit_enable/disable = %d\n", enable);
    return switch_int_transit_enable(device, switch_id, enable);
  }


  switcht_status_t switcht_api_mac_table_set_learning_timeout(const switcht_device_t device, const int32_t timeout) {
    // Your implementation goes here
    printf("switcht_api_mac_table_set_learning_timeout\n");
    return (switch_api_mac_table_set_learning_timeout(device, timeout));
  }

  switcht_status_t switcht_api_mac_table_aging_time_set(const int64_t value) {
    // Your implementation goes here
    printf("switcht_api_mac_table_aging_time_set\n");
    return switch_api_mac_table_aging_time_set(value);
  }

  switcht_status_t switcht_api_vlan_aging_interval_set(const switcht_handle_t vlan_handle, const int64_t value) {
    printf("switcht_api_vlan_aging_interface_set\n");
    return (switch_api_vlan_aging_interval_set(vlan_handle, value));
  }

  switcht_status_t switcht_api_mpls_tunnel_transit_create(const switcht_device_t device, const switcht_mpls_encap_t& mpls_encap) {
    // Your implementation goes here
    printf("switch_api_mpls_tunnel_transit_create\n");
    switch_mpls_encap_t lmpls_encap;
    memset(&lmpls_encap, 0, sizeof(switch_mpls_encap_t));
    lmpls_encap.mpls_type = (switch_mpls_type_t) mpls_encap.mpls_type;
    lmpls_encap.mpls_action = (switch_mpls_action_t) mpls_encap.mpls_action;
    lmpls_encap.mpls_mode = (switch_mpls_mode_t) mpls_encap.mpls_mode;
    lmpls_encap.nhop_handle = mpls_encap.nhop_handle;
    lmpls_encap.bd_handle = mpls_encap.bd_handle;
    lmpls_encap.vrf_handle = mpls_encap.vrf_handle;
    lmpls_encap.egress_if = mpls_encap.egress_if;
    if (lmpls_encap.mpls_action == SWITCH_API_MPLS_ACTION_SWAP) {
        lmpls_encap.u.swap_info.old_tag.label = mpls_encap.u.swap_info.old_tag.label;
        lmpls_encap.u.swap_info.old_tag.exp = mpls_encap.u.swap_info.old_tag.exp;
        lmpls_encap.u.swap_info.old_tag.ttl = mpls_encap.u.swap_info.old_tag.ttl;
        lmpls_encap.u.swap_info.old_tag.bos = mpls_encap.u.swap_info.old_tag.bos;
        lmpls_encap.u.swap_info.new_tag.label = mpls_encap.u.swap_info.new_tag.label;
        lmpls_encap.u.swap_info.new_tag.exp = mpls_encap.u.swap_info.new_tag.exp;
        lmpls_encap.u.swap_info.new_tag.ttl = mpls_encap.u.swap_info.new_tag.ttl;
        lmpls_encap.u.swap_info.new_tag.bos = mpls_encap.u.swap_info.new_tag.bos;
    } else if (lmpls_encap.mpls_action == SWITCH_API_MPLS_ACTION_SWAP_PUSH) {
        lmpls_encap.u.swap_push_info.old_tag.label = mpls_encap.u.swap_push_info.old_tag.label;
        lmpls_encap.u.swap_push_info.old_tag.exp = mpls_encap.u.swap_push_info.old_tag.exp;
        lmpls_encap.u.swap_push_info.old_tag.ttl = mpls_encap.u.swap_push_info.old_tag.ttl;
        lmpls_encap.u.swap_push_info.old_tag.bos = mpls_encap.u.swap_push_info.old_tag.bos;

        int count = mpls_encap.u.swap_push_info.new_tag.size();
        lmpls_encap.u.swap_push_info.count = count;
        std::vector<switcht_mpls_t>::const_iterator it = mpls_encap.u.swap_push_info.new_tag.begin();
        for(int i = 0; i < count; i++, it++) {
            lmpls_encap.u.swap_push_info.new_tag[i].label = it->label;
            lmpls_encap.u.swap_push_info.new_tag[i].exp = it->exp;
            lmpls_encap.u.swap_push_info.new_tag[i].ttl = it->ttl;
            lmpls_encap.u.swap_push_info.new_tag[i].bos = it->bos;
        }
    }
    return switch_api_mpls_tunnel_transit_create(device, &lmpls_encap);
  }

  switcht_status_t switcht_api_mpls_tunnel_transit_delete(const switcht_device_t device, const switcht_mpls_encap_t& mpls_encap) {
    // Your implementation goes here
    printf("switch_api_mpls_tunnel_transit_delete\n");
    switch_mpls_encap_t lmpls_encap;
    memset(&lmpls_encap, 0, sizeof(switch_mpls_encap_t));
    lmpls_encap.mpls_type = (switch_mpls_type_t) mpls_encap.mpls_type;
    lmpls_encap.mpls_action = (switch_mpls_action_t) mpls_encap.mpls_action;
    lmpls_encap.mpls_mode = (switch_mpls_mode_t) mpls_encap.mpls_mode;
    lmpls_encap.nhop_handle = mpls_encap.nhop_handle;
    lmpls_encap.bd_handle = mpls_encap.bd_handle;
    lmpls_encap.vrf_handle = mpls_encap.vrf_handle;
    lmpls_encap.egress_if = mpls_encap.egress_if;
    if (lmpls_encap.mpls_action == SWITCH_API_MPLS_ACTION_SWAP) {
        lmpls_encap.u.swap_info.old_tag.label = mpls_encap.u.swap_info.old_tag.label;
        lmpls_encap.u.swap_info.old_tag.exp = mpls_encap.u.swap_info.old_tag.exp;
        lmpls_encap.u.swap_info.old_tag.ttl = mpls_encap.u.swap_info.old_tag.ttl;
        lmpls_encap.u.swap_info.old_tag.bos = mpls_encap.u.swap_info.old_tag.bos;
        lmpls_encap.u.swap_info.new_tag.label = mpls_encap.u.swap_info.new_tag.label;
        lmpls_encap.u.swap_info.new_tag.exp = mpls_encap.u.swap_info.new_tag.exp;
        lmpls_encap.u.swap_info.new_tag.ttl = mpls_encap.u.swap_info.new_tag.ttl;
        lmpls_encap.u.swap_info.new_tag.bos = mpls_encap.u.swap_info.new_tag.bos;
    } else if (lmpls_encap.mpls_action == SWITCH_API_MPLS_ACTION_SWAP_PUSH) {
        lmpls_encap.u.swap_push_info.old_tag.label = mpls_encap.u.swap_push_info.old_tag.label;
        lmpls_encap.u.swap_push_info.old_tag.exp = mpls_encap.u.swap_push_info.old_tag.exp;
        lmpls_encap.u.swap_push_info.old_tag.ttl = mpls_encap.u.swap_push_info.old_tag.ttl;
        lmpls_encap.u.swap_push_info.old_tag.bos = mpls_encap.u.swap_push_info.old_tag.bos;

        int count = mpls_encap.u.swap_push_info.new_tag.size();
        lmpls_encap.u.swap_push_info.count = count;
        std::vector<switcht_mpls_t>::const_iterator it = mpls_encap.u.swap_push_info.new_tag.begin();
        for(int i = 0; i < count; i++, it++) {
            lmpls_encap.u.swap_push_info.new_tag[i].label = it->label;
            lmpls_encap.u.swap_push_info.new_tag[i].exp = it->exp;
            lmpls_encap.u.swap_push_info.new_tag[i].ttl = it->ttl;
            lmpls_encap.u.swap_push_info.new_tag[i].bos = it->bos;
        }
    }
    return switch_api_mpls_tunnel_transit_delete(device, &lmpls_encap);
  }

  switcht_handle_t switcht_api_hostif_group_create(const switcht_device_t device, const switcht_hostif_group_t& hostif_group) {
    // Your implementation goes here
    printf("switcht_api_hostif_group_create\n");
    switch_hostif_group_t lhostif_group;
    lhostif_group.egress_queue = hostif_group.egress_queue;
    lhostif_group.priority = hostif_group.priority;
    return switch_api_hostif_group_create(device, &lhostif_group);
  }

  switcht_status_t switcht_api_hostif_group_delete(const switcht_device_t device, const switcht_handle_t hostif_group_handle) {
    // Your implementation goes here
    printf("switcht_api_hostif_group_delete\n");
    return switch_api_hostif_group_delete(device, hostif_group_handle);
  }

  switcht_status_t switcht_api_hostif_reason_code_create(const switcht_device_t device, const switcht_api_hostif_rcode_info_t& rcode_api_info) {
    // Your implementation goes here
    printf("switcht_api_hostif_reason_code_create\n");
    switch_api_hostif_rcode_info_t lrcode_api_info;
    lrcode_api_info.reason_code = (switch_hostif_reason_code_t) rcode_api_info.reason_code;
    lrcode_api_info.action = (switch_acl_action_t) rcode_api_info.action;
    lrcode_api_info.priority = rcode_api_info.priority;
    lrcode_api_info.channel = (switch_hostif_channel_t) rcode_api_info.channel;
    lrcode_api_info.hostif_group_id = rcode_api_info.hostif_group_id;
    return switch_api_hostif_reason_code_create(device, &lrcode_api_info);
  }

  switcht_status_t switcht_api_hostif_reason_code_delete(const switcht_device_t device, const switcht_hostif_reason_code_t reason_code) {
    // Your implementation goes here
    printf("switcht_api_hostif_reason_code_delete\n");
    return switch_api_hostif_reason_code_delete(device, (switch_hostif_reason_code_t) reason_code);
  }

  switcht_handle_t switcht_api_hostif_create(const switcht_device_t device, const switcht_hostif_t& hostif) {
    // Your implementation goes here
    printf("switcht_api_hostif_create\n");
    switch_hostif_t lhostif;
    lhostif.handle = hostif.handle;
    memcpy(lhostif.intf_name, hostif.intf_name.c_str(), SWITCH_HOSTIF_NAME_SIZE);
    return switch_api_hostif_create(device, &lhostif);
  }

  switcht_status_t switcht_api_hostif_delete(const switcht_device_t device, const switcht_handle_t hostif_handle) {
    // Your implementation goes here
    printf("switcht_api_hostif_delete\n");
    return switch_api_hostif_delete(device, hostif_handle);
  }
};

static void *api_rpc_server_thread(void *args) {
  int port = SWITCH_API_RPC_SERVER_PORT;
  shared_ptr<switch_api_rpcHandler> handler(new switch_api_rpcHandler());
  shared_ptr<TProcessor> processor(new switch_api_rpcProcessor(handler));
  shared_ptr<TServerTransport> serverTransport(new TServerSocket(port));
  shared_ptr<TTransportFactory> transportFactory(new TBufferedTransportFactory());
  shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());

  TSimpleServer server(processor, serverTransport, transportFactory, protocolFactory);
  /* set thread name to "api_thrift" */
  pthread_setname_np(pthread_self(), "api_thrift");
  server.serve();
  return NULL;
}

static pthread_t api_rpc_thread;

extern "C" {
        int start_switch_api_rpc_server(void)
        {
                std::cerr << "Starting API RPC server on port " <<
                        SWITCH_API_RPC_SERVER_PORT << std::endl;

                return pthread_create(&api_rpc_thread, NULL, api_rpc_server_thread, NULL);
        }
}

