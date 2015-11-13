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

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sai.h>
#include "switchlink.h"
#include "switchlink_link.h"
#include "switchlink_neigh.h"
#include "switchlink_packet.h"
#include "switchlink_db.h"

extern void sai_initialize();
extern sai_status_t sai_create_hostif_trap(sai_hostif_trap_id_t hostif_trapid,
                                           uint32_t attr_count,
                                           const sai_attribute_t *attr_list);

static sai_switch_api_t                 *switch_api = NULL;
static sai_virtual_router_api_t         *vrf_api = NULL;
static sai_vlan_api_t                   *vlan_api = NULL;
static sai_stp_api_t                    *stp_api = NULL;
static sai_fdb_api_t                    *fdb_api = NULL;
static sai_router_interface_api_t       *rintf_api = NULL;
static sai_neighbor_api_t               *neigh_api = NULL;
static sai_next_hop_api_t               *nhop_api = NULL;
static sai_next_hop_group_api_t         *nhop_group_api = NULL;
static sai_route_api_t                  *route_api = NULL;
static sai_hostif_api_t                 *host_intf_api = NULL;
static sai_object_id_t                  *s_port_list = NULL;
static sai_object_id_t                   s_cpu_port;
static uint16_t                          s_max_ports = 0;

static inline uint32_t
ipv4_prefix_len_to_mask(uint32_t prefix_len) {
    return (((uint32_t)0xFFFFFFFF) << (32 - prefix_len));
}

static inline struct in6_addr
ipv6_prefix_len_to_mask(uint32_t prefix_len) {
    struct in6_addr mask;
    memset(&mask, 0, sizeof(mask));
    assert(prefix_len <= 128);

    int i;
    for (i = 0; i < 4; i++) {
        if (prefix_len > 32) {
            mask.s6_addr32[i] = 0xFFFFFFFF;
        } else {
            mask.s6_addr32[i] = htonl(ipv4_prefix_len_to_mask(prefix_len));
            break;
        }
        prefix_len -= 32;
    }
    return mask;
}

static void
get_port_list() {
    sai_status_t status = SAI_STATUS_SUCCESS;
    sai_attribute_t port_attr;

    memset(&port_attr, 0, sizeof(port_attr));
    port_attr.id = SAI_SWITCH_ATTR_CPU_PORT;
    status = switch_api->get_switch_attribute(1, &port_attr);
    assert(status == SAI_STATUS_SUCCESS);
    s_cpu_port = port_attr.value.oid;

    memset(&port_attr, 0, sizeof(port_attr));
    port_attr.id = SAI_SWITCH_ATTR_PORT_NUMBER;
    status = switch_api->get_switch_attribute(1, &port_attr);
    assert(status == SAI_STATUS_SUCCESS);
    s_max_ports = port_attr.value.u32;

    memset(&port_attr, 0, sizeof(port_attr));
    port_attr.id = SAI_SWITCH_ATTR_PORT_LIST;
    s_port_list = (sai_object_id_t *)switchlink_malloc(sizeof(sai_object_id_t),
                                                       s_max_ports);
    port_attr.value.objlist.list = s_port_list;
    status = switch_api->get_switch_attribute(1, &port_attr);
    assert(status == SAI_STATUS_SUCCESS);
}

static sai_object_id_t
get_port_object(uint16_t port_id) {
    if (port_id > s_max_ports) {
        return s_cpu_port;
    } else {
        return s_port_list[port_id];
    }
}

static int
port_handle_to_port_id(switchlink_handle_t port_h, uint16_t *port_id) {
    int i;
    for (i = 0; i < s_max_ports; i++) {
        if (s_port_list[i] == port_h) {
            *port_id = i;
            return 0;
        }
    }
    return -1;
}

static void
on_packet_event(const void *buf, sai_size_t buf_size, uint32_t attr_count,
                const sai_attribute_t *attr_list) {
    int ret;
    uint32_t i;
    uint16_t port_id;
    switchlink_handle_t port_h = 0;

    for (i = 0; i < attr_count; i++, attr_list++) {
        switch (attr_list->id) {
            case SAI_HOSTIF_PACKET_INGRESS_PORT:
                port_h = attr_list->value.oid;
                break;
            default:
                break;
        }
    }
    if (port_h == 0) {
        return;
    }

    ret = port_handle_to_port_id(port_h, &port_id);
    if (ret == -1) {
        return;
    }
    switchlink_packet_from_hardware(buf, buf_size, port_id);
}

static void
init_packet_handler() {
    sai_switch_notification_t switch_notifications;
    sai_status_t status = SAI_STATUS_SUCCESS;
    sai_attribute_t attr_list[3];

    memset(&switch_notifications, 0, sizeof(switch_notifications));
    switch_notifications.on_packet_event = on_packet_event;
    status = switch_api->initialize_switch(0, NULL, NULL,
                                           &switch_notifications);
    assert(status == SAI_STATUS_SUCCESS);

    // STP, redirect to CPU
    memset(attr_list, 0, sizeof(attr_list));
    attr_list[0].id = SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION;
    attr_list[0].value.u32 = SAI_PACKET_ACTION_TRAP;
    attr_list[1].id = SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY;
    attr_list[1].value.u32 = 1;
    attr_list[2].id = SAI_HOSTIF_TRAP_ATTR_TRAP_CHANNEL;
    attr_list[2].value.u32 = SAI_HOSTIF_TRAP_CHANNEL_CB;
    status = sai_create_hostif_trap(SAI_HOSTIF_TRAP_ID_STP, 3, attr_list);
    assert(status == SAI_STATUS_SUCCESS);

    // OSPF, copy to CPU
    memset(attr_list, 0, sizeof(attr_list));
    attr_list[0].id = SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION;
    attr_list[0].value.u32 = SAI_PACKET_ACTION_LOG;
    attr_list[1].id = SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY;
    attr_list[1].value.u32 = 101;
    attr_list[2].id = SAI_HOSTIF_TRAP_ATTR_TRAP_CHANNEL;
    attr_list[2].value.u32 = SAI_HOSTIF_TRAP_CHANNEL_CB;
    status = sai_create_hostif_trap(SAI_HOSTIF_TRAP_ID_OSPF, 3, attr_list);
    assert(status == SAI_STATUS_SUCCESS);
}

int
switchlink_vrf_create(uint16_t vrf_id, switchlink_handle_t *vrf_h) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    sai_attribute_t attr_list[2];

    memset(attr_list, 0, sizeof(attr_list));
    attr_list[0].id = SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE;
    attr_list[0].value.booldata = true;
    attr_list[1].id = SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE;
    attr_list[1].value.booldata = true;

    status = vrf_api->create_virtual_router(vrf_h, 2, attr_list);
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int
switchlink_interface_create(switchlink_db_interface_info_t *intf,
                            switchlink_handle_t *intf_h) {
    sai_status_t status = SAI_STATUS_SUCCESS;

    if (intf->intf_type == SWITCHLINK_INTF_TYPE_L2_ACCESS) {
        *intf_h = get_port_object(intf->port_id);
    } else if (intf->intf_type == SWITCHLINK_INTF_TYPE_L3) {
        sai_attribute_t attr_list[6];
        memset(attr_list, 0, sizeof(attr_list));
        attr_list[0].id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
        attr_list[0].value.oid = intf->vrf_h;
        attr_list[1].id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
        attr_list[1].value.u8 = SAI_ROUTER_INTERFACE_TYPE_PORT;
        attr_list[2].id = SAI_ROUTER_INTERFACE_ATTR_PORT_ID;
        attr_list[2].value.oid = get_port_object(intf->port_id);
        attr_list[3].id = SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE;
        attr_list[3].value.booldata = true;
        attr_list[4].id = SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE;
        attr_list[4].value.booldata = true;
        attr_list[5].id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
        memcpy(attr_list[5].value.mac, intf->mac_addr, sizeof(sai_mac_t));
        status = rintf_api->create_router_interface(intf_h, 6, attr_list);
    }
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int
switchlink_interface_delete(switchlink_db_interface_info_t *intf,
                            switchlink_handle_t intf_h) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    if (intf->intf_type == SWITCHLINK_INTF_TYPE_L2_ACCESS) {
        // nothing to do
    } else if (intf->intf_type == SWITCHLINK_INTF_TYPE_L3) {
        status = rintf_api->remove_router_interface(intf_h);
    }
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

static sai_port_stp_port_state_t
get_sai_stp_state(switchlink_stp_state_t switchlink_stp_state) {
    sai_port_stp_port_state_t sai_stp_state = SAI_PORT_STP_STATE_FORWARDING;
    switch (switchlink_stp_state) {
        case SWITCHLINK_STP_STATE_NONE:
        case SWITCHLINK_STP_STATE_DISABLED:
        case SWITCHLINK_STP_STATE_FORWARDING:
            sai_stp_state = SAI_PORT_STP_STATE_FORWARDING;
            break;
        case SWITCHLINK_STP_STATE_LEARNING:
            sai_stp_state = SAI_PORT_STP_STATE_LEARNING;
            break;
        case SWITCHLINK_STP_STATE_BLOCKING:
            sai_stp_state = SAI_PORT_STP_STATE_BLOCKING;
            break;
    }
    return sai_stp_state;
}

int
switchlink_stp_state_update(switchlink_db_interface_info_t *intf) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    status = stp_api->set_stp_port_state(intf->stp_h, intf->intf_h,
                                         get_sai_stp_state(intf->stp_state));
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int
switchlink_add_interface_to_bridge(switchlink_db_interface_info_t *intf) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    sai_vlan_port_t vlan_port;

    vlan_port.port_id = intf->intf_h;
    vlan_port.tagging_mode = SAI_VLAN_PORT_UNTAGGED;
    status = vlan_api->add_ports_to_vlan(intf->bridge_h, 1, &vlan_port);
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int
switchlink_del_interface_from_bridge(switchlink_db_interface_info_t *intf,
                                     switchlink_handle_t old_bridge_h) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    sai_vlan_port_t vlan_port;

    vlan_port.port_id = intf->intf_h;
    vlan_port.tagging_mode = SAI_VLAN_PORT_UNTAGGED;
    status = vlan_api->remove_ports_from_vlan(old_bridge_h, 1, &vlan_port);
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int
switchlink_bridge_create(switchlink_db_bridge_info_t *bridge_db_info) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    static uint32_t vlan_id = 1;

    status = vlan_api->create_vlan(vlan_id);
    if (status != SAI_STATUS_SUCCESS) {
        return -1;
    }

    sai_attribute_t attr_list[1];
    memset(attr_list, 0, sizeof(attr_list));
    attr_list[0].id = SAI_STP_ATTR_VLAN_LIST;
    attr_list[0].value.vlanlist.vlan_count = 1;
    attr_list[0].value.vlanlist.vlan_list = (sai_vlan_id_t *)&vlan_id;
    status = stp_api->create_stp(&(bridge_db_info->stp_h), 1, attr_list);
    if (status != SAI_STATUS_SUCCESS) {
        return -1;
    }

    bridge_db_info->bridge_h = vlan_id;
    vlan_id++;

    return 0;
}

int
switchlink_bridge_update(switchlink_db_bridge_info_t *bridge_db_info) {
    return 0;
}

int
switchlink_bridge_delete(switchlink_db_bridge_info_t *bridge_db_info) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    int ret = 0;

    status = stp_api->remove_stp(bridge_db_info->stp_h);
    if (status != SAI_STATUS_SUCCESS) {
        ret = -1;
    }

    status = vlan_api->remove_vlan(bridge_db_info->bridge_h);
    if (status != SAI_STATUS_SUCCESS) {
        ret = -1;
    }

    return ret;
}

int
switchlink_lag_create(switchlink_handle_t *lag_h) {
    return -1;
}

int
switchlink_mac_create(switchlink_mac_addr_t mac_addr,
                      switchlink_handle_t bridge_h,
                      switchlink_handle_t intf_h) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    sai_fdb_entry_t fdb_entry;
    memset(&fdb_entry, 0, sizeof(fdb_entry));
    memcpy(fdb_entry.mac_address, mac_addr, sizeof(sai_mac_t));
    fdb_entry.vlan_id = bridge_h;

    sai_attribute_t attr_list[3];
    memset(&attr_list, 0, sizeof(attr_list));
    attr_list[0].id = SAI_FDB_ENTRY_ATTR_TYPE;
    attr_list[0].value.u8 = SAI_FDB_ENTRY_STATIC;
    attr_list[1].id = SAI_FDB_ENTRY_ATTR_PORT_ID;
    attr_list[1].value.oid = intf_h;
    attr_list[2].id = SAI_FDB_ENTRY_ATTR_PACKET_ACTION;
    attr_list[2].value.u8 = SAI_PACKET_ACTION_FORWARD;

    status = fdb_api->create_fdb_entry(&fdb_entry, 3, attr_list);
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int
switchlink_mac_delete(switchlink_mac_addr_t mac_addr,
                      switchlink_handle_t bridge_h) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    sai_fdb_entry_t fdb_entry;
    memset(&fdb_entry, 0, sizeof(fdb_entry));
    memcpy(fdb_entry.mac_address, mac_addr, sizeof(sai_mac_t));
    fdb_entry.vlan_id = bridge_h;

    status = fdb_api->remove_fdb_entry(&fdb_entry);
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int
switchlink_nexthop_create(switchlink_db_neigh_info_t *neigh_info) {
    sai_status_t status = SAI_STATUS_SUCCESS;

    sai_attribute_t attr_list[3];
    memset(attr_list, 0, sizeof(attr_list));
    attr_list[0].id = SAI_NEXT_HOP_ATTR_TYPE;
    attr_list[0].value.u8 = SAI_NEXT_HOP_IP;
    attr_list[1].id = SAI_NEXT_HOP_ATTR_IP;
    if (neigh_info->ip_addr.family == AF_INET) {
        attr_list[1].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        attr_list[1].value.ipaddr.addr.ip4 =
            htonl(neigh_info->ip_addr.ip.v4addr.s_addr);
    } else {
        attr_list[1].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(attr_list[1].value.ipaddr.addr.ip6,
               &(neigh_info->ip_addr.ip.v6addr), sizeof(sai_ip6_t));
    }
    attr_list[2].id = SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID;
    attr_list[2].value.oid = neigh_info->intf_h;
    status = nhop_api->create_next_hop(&(neigh_info->nhop_h), 3, attr_list);
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int
switchlink_nexthop_delete(switchlink_db_neigh_info_t *neigh_info) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    status = nhop_api->remove_next_hop(neigh_info->nhop_h);
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int
switchlink_neighbor_create(switchlink_db_neigh_info_t *neigh_info) {
    sai_status_t status = SAI_STATUS_SUCCESS;

    sai_attribute_t attr_list[1];
    memset(attr_list, 0, sizeof(attr_list));
    attr_list[0].id = SAI_NEIGHBOR_ATTR_DST_MAC_ADDRESS;
    memcpy(attr_list[0].value.mac, neigh_info->mac_addr, sizeof(sai_mac_t));

    sai_neighbor_entry_t neighbor_entry;
    memset(&neighbor_entry, 0, sizeof(neighbor_entry));
    neighbor_entry.rif_id = neigh_info->intf_h;
    if (neigh_info->ip_addr.family == AF_INET) {
        neighbor_entry.ip_address.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        neighbor_entry.ip_address.addr.ip4 =
            htonl(neigh_info->ip_addr.ip.v4addr.s_addr);
    } else {
        assert(neigh_info->ip_addr.family == AF_INET6);
        neighbor_entry.ip_address.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(neighbor_entry.ip_address.addr.ip6,
               &(neigh_info->ip_addr.ip.v6addr), sizeof(sai_ip6_t));
    }

    status = neigh_api->create_neighbor_entry(&neighbor_entry, 1, attr_list);
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int
switchlink_neighbor_delete(switchlink_db_neigh_info_t *neigh_info) {
    sai_status_t status = SAI_STATUS_SUCCESS;

    sai_neighbor_entry_t neighbor_entry;
    memset(&neighbor_entry, 0, sizeof(neighbor_entry));
    neighbor_entry.rif_id = neigh_info->intf_h;
    neighbor_entry.ip_address.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    neighbor_entry.ip_address.addr.ip4 =
        htonl(neigh_info->ip_addr.ip.v4addr.s_addr);

    status = neigh_api->remove_neighbor_entry(&neighbor_entry);
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int
switchlink_ecmp_create(switchlink_db_ecmp_info_t *ecmp_info) {
    sai_status_t status = SAI_STATUS_SUCCESS;

    sai_attribute_t attr_list[3];
    memset(attr_list, 0, sizeof(attr_list));
    attr_list[0].id = SAI_NEXT_HOP_GROUP_ATTR_TYPE;
    attr_list[0].value.u8 = SAI_NEXT_HOP_GROUP_ECMP;
    attr_list[1].id = SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_COUNT;
    attr_list[1].value.u32 = ecmp_info->num_nhops;
    attr_list[2].id = SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_LIST;
    attr_list[2].value.objlist.count = ecmp_info->num_nhops;
    attr_list[2].value.objlist.list = (sai_object_id_t *)ecmp_info->nhops;
    status = nhop_group_api->create_next_hop_group(&(ecmp_info->ecmp_h), 3,
                                                   attr_list);
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int
switchlink_ecmp_delete(switchlink_db_ecmp_info_t *ecmp_info) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    status = nhop_group_api->remove_next_hop_group(ecmp_info->ecmp_h);
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int
switchlink_route_create(switchlink_db_route_info_t *route_info) {
    sai_status_t status = SAI_STATUS_SUCCESS;

    sai_unicast_route_entry_t route_entry;
    memset(&route_entry, 0, sizeof(route_entry));
    route_entry.vr_id = route_info->vrf_h;
    if (route_info->ip_addr.family == AF_INET) {
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        route_entry.destination.addr.ip4 =
            htonl(route_info->ip_addr.ip.v4addr.s_addr);
        route_entry.destination.mask.ip4 =
            htonl(ipv4_prefix_len_to_mask(route_info->ip_addr.prefix_len));
    } else {
        assert(route_info->ip_addr.family == AF_INET6);
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(route_entry.destination.addr.ip6,
               &(route_info->ip_addr.ip.v6addr), sizeof(sai_ip6_t));
        struct in6_addr mask =
            ipv6_prefix_len_to_mask(route_info->ip_addr.prefix_len);
        memcpy(route_entry.destination.mask.ip6, &mask, sizeof(sai_ip6_t));
    }

    sai_attribute_t attr_list[1];
    memset(attr_list, 0, sizeof(attr_list));
    if (route_info->nhop_h == g_cpu_rx_nhop_h) {
        attr_list[0].id = SAI_ROUTE_ATTR_PACKET_ACTION;
        attr_list[0].value.s32 = SAI_PACKET_ACTION_TRAP;
    } else {
        attr_list[0].id = SAI_ROUTE_ATTR_NEXT_HOP_ID;
        attr_list[0].value.oid = route_info->nhop_h;
    }

    status = route_api->create_route(&route_entry, 1, attr_list);
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int
switchlink_route_delete(switchlink_db_route_info_t *route_info) {
    sai_status_t status = SAI_STATUS_SUCCESS;

    sai_unicast_route_entry_t route_entry;
    memset(&route_entry, 0, sizeof(route_entry));
    route_entry.vr_id = route_info->vrf_h;
    if (route_info->ip_addr.family == AF_INET) {
        route_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        route_entry.destination.addr.ip4 =
            htonl(route_info->ip_addr.ip.v4addr.s_addr);
        route_entry.destination.mask.ip4 =
            htonl(ipv4_prefix_len_to_mask(route_info->ip_addr.prefix_len));
    } else {
        assert(route_info->ip_addr.family == AF_INET6);
    }

    status = route_api->remove_route(&route_entry);
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

int
switchlink_send_packet(char *buf, uint32_t buf_size, uint16_t port_id) {
    sai_status_t status = SAI_STATUS_SUCCESS;

    sai_attribute_t attr_list[2];
    memset(attr_list, 0, sizeof(attr_list));
    attr_list[0].id = SAI_HOSTIF_PACKET_TX_TYPE;
    attr_list[0].value.u32 = SAI_HOSTIF_TX_TYPE_PIPELINE_BYPASS;
    attr_list[1].id = SAI_HOSTIF_PACKET_EGRESS_PORT_OR_LAG;
    attr_list[1].value.oid = get_port_object(port_id);

    status = host_intf_api->send_packet(0, buf, buf_size, 2, attr_list);
    return ((status == SAI_STATUS_SUCCESS) ? 0 : -1);
}

void
switchlink_api_init() {
    sai_status_t status = SAI_STATUS_SUCCESS;

    sai_initialize();

    status = sai_api_query(SAI_API_SWITCH, (void **)&switch_api);
    assert(status == SAI_STATUS_SUCCESS);
    status = sai_api_query(SAI_API_VIRTUAL_ROUTER, (void **)&vrf_api);
    assert(status == SAI_STATUS_SUCCESS);
    status = sai_api_query(SAI_API_VLAN, (void **)&vlan_api);
    assert(status == SAI_STATUS_SUCCESS);
    status = sai_api_query(SAI_API_STP, (void **)&stp_api);
    assert(status == SAI_STATUS_SUCCESS);
    status = sai_api_query(SAI_API_FDB, (void **)&fdb_api);
    assert(status == SAI_STATUS_SUCCESS);
    status = sai_api_query(SAI_API_ROUTER_INTERFACE, (void **)&rintf_api);
    assert(status == SAI_STATUS_SUCCESS);
    status = sai_api_query(SAI_API_NEIGHBOR, (void **)&neigh_api);
    assert(status == SAI_STATUS_SUCCESS);
    status = sai_api_query(SAI_API_NEXT_HOP, (void **)&nhop_api);
    assert(status == SAI_STATUS_SUCCESS);
    status = sai_api_query(SAI_API_NEXT_HOP_GROUP, (void **)&nhop_group_api);
    assert(status == SAI_STATUS_SUCCESS);
    status = sai_api_query(SAI_API_ROUTE, (void **)&route_api);
    assert(status == SAI_STATUS_SUCCESS);
    status = sai_api_query(SAI_API_HOST_INTERFACE, (void **)&host_intf_api);
    assert(status == SAI_STATUS_SUCCESS);

    init_packet_handler();
    get_port_list();
}
