# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Thrift SAI interface basic tests
"""

import switch_sai_thrift

import time
import sys
import logging

import unittest
import random

from ptf.testutils import *
from ptf.thriftutils import *

import os

from switch_sai_thrift.ttypes import  *
from switch_sai_thrift.sai_headers import  *

this_dir = os.path.dirname(os.path.abspath(__file__))

switch_inited=0
port_list = []
table_attr_list = []

def sai_thrift_create_fdb(client, vlan_id, mac, port, mac_action):
    fdb_entry = sai_thrift_fdb_entry_t(mac_address=mac, vlan_id=vlan_id)
    #value 0 represents static entry, id=0, represents entry type
    fdb_attribute1_value = sai_thrift_attribute_value_t(u8=SAI_FDB_ENTRY_STATIC)
    fdb_attribute1 = sai_thrift_attribute_t(id=SAI_FDB_ENTRY_ATTR_TYPE,
                                            value=fdb_attribute1_value)
    #value oid represents object id, id=1 represents port id
    fdb_attribute2_value = sai_thrift_attribute_value_t(oid=port)
    fdb_attribute2 = sai_thrift_attribute_t(id=SAI_FDB_ENTRY_ATTR_PORT_ID,
                                            value=fdb_attribute2_value)
    #value oid represents object id, id=1 represents port id
    fdb_attribute3_value = sai_thrift_attribute_value_t(u8=mac_action)
    fdb_attribute3 = sai_thrift_attribute_t(id=SAI_FDB_ENTRY_ATTR_PACKET_ACTION,
                                            value=fdb_attribute3_value)
    fdb_attr_list = [fdb_attribute1, fdb_attribute2, fdb_attribute3]
    client.sai_thrift_create_fdb_entry(thrift_fdb_entry=fdb_entry, thrift_attr_list=fdb_attr_list)

def sai_thrift_delete_fdb(client, vlan_id, mac, port):
    fdb_entry = sai_thrift_fdb_entry_t(mac_address=mac, vlan_id=vlan_id)
    client.sai_thrift_delete_fdb_entry(thrift_fdb_entry=fdb_entry)

def sai_thrift_flush_fdb_by_vlan(client, vlan_id):
    fdb_attribute1_value = sai_thrift_attribute_value_t(u16=vlan_id)
    fdb_attribute1 = sai_thrift_attribute_t(id=SAI_FDB_FLUSH_ATTR_VLAN_ID,
                                            value=fdb_attribute1_value)
    fdb_attribute2_value = sai_thrift_attribute_value_t(u8=SAI_FDB_FLUSH_ENTRY_STATIC)
    fdb_attribute2 = sai_thrift_attribute_t(id=SAI_FDB_FLUSH_ATTR_ENTRY_TYPE,
                                            value=fdb_attribute2_value)
    fdb_attr_list = [fdb_attribute1, fdb_attribute2]
    client.sai_thrift_flush_fdb_entries(thrift_attr_list=fdb_attr_list)

def sai_thrift_create_virtual_router(client, v4_enabled, v6_enabled):
    #v4 enabled
    vr_attribute1_value = sai_thrift_attribute_value_t(booldata=v4_enabled)
    vr_attribute1 = sai_thrift_attribute_t(id=SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE,
                                           value=vr_attribute1_value)
    #v6 enabled
    vr_attribute2_value = sai_thrift_attribute_value_t(booldata=v6_enabled)
    vr_attribute2 = sai_thrift_attribute_t(id=SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE,
                                           value=vr_attribute1_value)
    vr_attr_list = [vr_attribute1, vr_attribute2]
    vr_id = client.sai_thrift_create_virtual_router(thrift_attr_list=vr_attr_list)
    return vr_id

def sai_thrift_create_router_interface(client, vr_id, is_port, port_id, vlan_id, v4_enabled, v6_enabled, mac):
    #vrf attribute
    rif_attr_list = []
    rif_attribute1_value = sai_thrift_attribute_value_t(oid=vr_id)
    rif_attribute1 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID,
                                            value=rif_attribute1_value)
    rif_attr_list.append(rif_attribute1)
    if is_port:
        #port type and port id
        rif_attribute2_value = sai_thrift_attribute_value_t(u8=SAI_ROUTER_INTERFACE_TYPE_PORT)
        rif_attribute2 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_TYPE,
                                                value=rif_attribute2_value)
        rif_attr_list.append(rif_attribute2)
        rif_attribute3_value = sai_thrift_attribute_value_t(oid=port_id)
        rif_attribute3 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_PORT_ID,
                                                value=rif_attribute3_value)
        rif_attr_list.append(rif_attribute3)
    else:
        #vlan type and vlan id
        rif_attribute2_value = sai_thrift_attribute_value_t(u8=SAI_ROUTER_INTERFACE_TYPE_VLAN)
        rif_attribute2 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_TYPE,
                                                value=rif_attribute2_value)
        rif_attr_list.append(rif_attribute2)
        rif_attribute3_value = sai_thrift_attribute_value_t(u16=vlan_id)
        rif_attribute3 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_VLAN_ID,
                                                value=rif_attribute3_value)
        rif_attr_list.append(rif_attribute3)

    #v4_enabled
    rif_attribute4_value = sai_thrift_attribute_value_t(booldata=v4_enabled)
    rif_attribute4 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE,
                                            value=rif_attribute4_value)
    rif_attr_list.append(rif_attribute4)
    #v6_enabled
    rif_attribute5_value = sai_thrift_attribute_value_t(booldata=v6_enabled)
    rif_attribute5 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE,
                                            value=rif_attribute5_value)
    rif_attr_list.append(rif_attribute5)

    if mac:
        rif_attribute6_value = sai_thrift_attribute_value_t(mac=mac)
        rif_attribute6 = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS,
                                                value=rif_attribute6_value)
        rif_attr_list.append(rif_attribute6)

    rif_id = client.sai_thrift_create_router_interface(rif_attr_list)
    return rif_id

def sai_thrift_create_route(client, vr_id, addr_family, ip_addr, ip_mask, nhop):
    if addr_family == SAI_IP_ADDR_FAMILY_IPV4:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        mask = sai_thrift_ip_t(ip4=ip_mask)
        ip_prefix = sai_thrift_ip_prefix_t(addr_family=SAI_IP_ADDR_FAMILY_IPV4, addr=addr, mask=mask)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        mask = sai_thrift_ip_t(ip6=ip_mask)
        ip_prefix = sai_thrift_ip_prefix_t(addr_family=SAI_IP_ADDR_FAMILY_IPV6, addr=addr, mask=mask)
    route_attribute1_value = sai_thrift_attribute_value_t(oid=nhop)
    route_attribute1 = sai_thrift_attribute_t(id=SAI_ROUTE_ATTR_NEXT_HOP_ID,
                                              value=route_attribute1_value)
    route = sai_thrift_unicast_route_entry_t(vr_id, ip_prefix)
    route_attr_list = [route_attribute1]
    client.sai_thrift_create_route(thrift_unicast_route_entry=route, thrift_attr_list=route_attr_list)

def sai_thrift_remove_route(client, vr_id, addr_family, ip_addr, ip_mask, nhop):
    if addr_family == SAI_IP_ADDR_FAMILY_IPV4:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        mask = sai_thrift_ip_t(ip4=ip_mask)
        ip_prefix = sai_thrift_ip_prefix_t(addr_family=SAI_IP_ADDR_FAMILY_IPV4, addr=addr, mask=mask)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        mask = sai_thrift_ip_t(ip6=ip_mask)
        ip_prefix = sai_thrift_ip_prefix_t(addr_family=SAI_IP_ADDR_FAMILY_IPV6, addr=addr, mask=mask)
    route = sai_thrift_unicast_route_entry_t(vr_id, ip_prefix)
    client.sai_thrift_remove_route(thrift_unicast_route_entry=route)

def sai_thrift_create_nhop(client, addr_family, ip_addr, rif_id):
    if addr_family == SAI_IP_ADDR_FAMILY_IPV4:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=SAI_IP_ADDR_FAMILY_IPV4, addr=addr)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=SAI_IP_ADDR_FAMILY_IPV6, addr=addr)
    nhop_attribute1_value = sai_thrift_attribute_value_t(ipaddr=ipaddr)
    nhop_attribute1 = sai_thrift_attribute_t(id=SAI_NEXT_HOP_ATTR_IP,
                                             value=nhop_attribute1_value)
    nhop_attribute2_value = sai_thrift_attribute_value_t(oid=rif_id)
    nhop_attribute2 = sai_thrift_attribute_t(id=SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID,
                                             value=nhop_attribute2_value)
    nhop_attr_list = [nhop_attribute1, nhop_attribute2]
    nhop = client.sai_thrift_create_next_hop(thrift_attr_list=nhop_attr_list)
    return nhop

def sai_thrift_create_neighbor(client, addr_family, rif_id, ip_addr, dmac):
    if addr_family == SAI_IP_ADDR_FAMILY_IPV4:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=SAI_IP_ADDR_FAMILY_IPV4, addr=addr)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=SAI_IP_ADDR_FAMILY_IPV6, addr=addr)
    neighbor_attribute1_value = sai_thrift_attribute_value_t(mac=dmac)
    neighbor_attribute1 = sai_thrift_attribute_t(id=SAI_NEIGHBOR_ATTR_DST_MAC_ADDRESS,
                                                 value=neighbor_attribute1_value)
    neighbor_attr_list = [neighbor_attribute1]
    neighbor_entry = sai_thrift_neighbor_entry_t(rif_id=rif_id, ip_address=ipaddr)
    client.sai_thrift_create_neighbor_entry(neighbor_entry, neighbor_attr_list)

def sai_thrift_remove_neighbor(client, addr_family, rif_id, ip_addr, dmac):
    if addr_family == SAI_IP_ADDR_FAMILY_IPV4:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=SAI_IP_ADDR_FAMILY_IPV4, addr=addr)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        ipaddr = sai_thrift_ip_address_t(addr_family=SAI_IP_ADDR_FAMILY_IPV4, addr=addr)
    neighbor_entry = sai_thrift_neighbor_entry_t(rif_id=rif_id, ip_address=ipaddr)
    client.sai_thrift_remove_neighbor_entry(neighbor_entry)

def sai_thrift_create_next_hop_group(client, nhop_list):
    nhop_group_attribute1_value = sai_thrift_attribute_value_t(u8=SAI_NEXT_HOP_GROUP_ECMP)
    nhop_group_attribute1 = sai_thrift_attribute_t(id=SAI_NEXT_HOP_GROUP_ATTR_TYPE,
                                                   value=nhop_group_attribute1_value)
    nhop_objlist = sai_thrift_object_list_t(count=len(nhop_list), object_id_list=nhop_list)
    nhop_group_attribute2_value = sai_thrift_attribute_value_t(objlist=nhop_objlist)
    nhop_group_attribute2 = sai_thrift_attribute_t(id=SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_LIST,
                                                   value=nhop_group_attribute2_value)
    nhop_group_attr_list = [nhop_group_attribute1, nhop_group_attribute2]
    nhop_group = client.sai_thrift_create_next_hop_group(thrift_attr_list=nhop_group_attr_list)
    return nhop_group

def sai_thrift_create_lag_member(client, lag_id,  port_id, ingress_disable=False, egress_disable=False):
    attr_list = []
    attribute_value = sai_thrift_attribute_value_t(oid=lag_id)
    attribute = sai_thrift_attribute_t(id=SAI_LAG_MEMBER_ATTR_LAG_ID,
                                       value=attribute_value)
    attr_list.append(attribute)

    attribute_value = sai_thrift_attribute_value_t(oid=port_id)
    attribute = sai_thrift_attribute_t(id=SAI_LAG_MEMBER_ATTR_PORT_ID,
                                       value=attribute_value)
    attr_list.append(attribute)

    attribute_value = sai_thrift_attribute_value_t(booldata=ingress_disable)
    attribute = sai_thrift_attribute_t(id=SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE,
                                       value=attribute_value)
    attr_list.append(attribute)

    attribute_value = sai_thrift_attribute_value_t(booldata=egress_disable)
    attribute = sai_thrift_attribute_t(id=SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE,
                                       value=attribute_value)
    attr_list.append(attribute)

    lag_member = client.sai_thrift_create_lag_member(attr_list)
    return lag_member

def sai_thrift_create_stp_entry(client, vlan_list):
    vlanlist=sai_thrift_vlan_list_t(vlan_count=len(vlan_list), vlan_list=vlan_list)
    stp_attribute1_value = sai_thrift_attribute_value_t(vlanlist=vlanlist)
    stp_attribute1 = sai_thrift_attribute_t(id=SAI_STP_ATTR_VLAN_LIST,
                                            value=stp_attribute1_value)
    stp_attr_list = [stp_attribute1]
    stp_id = client.sai_thrift_create_stp_entry(stp_attr_list)
    return stp_id

def sai_thrift_create_hostif_trap_group(client, queue_id, priority):
    attribute1_value = sai_thrift_attribute_value_t(u32=priority)
    attribute1 = sai_thrift_attribute_t(id=SAI_HOSTIF_TRAP_GROUP_ATTR_PRIO,
                                        value=attribute1_value)
    attribute2_value = sai_thrift_attribute_value_t(u32=queue_id)
    attribute2 = sai_thrift_attribute_t(id=SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE,
                                        value=attribute2_value)
    attr_list = [attribute1, attribute2]
    trap_group_id = client.sai_thrift_create_hostif_trap_group(thrift_attr_list=attr_list)
    return trap_group_id

def sai_thrift_create_hostif_trap(client, trap_id, action, priority, channel, trap_group_id):
    attribute3_value = sai_thrift_attribute_value_t(u32=channel)
    attribute3 = sai_thrift_attribute_t(id=SAI_HOSTIF_TRAP_ATTR_TRAP_CHANNEL,
                                        value=attribute3_value)
    client.sai_thrift_set_hostif_trap(trap_id, attribute3)
    attribute4_value = sai_thrift_attribute_value_t(oid=trap_group_id)
    attribute4 = sai_thrift_attribute_t(id=SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP,
                                        value=attribute4_value)
    client.sai_thrift_set_hostif_trap(trap_id, attribute4)
    attribute1_value = sai_thrift_attribute_value_t(u32=action)
    attribute1 = sai_thrift_attribute_t(id=SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION,
                                        value=attribute1_value)
    client.sai_thrift_set_hostif_trap(trap_id, attribute1)
    attribute2_value = sai_thrift_attribute_value_t(u32=priority)
    attribute2 = sai_thrift_attribute_t(id=SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY,
                                        value=attribute2_value)
    client.sai_thrift_set_hostif_trap(trap_id, attribute2)

def sai_thrift_create_hostif(client, rif_or_port_id, intf_name):
    attribute1_value = sai_thrift_attribute_value_t(u32=SAI_HOSTIF_TYPE_NETDEV)
    attribute1 = sai_thrift_attribute_t(id=SAI_HOSTIF_ATTR_TYPE,
                                        value=attribute1_value)
    attribute2_value = sai_thrift_attribute_value_t(oid=rif_or_port_id)
    attribute2 = sai_thrift_attribute_t(id=SAI_HOSTIF_ATTR_RIF_OR_PORT_ID,
                                        value=attribute2_value)
    attribute3_value = sai_thrift_attribute_value_t(chardata=intf_name)
    attribute3 = sai_thrift_attribute_t(id=SAI_HOSTIF_ATTR_NAME,
                                        value=attribute3_value)
    attr_list = [attribute1, attribute2, attribute3]
    hif_id = client.sai_thrift_create_hostif(attr_list)
    return hif_id

def sai_thrift_create_acl_table(client,
                                addr_family = False,
                                ip_src = False,
                                ip_dst = False,
                                ip_proto = False,
                                in_ports = False,
                                out_ports = False,
                                in_port = False,
                                out_port = False):
    acl_attr_list = []
    if ip_src:
        attribute_value = sai_thrift_attribute_value_t(booldata=1)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
                                           value=attribute_value)
        acl_attr_list.append(attribute)
    if ip_dst:
        attribute_value = sai_thrift_attribute_value_t(booldata=1)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
                                           value=attribute_value)
        acl_attr_list.append(attribute)
    if ip_proto:
        attribute_value = sai_thrift_attribute_value_t(booldata=1)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
                                           value=attribute_value)
        acl_attr_list.append(attribute)
    if in_ports:
        attribute_value = sai_thrift_attribute_value_t(booldata=1)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_TABLE_ATTR_FIELD_IN_PORTS,
                                           value=attribute_value)
        acl_attr_list.append(attribute)
    if out_ports:
        attribute_value = sai_thrift_attribute_value_t(booldata=1)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_TABLE_ATTR_FIELD_OUT_PORTS,
                                           value=attribute_value)
        acl_attr_list.append(attribute)
    if in_port:
        attribute_value = sai_thrift_attribute_value_t(booldata=1)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_TABLE_ATTR_FIELD_IN_PORT,
                                           value=attribute_value)
        acl_attr_list.append(attribute)
    if out_port:
        attribute_value = sai_thrift_attribute_value_t(booldata=1)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_TABLE_ATTR_FIELD_OUT_PORT,
                                           value=attribute_value)
        acl_attr_list.append(attribute)

    acl_table_id = client.sai_thrift_create_acl_table(acl_attr_list)
    return acl_table_id

def sai_thrift_create_acl_entry(client, acl_table_id,
                                action_list = None,
                                addr_family = None,
                                ip_src = None,
                                ip_src_mask = None,
                                ip_dst = None,
                                ip_dst_mask = None,
                                ip_proto = None,
                                in_ports = None,
                                out_ports = None,
                                in_port = None,
                                out_port = None,
                                packet_action = None,
                                ingress_mirror_id = None,
                                egress_mirror_id = None,
                                acl_counter_id = None,
                                policer_id = None):
    acl_attr_list = []

    #OID
    attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(oid=acl_table_id)))
    attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_TABLE_ID,
                                       value=attribute_value)
    acl_attr_list.append(attribute)

    #Priority
    attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(u32=10)))
    attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_PRIORITY,
                                       value=attribute_value)
    acl_attr_list.append(attribute)

    #Ip source
    if ip_src != None:
        attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(ip4=ip_src), mask =sai_thrift_acl_mask_t(ip4=ip_src_mask)))
        attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP,
                                           value=attribute_value)
        acl_attr_list.append(attribute)

    if ip_dst != None:
        attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(ip4=ip_dst), mask =sai_thrift_acl_mask_t(ip4=ip_dst_mask)))
        attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_FIELD_DST_IP,
                                           value=attribute_value)
        acl_attr_list.append(attribute)

    #Input ports

    #Input ports
    if in_ports:
        acl_port_list = sai_thrift_object_list_t(count=len(in_ports), object_id_list=in_ports)
        attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(objlist=acl_port_list)))
        attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS,
                                           value=attribute_value)
        acl_attr_list.append(attribute)

    #Output ports
    if out_ports:
        acl_port_list = sai_thrift_object_list_t(count=len(out_ports), object_id_list=out_ports)
        attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(objlist=acl_port_list)))
        attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS,
                                           value=attribute_value)
        acl_attr_list.append(attribute)

    if in_port != None:
        attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(oid=in_port)))
        attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT,
                                           value=attribute_value)
        acl_attr_list.append(attribute)

    if out_port != None:
        attribute_value = sai_thrift_attribute_value_t(aclfield=sai_thrift_acl_field_data_t(data = sai_thrift_acl_data_t(oid=out_port)))
        attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT,
                                           value=attribute_value)
        acl_attr_list.append(attribute)

    #Packet action
    for action in action_list:
        if action == SAI_ACL_ENTRY_ATTR_PACKET_ACTION:
            #Drop
            attribute_value = sai_thrift_attribute_value_t(
                             aclfield = sai_thrift_acl_field_data_t(
                             data = sai_thrift_acl_data_t(u8 = packet_action)))
            attribute = sai_thrift_attribute_t(
                             id = SAI_ACL_ENTRY_ATTR_PACKET_ACTION,
                             value=attribute_value)
            acl_attr_list.append(attribute)

        elif action == SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS:
            #Ingress mirroring
            attribute_value = sai_thrift_attribute_value_t(
                             aclfield = sai_thrift_acl_field_data_t(
                             data = sai_thrift_acl_data_t(oid = ingress_mirror_id)))
            attribute = sai_thrift_attribute_t(
                             id = SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS,
                             value = attribute_value)
            acl_attr_list.append(attribute)

        elif action == SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS:
            #Egress mirroring
            attribute_value = sai_thrift_attribute_value_t(
                             aclfield = sai_thrift_acl_field_data_t(
                             data = sai_thrift_acl_data_t(oid = egress_mirror_id)))
            attribute = sai_thrift_attribute_t(
                             id = SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS,
                             value = attribute_value)
            acl_attr_list.append(attribute)
        elif action == SAI_ACL_ENTRY_ATTR_ACTION_COUNTER:
            attribute_value = sai_thrift_attribute_value_t(
                             aclfield = sai_thrift_acl_field_data_t(
                             data = sai_thrift_acl_data_t(oid = acl_counter_id)))
            attribute = sai_thrift_attribute_t(
                             id = SAI_ACL_ENTRY_ATTR_ACTION_COUNTER,
                             value = attribute_value)
            acl_attr_list.append(attribute)
        elif action == SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER:
            attribute_value = sai_thrift_attribute_value_t(
                             aclfield = sai_thrift_acl_field_data_t(
                             data = sai_thrift_acl_data_t(oid = policer_id)))
            attribute = sai_thrift_attribute_t(
                             id = SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER,
                             value = attribute_value)
            acl_attr_list.append(attribute)

    acl_entry_id = client.sai_thrift_create_acl_entry(acl_attr_list)
    return acl_entry_id

def sai_thrift_create_acl_counter(client, acl_table_id, packet_enable = True, byte_enable = True):
    attr_list = []

    attribute1_value = sai_thrift_attribute_value_t(oid=acl_table_id)
    attribute1 = sai_thrift_attribute_t(
                             id=SAI_ACL_COUNTER_ATTR_TABLE_ID,
                             value=attribute1_value)
    attr_list.append(attribute1)

    attribute2_value = sai_thrift_attribute_value_t(booldata=True)
    attribute2 = sai_thrift_attribute_t(
                             id=SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT,
                             value=attribute2_value)
    attr_list.append(attribute2)

    attribute3_value = sai_thrift_attribute_value_t(booldata=True)
    attribute3 = sai_thrift_attribute_t(
                            id=SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT,
                             value=attribute3_value)
    attr_list.append(attribute3)

    acl_counter_id = client.sai_thrift_create_acl_counter(attr_list)
    return acl_counter_id

def sai_thrift_create_mirror_session(client, mirror_type, port,
                                     vlan, vlan_priority, vlan_tpid,
                                     src_mac, dst_mac,
                                     addr_family, src_ip, dst_ip,
                                     encap_type, protocol, ttl, tos):
    mirror_attr_list = []

    #Mirror type
    attribute1_value = sai_thrift_attribute_value_t(u8=mirror_type)
    attribute1 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_TYPE,
                                        value=attribute1_value)
    mirror_attr_list.append(attribute1)

    #Monitor port
    attribute2_value = sai_thrift_attribute_value_t(oid=port)
    attribute2 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_MONITOR_PORT,
                                        value=attribute2_value)
    mirror_attr_list.append(attribute2)

    if mirror_type == SAI_MIRROR_TYPE_LOCAL:
        attribute4_value = sai_thrift_attribute_value_t(u16=vlan)
        attribute4 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_VLAN_ID,
                                            value=attribute4_value)
        mirror_attr_list.append(attribute4)
    elif mirror_type == SAI_MIRROR_TYPE_REMOTE:
        #vlan tpid
        attribute3_value = sai_thrift_attribute_value_t(u16=vlan_tpid)
        attribute3 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_VLAN_TPID,
                                            value=attribute3_value)
        mirror_attr_list.append(attribute3)

        #vlan
        attribute4_value = sai_thrift_attribute_value_t(u16=vlan)
        attribute4 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_VLAN_ID,
                                            value=attribute4_value)
        mirror_attr_list.append(attribute4)

        #vlan priority
        attribute5_value = sai_thrift_attribute_value_t(u16=vlan_priority)
        attribute4 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_VLAN_PRI,
                                            value=attribute5_value)
        mirror_attr_list.append(attribute5)
    elif mirror_type == SAI_MIRROR_TYPE_ENHANCED_REMOTE:
        #encap type
        attribute3_value = sai_thrift_attribute_value_t(u8=encap_type)
        attribute3 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_ENCAP_TYPE,
                                            value=attribute3_value)
        mirror_attr_list.append(attribute3)

        #source ip
        addr = sai_thrift_ip_t(ip4=src_ip)
        src_ip_addr = sai_thrift_ip_address_t(addr_family=addr_family, addr=addr)
        attribute4_value = sai_thrift_attribute_value_t(ipaddr=src_ip_addr)
        attribute4 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS,
                                            value=attribute4_value)
        mirror_attr_list.append(attribute4)

        #dst ip
        addr = sai_thrift_ip_t(ip4=dst_ip)
        dst_ip_addr = sai_thrift_ip_address_t(addr_family=addr_family, addr=addr)
        attribute5_value = sai_thrift_attribute_value_t(ipaddr=dst_ip_addr)
        attribute5 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS,
                                            value=attribute5_value)
        mirror_attr_list.append(attribute5)

        #source mac
        attribute6_value = sai_thrift_attribute_value_t(mac=src_mac)
        attribute6 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS,
                                            value=attribute6_value)
        mirror_attr_list.append(attribute6)

        #dst mac
        attribute7_value = sai_thrift_attribute_value_t(mac=dst_mac)
        attribute7 = sai_thrift_attribute_t(id=SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS,
                                            value=attribute7_value)
        mirror_attr_list.append(attribute7)

    mirror_id = client.sai_thrift_create_mirror_session(mirror_attr_list)
    return mirror_id

def sai_thrift_get_vlan_stats(client, vlan_id, ingress=True, egress=True):
    counter_ids = []
    if ingress:
        counter_ids.append(SAI_VLAN_STAT_IN_OCTETS)
        counter_ids.append(SAI_VLAN_STAT_IN_UCAST_PKTS)
        counter_ids.append(SAI_VLAN_STAT_IN_NON_UCAST_PKTS)
        counter_ids.append(SAI_VLAN_STAT_IN_DISCARDS)
        counter_ids.append(SAI_VLAN_STAT_IN_ERRORS)
        counter_ids.append(SAI_VLAN_STAT_IN_UNKNOWN_PROTOS)
    if egress:
        counter_ids.append(SAI_VLAN_STAT_OUT_OCTETS)
        counter_ids.append(SAI_VLAN_STAT_OUT_UCAST_PKTS)
        counter_ids.append(SAI_VLAN_STAT_OUT_NON_UCAST_PKTS)
        counter_ids.append(SAI_VLAN_STAT_OUT_DISCARDS)
        counter_ids.append(SAI_VLAN_STAT_OUT_ERRORS)
        counter_ids.append(SAI_VLAN_STAT_OUT_QLEN)

    number_of_counters = len(counter_ids)
    counters = client.sai_thrift_get_vlan_stats(
                             vlan_id,
                             counter_ids,
                             number_of_counters)
    return counter_ids, counters

def sai_thrift_print_vlan_stats(counter_ids, counter):
    if SAI_VLAN_STAT_IN_OCTETS in counter_ids:
        print "In octets: ", counter[SAI_VLAN_STAT_IN_OCTETS]
    if SAI_VLAN_STAT_IN_UCAST_PKTS in counter_ids:
        print "In ucast pkts: ", counter[SAI_VLAN_STAT_IN_UCAST_PKTS]
    if SAI_VLAN_STAT_IN_NON_UCAST_PKTS in counter_ids:
        print "In non ucast pkts: ", counter[SAI_VLAN_STAT_IN_NON_UCAST_PKTS]
    if SAI_VLAN_STAT_IN_DISCARDS in counter_ids:
        print "In discards: ", counter[SAI_VLAN_STAT_IN_DISCARDS]
    if SAI_VLAN_STAT_IN_ERRORS in counter_ids:
        print "In errors: ", counter[SAI_VLAN_STAT_IN_ERRORS]
    if SAI_VLAN_STAT_IN_UNKNOWN_PROTOS in counter_ids:
        print "In unknown protos: ", counter[SAI_VLAN_STAT_IN_UNKNOWN_PROTOS]

    if SAI_VLAN_STAT_OUT_OCTETS in counter_ids:
        print "Out octets: ", counter[SAI_VLAN_STAT_OUT_OCTETS]
    if SAI_VLAN_STAT_OUT_UCAST_PKTS in counter_ids:
        print "Out ucast pkts: ", counter[SAI_VLAN_STAT_OUT_UCAST_PKTS]
    if SAI_VLAN_STAT_OUT_NON_UCAST_PKTS in counter_ids:
        print "Out non ucast pkts: ", counter[SAI_VLAN_STAT_OUT_NON_UCAST_PKTS]
    if SAI_VLAN_STAT_OUT_DISCARDS in counter_ids:
        print "Out discards: ", counter[SAI_VLAN_STAT_OUT_DISCARDS]
    if SAI_VLAN_STAT_OUT_ERRORS in counter_ids:
        print "Out errors: ", counter[SAI_VLAN_STAT_OUT_ERRORS]
    if SAI_VLAN_STAT_OUT_QLEN in counter_ids:
        print "Out qlen: ", counter[SAI_VLAN_STAT_OUT_QLEN]

def sai_thrift_get_acl_counter_attribute(client, acl_counter_id):
    attr_list = []

    attribute_id1 = SAI_ACL_COUNTER_ATTR_PACKETS
    attr_list.append(attribute_id1)

    attribute_id2 = SAI_ACL_COUNTER_ATTR_BYTES
    attr_list.append(attribute_id2)

    attr_values = client.sai_thrift_get_acl_counter_attribute(
                             acl_counter_id,
                             attr_list)
    return attr_values

def sai_thrift_create_policer(
        client,
        meter_type = SAI_METER_TYPE_BYTES,
        meter_mode = SAI_POLICER_MODE_Tr_TCM,
        color_source = SAI_POLICER_COLOR_SOURCE_BLIND,
        cbs = 0,
        cir = 0,
        pbs = 0,
        pir = 0,
        green_action = SAI_PACKET_ACTION_FORWARD,
        yellow_action = SAI_PACKET_ACTION_FORWARD,
        red_action = SAI_PACKET_ACTION_FORWARD):

    attr_list = []

    attribute1_value = sai_thrift_attribute_value_t(u8=meter_type)
    attribute1 = sai_thrift_attribute_t(id=SAI_POLICER_ATTR_METER_TYPE,
                                        value=attribute1_value)
    attr_list.append(attribute1)

    attribute2_value = sai_thrift_attribute_value_t(u8=meter_mode)
    attribute2 = sai_thrift_attribute_t(id=SAI_POLICER_ATTR_MODE,
                                        value=attribute2_value)
    attr_list.append(attribute2)

    attribute3_value = sai_thrift_attribute_value_t(u8=color_source)
    attribute3 = sai_thrift_attribute_t(id=SAI_POLICER_ATTR_COLOR_SOURCE,
                                        value=attribute3_value)
    attr_list.append(attribute3)

    attribute4_value = sai_thrift_attribute_value_t(u64=cbs)
    attribute4 = sai_thrift_attribute_t(id=SAI_POLICER_ATTR_CBS,
                                        value=attribute4_value)
    attr_list.append(attribute4)

    attribute5_value = sai_thrift_attribute_value_t(u64=cir)
    attribute5 = sai_thrift_attribute_t(id=SAI_POLICER_ATTR_CIR,
                                        value=attribute5_value)
    attr_list.append(attribute5)

    attribute6_value = sai_thrift_attribute_value_t(u64=pbs)
    attribute6 = sai_thrift_attribute_t(id=SAI_POLICER_ATTR_PBS,
                                        value=attribute6_value)
    attr_list.append(attribute6)

    attribute7_value = sai_thrift_attribute_value_t(u64=pir)
    attribute7 = sai_thrift_attribute_t(id=SAI_POLICER_ATTR_PIR,
                                        value=attribute7_value)
    attr_list.append(attribute7)

    attribute8_value = sai_thrift_attribute_value_t(u8=green_action)
    attribute8 = sai_thrift_attribute_t(id=SAI_POLICER_ATTR_GREEN_PACKET_ACTION,
                                        value=attribute8_value)
    attr_list.append(attribute8)

    attribute9_value = sai_thrift_attribute_value_t(u8=yellow_action)
    attribute9 = sai_thrift_attribute_t(id=SAI_POLICER_ATTR_YELLOW_PACKET_ACTION,
                                        value=attribute9_value)
    attr_list.append(attribute9)

    attribute10_value = sai_thrift_attribute_value_t(u8=red_action)
    attribute10 = sai_thrift_attribute_t(id=SAI_POLICER_ATTR_RED_PACKET_ACTION,
                                        value=attribute10_value)
    attr_list.append(attribute10)

    policer_id = client.sai_thrift_create_policer(attr_list)
    return policer_id

def sai_thrift_get_policer_stats(client, policer_id):
    attr_list = []

    attr_list.append(SAI_POLICER_STAT_PACKETS)
    attr_list.append(SAI_POLICER_STAT_ATTR_BYTES)
    attr_list.append(SAI_POLICER_STAT_GREEN_PACKETS)
    attr_list.append(SAI_POLICER_STAT_GREEN_BYTES)
    attr_list.append(SAI_POLICER_STAT_YELLOW_PACKETS)
    attr_list.append(SAI_POLICER_STAT_YELLOW_BYTES)
    attr_list.append(SAI_POLICER_STAT_RED_PACKETS)
    attr_list.append(SAI_POLICER_STAT_RED_BYTES)

    attr_value_list = client.sai_thrift_get_policer_stats(policer_id, attr_list)
    return attr_value_list
