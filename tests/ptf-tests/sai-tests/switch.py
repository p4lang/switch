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

import sai_base_test

from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *

import os

from switch_sai_thrift.ttypes import  *
from switch_sai_thrift.sai_headers import  *

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(this_dir, '..'))
from common.utils import *
from common.sai_utils import *

from erspan3 import *

this_dir = os.path.dirname(os.path.abspath(__file__))

cpu_port=64
switch_inited=0
port_list = []
table_attr_list = []

is_bmv2 = ('BMV2_TEST' in os.environ) and (int(os.environ['BMV2_TEST']) == 1)

def switch_init(client):
    global switch_inited
    if switch_inited:
        return

    switch_attr_list = client.sai_thrift_get_switch_attribute()
    attr_list = switch_attr_list.attr_list
    for attribute in attr_list:
        if attribute.id == 0:
            print "max ports: " + attribute.value.u32
        elif attribute.id == 1:
            for x in attribute.value.objlist.object_id_list:
                port_list.append(x)
        else:
            print "unknown switch attribute"

    attr_value = sai_thrift_attribute_value_t(mac='00:77:66:55:44:33')
    attr = sai_thrift_attribute_t(id=SAI_SWITCH_ATTR_SRC_MAC_ADDRESS, value=attr_value)
    client.sai_thrift_set_switch_attribute(attr)
    switch_inited = 1

class L2AccessToAccessVlanTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet port 1 -> port 2 [access vlan=10])"
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = SAI_PACKET_ACTION_FORWARD

        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_member1 = sai_thrift_create_vlan_member(self.client, vlan_id, port1, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member2 = sai_thrift_create_vlan_member(self.client, vlan_id, port2, SAI_VLAN_TAGGING_MODE_UNTAGGED)

        sai_thrift_create_fdb(self.client, vlan_id, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port2, mac_action)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=101,
                                ip_ttl=64)

        try:
            send_packet(self, 2, str(pkt))
            verify_packets(self, pkt, [1])
        finally:
            sai_thrift_delete_fdb(self.client, vlan_id, mac1, port1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port2)

            self.client.sai_thrift_remove_vlan_member(vlan_member1)
            self.client.sai_thrift_remove_vlan_member(vlan_member2)
            self.client.sai_thrift_delete_vlan(vlan_id)

class L2TrunkToTrunkVlanTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet - port 1 -> port 2 [trunk vlan=10])"
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = SAI_PACKET_ACTION_FORWARD

        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_member1 = sai_thrift_create_vlan_member(self.client, vlan_id, port1, SAI_VLAN_TAGGING_MODE_TAGGED)
        vlan_member2 = sai_thrift_create_vlan_member(self.client, vlan_id, port2, SAI_VLAN_TAGGING_MODE_TAGGED)

        sai_thrift_create_fdb(self.client, vlan_id, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port2, mac_action)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                dl_vlan_enable=True,
                                vlan_vid=10,
                                ip_dst='10.0.0.1',
                                ip_id=102,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=102,
                                dl_vlan_enable=True,
                                vlan_vid=10,
                                ip_ttl=64)

        try:
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_delete_fdb(self.client, vlan_id, mac1, port1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port2)

            self.client.sai_thrift_remove_vlan_member(vlan_member1)
            self.client.sai_thrift_remove_vlan_member(vlan_member2)
            self.client.sai_thrift_delete_vlan(vlan_id)

class L2AccessToTrunkVlanTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet - port 1 -> port 2 [trunk vlan=10])"
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = SAI_PACKET_ACTION_FORWARD

        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_member1 = sai_thrift_create_vlan_member(self.client, vlan_id, port1, SAI_VLAN_TAGGING_MODE_TAGGED)
        vlan_member2 = sai_thrift_create_vlan_member(self.client, vlan_id, port2, SAI_VLAN_TAGGING_MODE_UNTAGGED)

        sai_thrift_create_fdb(self.client, vlan_id, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port2, mac_action)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=102,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                dl_vlan_enable=True,
                                vlan_vid=10,
                                ip_id=102,
                                ip_ttl=64,
                                pktlen=104)
        try:
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_delete_fdb(self.client, vlan_id, mac1, port1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port2)

            self.client.sai_thrift_remove_vlan_member(vlan_member1)
            self.client.sai_thrift_remove_vlan_member(vlan_member2)
            self.client.sai_thrift_delete_vlan(vlan_id)

class L2TrunkToAccessVlanTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet - port 1 -> port 2 [trunk vlan=10])"
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = SAI_PACKET_ACTION_FORWARD

        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_member1 = sai_thrift_create_vlan_member(self.client, vlan_id, port1, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member2 = sai_thrift_create_vlan_member(self.client, vlan_id, port2, SAI_VLAN_TAGGING_MODE_TAGGED)

        sai_thrift_create_fdb(self.client, vlan_id, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port2, mac_action)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                dl_vlan_enable=True,
                                vlan_vid=10,
                                ip_dst='10.0.0.1',
                                ip_id=102,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=102,
                                ip_ttl=64,
                                pktlen=96)
        try:
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_delete_fdb(self.client, vlan_id, mac1, port1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port2)

            self.client.sai_thrift_remove_vlan_member(vlan_member1)
            self.client.sai_thrift_remove_vlan_member(vlan_member2)
            self.client.sai_thrift_delete_vlan(vlan_id)

class L2StpTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet - port 1 -> port 2 [trunk vlan=10])"
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        vlan_list = [vlan_id]
        mac_action = SAI_PACKET_ACTION_FORWARD

        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_member1 = sai_thrift_create_vlan_member(self.client, vlan_id, port1, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member2 = sai_thrift_create_vlan_member(self.client, vlan_id, port2, SAI_VLAN_TAGGING_MODE_UNTAGGED)

        stp_id = sai_thrift_create_stp(self.client, vlan_list)
        stp_port_id1 = sai_thrift_create_stp_port(self.client, stp_id, port1, SAI_PORT_STP_STATE_FORWARDING)
        stp_port_id2 = sai_thrift_create_stp_port(self.client, stp_id, port2, SAI_PORT_STP_STATE_FORWARDING)

        sai_thrift_create_fdb(self.client, vlan_id, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port2, mac_action)

        try:
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=113,
                                ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=113,
                                ip_ttl=64)
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [1])

            stp_port_id2 = sai_thrift_create_stp_port(self.client, stp_id, port2, SAI_PORT_STP_STATE_FORWARDING)
            stp_port_id2 = sai_thrift_create_stp_port(self.client, stp_id, port2, SAI_PORT_STP_STATE_BLOCKING)

            print "Sending packet port 1 (blocked) -> port 2 (192.168.0.1 -> 10.0.0.1 [id = 101])"
            pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.0.0.1',
                                    ip_id=113,
                                    ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.0.0.1',
                                    ip_id=113,
                                    ip_ttl=64)
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [])
        finally:
            sai_thrift_delete_fdb(self.client, vlan_id, mac1, port1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port2)

            self.client.sai_thrift_remove_stp_port(stp_port_id1)
            self.client.sai_thrift_remove_stp_port(stp_port_id2)
            self.client.sai_thrift_remove_stp(stp_id)

            self.client.sai_thrift_remove_vlan_member(vlan_member1)
            self.client.sai_thrift_remove_vlan_member(vlan_member2)
            self.client.sai_thrift_delete_vlan(vlan_id)

class L3IPv4HostTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 2 -> port 1 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac_valid = 0
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=63)
        try:
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv4LpmTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.0'
        dmac1 = '00:11:22:33:44:55'
        nhop_ip1 = '20.20.20.1'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=63)
        try:
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv6HostTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (2000::1 -> 3000::1)"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV6
        ip_addr1 = '1234:5678:9abc:def0:4422:1133:5577:99aa'
        ip_mask1 = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        dmac1 = '00:11:22:33:44:55'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        # send the test packet(s)
        pkt = simple_tcpv6_packet( eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ipv6_dst='1234:5678:9abc:def0:4422:1133:5577:99aa',
                                ipv6_src='2000::1',
                                ipv6_hlim=64)
        exp_pkt = simple_tcpv6_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ipv6_dst='1234:5678:9abc:def0:4422:1133:5577:99aa',
                                ipv6_src='2000::1',
                                ipv6_hlim=63)
        try:
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv6LpmTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "IPv6 Lpm Test"
        print "Sending packet port 2 -> port 1 (2000::1 -> 1234:5678:9abc:def0:4422:1133:5577:9900, routing with 1234:5678:9abc:def0:4422:1133:5577:9900/120 route"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV6
        ip_addr1 = '0034:5678:9abc:def0:4422:1133:5577:9900'
        ip_mask1 = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00'
        dmac1 = '00:11:22:33:44:55'
        nhop_ip1 = '3000::1'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)

        # send the test packet(s)
        pkt = simple_tcpv6_packet( eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ipv6_dst='0034:5678:9abc:def0:4422:1133:5577:99aa',
                                ipv6_src='2000::1',
                                ipv6_hlim=64)
        exp_pkt = simple_tcpv6_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ipv6_dst='0034:5678:9abc:def0:4422:1133:5577:99aa',
                                ipv6_src='2000::1',
                                ipv6_hlim=63)
        try:
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv4EcmpHostTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)
        rif_id3 = sai_thrift_create_router_interface(self.client, vr_id, 1, port3, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        dmac2 = '00:11:22:33:44:56'

        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        nhop2 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id2)
        nhop_group1 = sai_thrift_create_next_hop_group(self.client)
        nhop_member1 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop1)
        nhop_member2 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop2)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id2, ip_addr1, dmac2)

        # send the test packet(s)
        try:
            pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=106,
                                ip_ttl=64)

            exp_pkt1 = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=106,
                                #ip_tos=3,
                                ip_ttl=63)
            exp_pkt2 = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:56',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=106,
                                #ip_tos=3,
                                ip_ttl=63)

            send_packet(self, 3, str(pkt))
            verify_any_packet_any_port(self, [exp_pkt1, exp_pkt2], [1, 2])

            pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_src='192.168.100.3',
                                    ip_id=106,
                                    ip_ttl=64)

            exp_pkt1 = simple_tcp_packet(
                                    eth_dst='00:11:22:33:44:55',
                                    eth_src='00:77:66:55:44:33',
                                    ip_dst='10.10.10.1',
                                    ip_src='192.168.100.3',
                                    ip_id=106,
                                    #ip_tos=3,
                                    ip_ttl=63)
            exp_pkt2 = simple_tcp_packet(
                                    eth_dst='00:11:22:33:44:56',
                                    eth_src='00:77:66:55:44:33',
                                    ip_dst='10.10.10.1',
                                    ip_src='192.168.100.3',
                                    ip_id=106,
                                    #ip_tos=3,
                                    ip_ttl=63)
            send_packet(self, 3, str(pkt))
            verify_any_packet_any_port(self, [exp_pkt1, exp_pkt2], [1, 2])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id2, ip_addr1, dmac2)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
            self.client.sai_thrift_remove_next_hop_group_member(nhop_member1)
            self.client.sai_thrift_remove_next_hop_group_member(nhop_member2)
            self.client.sai_thrift_remove_next_hop_group(nhop_group1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_next_hop(nhop2)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_router_interface(rif_id3)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv6EcmpHostTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)
        rif_id3 = sai_thrift_create_router_interface(self.client, vr_id, 1, port3, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV6
        ip_addr1 = '5000:1:1:0:0:0:0:1'
        ip_mask1 = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        dmac1 = '00:11:22:33:44:55'
        dmac2 = '00:11:22:33:44:56'

        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        nhop2 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id2)
        nhop_group1 = sai_thrift_create_next_hop_group(self.client)
        nhop_member1 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop1)
        nhop_member2 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop2)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id2, ip_addr1, dmac2)

        # send the test packet(s)
        try:
            pkt = simple_tcpv6_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:22',
                                    ipv6_dst='5000:1:1:0:0:0:0:1',
                                    ipv6_src='2000:1:1:0:0:0:0:1',
                                    tcp_sport=0x1234,
                                    ipv6_hlim=64)

            exp_pkt1 = simple_tcpv6_packet(
                                    eth_dst='00:11:22:33:44:55',
                                    eth_src='00:77:66:55:44:33',
                                    ipv6_dst='5000:1:1:0:0:0:0:1',
                                    ipv6_src='2000:1:1:0:0:0:0:1',
                                    tcp_sport=0x1234,
                                    ipv6_hlim=63)
            exp_pkt2 = simple_tcpv6_packet(
                                    eth_dst='00:11:22:33:44:56',
                                    eth_src='00:77:66:55:44:33',
                                    ipv6_dst='5000:1:1:0:0:0:0:1',
                                    ipv6_src='2000:1:1:0:0:0:0:1',
                                    tcp_sport=0x1234,
                                    ipv6_hlim=63)

            send_packet(self, 3, str(pkt))
            verify_any_packet_any_port(self, [exp_pkt1, exp_pkt2], [1, 2])

            pkt = simple_tcpv6_packet(
                                    eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:45',
                                    ipv6_dst='5000:1:1:0:0:0:0:1',
                                    ipv6_src='2000:1:1:0:0:0:0:1',
                                    tcp_sport=0x1248,
                                    ipv6_hlim=64)

            exp_pkt1 = simple_tcpv6_packet(
                                    eth_dst='00:11:22:33:44:55',
                                    eth_src='00:77:66:55:44:33',
                                    ipv6_dst='5000:1:1:0:0:0:0:1',
                                    ipv6_src='2000:1:1:0:0:0:0:1',
                                    tcp_sport=0x1248,
                                    ipv6_hlim=63)
            exp_pkt2 = simple_tcpv6_packet(
                                    eth_dst='00:11:22:33:44:56',
                                    eth_src='00:77:66:55:44:33',
                                    ipv6_dst='5000:1:1:0:0:0:0:1',
                                    ipv6_src='2000:1:1:0:0:0:0:1',
                                    tcp_sport=0x1248,
                                    ipv6_hlim=63)

            send_packet(self, 3, str(pkt))
            verify_any_packet_any_port(self, [exp_pkt1, exp_pkt2], [1, 2])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id2, ip_addr1, dmac2)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
            self.client.sai_thrift_remove_next_hop_group_member(nhop_member1)
            self.client.sai_thrift_remove_next_hop_group_member(nhop_member2)
            self.client.sai_thrift_remove_next_hop_group(nhop_group1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_next_hop(nhop2)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_router_interface(rif_id3)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv4EcmpLpmTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        port4 = port_list[4]
        port5 = port_list[5]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)
        rif_id3 = sai_thrift_create_router_interface(self.client, vr_id, 1, port3, 0, v4_enabled, v6_enabled, mac)
        rif_id4 = sai_thrift_create_router_interface(self.client, vr_id, 1, port4, 0, v4_enabled, v6_enabled, mac)
        rif_id5 = sai_thrift_create_router_interface(self.client, vr_id, 1, port5, 0, v4_enabled, v6_enabled, mac)


        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.0.0'
        ip_mask1 = '255.255.0.0'
        nhop_ip1 = '11.11.11.11'
        nhop_ip2 = '22.22.22.22'
        nhop_ip3 = '33.33.33.33'
        nhop_ip4 = '44.44.44.44'
        dmac1 = '00:11:22:33:44:55'
        dmac2 = '00:11:22:33:44:56'
        dmac3 = '00:11:22:33:44:57'
        dmac4 = '00:11:22:33:44:58'

        nhop1 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip1, rif_id1)
        nhop2 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip2, rif_id2)
        nhop3 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip3, rif_id3)
        nhop4 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip4, rif_id4)
        nhop_group1 = sai_thrift_create_next_hop_group(self.client)
        nhop_member1 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop1)
        nhop_member2 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop2)
        nhop_member3 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop3)
        nhop_member4 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop4)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id2, nhop_ip2, dmac2)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id3, nhop_ip3, dmac3)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id4, nhop_ip4, dmac4)

        # send the test packet(s)
        try:
            count = [0, 0, 0, 0]
            dst_ip = int(socket.inet_aton('10.10.10.1').encode('hex'),16)
            max_itrs = 200
            for i in range(0, max_itrs):
                dst_ip_addr = socket.inet_ntoa(hex(dst_ip)[2:].zfill(8).decode('hex'))
                pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                        eth_src='00:22:22:22:22:22',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=64)

                exp_pkt1 = simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)
                exp_pkt2 = simple_tcp_packet(eth_dst='00:11:22:33:44:56',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)
                exp_pkt3 = simple_tcp_packet(eth_dst='00:11:22:33:44:57',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)
                exp_pkt4 = simple_tcp_packet(eth_dst='00:11:22:33:44:58',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)

                send_packet(self, 5, str(pkt))
                rcv_idx = verify_any_packet_any_port(self,
                              [exp_pkt1, exp_pkt2, exp_pkt3, exp_pkt4],
                              [1, 2, 3, 4])
                count[rcv_idx] += 1
                dst_ip += 1

            for i in range(0, 4):
                self.assertTrue((count[i] >= ((max_itrs / 4) * 0.8)),
                        "Not all paths are equally balanced")
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id2, nhop_ip2, dmac2)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id3, nhop_ip3, dmac3)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id4, nhop_ip4, dmac4)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
            self.client.sai_thrift_remove_next_hop_group_member(nhop_member1)
            self.client.sai_thrift_remove_next_hop_group_member(nhop_member2)
            self.client.sai_thrift_remove_next_hop_group_member(nhop_member3)
            self.client.sai_thrift_remove_next_hop_group_member(nhop_member4)
            self.client.sai_thrift_remove_next_hop_group(nhop_group1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_next_hop(nhop2)
            self.client.sai_thrift_remove_next_hop(nhop3)
            self.client.sai_thrift_remove_next_hop(nhop4)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_router_interface(rif_id3)
            self.client.sai_thrift_remove_router_interface(rif_id4)
            self.client.sai_thrift_remove_router_interface(rif_id5)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv6EcmpLpmTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        port4 = port_list[4]
        port5 = port_list[5]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)
        rif_id3 = sai_thrift_create_router_interface(self.client, vr_id, 1, port3, 0, v4_enabled, v6_enabled, mac)
        rif_id4 = sai_thrift_create_router_interface(self.client, vr_id, 1, port4, 0, v4_enabled, v6_enabled, mac)
        rif_id5 = sai_thrift_create_router_interface(self.client, vr_id, 1, port5, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV6
        ip_addr1 = '6000:1:1:0:0:0:0:0'
        ip_mask1 = 'ffff:ffff:ffff:ffff:0:0:0:0'
        nhop_ip1 = '2000:1:1:0:0:0:0:1'
        nhop_ip2 = '3000:1:1:0:0:0:0:1'
        nhop_ip3 = '4000:1:1:0:0:0:0:1'
        nhop_ip4 = '5000:1:1:0:0:0:0:1'
        dmac1 = '00:11:22:33:44:55'
        dmac2 = '00:11:22:33:44:56'
        dmac3 = '00:11:22:33:44:57'
        dmac4 = '00:11:22:33:44:58'

        nhop1 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip1, rif_id1)
        nhop2 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip2, rif_id2)
        nhop3 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip3, rif_id3)
        nhop4 = sai_thrift_create_nhop(self.client, addr_family, nhop_ip4, rif_id4)
        nhop_group1 = sai_thrift_create_next_hop_group(self.client)
        nhop_member1 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop1)
        nhop_member2 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop2)
        nhop_member3 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop3)
        nhop_member4 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop4)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id2, nhop_ip2, dmac2)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id3, nhop_ip3, dmac3)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id4, nhop_ip4, dmac4)

        # send the test packet(s)
        try:
            count = [0, 0, 0, 0]
            dst_ip = socket.inet_pton(socket.AF_INET6, '6000:1:1:0:0:0:0:1')
            dst_ip_arr = list(dst_ip)
            max_itrs = 200
            sport = 0x1234
            dport = 0x50
            for i in range(0, max_itrs):
                dst_ip_addr = socket.inet_ntop(socket.AF_INET6, dst_ip)
                #HACK: sport is a hack for hashing since the ecmp hash does not
                #include ipv6 sa and da.
                pkt = simple_tcpv6_packet(
                        eth_dst='00:77:66:55:44:33',
                        eth_src='00:22:22:22:22:22',
                        ipv6_dst=dst_ip_addr,
                        ipv6_src='1001:1:1:0:0:0:0:2',
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=64)
                exp_pkt1 = simple_tcpv6_packet(
                        eth_dst='00:11:22:33:44:55',
                        eth_src='00:77:66:55:44:33',
                        ipv6_dst=dst_ip_addr,
                        ipv6_src='1001:1:1:0:0:0:0:2',
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=63)
                exp_pkt2 = simple_tcpv6_packet(
                        eth_dst='00:11:22:33:44:56',
                        eth_src='00:77:66:55:44:33',
                        ipv6_dst=dst_ip_addr,
                        ipv6_src='1001:1:1:0:0:0:0:2',
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=63)
                exp_pkt3 = simple_tcpv6_packet(
                        eth_dst='00:11:22:33:44:57',
                        eth_src='00:77:66:55:44:33',
                        ipv6_dst=dst_ip_addr,
                        ipv6_src='1001:1:1:0:0:0:0:2',
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=63)
                exp_pkt4 = simple_tcpv6_packet(
                        eth_dst='00:11:22:33:44:58',
                        eth_src='00:77:66:55:44:33',
                        ipv6_dst=dst_ip_addr,
                        ipv6_src='1001:1:1:0:0:0:0:2',
                        tcp_sport=sport,
                        tcp_dport=dport,
                        ipv6_hlim=63)

                send_packet(self, 5, str(pkt))
                rcv_idx = verify_any_packet_any_port(self,
                              [exp_pkt1, exp_pkt2, exp_pkt3, exp_pkt4],
                              [1, 2, 3, 4])
                count[rcv_idx] += 1
                dst_ip_arr[15] = chr(ord(dst_ip_arr[15]) + 1)
                dst_ip = ''.join(dst_ip_arr)
                sport += 15
                dport += 20

            print "Count = %s" % str(count)
            for i in range(0, 4):
                self.assertTrue((count[i] >= ((max_itrs / 4) * 0.50)),
                        "Not all paths are equally balanced")
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, nhop_ip1, dmac1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id2, nhop_ip2, dmac2)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id3, nhop_ip3, dmac3)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id4, nhop_ip4, dmac4)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)
            self.client.sai_thrift_remove_next_hop_group_member(nhop_member1)
            self.client.sai_thrift_remove_next_hop_group_member(nhop_member2)
            self.client.sai_thrift_remove_next_hop_group_member(nhop_member3)
            self.client.sai_thrift_remove_next_hop_group_member(nhop_member4)
            self.client.sai_thrift_remove_next_hop_group(nhop_group1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_next_hop(nhop2)
            self.client.sai_thrift_remove_next_hop(nhop3)
            self.client.sai_thrift_remove_next_hop(nhop4)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_router_interface(rif_id3)
            self.client.sai_thrift_remove_router_interface(rif_id4)
            self.client.sai_thrift_remove_router_interface(rif_id5)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L2FloodTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print 'Flood test on ports 1, 2 and 3'
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'

        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_member1 = sai_thrift_create_vlan_member(self.client, vlan_id, port1, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member2 = sai_thrift_create_vlan_member(self.client, vlan_id, port2, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member3 = sai_thrift_create_vlan_member(self.client, vlan_id, port3, SAI_VLAN_TAGGING_MODE_UNTAGGED)

        pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=107,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=107,
                                ip_ttl=64)
        try:
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [2, 3])
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [1, 3])
            send_packet(self, 3, str(pkt))
            verify_packets(self, exp_pkt, [1, 2])
        finally:
            sai_thrift_flush_fdb_by_vlan(self.client, vlan_id)
            self.client.sai_thrift_remove_vlan_member(vlan_member1)
            self.client.sai_thrift_remove_vlan_member(vlan_member2)
            self.client.sai_thrift_remove_vlan_member(vlan_member3)
            self.client.sai_thrift_delete_vlan(vlan_id)

class L2LagTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        port4 = port_list[4]
        port5 = port_list[5]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = SAI_PACKET_ACTION_FORWARD

        self.client.sai_thrift_create_vlan(vlan_id)

        lag_id1 = self.client.sai_thrift_create_lag([])
        lag_member1 = sai_thrift_create_lag_member(self.client, lag_id1, port1)
        lag_member2 = sai_thrift_create_lag_member(self.client, lag_id1, port2)
        lag_member3 = sai_thrift_create_lag_member(self.client, lag_id1, port3)
        lag_member4 = sai_thrift_create_lag_member(self.client, lag_id1, port4)

        vlan_member1 = sai_thrift_create_vlan_member(self.client, vlan_id, lag_id1, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member2 = sai_thrift_create_vlan_member(self.client, vlan_id, port5, SAI_VLAN_TAGGING_MODE_UNTAGGED)

        sai_thrift_create_fdb(self.client, vlan_id, mac1, lag_id1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port5, mac_action)

        try:
            count = [0, 0, 0, 0]
            dst_ip = int(socket.inet_aton('10.10.10.1').encode('hex'),16)
            max_itrs = 200
            for i in range(0, max_itrs):
                dst_ip_addr = socket.inet_ntoa(hex(dst_ip)[2:].zfill(8).decode('hex'))
                pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                        eth_src='00:22:22:22:22:22',
                                        ip_dst=dst_ip_addr,
                                        ip_src='192.168.8.1',
                                        ip_id=109,
                                        ip_ttl=64)

                exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                            eth_src='00:22:22:22:22:22',
                                            ip_dst=dst_ip_addr,
                                            ip_src='192.168.8.1',
                                            ip_id=109,
                                            ip_ttl=64)

                send_packet(self, 5, str(pkt))
                rcv_idx = verify_any_packet_any_port(self, [exp_pkt], [1, 2, 3, 4])
                count[rcv_idx] += 1
                dst_ip += 1

            print count
            for i in range(0, 4):
                self.assertTrue((count[i] >= ((max_itrs / 4) * 0.8)),
                        "Not all paths are equally balanced")

            pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.0.0.1',
                                    ip_id=109,
                                    ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.0.0.1',
                                    ip_id=109,
                                    ip_ttl=64)
            print "Sending packet port 1 (lag member) -> port 1"
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [5])
            print "Sending packet port 2 (lag member) -> port 1"
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [5])
            print "Sending packet port 3 (lag member) -> port 1"
            send_packet(self, 3, str(pkt))
            verify_packets(self, exp_pkt, [5])
            print "Sending packet port 4 (lag member) -> port 1"
            send_packet(self, 4, str(pkt))
            verify_packets(self, exp_pkt, [5])
        finally:

            sai_thrift_delete_fdb(self.client, vlan_id, mac1, lag_id1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port5)

            self.client.sai_thrift_remove_vlan_member(vlan_member1)
            self.client.sai_thrift_remove_vlan_member(vlan_member2)

            self.client.sai_thrift_remove_lag_member(lag_member1)
            self.client.sai_thrift_remove_lag_member(lag_member2)
            self.client.sai_thrift_remove_lag_member(lag_member3)
            self.client.sai_thrift_remove_lag_member(lag_member4)

            self.client.sai_thrift_remove_lag(lag_id1)
            self.client.sai_thrift_delete_vlan(vlan_id)

class L2LagMemberTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        port4 = port_list[4]
        port5 = port_list[5]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = SAI_PACKET_ACTION_FORWARD

        self.client.sai_thrift_create_vlan(vlan_id)

        lag_id1 = self.client.sai_thrift_create_lag([])
        lag_member1 = sai_thrift_create_lag_member(self.client, lag_id1, port1)
        lag_member2 = sai_thrift_create_lag_member(self.client, lag_id1, port2)
        lag_member3 = sai_thrift_create_lag_member(self.client, lag_id1, port3)
        lag_member4 = sai_thrift_create_lag_member(self.client, lag_id1, port4)

        vlan_member1 = sai_thrift_create_vlan_member(self.client, vlan_id, port1, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member2 = sai_thrift_create_vlan_member(self.client, vlan_id, port2, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member3 = sai_thrift_create_vlan_member(self.client, vlan_id, port3, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member4 = sai_thrift_create_vlan_member(self.client, vlan_id, port4, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member5 = sai_thrift_create_vlan_member(self.client, vlan_id, port5, SAI_VLAN_TAGGING_MODE_UNTAGGED)

        sai_thrift_create_fdb(self.client, vlan_id, mac1, lag_id1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port5, mac_action)

        try:
            count = [0, 0, 0, 0]
            dst_ip = int(socket.inet_aton('10.10.10.1').encode('hex'),16)
            max_itrs = 200
            for i in range(0, max_itrs):
                dst_ip_addr = socket.inet_ntoa(hex(dst_ip)[2:].zfill(8).decode('hex'))
                pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                        eth_src='00:22:22:22:22:22',
                                        ip_dst=dst_ip_addr,
                                        ip_src='192.168.8.1',
                                        ip_id=109,
                                        ip_ttl=64)

                exp_pkt = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                            eth_src='00:22:22:22:22:22',
                                            ip_dst=dst_ip_addr,
                                            ip_src='192.168.8.1',
                                            ip_id=109,
                                            ip_ttl=64)

                send_packet(self, 5, str(pkt))
                rcv_idx = verify_any_packet_any_port(self, [exp_pkt], [1, 2, 3, 4])
                count[rcv_idx] += 1
                dst_ip += 1

            print count
            for i in range(0, 4):
                self.assertTrue((count[i] >= ((max_itrs / 4) * 0.8)),
                        "Not all paths are equally balanced")

            pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.0.0.1',
                                    ip_id=109,
                                    ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_src='00:11:11:11:11:11',
                                    eth_dst='00:22:22:22:22:22',
                                    ip_dst='10.0.0.1',
                                    ip_id=109,
                                    ip_ttl=64)
            print "Sending packet port 1 (lag member) -> port 1"
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [5])
            print "Sending packet port 2 (lag member) -> port 1"
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [5])
            print "Sending packet port 3 (lag member) -> port 1"
            send_packet(self, 3, str(pkt))
            verify_packets(self, exp_pkt, [5])
            print "Sending packet port 4 (lag member) -> port 1"
            send_packet(self, 4, str(pkt))
            verify_packets(self, exp_pkt, [5])
        finally:

            sai_thrift_delete_fdb(self.client, vlan_id, mac1, lag_id1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port5)

            self.client.sai_thrift_remove_vlan_member(vlan_member1)
            self.client.sai_thrift_remove_vlan_member(vlan_member2)
            self.client.sai_thrift_remove_vlan_member(vlan_member3)
            self.client.sai_thrift_remove_vlan_member(vlan_member4)
            self.client.sai_thrift_remove_vlan_member(vlan_member5)

            self.client.sai_thrift_remove_lag_member(lag_member1)
            self.client.sai_thrift_remove_lag_member(lag_member2)
            self.client.sai_thrift_remove_lag_member(lag_member3)
            self.client.sai_thrift_remove_lag_member(lag_member4)

            self.client.sai_thrift_remove_lag(lag_id1)
            self.client.sai_thrift_delete_vlan(vlan_id)

class L3IPv4LagTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        lag_id1 = self.client.sai_thrift_create_lag([])
        lag_member1 = sai_thrift_create_lag_member(self.client, lag_id1, port1)
        lag_member2 = sai_thrift_create_lag_member(self.client, lag_id1, port2)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, lag_id1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port3, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        # send the test packet(s)
        try:
            pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:22',
                                    ip_dst='10.10.10.1',
                                    ip_src='192.168.0.1',
                                    ip_id=110,
                                    ip_ttl=64)

            exp_pkt = simple_tcp_packet(
                                    eth_dst='00:11:22:33:44:55',
                                    eth_src='00:77:66:55:44:33',
                                    ip_dst='10.10.10.1',
                                    ip_src='192.168.0.1',
                                    ip_id=110,
                                    ip_ttl=63)
            send_packet(self, 3, str(pkt))
            verify_packets_any(self, exp_pkt, [1, 2])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_lag_member(lag_member1)
            self.client.sai_thrift_remove_lag_member(lag_member2)
            self.client.sai_thrift_remove_lag(lag_id1)
            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv6LagTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        lag_id1 = self.client.sai_thrift_create_lag([])
        lag_member1 = sai_thrift_create_lag_member(self.client, lag_id1, port1)
        lag_member2 = sai_thrift_create_lag_member(self.client, lag_id1, port2)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, lag_id1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port3, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV6
        ip_addr1 = '4001::1'
        ip_mask1 = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        dmac1 = '00:11:22:33:44:55'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        # send the test packet(s)
        try:
            pkt = simple_tcpv6_packet(eth_dst='00:77:66:55:44:33',
                                    eth_src='00:22:22:22:22:22',
                                    ipv6_dst='4001::1',
                                    ipv6_src='5001::1',
                                    ipv6_hlim=64)

            exp_pkt = simple_tcpv6_packet(
                                    eth_dst='00:11:22:33:44:55',
                                    eth_src='00:77:66:55:44:33',
                                    ipv6_dst='4001::1',
                                    ipv6_src='5001::1',
                                    ipv6_hlim=63)
            send_packet(self, 3, str(pkt))
            verify_packets_any(self, exp_pkt, [1, 2])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_lag_member(lag_member1)
            self.client.sai_thrift_remove_lag_member(lag_member2)
            self.client.sai_thrift_remove_lag(lag_id1)
            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3EcmpLagTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        port4 = port_list[4]
        port5 = port_list[5]
        port6 = port_list[6]
        port7 = port_list[7]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        lag_id1 = self.client.sai_thrift_create_lag([])
        lag_member11 = sai_thrift_create_lag_member(self.client, lag_id1, port1)
        lag_member12 = sai_thrift_create_lag_member(self.client, lag_id1, port2)
        lag_member13 = sai_thrift_create_lag_member(self.client, lag_id1, port3)

        lag_id2 = self.client.sai_thrift_create_lag([])
        lag_member21 = sai_thrift_create_lag_member(self.client, lag_id2, port4)
        lag_member22 = sai_thrift_create_lag_member(self.client, lag_id2, port5)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, lag_id1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, lag_id2, 0, v4_enabled, v6_enabled, mac)
        rif_id3 = sai_thrift_create_router_interface(self.client, vr_id, 1, port6, 0, v4_enabled, v6_enabled, mac)
        rif_id4 = sai_thrift_create_router_interface(self.client, vr_id, 1, port7, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.0.0'
        ip_mask1 = '255.255.0.0'
        dmac1 = '00:11:22:33:44:55'
        dmac2 = '00:11:22:33:44:56'
        dmac3 = '00:11:22:33:44:57'

        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        nhop2 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id2)
        nhop3 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id3)

        nhop_group1 = sai_thrift_create_next_hop_group(self.client)
        nhop_member1 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop1)
        nhop_member2 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop2)
        nhop_member3 = sai_thrift_create_next_hop_group_member(self.client, nhop_group1, nhop3)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)

        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id2, ip_addr1, dmac2)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id3, ip_addr1, dmac3)

        try:
            count = [0, 0, 0, 0, 0, 0]
            dst_ip = int(socket.inet_aton('10.10.10.1').encode('hex'), 16)
            src_mac_start = '00:22:22:22:23:'
            max_itrs = 500
            for i in range(0, max_itrs):
                dst_ip_addr = socket.inet_ntoa(hex(dst_ip)[2:].zfill(8).decode('hex'))
                src_mac = src_mac_start + str(i%99).zfill(2)
                pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                        eth_src=src_mac,
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=64)

                exp_pkt1 = simple_tcp_packet(eth_dst='00:11:22:33:44:55',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)
                exp_pkt2 = simple_tcp_packet(eth_dst='00:11:22:33:44:56',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)
                exp_pkt3 = simple_tcp_packet(eth_dst='00:11:22:33:44:57',
                        eth_src='00:77:66:55:44:33',
                        ip_dst=dst_ip_addr,
                        ip_src='192.168.8.1',
                        ip_id=106,
                        ip_ttl=63)

                send_packet(self, 7, str(pkt))
                rcv_idx = verify_any_packet_any_port(self,
                              [exp_pkt1, exp_pkt2, exp_pkt3],
                              [1, 2, 3, 4, 5, 6])
                count[rcv_idx] += 1
                dst_ip += 1

            print count
            ecmp_count = [count[0]+count[1]+count[2], count[3]+count[4],
                    count[5]]
            for i in range(0, 3):
                self.assertTrue((ecmp_count[i] >= ((max_itrs / 3) * 0.75)),
                        "Ecmp paths are not equally balanced")
            for i in range(0, 3):
                self.assertTrue((count[i] >= ((max_itrs / 9) * 0.75)),
                        "Lag path1 is not equally balanced")
            for i in range(3, 5):
                self.assertTrue((count[i] >= ((max_itrs / 6) * 0.75)),
                        "Lag path2 is not equally balanced")
        finally:
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop_group1)

            self.client.sai_thrift_remove_next_hop_group_member(nhop_member1)
            self.client.sai_thrift_remove_next_hop_group_member(nhop_member2)
            self.client.sai_thrift_remove_next_hop_group_member(nhop_member3)
            self.client.sai_thrift_remove_next_hop_group(nhop_group1)

            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            sai_thrift_remove_neighbor(self.client, addr_family, rif_id2, ip_addr1, dmac2)
            self.client.sai_thrift_remove_next_hop(nhop2)

            sai_thrift_remove_neighbor(self.client, addr_family, rif_id3, ip_addr1, dmac3)
            self.client.sai_thrift_remove_next_hop(nhop3)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_router_interface(rif_id3)
            self.client.sai_thrift_remove_router_interface(rif_id4)

            self.client.sai_thrift_remove_lag_member(lag_member11)
            self.client.sai_thrift_remove_lag_member(lag_member12)
            self.client.sai_thrift_remove_lag_member(lag_member13)
            self.client.sai_thrift_remove_lag(lag_id1)

            self.client.sai_thrift_remove_lag_member(lag_member21)
            self.client.sai_thrift_remove_lag_member(lag_member22)
            self.client.sai_thrift_remove_lag(lag_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class IPAclTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=63)
        if True:

            # setup ACL to block based on Source IP
            action_list = [SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION]
            packet_action = SAI_PACKET_ACTION_DROP
            in_ports = [port1, port2]
            ip_src = "192.168.0.1"
            ip_src_mask = "255.255.255.0"

            acl_table_id = sai_thrift_create_acl_table(
                             client = self.client,
                             ip_src = True,
                             in_ports = True)

            acl_entry_id = sai_thrift_create_acl_entry(
                             client = self.client,
                             acl_table_id = acl_table_id,
                             action_list = action_list,
                             ip_src = ip_src,
                             ip_src_mask = ip_src_mask,
                             in_ports = in_ports)

            # send the same packet
            failed = 0
            send_packet(self, 2, str(pkt))

            # ensure packet is dropped
            # check for absence of packet here!
            try:
                verify_packets(self, exp_pkt, [1])
                print 'FAILED - did not expect packet'
                failed = 1
            except:
                print 'Success'

            finally:
                if failed == 1:
                    self.assertFalse()


            # delete ACL
            self.client.sai_thrift_remove_acl_entry(acl_entry_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)

            # cleanup
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class IPIngressAclRangeTcamTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=63)
        if True:

            u32range = sai_thrift_range_t(min=1000, max=2000)
            acl_range_id = sai_thrift_create_acl_range(self.client, SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE, u32range)
            range_list = [acl_range_id]

            # setup ACL to block based on Source IP
            action_list = [SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION]
            packet_action = SAI_PACKET_ACTION_DROP
            in_ports = [port1, port2]
            ip_src = "192.168.0.1"
            ip_src_mask = "255.255.255.0"

            acl_table_id = sai_thrift_create_acl_table(
                             client = self.client,
                             ip_src = True,
                             in_ports = True)

            acl_entry_id = sai_thrift_create_acl_entry(
                             client = self.client,
                             acl_table_id = acl_table_id,
                             action_list = action_list,
                             range_list = range_list,
                             ip_src = ip_src,
                             ip_src_mask = ip_src_mask,
                             in_ports = in_ports)

            # send the same packet
            failed = 0
            send_packet(self, 2, str(pkt))

            # ensure packet is dropped
            # check for absence of packet here!
            try:
                verify_packets(self, exp_pkt, [1])
                print 'FAILED - did not expect packet'
                failed = 1
            except:
                print 'Success'

            finally:
                if failed == 1:
                    self.assertFalse()


            # delete ACL
            self.client.sai_thrift_remove_acl_entry(acl_entry_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)
            self.client.sai_thrift_delete_acl_range(acl_range_id)

            # cleanup
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class IPEgressAclTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print

        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=63)
        if True:

            # setup ACL to block based on Source IP
            action_list = [SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION]
            packet_action = SAI_PACKET_ACTION_DROP
            in_ports = [port1, port2]
            ip_src = "192.168.0.1"
            ip_src_mask = "255.255.255.0"

            acl_table_id = sai_thrift_create_acl_table(
                             client = self.client,
                             acl_stage = SAI_ACL_STAGE_EGRESS,
                             ip_src = True,
                             in_ports = True)

            acl_entry_id = sai_thrift_create_acl_entry(
                             client = self.client,
                             acl_table_id = acl_table_id,
                             action_list = action_list,
                             ip_src = ip_src,
                             ip_src_mask = ip_src_mask,
                             in_ports = in_ports)

            # send the same packet
            failed = 0
            send_packet(self, 2, str(pkt))

            # ensure packet is dropped
            # check for absence of packet here!
            try:
                verify_packets(self, exp_pkt, [1])
                print 'FAILED - did not expect packet'
                failed = 1
            except:
                print 'Success'

            finally:
                if failed == 1:
                    self.assertFalse()


            # delete ACL
            self.client.sai_thrift_remove_acl_entry(acl_entry_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)

            # cleanup
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3VIIPv4HostTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        vlan_id = 10
        mac_action = SAI_PACKET_ACTION_FORWARD

        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_member1 = sai_thrift_create_vlan_member(self.client, vlan_id, port1, SAI_VLAN_TAGGING_MODE_UNTAGGED)

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        mac1 = ''
        mac2 = ''

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 0, 0, vlan_id, v4_enabled, v6_enabled, mac1)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac2)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:0a:00:00:00:01'
        sai_thrift_create_fdb(self.client, vlan_id, dmac1, port1, mac_action)
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        ip_addr2 = '11.11.11.1'
        ip_mask2 = '255.255.255.255'
        dmac2 = '00:0b:00:00:00:01'
        nhop2 = sai_thrift_create_nhop(self.client, addr_family, ip_addr2, rif_id2)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr2, ip_mask2, nhop2)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id2, ip_addr2, dmac2)

        try:
            # send the test packet(s)
            pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:0a:00:00:00:01',
                                ip_dst='11.11.11.1',
                                ip_src='10.10.10.1',
                                ip_id=105,
                                ip_ttl=64)
            exp_pkt = simple_tcp_packet(
                                eth_dst='00:0b:00:00:00:01',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='11.11.11.1',
                                ip_src='10.10.10.1',
                                ip_id=105,
                                ip_ttl=63)
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [2])

            # send the test packet(s)
            pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:0b:00:00:00:01',
                                ip_dst='10.10.10.1',
                                ip_src='11.11.11.1',
                                ip_id=105,
                                ip_ttl=64)
            exp_pkt = simple_tcp_packet(
                                eth_dst='00:0a:00:00:00:01',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='11.11.11.1',
                                ip_id=105,
                                ip_ttl=63)
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_delete_fdb(self.client, vlan_id, dmac1, port1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id2, ip_addr2, dmac2)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr2, ip_mask2, nhop2)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_next_hop(nhop2)
            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_vlan_member(vlan_member1)
            self.client.sai_thrift_delete_vlan(vlan_id)
            self.client.sai_thrift_remove_virtual_router(vr_id)

class L3IPv4MacRewriteTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1

        mac1 = '00:0a:00:00:00:01'
        mac2 = '00:0b:00:00:00:01'

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac1)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac2)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.10.1'
        ip_mask1 = '255.255.255.255'
        dmac1 = '00:11:22:33:44:55'

        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst='00:0b:00:00:00:01',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:0a:00:00:00:01',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=63)
        try:
            send_packet(self, 2, str(pkt))
            verify_packets(self, exp_pkt, [1])
        finally:
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)
            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)
            self.client.sai_thrift_remove_virtual_router(vr_id)

class IngressLocalMirrorTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        v4_enabled = 1
        v6_enabled = 1
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = SAI_PACKET_ACTION_FORWARD

        self.client.sai_thrift_create_vlan(vlan_id)

        vlan_member1 = sai_thrift_create_vlan_member(self.client, vlan_id, port1, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member2 = sai_thrift_create_vlan_member(self.client, vlan_id, port2, SAI_VLAN_TAGGING_MODE_TAGGED)

        sai_thrift_create_fdb(self.client, vlan_id, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port2, mac_action)

        action_list = [SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS]
        in_ports = [port1, port2]
        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_src = "192.168.0.1"
        ip_src_mask = "255.255.255.255"

        mirror_type = SAI_MIRROR_TYPE_LOCAL
        ingress_mirror_id = sai_thrift_create_mirror_session(self.client, mirror_type, port3,
                                                     0, 0, 0,
                                                     None, None,
                                                     0, None, None,
                                                     0, 0, 0, 0)

        acl_table_id = sai_thrift_create_acl_table(
                             client = self.client,
                             ip_src = True,
                             in_ports = True)

        acl_entry_id = sai_thrift_create_acl_entry(
                             client = self.client,
                             acl_table_id = acl_table_id,
                             action_list = action_list,
                             ip_src = ip_src,
                             ip_src_mask = ip_src_mask,
                             in_ports = in_ports,
                             ingress_mirror_id = ingress_mirror_id)

        try:
            pkt = simple_tcp_packet(eth_dst=mac2,
                                eth_src=mac1,
                                ip_dst='10.0.0.1',
                                ip_src='192.168.0.1',
                                ip_id=102,
                                ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_dst=mac2,
                                eth_src=mac1,
                                ip_dst='10.0.0.1',
                                ip_src='192.168.0.1',
                                dl_vlan_enable=True,
                                vlan_vid=10,
                                ip_id=102,
                                ip_ttl=64,
                                pktlen=104)

            print "Sending packet port 1 -> port 2 and port 3 (local mirror)"
            send_packet(self, 1, str(pkt))
            verify_each_packet_on_each_port(self, [exp_pkt, pkt], [2, 3])

            time.sleep(1)

            pkt = simple_tcp_packet(eth_dst=mac1,
                                eth_src=mac2,
                                ip_dst='10.0.0.1',
                                ip_src='192.168.0.1',
                                vlan_vid=10,
                                dl_vlan_enable=True,
                                ip_id=102,
                                ip_ttl=64,
                                pktlen=104)
            exp_pkt = simple_tcp_packet(eth_dst=mac1,
                                eth_src=mac2,
                                ip_dst='10.0.0.1',
                                ip_src='192.168.0.1',
                                ip_id=102,
                                ip_ttl=64,
                                pktlen=100)

            print "Sending packet port 2 -> port 1 and port 3 (local mirror)"
            send_packet(self, 2, str(pkt))
            verify_each_packet_on_each_port(self, [exp_pkt, pkt], [1, 3])

        finally:
            self.client.sai_thrift_remove_acl_entry(acl_entry_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)

            self.client.sai_thrift_remove_mirror_session(ingress_mirror_id)

            sai_thrift_delete_fdb(self.client, vlan_id, mac1, port1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port2)

            self.client.sai_thrift_remove_vlan_member(vlan_member1)
            self.client.sai_thrift_remove_vlan_member(vlan_member2)
            self.client.sai_thrift_delete_vlan(vlan_id)

class IngressERSpanMirrorTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        v4_enabled = 1
        v6_enabled = 1
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = SAI_PACKET_ACTION_FORWARD

        self.client.sai_thrift_create_vlan(vlan_id)

        vlan_member1 = sai_thrift_create_vlan_member(self.client, vlan_id, port1, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member2 = sai_thrift_create_vlan_member(self.client, vlan_id, port2, SAI_VLAN_TAGGING_MODE_TAGGED)

        sai_thrift_create_fdb(self.client, vlan_id, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port2, mac_action)

        action_list = [SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS]
        in_ports = [port1, port2]
        ip_src = "192.168.0.1"
        ip_src_mask = "255.255.255.255"

        mirror_type = SAI_MIRROR_TYPE_ENHANCED_REMOTE
        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        tunnel_src_ip = "1.1.1.1"
        tunnel_dst_ip = "1.1.1.2"
        tunnel_src_mac = "00:77:66:55:44:33"
        tunnel_dst_mac = "00:33:33:33:33:33"
        encap_type = SAI_ERSPAN_ENCAPSULATION_TYPE_MIRROR_L3_GRE_TUNNEL
        protocol = 47

        ip_dst = None
        ip_dst_mask = None
        ip_proto = None
        in_port = None
        out_port = None
        out_ports = []
        egress_mirror_id = None

        ingress_mirror_id = sai_thrift_create_mirror_session(self.client, mirror_type, port3,
                                                     0, 0, 0,
                                                     tunnel_src_mac, tunnel_dst_mac,
                                                     addr_family, tunnel_src_ip, tunnel_dst_ip,
                                                     encap_type, protocol, 0, 0)

        acl_table_id = sai_thrift_create_acl_table(
                             client = self.client,
                             ip_src = True,
                             in_ports = True)

        acl_entry_id = sai_thrift_create_acl_entry(
                             client = self.client,
                             acl_table_id = acl_table_id,
                             action_list = action_list,
                             ip_src = ip_src,
                             ip_src_mask = ip_src_mask,
                             in_ports = in_ports,
                             ingress_mirror_id = ingress_mirror_id)

        try:
            pkt = simple_tcp_packet(eth_dst=mac2,
                                eth_src=mac1,
                                ip_dst='10.0.0.1',
                                ip_src='192.168.0.1',
                                ip_id=102,
                                ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_dst=mac2,
                                eth_src=mac1,
                                ip_dst='10.0.0.1',
                                ip_src='192.168.0.1',
                                dl_vlan_enable=True,
                                vlan_vid=10,
                                ip_id=102,
                                ip_ttl=64,
                                pktlen=104)
            exp_mirrored_pkt = ipv4_erspan_pkt(eth_dst=tunnel_dst_mac,
                                           eth_src=tunnel_src_mac,
                                           ip_src=tunnel_src_ip,
                                           ip_dst=tunnel_dst_ip,
                                           ip_id=0,
                                           ip_ttl=64,
                                           version=2,
                                           mirror_id=(ingress_mirror_id & 0x3FFFFFFF),
                                           inner_frame=pkt);

            print "Sending packet port 1 -> port 2 and port 3 (erspan mirror)"
            send_packet(self, 1, str(pkt))
            verify_erspan3_packet(self, exp_mirrored_pkt, 3)
            verify_packets(self, exp_pkt, [2])
            verify_no_other_packets(self)

            time.sleep(1)

        finally:
            self.client.sai_thrift_remove_acl_entry(acl_entry_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)

            self.client.sai_thrift_remove_mirror_session(ingress_mirror_id)

            sai_thrift_delete_fdb(self.client, vlan_id, mac1, port1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port2)

            self.client.sai_thrift_remove_vlan_member(vlan_member1)
            self.client.sai_thrift_remove_vlan_member(vlan_member2)
            self.client.sai_thrift_delete_vlan(vlan_id)

class EgressLocalMirrorTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        v4_enabled = 1
        v6_enabled = 1
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = SAI_PACKET_ACTION_FORWARD

        self.client.sai_thrift_create_vlan(vlan_id)

        vlan_member1 = sai_thrift_create_vlan_member(self.client, vlan_id, port1, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member2 = sai_thrift_create_vlan_member(self.client, vlan_id, port2, SAI_VLAN_TAGGING_MODE_TAGGED)

        sai_thrift_create_fdb(self.client, vlan_id, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port2, mac_action)

        action_list = [SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS]
        addr_family = SAI_IP_ADDR_FAMILY_IPV4

        mirror_type = SAI_MIRROR_TYPE_LOCAL
        out_port = port2

        egress_mirror_id = sai_thrift_create_mirror_session(self.client, mirror_type, port3,
                                                     0, 0, 0,
                                                     None, None,
                                                     0, None, None,
                                                     0, 0, 0, 0)

        acl_table_id = sai_thrift_create_acl_table(
                             client = self.client,
                             acl_stage = SAI_ACL_STAGE_EGRESS,
                             out_port = True)

        acl_entry_id = sai_thrift_create_acl_entry(
                             client = self.client,
                             acl_table_id = acl_table_id,
                             action_list = action_list,
                             out_port = out_port,
                             egress_mirror_id = egress_mirror_id)

        try:
            pkt = simple_tcp_packet(eth_dst=mac2,
                                eth_src=mac1,
                                ip_dst='10.0.0.1',
                                ip_src='192.168.0.1',
                                ip_id=102,
                                ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_dst=mac2,
                                eth_src=mac1,
                                ip_dst='10.0.0.1',
                                ip_src='192.168.0.1',
                                dl_vlan_enable=True,
                                vlan_vid=10,
                                ip_id=102,
                                ip_ttl=64,
                                pktlen=104)

            print "Sending packet port 1 -> port 2 and port 3 (local mirror)"
            send_packet(self, 1, str(pkt))
            verify_each_packet_on_each_port(self, [exp_pkt, exp_pkt], [2, 3])

            time.sleep(1)

        finally:
            self.client.sai_thrift_remove_acl_entry(acl_entry_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)

            self.client.sai_thrift_remove_mirror_session(egress_mirror_id)

            sai_thrift_delete_fdb(self.client, vlan_id, mac1, port1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port2)

            self.client.sai_thrift_remove_vlan_member(vlan_member1)
            self.client.sai_thrift_remove_vlan_member(vlan_member2)
            self.client.sai_thrift_delete_vlan(vlan_id)

class EgressERSpanMirrorTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        port3 = port_list[3]
        v4_enabled = 1
        v6_enabled = 1
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = SAI_PACKET_ACTION_FORWARD

        self.client.sai_thrift_create_vlan(vlan_id)

        vlan_member1 = sai_thrift_create_vlan_member(self.client, vlan_id, port1, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member2 = sai_thrift_create_vlan_member(self.client, vlan_id, port2, SAI_VLAN_TAGGING_MODE_UNTAGGED)

        sai_thrift_create_fdb(self.client, vlan_id, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port2, mac_action)

        action_list = [SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS]

        mirror_type = SAI_MIRROR_TYPE_ENHANCED_REMOTE
        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        tunnel_src_ip = "1.1.1.1"
        tunnel_dst_ip = "1.1.1.2"
        tunnel_src_mac = "00:77:66:55:44:33"
        tunnel_dst_mac = "00:33:33:33:33:33"
        encap_type = SAI_ERSPAN_ENCAPSULATION_TYPE_MIRROR_L3_GRE_TUNNEL
        protocol = 47

        out_port = port2

        egress_mirror_id = sai_thrift_create_mirror_session(self.client, mirror_type, port3,
                                                     0, 0, 0,
                                                     tunnel_src_mac, tunnel_dst_mac,
                                                     addr_family, tunnel_src_ip, tunnel_dst_ip,
                                                     encap_type, protocol, 0, 0)

        acl_table_id = sai_thrift_create_acl_table(
                             client = self.client,
                             acl_stage=SAI_ACL_STAGE_EGRESS,
                             out_port = True)

        acl_entry_id = sai_thrift_create_acl_entry(
                             client = self.client,
                             acl_table_id = acl_table_id,
                             action_list = action_list,
                             out_port = out_port,
                             egress_mirror_id = egress_mirror_id)

        try:
            pkt = simple_tcp_packet(eth_dst=mac2,
                                eth_src=mac1,
                                ip_dst='10.0.0.1',
                                ip_src='192.168.0.1',
                                ip_id=102,
                                ip_ttl=64)
            exp_pkt = simple_tcp_packet(eth_dst=mac2,
                                eth_src=mac1,
                                ip_dst='10.0.0.1',
                                ip_src='192.168.0.1',
                                ip_id=102,
                                ip_ttl=64)
            exp_mirrored_pkt = ipv4_erspan_pkt(eth_dst=tunnel_dst_mac,
                                           eth_src=tunnel_src_mac,
                                           ip_src=tunnel_src_ip,
                                           ip_dst=tunnel_dst_ip,
                                           ip_id=0,
                                           ip_ttl=64,
                                           version=2,
                                           mirror_id=(egress_mirror_id & 0x3FFFFFFF),
                                           inner_frame=pkt);

            print "Sending packet port 1 -> port 2 and port 3 (erspan mirror)"

            send_packet(self, 1, str(pkt))
            verify_erspan3_packet(self, exp_mirrored_pkt, 3)
            verify_packets(self, exp_pkt, [2])
            verify_no_other_packets(self)

            time.sleep(1)

        finally:
            self.client.sai_thrift_remove_acl_entry(acl_entry_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)

            self.client.sai_thrift_remove_mirror_session(egress_mirror_id)

            sai_thrift_delete_fdb(self.client, vlan_id, mac1, port1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port2)

            self.client.sai_thrift_remove_vlan_member(vlan_member1)
            self.client.sai_thrift_remove_vlan_member(vlan_member2)
            self.client.sai_thrift_delete_vlan(vlan_id)

class L2VlanStatsTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending L2 packet port 1 -> port 2 [access vlan=10])"
        switch_init(self.client)
        vlan_id = 10
        port1 = port_list[1]
        port2 = port_list[2]
        mac1 = '00:11:11:11:11:11'
        mac2 = '00:22:22:22:22:22'
        mac_action = SAI_PACKET_ACTION_FORWARD

        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_member1 = sai_thrift_create_vlan_member(self.client, vlan_id, port1, SAI_VLAN_TAGGING_MODE_UNTAGGED)
        vlan_member2 = sai_thrift_create_vlan_member(self.client, vlan_id, port2, SAI_VLAN_TAGGING_MODE_UNTAGGED)

        sai_thrift_create_fdb(self.client, vlan_id, mac1, port1, mac_action)
        sai_thrift_create_fdb(self.client, vlan_id, mac2, port2, mac_action)

        counter1_ids, counter1 = sai_thrift_get_vlan_stats(self.client, vlan_id)

        try:
            num_bytes = 0
            num_packets = 200
            random.seed(314159)
            for i in range(0, num_packets):
                pktlen = random.randint(100, 250)
                pkt = simple_tcp_packet(
                                eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.0.0.1',
                                ip_id=101,
                                ip_ttl=64,
                                pktlen=pktlen)

                send_packet(self, 2, str(pkt))
                verify_packets(self, pkt, [1])
                num_bytes += pktlen

            counter2_ids, counter2 = sai_thrift_get_vlan_stats(self.client, vlan_id)

            for i in range(0, len(counter2)):
                counter2[i] = counter2[i] - counter1[i]

            sai_thrift_print_vlan_stats(counter2_ids, counter2)

            self.assertEqual(counter2[SAI_VLAN_STAT_IN_OCTETS], num_bytes)
            self.assertEqual(counter2[SAI_VLAN_STAT_IN_UCAST_PKTS], num_packets)
            #self.assertEqual(counter2[6], num_bytes)
            self.assertEqual(counter2[SAI_VLAN_STAT_OUT_UCAST_PKTS], num_packets)

        finally:
            sai_thrift_delete_fdb(self.client, vlan_id, mac1, port1)
            sai_thrift_delete_fdb(self.client, vlan_id, mac2, port2)

            self.client.sai_thrift_remove_vlan_member(vlan_member1)
            self.client.sai_thrift_remove_vlan_member(vlan_member2)
            self.client.sai_thrift_delete_vlan(vlan_id)

class IPAclStatsTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port 1 -> port 2 (192.168.0.1 -> 10.10.10.1 [id = 101])"
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr1 = '10.10.0.0'
        ip_mask1 = '255.255.0.0'
        dmac1 = '00:11:22:33:44:55'
        nhop1 = sai_thrift_create_nhop(self.client, addr_family, ip_addr1, rif_id1)
        sai_thrift_create_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
        sai_thrift_create_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=63)
        # setup ACL to block based on Source IP
        action_list = [SAI_ACL_ENTRY_ATTR_ACTION_COUNTER, SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION]
        packet_action1 = SAI_PACKET_ACTION_FORWARD
        packet_action2 = SAI_PACKET_ACTION_DROP
        in_ports = [port1, port2]

        ip_dst1 = "10.10.10.1"
        ip_dst1_mask = "255.255.255.255"
        ip_dst2 = "10.10.10.2"
        ip_dst2_mask = "255.255.255.255"

        acl_table_id = sai_thrift_create_acl_table(
                             client = self.client,
                             ip_dst = True,
                             in_ports = True)

        acl_counter_id = sai_thrift_create_acl_counter(
                             client = self.client,
                             acl_table_id = acl_table_id)

        acl_entry1_id = sai_thrift_create_acl_entry(
                             client = self.client,
                             acl_table_id = acl_table_id,
                             action_list = action_list,
                             ip_dst = ip_dst1,
                             ip_dst_mask = ip_dst1_mask,
                             in_ports = in_ports,
                             packet_action = packet_action1,
                             acl_counter_id = acl_counter_id)

        acl_entry2_id = sai_thrift_create_acl_entry(
                             client = self.client,
                             acl_table_id = acl_table_id,
                             action_list = action_list,
                             ip_dst = ip_dst2,
                             ip_dst_mask = ip_dst2_mask,
                             in_ports = in_ports,
                             packet_action = packet_action2,
                             acl_counter_id = acl_counter_id)

        try:

            counter_values1 = sai_thrift_get_acl_counter_attribute(
                             client = self.client,
                             acl_counter_id = acl_counter_id)
            num_bytes = 0
            num_packets = 0
            random.seed(314159)
            for i in range(0, 10):
                pktlen = random.randint(100, 250)
                pkt = simple_tcp_packet(
                        eth_dst='00:77:66:55:44:33',
                        eth_src='00:22:22:22:22:22',
                        ip_dst='10.10.10.1',
                        ip_src='192.168.0.1',
                        ip_id=105,
                        ip_ttl=64,
                        pktlen=pktlen)

                exp_pkt = simple_tcp_packet(
                        eth_dst='00:11:22:33:44:55',
                        eth_src='00:77:66:55:44:33',
                        ip_dst='10.10.10.1',
                        ip_src='192.168.0.1',
                        ip_id=105,
                        ip_ttl=63,
                        pktlen=pktlen)
                send_packet(self, 2, str(pkt))
                verify_packets(self, exp_pkt, [1])
                num_bytes += pktlen
                num_packets += 1

            for i in range(0, 10):
                pktlen = random.randint(100, 250)
                pkt = simple_tcp_packet(
                        eth_dst='00:77:66:55:44:33',
                        eth_src='00:22:22:22:22:22',
                        ip_dst='10.10.10.2',
                        ip_src='192.168.0.1',
                        ip_id=105,
                        ip_ttl=64,
                        pktlen=pktlen)

                exp_pkt = simple_tcp_packet(
                        eth_dst='00:11:22:33:44:55',
                        eth_src='00:77:66:55:44:33',
                        ip_dst='10.10.10.2',
                        ip_src='192.168.0.1',
                        ip_id=105,
                        ip_ttl=63,
                        pktlen=pktlen)
                send_packet(self, 2, str(pkt))
                verify_no_other_packets(self)
                num_bytes += pktlen
                num_packets += 1

            time.sleep(65)
            counter_values2 = sai_thrift_get_acl_counter_attribute(
                             client = self.client,
                             acl_counter_id = acl_counter_id)

            counter_values2[0].u64 = counter_values2[0].u64 - counter_values1[0].u64
            counter_values2[1].u64 = counter_values2[1].u64 - counter_values1[1].u64
            print "ACL stats:"
            print "packets: ", counter_values2[0].u64
            print "bytes: ", counter_values2[1].u64

            self.assertEqual(counter_values2[0].u64, num_packets)
            self.assertEqual(counter_values2[1].u64, num_bytes)

        finally:
            # delete ACL
            self.client.sai_thrift_remove_acl_counter(acl_counter_id)
            self.client.sai_thrift_remove_acl_entry(acl_entry1_id)
            self.client.sai_thrift_remove_acl_entry(acl_entry2_id)
            self.client.sai_thrift_remove_acl_table(acl_table_id)

            # cleanup
            sai_thrift_remove_neighbor(self.client, addr_family, rif_id1, ip_addr1, dmac1)
            sai_thrift_remove_route(self.client, vr_id, addr_family, ip_addr1, ip_mask1, nhop1)
            self.client.sai_thrift_remove_next_hop(nhop1)

            self.client.sai_thrift_remove_router_interface(rif_id1)
            self.client.sai_thrift_remove_router_interface(rif_id2)

            self.client.sai_thrift_remove_virtual_router(vr_id)

class NexthopGetSetTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        port1 = port_list[1]
        port2 = port_list[2]
        v4_enabled = 1
        v6_enabled = 1
        v6_disabled = 0
        mac_valid = 0
        mac = ''

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        rif_id = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)

        addr_family = SAI_IP_ADDR_FAMILY_IPV4
        ip_addr = '10.10.10.1'
        ip_mask = '255.255.255.255'
        nhop = sai_thrift_create_nhop(self.client, addr_family, ip_addr, rif_id)

        # check get returns correct value
        rif_attribute = sai_thrift_attribute_t(id=SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID)
        resp = self.client.sai_thrift_get_next_hop_attribute(nhop, 1, [rif_attribute])
        assert(resp.status == 0)
        assert(resp.attributes[0].value.oid == rif_id)

        # create a new vr_id, rif_id pair for set
        rif_id2 = sai_thrift_create_router_interface(self.client, vr_id, 1, port2, 0, v4_enabled, v6_disabled, mac)
        rif_attribute2 = sai_thrift_attribute_t(id=SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID,
                             value=sai_thrift_attribute_value_t(oid=rif_id2))
        status = self.client.sai_thrift_set_next_hop_attribute(nhop, [rif_attribute2])
        assert(status == 0)

        # get the new value to check if it's right
        resp = self.client.sai_thrift_get_next_hop_attribute(nhop, 1, [rif_attribute])
        assert(resp.status == 0)
        assert(resp.attributes[0].value.oid == rif_id2)

# TODO: ip get/set

        self.client.sai_thrift_remove_next_hop(nhop)
        self.client.sai_thrift_remove_router_interface(rif_id)
        self.client.sai_thrift_remove_router_interface(rif_id2)
        self.client.sai_thrift_remove_virtual_router(vr_id)

class InterfaceGetSetTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        switch_init(self.client)
        port1 = port_list[1]
        v4_enabled = 1
        v6_enabled = 1
        v6_disabled = 0
        mac_valid = 0
        mac = '00:11:22:33:44:55'

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)
        port_rif_id = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)

        # test gets -- these fields are read only
        # vr_id
        vr_id_attribute = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID)
        resp = self.client.sai_thrift_get_router_interface_attribute(port_rif_id, 1, [vr_id_attribute])
        assert(resp.status == 0)
        assert(resp.attributes[0].value.oid == vr_id)

        # port_id
        port_id_attribute = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_PORT_ID)
        resp = self.client.sai_thrift_get_router_interface_attribute(port_rif_id, 1, [port_id_attribute])
        assert(resp.status == 0)
        assert(resp.attributes[0].value.oid == port1)

        # need to create a new interface of type vlan to test vlan id get
        # first delete the old interface
        self.client.sai_thrift_remove_router_interface(port_rif_id)

        vlan_id = 10
        self.client.sai_thrift_create_vlan(vlan_id)
        vlan_rif_id = sai_thrift_create_router_interface(self.client, vr_id, 0, 0, vlan_id, v4_enabled, v6_enabled, mac)

        vlan_id_attribute = sai_thrift_attribute_t(id=SAI_ROUTER_INTERFACE_ATTR_VLAN_ID)
        resp = self.client.sai_thrift_get_router_interface_attribute(vlan_rif_id, 1, [vlan_id_attribute])
        assert(resp.status == 0)
        assert(resp.attributes[0].value.u16 == vlan_id)

# TODO: mac get/set

        self.client.sai_thrift_remove_router_interface(vlan_rif_id)
        self.client.sai_thrift_remove_virtual_router(vr_id)

class PortGetSetTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        pass

class HostIfTest(sai_base_test.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        switch_init(self.client)
        port1 = port_list[1]
        v4_enabled = 1
        v6_enabled = 1
        mac_valid = 0
        mac = ''
        l2_qid = 1
        l2_policer = 2
        l3_qid = 3
        l3_policer = 4

        vr_id = sai_thrift_create_virtual_router(self.client, v4_enabled, v6_enabled)

        rif_id1 = sai_thrift_create_router_interface(self.client, vr_id, 1, port1, 0, v4_enabled, v6_enabled, mac)

        l2_trap_group = sai_thrift_create_hostif_trap_group(self.client, l2_qid, l2_policer)
        l3_trap_group = sai_thrift_create_hostif_trap_group(self.client, l3_qid, l3_policer)

        try:
            trap_id1 = sai_thrift_create_hostif_trap(
                       self.client,
                       SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST,
                       SAI_PACKET_ACTION_TRAP,
                       1000, SAI_HOSTIF_TRAP_CHANNEL_CB,
                       l2_trap_group)

            trap_id2 = sai_thrift_create_hostif_trap(
                       self.client,
                       SAI_HOSTIF_TRAP_TYPE_ARP_RESPONSE,
                       SAI_PACKET_ACTION_TRAP,
                       1001,
                       SAI_HOSTIF_TRAP_CHANNEL_CB,
                       l2_trap_group)

            trap_id3 = sai_thrift_create_hostif_trap(
                       self.client,
                       SAI_HOSTIF_TRAP_TYPE_STP,
                       SAI_PACKET_ACTION_TRAP,
                       1002,
                       SAI_HOSTIF_TRAP_CHANNEL_CB,
                       l2_trap_group)

            trap_id4 = sai_thrift_create_hostif_trap(
                       self.client,
                       SAI_HOSTIF_TRAP_TYPE_OSPF,
                       SAI_PACKET_ACTION_LOG,
                       1003,
                       SAI_HOSTIF_TRAP_CHANNEL_CB,
                       l3_trap_group)

            trap_id5 = sai_thrift_create_hostif_trap(
                       self.client,
                       SAI_HOSTIF_TRAP_TYPE_PIM,
                       SAI_PACKET_ACTION_LOG,
                       1004,
                       SAI_HOSTIF_TRAP_CHANNEL_CB,
                       l3_trap_group)

            trap_id6 = sai_thrift_create_hostif_trap(
                       self.client,
                       SAI_HOSTIF_TRAP_TYPE_IGMP_TYPE_V2_REPORT,
                       SAI_PACKET_ACTION_LOG,
                       1004,
                       SAI_HOSTIF_TRAP_CHANNEL_CB,
                       l3_trap_group)

            pkt = simple_arp_packet(arp_op=1, pktlen=100)
            exp_pkt = simple_cpu_packet(ingress_port=1,
                                        ingress_ifindex=2,
                                        reason_code=0x201,
                                        ingress_bd=2,
                                        inner_pkt = pkt)

            print 'Sending ARP request broadcast'
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [cpu_port])

            pkt = simple_arp_packet(arp_op=2, eth_dst='00:77:66:55:44:33', pktlen=100)
            exp_pkt = simple_cpu_packet(ingress_port=1,
                                        ingress_ifindex=2,
                                        reason_code=0x202,
                                        ingress_bd=2,
                                        inner_pkt = pkt)

            print 'Sending ARP response'
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [cpu_port])

            pkt = simple_ip_packet(ip_proto=89, ip_dst='224.0.0.5')
            exp_pkt = simple_cpu_packet(ingress_port=1,
                                        ingress_ifindex=2,
                                        reason_code=0x204,
                                        ingress_bd=2,
                                        inner_pkt = pkt)

            print 'Sending OSPF packet destined to 224.0.0.5'
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [cpu_port])

            pkt = simple_ip_packet(ip_proto=89, ip_dst='224.0.0.6')
            exp_pkt = simple_cpu_packet(ingress_port=1,
                                        ingress_ifindex=2,
                                        reason_code=0x204,
                                        ingress_bd=2,
                                        inner_pkt = pkt)

            print 'Sending OSPF packet destined to 224.0.0.6'
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [cpu_port])

            pkt = simple_ip_packet(ip_proto=2)
            exp_pkt = simple_cpu_packet(ingress_port=1,
                                        ingress_ifindex=2,
                                        reason_code=0x108,
                                        ingress_bd=2,
                                        inner_pkt = pkt)

            print 'Sending IGMP v2 report'
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [cpu_port])

            pkt = simple_ip_packet(ip_proto=103)
            exp_pkt = simple_cpu_packet(ingress_port=1,
                                        ingress_ifindex=2,
                                        reason_code=0x205,
                                        ingress_bd=2,
                                        inner_pkt = pkt)

            print 'Sending PIM packet'
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [cpu_port])

            pkt = simple_eth_packet(eth_dst='01:80:C2:00:00:00', pktlen=100)
            exp_pkt = simple_cpu_packet(ingress_port=1,
                                        ingress_ifindex=2,
                                        reason_code=0x100,
                                        ingress_bd=2,
                                        inner_pkt = pkt)
            print 'Sending STP packet'
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [cpu_port])

            print 'Deleting hostif reason codes Arp Request/Resp, OSPF, PIM, IGMP and STP'
            self.client.sai_thrift_remove_hostif_trap(trap_id1)
            self.client.sai_thrift_remove_hostif_trap(trap_id2)
            self.client.sai_thrift_remove_hostif_trap(trap_id3)
            self.client.sai_thrift_remove_hostif_trap(trap_id4)
            self.client.sai_thrift_remove_hostif_trap(trap_id5)
            self.client.sai_thrift_remove_hostif_trap(trap_id6)

            print 'Sending ARP request broadcast'
            pkt = simple_arp_packet(arp_op=1, pktlen=100)
            send_packet(self, 1, str(pkt))

            print 'Sending OSPF packet destined to 224.0.0.5'
            pkt = simple_ip_packet(ip_proto=89, ip_dst='224.0.0.5')
            send_packet(self, 1, str(pkt))

            print 'Sending OSPF packet destined to 224.0.0.6'
            pkt = simple_ip_packet(ip_proto=89, ip_dst='224.0.0.6')
            send_packet(self, 1, str(pkt))

            print 'Sending IGMP v2 report'
            pkt = simple_ip_packet(ip_proto=2)
            send_packet(self, 1, str(pkt))

            print 'Sending PIM packet'
            pkt = simple_ip_packet(ip_proto=103)
            send_packet(self, 1, str(pkt))

            print 'Sending STP packet'
            pkt = simple_eth_packet(eth_dst='01:80:C2:00:00:00', pktlen=100)
            send_packet(self, 1, str(pkt))

            verify_no_other_packets(self, timeout=1)

        finally:
            self.client.sai_thrift_remove_hostif_trap_group(l2_trap_group)
            self.client.sai_thrift_remove_hostif_trap_group(l3_trap_group)

            self.client.sai_thrift_remove_router_interface(rif_id1)

            self.client.sai_thrift_remove_virtual_router(vr_id)

