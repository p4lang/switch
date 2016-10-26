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

switch_inited=0
port_list = []
table_attr_list = []

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

class L3IPv4QosDscpRewriteTest(sai_base_test.ThriftInterfaceDataPlane):
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

        ingress_dscp_list = [1, 2, 3, 4]
        ingress_tc_list = [11, 12, 13, 14]
        ingress_qos_map_id = sai_thrift_create_qos_map(self.client, SAI_QOS_MAP_TYPE_DSCP_TO_TC, ingress_dscp_list, ingress_tc_list)

        ingress_tc_list = [11, 12, 13, 14]
        ingress_queue_list = [1, 2, 3, 4]
        tc_qos_map_id = sai_thrift_create_qos_map(self.client, SAI_QOS_MAP_TYPE_TC_TO_QUEUE, ingress_tc_list, ingress_queue_list)

        egress_tc_and_color_list = [[11, 0], [12, 0], [13, 0,], [14, 0]]
        egress_dscp_list = [10, 20, 30, 40]
        egress_qos_map_id = sai_thrift_create_qos_map(self.client, SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DSCP, egress_tc_and_color_list, egress_dscp_list)

        sai_thrift_set_port_attribute(self.client, port1, SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP, ingress_qos_map_id)
        sai_thrift_set_port_attribute(self.client, port1, SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP, tc_qos_map_id)
        sai_thrift_set_port_attribute(self.client, port1, SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DSCP_MAP, egress_qos_map_id)

        sai_thrift_set_port_attribute(self.client, port2, SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP, ingress_qos_map_id)
        sai_thrift_set_port_attribute(self.client, port2, SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP, tc_qos_map_id)
        sai_thrift_set_port_attribute(self.client, port2, SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DSCP_MAP, egress_qos_map_id)

        # send the test packet(s)
        pkt = simple_tcp_packet(eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_tos=1,
                                ip_id=105,
                                ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_tos=10,
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
