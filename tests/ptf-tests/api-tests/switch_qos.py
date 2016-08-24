"""
Thrift API interface ACL tests
"""

import switch_api_thrift

import time
import sys
import logging

import unittest
import random
import pdb

import ptf.dataplane as dataplane
import api_base_tests

from ptf.testutils import *
from ptf.thriftutils import *


import os

from switch_api_thrift.ttypes import  *
from switch_api_thrift.switch_api_headers import  *

from erspan3 import *

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(this_dir, '..'))
from common.utils import *

device=0
cpu_port=64
swports = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
invalid_hdl = -1

###############################################################################
@group('qos')
class L3IPv4QosDscpRewriteTest(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print
        print "Sending packet port %d" % swports[1], "  -> port %d" % swports[2], "  (192.168.0.1 -> 10.0.0.1 [id = 101])"
        self.client.switcht_api_init(0)
        vrf = self.client.switcht_api_vrf_create(0, 1)

        rmac = self.client.switcht_api_router_mac_group_create(0)
        self.client.switcht_api_router_mac_add(0, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = swports[1])
        i_info1 = switcht_interface_info_t(device=0, type=SWITCH_API_INTERFACE_L3, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(0, i_info1)
        i_ip1 = switcht_ip_addr_t(ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(0, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = swports[2])
        i_info2 = switcht_interface_info_t(device=0, type=SWITCH_API_INTERFACE_L3, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if2 = self.client.switcht_api_interface_create(0, i_info2)
        i_ip2 = switcht_ip_addr_t(ipaddr='10.0.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(0, if2, vrf, i_ip2)

        # Add a static route
        i_ip3 = switcht_ip_addr_t(ipaddr='10.10.10.1', prefix_length=32)
        nhop_key = switcht_nhop_key_t(intf_handle=if2, ip_addr_valid=0)
        nhop = self.client.switcht_api_nhop_create(0, nhop_key)
        neighbor_entry = switcht_neighbor_info_t(nhop_handle=nhop,
                                                 interface_handle=if2,
                                                 mac_addr='00:11:22:33:44:55',
                                                 ip_addr=i_ip3,
                                                 rw_type=SWITCH_API_NEIGHBOR_RW_TYPE_L3)
        neighbor = self.client.switcht_api_neighbor_entry_add(0, neighbor_entry)
        self.client.switcht_api_l3_route_add(0, vrf, i_ip3, nhop)

        qos_map1 = switcht_qos_map_t(dscp=1, tc=11)
        qos_map2 = switcht_qos_map_t(dscp=2, tc=12)
        qos_map3 = switcht_qos_map_t(dscp=3, tc=13)
        qos_map4 = switcht_qos_map_t(dscp=4, tc=14)
        ingress_qos_map_list = [qos_map1, qos_map2, qos_map3, qos_map4]
        ingress_qos_handle = self.client.switcht_api_qos_map_ingress_create(
                             device=0,
                             qos_map_type=SWITCH_QOS_MAP_INGRESS_DSCP_TO_TC,
                             qos_map=ingress_qos_map_list)

        qos_map5 = switcht_qos_map_t(tc=11, icos=1)
        qos_map6 = switcht_qos_map_t(tc=12, icos=2)
        qos_map7 = switcht_qos_map_t(tc=13, icos=3)
        qos_map8 = switcht_qos_map_t(tc=14, icos=4)
        tc_qos_map_list = [qos_map5, qos_map6, qos_map7, qos_map8]
        tc_qos_handle = self.client.switcht_api_qos_map_ingress_create(
                             device=0,
                             qos_map_type=SWITCH_QOS_MAP_INGRESS_TC_TO_ICOS,
                             qos_map=tc_qos_map_list)

        qos_map9 = switcht_qos_map_t(tc=11, dscp=10)
        qos_map10 = switcht_qos_map_t(tc=12, icos=20)
        qos_map11 = switcht_qos_map_t(tc=13, icos=30)
        qos_map12 = switcht_qos_map_t(tc=14, icos=40)
        egress_qos_map_list = [qos_map9, qos_map10, qos_map11, qos_map12]
        egress_qos_handle = self.client.switcht_api_qos_map_egress_create(
                             device=0,
                             qos_map_type=SWITCH_QOS_MAP_EGRESS_TC_TO_DSCP,
                             qos_map=egress_qos_map_list)

        self.client.switcht_api_port_qos_group_ingress_set(device=0, port_handle=1, qos_handle=ingress_qos_handle)
        self.client.switcht_api_port_qos_group_tc_set(device=0, port_handle=1, qos_handle=tc_qos_handle)
        self.client.switcht_api_port_qos_group_egress_set(device=0, port_handle=1, qos_handle=egress_qos_handle)
        self.client.switcht_api_port_trust_dscp_set(device=0, port_handle=1, trust_dscp=True)

        self.client.switcht_api_port_qos_group_ingress_set(device=0, port_handle=2, qos_handle=ingress_qos_handle)
        self.client.switcht_api_port_qos_group_tc_set(device=0, port_handle=2, qos_handle=tc_qos_handle)
        self.client.switcht_api_port_qos_group_egress_set(device=0, port_handle=2, qos_handle=egress_qos_handle)
        self.client.switcht_api_port_trust_dscp_set(device=0, port_handle=2, trust_dscp=True)

        # send the test packet(s)
        # send the test packet(s)
        pkt = simple_tcp_packet( eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_tos=1,
                                ip_ttl=64)
        send_packet(self, swports[1], str(pkt))

        exp_pkt = simple_tcp_packet(
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_tos=10,
                                ip_ttl=63)
        verify_packets(self, exp_pkt, [swports[2]])

        #cleanup
        self.client.switcht_api_port_qos_group_ingress_set(device=0, port_handle=1, qos_handle=0)
        self.client.switcht_api_port_qos_group_tc_set(device=0, port_handle=1, qos_handle=0)
        self.client.switcht_api_port_qos_group_egress_set(device=0, port_handle=1, qos_handle=0)
        self.client.switcht_api_port_trust_dscp_set(device=0, port_handle=1, trust_dscp=False)

        self.client.switcht_api_port_qos_group_ingress_set(device=0, port_handle=2, qos_handle=0)
        self.client.switcht_api_port_qos_group_tc_set(device=0, port_handle=2, qos_handle=0)
        self.client.switcht_api_port_qos_group_egress_set(device=0, port_handle=2, qos_handle=0)
        self.client.switcht_api_port_trust_dscp_set(device=0, port_handle=2, trust_dscp=False)

        self.client.switcht_api_qos_map_ingress_delete(device=0, qos_map_handle=ingress_qos_handle)
        self.client.switcht_api_qos_map_ingress_delete(device=0, qos_map_handle=tc_qos_handle)
        self.client.switcht_api_qos_map_egress_delete(device=0, qos_map_handle=egress_qos_handle)

        self.client.switcht_api_neighbor_entry_remove(0, neighbor)
        self.client.switcht_api_nhop_delete(0, nhop)
        self.client.switcht_api_l3_route_delete(0, vrf, i_ip3, if2)

        self.client.switcht_api_l3_interface_address_delete(0, if1, vrf, i_ip1)
        self.client.switcht_api_l3_interface_address_delete(0, if2, vrf, i_ip2)

        self.client.switcht_api_interface_delete(0, if1)
        self.client.switcht_api_interface_delete(0, if2)

        self.client.switcht_api_router_mac_delete(0, rmac, '00:77:66:55:44:33')
        self.client.switcht_api_router_mac_group_delete(0, rmac)
        self.client.switcht_api_vrf_delete(0, vrf)

###############################################################################
