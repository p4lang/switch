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

from erspan3 import *

this_dir = os.path.dirname(os.path.abspath(__file__))

sys.path.append(os.path.join(this_dir, '..'))
from common.utils import *


device=0
cpu_port=64
swports = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
invalid_hdl = -1

###############################################################################
@group('sflow')
class TestSflow_session(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print "Create/Delete sflow sessions Test"
        s_hdls = []
        # create 16 sessions (max allowed = 16)
        for s in range (0,16):
            print "Create sflow session ", s
            sflow_info1 = switcht_sflow_info_t(timeout_usec = 100,
                                            sample_rate = 100+s, #5
                                            extract_len = 80,
                                            collector_type = 0, #CPU
                                            egress_port_hdl = cpu_port);

            sf_hdl = self.client.switcht_api_sflow_session_create(device, sflow_info1)
            assert(sf_hdl != invalid_hdl)
            print "hdl = ",  sf_hdl
            s_hdls.append(sf_hdl)
        # create 17th session - should fail
        sflow_info1 = switcht_sflow_info_t(timeout_usec = 100,
                                            sample_rate = 1000,
                                            extract_len = 80,
                                            collector_type = 0, #CPU
                                            egress_port_hdl = cpu_port);
        sf_hdl = self.client.switcht_api_sflow_session_create(device, sflow_info1)
        print "hdl = ", sf_hdl
        assert(sf_hdl == invalid_hdl)

        # delete 2 sessions, create 2 sessions
        print "Delete a few sessions"
        self.client.switcht_api_sflow_session_delete(device, s_hdls[0], 0)
        self.client.switcht_api_sflow_session_delete(device, s_hdls[7], 0)
        print "Re-create a few sessions"
        s_hdls[0] = self.client.switcht_api_sflow_session_create(device, sflow_info1)
        assert(s_hdls[0] != invalid_hdl)
        s_hdls[7] = self.client.switcht_api_sflow_session_create(device, sflow_info1)
        assert(s_hdls[7] != invalid_hdl)

        # delete all sessions
        for s in range (0,16):
            self.client.switcht_api_sflow_session_delete(device, s_hdls[s], 0)
        print "Done"

###############################################################################
@group('sflow')
class TestSflow_ingress_port(api_base_tests.ThriftInterfaceDataPlane):
    def runTest(self):
        print "Test sflow based on ingress port using packet on port %d" % swports[1], "  -> port %d" % swports[2], "  (192.168.0.1 -> 10.0.0.1 [id = 101])"
        self.client.switcht_api_init(0)
        vrf = self.client.switcht_api_vrf_create(0, 1)

        rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(0, rmac, '00:77:66:55:44:33')

        iu1 = interface_union(port_lag_handle = swports[1])
        i_info1 = switcht_interface_info_t(device, type=4, u=iu1, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
        if1 = self.client.switcht_api_interface_create(0, i_info1)
        i_ip1 = switcht_ip_addr_t(ipaddr='192.168.0.2', prefix_length=16)
        self.client.switcht_api_l3_interface_address_add(0, if1, vrf, i_ip1)

        iu2 = interface_union(port_lag_handle = swports[2])
        i_info2 = switcht_interface_info_t(device, type=4, u=iu2, mac='00:77:66:55:44:33', label=0, vrf_handle=vrf, rmac_handle=rmac)
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
                                                 rw_type=1)
        neighbor = self.client.switcht_api_neighbor_entry_add(0, neighbor_entry)
        self.client.switcht_api_l3_route_add(0, vrf, i_ip3, nhop)

        # create an sflow session
        print "Create sflow session"
        sflow_info1 = switcht_sflow_info_t(timeout_usec = 100,
                                            sample_rate = 1,
                                            extract_len = 0,
                                            collector_type = 0, #CPU
                                            egress_port_hdl = cpu_port);

        sflow1 = self.client.switcht_api_sflow_session_create(device, sflow_info1)

        # attach sflow session to ingress port 1
        # create kvp to match ingress port
        print "Attach sflow session to port 1"
        kvp = []
        kvp_val = switcht_acl_value_t(value_num=if1)
        kvp_mask = switcht_acl_value_t(value_num=0xffffffff)
        kvp.append(switcht_acl_key_value_pair_t(0, kvp_val, kvp_mask))
        flow_hdl1 = self.client.switcht_api_sflow_session_attach(device, sflow1, 1, 0, 0, kvp)

        print "Attach sflow session to port 2"
        kvp = []
        kvp_val = switcht_acl_value_t(value_num=if2)
        kvp_mask = switcht_acl_value_t(value_num=0xffffffff)
        kvp.append(switcht_acl_key_value_pair_t(0, kvp_val, kvp_mask))
        flow_hdl2 = self.client.switcht_api_sflow_session_attach(device, sflow1, 1, 0, 0, kvp)

        # create and send the test packet(s)
        pkt = simple_tcp_packet(pktlen=100,
                                eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)

        exp_pkt = simple_tcp_packet(
                                pktlen=100,
                                eth_dst='00:11:22:33:44:55',
                                eth_src='00:77:66:55:44:33',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=63)

        exp_pkt_sflow = simple_tcp_packet(
                                pktlen = 100,
                                eth_dst='00:77:66:55:44:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.10.10.1',
                                ip_src='192.168.0.1',
                                ip_id=105,
                                ip_ttl=64)

        sflow_sid = sflow1 & 0x03FFFFFF             # handle_to_id
        flow_id = flow_hdl1 & 0x03FFFFFF
        print "sflow sid = %d, flow_id %d" % (sflow_sid, flow_id)
        exp_pkt_sflow = simple_cpu_packet(
                                          ingress_ifindex = 2,
                                          ingress_bd = 2,
                                          ingress_port = 1,
                                          reason_code=0x4,
                                          sflow_sid=sflow_sid,
                                          sflow_egress_port=3,
                                          inner_pkt=pkt)

        for i in range(0,1):
            send_packet(self, 1, str(pkt))
            verify_packet(self, exp_pkt, swports[2])
            verify_packet(self, exp_pkt_sflow, cpu_port)

        print "Get sflow session sample pool count"
        stats = self.client.switcht_api_sflow_session_sample_count_get(0, sflow1, flow_hdl1)
        self.assertEqual(stats.num_packets, 1)
        print stats

        print "Reset sflow session sample pool count"
        self.client.switcht_api_sflow_session_sample_count_reset(0, sflow1, flow_hdl1)
        stats = self.client.switcht_api_sflow_session_sample_count_get(0, sflow1, flow_hdl1)
        self.assertEqual(stats.num_packets, 0)
        print stats

        print "Detach sflow Session"
        self.client.switcht_api_sflow_session_detach(device, sflow1, flow_hdl1)
        # make sure pkts are not sent to cpu anymore
        send_packet(self, 1, str(pkt))
        verify_packet(self, exp_pkt, swports[2])
        verify_no_other_packets(self)

        print "Delete sflow Session"
        print "Attach more sflow sessions before deletion"
        kvp = []
        kvp_val = switcht_acl_value_t(value_num=if1)
        kvp_mask = switcht_acl_value_t(value_num=0xffffffff)
        kvp.append(switcht_acl_key_value_pair_t(0, kvp_val, kvp_mask))
        flow_hdl1 = self.client.switcht_api_sflow_session_attach(device, sflow1, 1, 0, 0, kvp)

        self.client.switcht_api_sflow_session_delete(device, sflow1, 1)
        #cleanup
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
