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
Thrift PD interface basic tests
"""

import time
import sys
import logging

import unittest
import random

import pd_base_tests

from ptf.testutils import *
from ptf.thriftutils import *

import os

from p4_pd_rpc.ttypes import *
from res_pd_rpc.ttypes import *
from mc_pd_rpc.ttypes import *

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(this_dir, '..'))
from common.utils import *
from common.pd_utils import *

#global defaults
inner_rmac_group = 1
outer_rmac_group = 2
smac_index = 1
rewrite_index = 1
vrf = 1
rmac = '00:33:33:33:33:33'

#Enable features based on p4src/p4feature.h
tunnel_enabled =1
ipv6_enabled = 1
acl_enabled = 1
multicast_enabled = 1
stats_enabled = 1
int_enabled = 1
learn_timeout = 6

#Basic L2 Test case
@group("L2Test")
class L2Test(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc")

    def runTest(self):
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        device = 0

        client_init(self.client, sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt, ipv6_enabled,
                                acl_enabled, tunnel_enabled, multicast_enabled,
                                int_enabled)
        ret_init = populate_init_entries(self.client, sess_hdl, dev_tgt,
                                        rewrite_index, rmac, inner_rmac_group,
                                        outer_rmac_group, ipv6_enabled, tunnel_enabled)

        #Create two ports
        ret_list = program_ports(self.client, sess_hdl, dev_tgt, 2)

        vlan=10
        port1=1
        port2=2
        v4_enabled=0
        v6_enabled=0

        # Add bd entry
        vlan_hdl = program_bd(self.client, sess_hdl, dev_tgt, vlan, 0)

        #Add ports to vlan
        #port vlan able programs (port, vlan) mapping and derives the bd
        hdl1, mbr_hdl1 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, vlan, port1,
                                              v4_enabled, v6_enabled, 0, 0,
                                              ctag=None, stag=None, rid=0)

        hdl2, mbr_hdl2 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, vlan, port2,
                                              v4_enabled, v6_enabled, 0, 0,
                                              ctag=None, stag=None, rid=0)

        #Add static macs to ports. (vlan, mac -> port)
        dmac_hdl1, smac_hdl1 = program_mac(self.client, sess_hdl, dev_tgt, vlan, '00:11:11:11:11:11', 1)
        dmac_hdl2, smac_hdl2 = program_mac(self.client, sess_hdl, dev_tgt, vlan, '00:22:22:22:22:22', 2)

        self.conn_mgr.complete_operations(sess_hdl)

        print "Sending packet port 1 -> port 2 on vlan 10 (192.168.0.1 -> 10.0.0.1 [id = 101])"
        pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                eth_src='00:11:11:11:11:11',
                                ip_dst='10.0.0.1',
                                ip_src='192.168.0.1',
                                ip_id=101,
                                ip_ttl=64,
                                ip_ihl=5)
        try:
            send_packet(self, 1, str(pkt))
            verify_packets(self, pkt, [2])
        finally:
            delete_default_entries(self.client, sess_hdl, device)

            delete_mac(self.client, sess_hdl, device, dmac_hdl2, smac_hdl2)
            delete_mac(self.client, sess_hdl, device, dmac_hdl1, smac_hdl1)

            delete_vlan_mapping(self.client, sess_hdl, device, hdl2, mbr_hdl2)
            delete_vlan_mapping(self.client, sess_hdl, device, hdl1, mbr_hdl1)

            # delete BD
            delete_bd(self.client, sess_hdl, device, vlan_hdl)

            # delete ports
            delete_ports(self.client, sess_hdl, device, 2, ret_list)

            # delete  init and default entries
            delete_init_entries(self.client, sess_hdl, device, ret_init,
                                tunnel_enabled)

            self.conn_mgr.complete_operations(sess_hdl)
            self.conn_mgr.client_cleanup(sess_hdl)


#Basic L3 Test case
class L3Ipv4Test(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc")

    def runTest(self):
        print
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        device = 0

        client_init(self.client, sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt, ipv6_enabled,
                                acl_enabled, tunnel_enabled, multicast_enabled,
                                int_enabled)
        ret_init = populate_init_entries(self.client, sess_hdl, dev_tgt,
                                        rewrite_index, rmac, inner_rmac_group,
                                        outer_rmac_group, ipv6_enabled, tunnel_enabled)

        #Create two ports
        ret_list = program_ports(self.client, sess_hdl, dev_tgt, 2)

        vlan1=10
        vlan2=11
        port1=1
        port2=2
        v4_enabled=1
        v6_enabled=0

        # Add bd entry
        vlan_hdl1 = program_bd(self.client, sess_hdl, dev_tgt, vlan1, 0)
        vlan_hdl2 = program_bd(self.client, sess_hdl, dev_tgt, vlan2, 0)

        #For every L3 port, an implicit vlan will be allocated
        #Add ports to vlan
        #Outer vlan table programs (port, vlan) mapping and derives the bd
        #Inner vlan table derives the bd state
        hdl1, mbr_hdl1 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, vlan1, port1,
                                              v4_enabled, v6_enabled,
                                              inner_rmac_group, 0,
                                              ctag=None, stag=None, rid=0)
        hdl2, mbr_hdl2 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, vlan2, port2,
                                              v4_enabled, v6_enabled,
                                              inner_rmac_group, 0,
                                              ctag=None, stag=None, rid=0)

        #Create nexthop
        nhop1=1
        nhop_hdl1 = program_nexthop(self.client, sess_hdl, dev_tgt, nhop1, vlan1, port1, 0)
        #Add rewrite information (ARP info)
        arp_hdl1 = program_ipv4_unicast_rewrite(self.client, sess_hdl, dev_tgt, vlan1, nhop1, '00:11:11:11:11:11')
        egress_bd_hdl1 = program_egress_bd_properties(self.client, sess_hdl,
                                                      dev_tgt, vlan1, rewrite_index)
        #Add route
        route_hdl1 = program_ipv4_route(self.client, sess_hdl, dev_tgt, vrf, 0x0a0a0a01, 32, nhop1)
        #Create nexthop
        nhop2=2
        nhop_hdl2 = program_nexthop(self.client, sess_hdl, dev_tgt, nhop2, vlan2, port2, 0)
        #Add rewrite information (ARP info)
        arp_hdl2 = program_ipv4_unicast_rewrite(self.client, sess_hdl, dev_tgt, vlan2, nhop2, '00:22:22:22:22:22')
        egress_bd_hdl2 = program_egress_bd_properties(self.client, sess_hdl,
                                                      dev_tgt, vlan2, rewrite_index)
        #Add route
        route_hdl2 = program_ipv4_route(self.client, sess_hdl, dev_tgt, vrf, 0x14141401, 32, nhop2)

        print "Sending packet port 1 -> port 2 (10.10.10.1 -> 20.20.20.1 [id = 101])"
        self.conn_mgr.complete_operations(sess_hdl)

        pkt = simple_tcp_packet(eth_dst='00:33:33:33:33:33',
                                eth_src='00:11:11:11:11:11',
                                ip_dst='20.20.20.1',
                                ip_src='10.10.10.1',
                                ip_id=101,
                                ip_ttl=64,
                                ip_ihl=5)
        exp_pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                eth_src='00:33:33:33:33:33',
                                ip_dst='20.20.20.1',
                                ip_src='10.10.10.1',
                                ip_id=101,
                                ip_ttl=63,
                                ip_ihl=5)
        try:
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [2])
        finally:
            delete_default_entries(self.client, sess_hdl, device)
            delete_egress_bd_properties(self.client, sess_hdl, device, egress_bd_hdl1)
            delete_egress_bd_properties(self.client, sess_hdl, device, egress_bd_hdl2)

            delete_ipv4_route(self.client, sess_hdl, device, 32, route_hdl2)
            delete_ipv4_unicast_rewrite(self.client, sess_hdl, device, arp_hdl2)
            delete_nexthop(self.client, sess_hdl, device, nhop_hdl2)

            delete_ipv4_route(self.client, sess_hdl, device, 32, route_hdl1)
            delete_ipv4_unicast_rewrite(self.client, sess_hdl, device, arp_hdl1)
            delete_nexthop(self.client, sess_hdl, device, nhop_hdl1)

            delete_vlan_mapping(self.client, sess_hdl, device, hdl2, mbr_hdl2)
            delete_vlan_mapping(self.client, sess_hdl, device, hdl1, mbr_hdl1)

            delete_bd(self.client, sess_hdl, device, vlan_hdl1)
            delete_bd(self.client, sess_hdl, device, vlan_hdl2)

            # delete ports
            delete_ports(self.client, sess_hdl, device, 2, ret_list)

            # delete  init and default entries
            delete_init_entries(self.client, sess_hdl, device, ret_init,
                                tunnel_enabled)

            self.conn_mgr.complete_operations(sess_hdl)
            self.conn_mgr.client_cleanup(sess_hdl)


class L3Ipv6Test(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc")

    def runTest(self):
        print
        if ipv6_enabled == 0:
            print "ipv6 not enabled"
            return

        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        device = 0

        client_init(self.client, sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt, ipv6_enabled,
                                acl_enabled, tunnel_enabled, multicast_enabled,
                                int_enabled)
        ret_init = populate_init_entries(self.client, sess_hdl, dev_tgt,
                                        rewrite_index, rmac, inner_rmac_group,
                                        outer_rmac_group, ipv6_enabled, tunnel_enabled)

        #Create two ports
        ret_list = program_ports(self.client, sess_hdl, dev_tgt, 2)

        vlan1=10
        vlan2=11
        port1=1
        port2=2
        v4_enabled=0
        v6_enabled=1

        # Add bd entry
        vlan_hdl1 = program_bd(self.client, sess_hdl, dev_tgt, vlan1, 0)
        vlan_hdl2 = program_bd(self.client, sess_hdl, dev_tgt, vlan2, 0)

        #For every L3 port, an implicit vlan will be allocated
        #Add ports to vlan
        #Outer vlan table programs (port, vlan) mapping and derives the bd
        #Inner vlan table derives the bd state
        hdl1, mbr_hdl1 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, vlan1, port1,
                                              v4_enabled, v6_enabled,
                                              inner_rmac_group, 0,
                                              ctag=None, stag=None, rid=0)
        hdl2, mbr_hdl2 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, vlan2, port2,
                                              v4_enabled, v6_enabled,
                                              inner_rmac_group, 0,
                                              ctag=None, stag=None, rid=0)

        #Create nexthop
        nhop1=1
        nhop_hdl1 = program_nexthop(self.client, sess_hdl, dev_tgt, nhop1, vlan1, port1, 0)
        #Add rewrite information (ARP info)
        arp_hdl1 = program_ipv6_unicast_rewrite(self.client, sess_hdl, dev_tgt,
                                                vlan1, nhop1, '00:11:11:11:11:11', ipv6_enabled)
        egress_bd_hdl1 = program_egress_bd_properties(self.client, sess_hdl,
                                                      dev_tgt, vlan1, rewrite_index)
        #Add route
        route_hdl1 = program_ipv6_route(self.client, sess_hdl, dev_tgt, vrf,
                                        '2000::1', 128, nhop1, ipv6_enabled)
        #Create nexthop
        nhop2=2
        nhop_hdl2 = program_nexthop(self.client, sess_hdl, dev_tgt, nhop2, vlan2, port2, 0)
        #Add rewrite information (ARP info)
        arp_hdl2 = program_ipv6_unicast_rewrite(self.client, sess_hdl, dev_tgt,
                                                vlan2, nhop2, '00:22:22:22:22:22', ipv6_enabled)
        egress_bd_hdl2 = program_egress_bd_properties(self.client, sess_hdl,
                                                      dev_tgt, vlan2, rewrite_index)
        #Add route
        route_hdl2 = program_ipv6_route(self.client, sess_hdl, dev_tgt, vrf,
                                        '3000::1', 128, nhop2, ipv6_enabled)

        print "Sending packet port 1 -> port 2 (10.10.10.1 -> 20.20.20.1 [id = 101])"
        self.conn_mgr.complete_operations(sess_hdl)

        pkt = simple_tcpv6_packet(eth_dst='00:33:33:33:33:33',
                                eth_src='00:11:11:11:11:11',
                                ipv6_dst='3000::1',
                                ipv6_src='2000::1',
                                ipv6_hlim=64)
        exp_pkt = simple_tcpv6_packet(eth_dst='00:22:22:22:22:22',
                                eth_src='00:33:33:33:33:33',
                                ipv6_dst='3000::1',
                                ipv6_src='2000::1',
                                ipv6_hlim=63)
        try:
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [2])
        finally:

            delete_default_entries(self.client, sess_hdl, device)

            delete_egress_bd_properties(self.client, sess_hdl, device, egress_bd_hdl1)
            delete_egress_bd_properties(self.client, sess_hdl, device, egress_bd_hdl2)

            delete_ipv6_route(self.client, sess_hdl, device, 128, route_hdl2,
                              ipv6_enabled)
            delete_ipv6_unicast_rewrite(self.client, sess_hdl, device,
                                        arp_hdl2, ipv6_enabled)
            delete_nexthop(self.client, sess_hdl, device, nhop_hdl2)

            delete_ipv6_route(self.client, sess_hdl, device, 128, route_hdl1,
                              ipv6_enabled)
            delete_ipv6_unicast_rewrite(self.client, sess_hdl, device,
                                        arp_hdl1, ipv6_enabled)
            delete_nexthop(self.client, sess_hdl, device, nhop_hdl1)

            delete_vlan_mapping(self.client, sess_hdl, device, hdl2, mbr_hdl2)
            delete_vlan_mapping(self.client, sess_hdl, device, hdl1, mbr_hdl1)

            delete_bd(self.client, sess_hdl, device, vlan_hdl1)
            delete_bd(self.client, sess_hdl, device, vlan_hdl2)

            # delete ports
            delete_ports(self.client, sess_hdl, device, 2, ret_list)

            # delete  init and default entries
            delete_init_entries(self.client, sess_hdl, device, ret_init,
                                tunnel_enabled)

            self.conn_mgr.complete_operations(sess_hdl)
            self.conn_mgr.client_cleanup(sess_hdl)


#Basic Vxlan Tunneling Test case
class L2VxlanTunnelTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc")

    def runTest(self):
        print
        if tunnel_enabled == 0:
            print "tunnel not enabled"
            return

        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        device = 0

        client_init(self.client, sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt, ipv6_enabled,
                                acl_enabled, tunnel_enabled, multicast_enabled,
                                int_enabled)
        ret_init = populate_init_entries(self.client, sess_hdl, dev_tgt,
                                        rewrite_index, rmac, inner_rmac_group,
                                        outer_rmac_group, ipv6_enabled, tunnel_enabled)

        #Create two ports
        ret_list = program_ports(self.client, sess_hdl, dev_tgt, 2)

        port1=1
        port2=2
        outer_v4_enabled=1
        inner_v4_enabled=0
        outer_v6_enabled=0
        inner_v6_enabled=0
        core_vlan=10
        tenant_vlan=1000
        vnid=0x1234
        tunnel_index = 0
        sip_index = 0
        dip_index = 0
        smac_index = 0
        dmac_index = 0
        tunnel_type=1 #vxlan

        #Indicates vxlan tunnel in Parser
        ingress_tunnel_type=1
        egress_tunnel_type=1

        # Add bd entry
        vlan_hdl1 = program_bd(self.client, sess_hdl, dev_tgt, core_vlan, 0)
        vlan_hdl2 = program_bd(self.client, sess_hdl, dev_tgt, tenant_vlan, 0)

        #Port2 belong to core vlan
        #Outer vlan table will derive core bd and the src vtep, dest vtep and vnid will derive the tenant bd
        hdl1, mbr_hdl1 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, core_vlan, port2,
                                              outer_v4_enabled, outer_v6_enabled,
                                              outer_rmac_group, 0,
                                              ctag=None, stag=None, rid=0)
        tun_hdl = program_tunnel_ethernet_vlan(self.client, sess_hdl, dev_tgt,
                                               vrf, tenant_vlan, port2, vnid,
                                               ingress_tunnel_type,
                                               inner_v4_enabled, 0)

        #Port1 belong to tenant vlan
        #Outer vlan table will derive tenant bd and inner bd table will derive bd state
        hdl2, mbr_hdl2 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, tenant_vlan, port1,
                                              inner_v4_enabled, inner_v6_enabled,
                                              0, 0,
                                              ctag=None, stag=None, rid=0)

        #Add static macs to ports. (vlan, mac -> port)
        #Nextop should be created during mac lookup when the destinaion interface is a tunnel.
        #Nexthop allocated will derive egress bd in the ingress and derive rewrite info
        # at egress
        nhop=1
        dmac_hdl1, smac_hdl1 = program_mac(self.client, sess_hdl, dev_tgt, tenant_vlan, '00:11:11:11:11:11', port1)
        dmac_hdl2, smac_hdl2 = program_mac_with_nexthop(self.client, sess_hdl, dev_tgt, tenant_vlan, '00:22:22:22:22:22', port2, nhop)

        #add nexthop table
        nhop_hdl1 = program_nexthop(self.client, sess_hdl, dev_tgt, nhop, tenant_vlan, port2, 1)

        encap1, encap2 = program_tunnel_encap(self.client, sess_hdl, dev_tgt)
        decap1, decap2 = program_tunnel_decap(self.client, sess_hdl, dev_tgt)

        tun_src = program_tunnel_src_ipv4_rewrite(self.client, sess_hdl, dev_tgt, sip_index, 0x0a0a0a01)
        tun_dst = program_tunnel_dst_ipv4_rewrite(self.client, sess_hdl, dev_tgt, dip_index, 0x0a0a0a02)
        tun_smac = program_tunnel_src_mac_rewrite(self.client, sess_hdl, dev_tgt, smac_index, '00:33:33:33:33:33')
        tun_dmac = program_tunnel_dst_mac_rewrite(self.client, sess_hdl, dev_tgt, dmac_index, '00:55:55:55:55:55')
        tun_l2 = program_tunnel_l2_unicast_rewrite(self.client, sess_hdl, dev_tgt, tunnel_index, tunnel_type, nhop, core_vlan)
        tun_rewrite = program_tunnel_rewrite(self.client, sess_hdl, dev_tgt, tunnel_index, sip_index, dip_index, smac_index, dmac_index, core_vlan)
        tun_svtep = program_tunnel_ipv4_src_vtep(self.client, sess_hdl, dev_tgt, vrf, 0x0a0a0a02, 0)
        tun_dvtep = program_tunnel_ipv4_dst_vtep(self.client, sess_hdl, dev_tgt, vrf, 0x0a0a0a01, 1)
        tun_vni = program_egress_vni(self.client, sess_hdl, dev_tgt, egress_tunnel_type, tenant_vlan, vnid)

        self.conn_mgr.complete_operations(sess_hdl)

        #Egress Tunnel Decap - Decapsulate the vxlan header

        print "Sending packet port 1 -> port 2 - Vxlan tunnel encap"
        print "Inner packet (192.168.10.1 -> 192.168.20.2 [id = 101])"
        print "Outer packet (10.10.10.1 -> 10.10.10.2 [vnid = 0x1234, id = 101])"
        pkt1 = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                eth_src='00:11:11:11:11:11',
                                ip_dst='192.168.10.2',
                                ip_src='192.168.10.1',
                                ip_id=101,
                                ip_ttl=64)
        udp_sport = entropy_hash(pkt1)
        vxlan_pkt1 = simple_vxlan_packet(
                                eth_dst='00:55:55:55:55:55',
                                eth_src='00:33:33:33:33:33',
                                ip_id=0,
                                ip_dst='10.10.10.2',
                                ip_src='10.10.10.1',
                                ip_ttl=64,
                                udp_sport=udp_sport,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                inner_frame=pkt1)

        print "Sending packet port 2 -> port 1 - Vxlan tunnel decap"
        print "Inner packet (192.168.10.2 -> 192.168.20.1 [id = 101])"
        print "Outer packet (10.10.10.2 -> 10.10.10.1 [vnid = 0x1234, id = 101])"
        pkt2 = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='192.168.10.1',
                                ip_src='192.168.10.2',
                                ip_id=101,
                                ip_ttl=64)
        vxlan_pkt2 = simple_vxlan_packet(
                                eth_dst='00:33:33:33:33:33',
                                eth_src='00:55:55:55:55:55',
                                ip_id=0,
                                ip_dst='10.10.10.1',
                                ip_src='10.10.10.2',
                                ip_ttl=63,
                                udp_sport=4966,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                inner_frame=pkt2)
        try:
            send_packet(self, 1, str(pkt1))
            verify_packets(self, vxlan_pkt1, [2])

            send_packet(self, 2, str(vxlan_pkt2))
            verify_packets(self, pkt2, [1])
        finally:
            delete_default_entries(self.client, sess_hdl, device)
            delete_egress_vni(self.client, sess_hdl, device, tun_vni)
            delete_tunnel_ipv4_dst_vtep(self.client, sess_hdl, device, tun_dvtep)
            delete_tunnel_ipv4_src_vtep(self.client, sess_hdl, device, tun_svtep)
            delete_tunnel_rewrite(self.client, sess_hdl, device, tun_rewrite)
            delete_tunnel_l2_unicast_rewrite(self.client, sess_hdl, device, tun_l2)
            delete_tunnel_dst_mac_rewrite(self.client, sess_hdl, device, tun_dmac)
            delete_tunnel_src_mac_rewrite(self.client, sess_hdl, device, tun_smac)
            delete_tunnel_dst_ipv4_rewrite(self.client, sess_hdl, device, tun_dst)
            delete_tunnel_src_ipv4_rewrite(self.client, sess_hdl, device, tun_src)

            delete_tunnel_decap(self.client, sess_hdl, device, decap1, decap2)
            delete_tunnel_encap(self.client, sess_hdl, device, encap1, encap2)

            delete_nexthop(self.client, sess_hdl, device, nhop_hdl1)

            delete_mac(self.client, sess_hdl, device, dmac_hdl2, smac_hdl2)
            delete_mac(self.client, sess_hdl, device, dmac_hdl1, smac_hdl1)

            delete_vlan_mapping(self.client, sess_hdl, device, hdl2, mbr_hdl2)
            delete_tunnel_ethernet_vlan(self.client, sess_hdl, device, tun_hdl)
            delete_vlan_mapping(self.client, sess_hdl, device, hdl1, mbr_hdl1)

            delete_bd(self.client, sess_hdl, device, vlan_hdl1)
            delete_bd(self.client, sess_hdl, device, vlan_hdl2)

            # delete ports
            delete_ports(self.client, sess_hdl, device, 2, ret_list)

            # delete  init and default entries
            delete_init_entries(self.client, sess_hdl, device, ret_init,
                                tunnel_enabled)

            self.conn_mgr.complete_operations(sess_hdl)
            self.conn_mgr.client_cleanup(sess_hdl)


class L3VxlanTunnelTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc")

    def runTest(self):
        print
        if tunnel_enabled == 0:
            print "tunnel not enabled"
            return
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        device = 0

        client_init(self.client, sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt, ipv6_enabled,
                                acl_enabled, tunnel_enabled, multicast_enabled,
                                int_enabled)
        ret_init = populate_init_entries(self.client, sess_hdl, dev_tgt,
                                        rewrite_index, rmac, inner_rmac_group,
                                        outer_rmac_group, ipv6_enabled, tunnel_enabled)

        #Create two ports
        ret_list = program_ports(self.client, sess_hdl, dev_tgt, 2)

        port1=1
        port2=2
        outer_v4_enabled=1
        inner_v4_enabled=1
        outer_v6_enabled=0
        inner_v6_enabled=0
        core_vlan=10
        tenant_vlan1=1000
        tenant_vlan2=2000
        vnid=0x1234
        tunnel_index = 0
        sip_index = 0
        dip_index = 0
        smac_index = 0
        dmac_index = 0

        #Indicates vxlan tunnel in Parser
        ingress_tunnel_type=1
        egress_tunnel_type=1

        # Add bd entry
        vlan_hdl1 = program_bd(self.client, sess_hdl, dev_tgt, core_vlan, 0)
        vlan_hdl2 = program_bd(self.client, sess_hdl, dev_tgt, tenant_vlan1, 0)
        vlan_hdl3 = program_bd(self.client, sess_hdl, dev_tgt, tenant_vlan2, 0)

        #Port2 belong to core vlan
        #Outer vlan table will derive core bd and the src vtep, dest vtep and vnid will derive the tenant bd
        hdl1, mbr_hdl1 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, core_vlan, port2, outer_v4_enabled,
                                              outer_v6_enabled,
                                              outer_rmac_group, 0,
                                              ctag=None, stag=None, rid=0)
        tun_hdl = program_tunnel_ipv4_vlan(self.client, sess_hdl, dev_tgt,
                                           tenant_vlan2, port2, vnid,
                                           ingress_tunnel_type, inner_v4_enabled,
                                           inner_rmac_group, vrf)

        #Port1 belong to tenant vlan
        #Outer vlan table will derive tenant bd and inner bd table will derive bd state
        hdl2, mbr_hdl2 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, tenant_vlan1, port1,
                                              inner_v4_enabled, inner_v6_enabled,
                                              inner_rmac_group, 0,
                                              ctag=None, stag=None, rid=0)

        #Add egress bd properties
        egress_bd_hdl1 = program_egress_bd_properties(self.client, sess_hdl,
                                                      dev_tgt, tenant_vlan1, rewrite_index)
        egress_bd_hdl2 = program_egress_bd_properties(self.client, sess_hdl,
                                                      dev_tgt, tenant_vlan2, rewrite_index)
        #Add L3 routes
        nhop1=1
        nhop2=2
        route_hdl1 = program_ipv4_route(self.client, sess_hdl, dev_tgt, vrf, 0x0aa80a01, 32, nhop1)
        route_hdl2 = program_ipv4_route(self.client, sess_hdl, dev_tgt, vrf, 0x0aa80b01, 32, nhop2)

        #Add nexthop table
        nhop_hdl1 = program_nexthop(self.client, sess_hdl, dev_tgt, nhop1, tenant_vlan1, port1, 1)
        arp_hdl1 = program_ipv4_unicast_rewrite(self.client, sess_hdl, dev_tgt, tenant_vlan1, nhop1, '00:11:11:11:11:11')

        nhop_hdl2 = program_nexthop(self.client, sess_hdl, dev_tgt, nhop2, tenant_vlan2, port2, 1)

        encap1, encap2 = program_tunnel_encap(self.client, sess_hdl, dev_tgt)
        decap1, decap2 = program_tunnel_decap(self.client, sess_hdl, dev_tgt)
        tun_src = program_tunnel_src_ipv4_rewrite(self.client, sess_hdl, dev_tgt, sip_index, 0x0a0a0a01)
        tun_dst = program_tunnel_dst_ipv4_rewrite(self.client, sess_hdl, dev_tgt, dip_index, 0x0a0a0a02)
        tun_smac = program_tunnel_src_mac_rewrite(self.client, sess_hdl, dev_tgt, smac_index, '00:33:33:33:33:33')
        tun_dmac = program_tunnel_dst_mac_rewrite(self.client, sess_hdl, dev_tgt, dmac_index, '00:55:55:55:55:55')
        tun_l3 = program_tunnel_l3_unicast_rewrite(self.client, sess_hdl, dev_tgt, tunnel_index, egress_tunnel_type, nhop2, tenant_vlan2, '00:22:22:22:22:22')
        tun_rewrite = program_tunnel_rewrite(self.client, sess_hdl, dev_tgt, tunnel_index, sip_index, dip_index, smac_index, dmac_index, core_vlan)
        tun_svtep = program_tunnel_ipv4_src_vtep(self.client, sess_hdl, dev_tgt, vrf, 0x0a0a0a02, 0)
        tun_dvtep = program_tunnel_ipv4_dst_vtep(self.client, sess_hdl, dev_tgt, vrf, 0x0a0a0a01, 1)
        tun_vni = program_egress_vni(self.client, sess_hdl, dev_tgt, egress_tunnel_type, tenant_vlan2, vnid)

        self.conn_mgr.complete_operations(sess_hdl)


        print "Sending packet port 1 -> port 2 - Vxlan tunnel encap"
        print "Inner packet (10.168.10.1 -> 10.168.11.1 [id = 101])"
        print "Outer packet (10.10.10.1 -> 10.10.10.2 [vnid = 0x1234, id = 101])"
        pkt1 = simple_tcp_packet(eth_dst='00:33:33:33:33:33',
                                eth_src='00:11:11:11:11:11',
                                ip_dst='10.168.11.1',
                                ip_src='10.168.10.1',
                                ip_id=101,
                                ip_ttl=64)

        pkt2 = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                                eth_src='00:33:33:33:33:33',
                                ip_dst='10.168.11.1',
                                ip_src='10.168.10.1',
                                ip_id=101,
                                ip_ttl=63)

        udp_sport = entropy_hash(pkt1)
        vxlan_pkt1 = simple_vxlan_packet(
                                eth_dst='00:55:55:55:55:55',
                                eth_src='00:33:33:33:33:33',
                                ip_id=0,
                                ip_dst='10.10.10.2',
                                ip_src='10.10.10.1',
                                ip_ttl=64,
                                udp_sport=udp_sport,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                inner_frame=pkt2)

        print "Sending packet port 2 -> port 1 - Vxlan tunnel decap"
        print "Inner packet (10.168.11.1 -> 10.168.10.1 [id = 101])"
        print "Outer packet (10.10.10.2 -> 10.10.10.1 [vnid = 0x1234, id = 101])"
        pkt3 = simple_tcp_packet(eth_dst='00:33:33:33:33:33',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.168.10.1',
                                ip_src='10.168.11.1',
                                ip_id=101,
                                ip_ttl=64)
        vxlan_pkt2 = simple_vxlan_packet(
                                eth_dst='00:33:33:33:33:33',
                                eth_src='00:55:55:55:55:55',
                                ip_id=0,
                                ip_dst='10.10.10.1',
                                ip_src='10.10.10.2',
                                ip_ttl=64,
                                udp_sport=14479,
                                with_udp_chksum=False,
                                vxlan_vni=0x1234,
                                inner_frame=pkt3)

        pkt4 = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                                eth_src='00:33:33:33:33:33',
                                ip_dst='10.168.10.1',
                                ip_src='10.168.11.1',
                                ip_id=101,
                                ip_ttl=63)

        try:
            send_packet(self, 1, str(pkt1))
            verify_packets(self, vxlan_pkt1, [2])
            send_packet(self, 2, str(vxlan_pkt2))
            verify_packets(self, pkt4, [1])
        finally:
            delete_default_entries(self.client, sess_hdl, device)
            delete_egress_bd_properties(self.client, sess_hdl, device, egress_bd_hdl1)
            delete_egress_bd_properties(self.client, sess_hdl, device, egress_bd_hdl2)
            delete_egress_vni(self.client, sess_hdl, device, tun_vni)
            delete_tunnel_ipv4_dst_vtep(self.client, sess_hdl, device, tun_dvtep)
            delete_tunnel_ipv4_src_vtep(self.client, sess_hdl, device, tun_svtep)
            delete_tunnel_rewrite(self.client, sess_hdl, device, tun_rewrite)
            delete_tunnel_l3_unicast_rewrite(self.client, sess_hdl, device, tun_l3)
            delete_tunnel_dst_mac_rewrite(self.client, sess_hdl, device, tun_dmac)
            delete_tunnel_src_mac_rewrite(self.client, sess_hdl, device, tun_smac)
            delete_tunnel_dst_ipv4_rewrite(self.client, sess_hdl, device, tun_dst)
            delete_tunnel_src_ipv4_rewrite(self.client, sess_hdl, device, tun_src)

            delete_tunnel_decap(self.client, sess_hdl, device, decap1, decap2)
            delete_tunnel_encap(self.client, sess_hdl, device, encap1, encap2)

            delete_ipv4_route(self.client, sess_hdl, device, 32, route_hdl2)
            delete_nexthop(self.client, sess_hdl, device, nhop_hdl2)

            delete_ipv4_route(self.client, sess_hdl, device, 32, route_hdl1)
            delete_ipv4_unicast_rewrite(self.client, sess_hdl, device, arp_hdl1)
            delete_nexthop(self.client, sess_hdl, device, nhop_hdl1)

            delete_vlan_mapping(self.client, sess_hdl, device, hdl2, mbr_hdl2)
            delete_tunnel_ipv4_vlan(self.client, sess_hdl, device, tun_hdl)
            delete_vlan_mapping(self.client, sess_hdl, device, hdl1, mbr_hdl1)

            # delete BD
            delete_bd(self.client, sess_hdl, device, vlan_hdl3)
            delete_bd(self.client, sess_hdl, device, vlan_hdl2)
            delete_bd(self.client, sess_hdl, device, vlan_hdl1)

            # delete ports
            delete_ports(self.client, sess_hdl, device, 2, ret_list)

            # delete  init and default entries
            delete_init_entries(self.client, sess_hdl, device, ret_init,
                                tunnel_enabled)

            self.conn_mgr.complete_operations(sess_hdl)
            self.conn_mgr.client_cleanup(sess_hdl)


class L2LearningTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc")

    def runTest(self):
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        device = 0

        client_init(self.client, sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt, ipv6_enabled,
                                acl_enabled, tunnel_enabled, multicast_enabled,
                                int_enabled)
        ret_init = populate_init_entries(self.client, sess_hdl, dev_tgt,
                                        rewrite_index, rmac, inner_rmac_group,
                                        outer_rmac_group, ipv6_enabled, tunnel_enabled)

        #Create two ports
        ret_list = program_ports(self.client, sess_hdl, dev_tgt, 2)

        vlan=10
        port1=1
        port2=2
        v4_enabled=0
        v6_enabled=0

        # Add bd entry
        vlan_hdl = program_bd(self.client, sess_hdl, dev_tgt, vlan, 0)

        #Add ports to vlan
        #Outer vlan table programs (port, vlan) mapping and derives the bd
        #Inner vlan table derives the bd state
        hdl1, mbr_hdl1 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, vlan, port1,
                                              v4_enabled, v6_enabled, 0, 1,
                                              ctag=None, stag=None, rid=0)
        hdl2, mbr_hdl2 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, vlan, port2, v4_enabled,
                                              v6_enabled, 0, 1,
                                              ctag=None, stag=None, rid=0)

        dmac_hdl1, smac_hdl1 = program_mac(self.client, sess_hdl, dev_tgt, vlan, '00:44:44:44:44:44', 2)

        enable_learning(self.client, sess_hdl, dev_tgt)

        self.client.set_learning_timeout(sess_hdl, 0, learn_timeout * 1000)
        self.client.mac_learn_digest_register(sess_hdl, 0)

        self.conn_mgr.complete_operations(sess_hdl)

        pkt = simple_tcp_packet(eth_dst='00:44:44:44:44:44',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.168.10.1',
                                ip_src='10.168.11.1',
                                ip_id=101,
                                ip_ttl=64)
        try:
            send_packet(self, 1, str(pkt))
            time.sleep(learn_timeout + 1)
            digests = self.client.mac_learn_digest_get_digest(sess_hdl)
            assert len(digests.msg) == 1
            mac_str = digests.msg[0].l2_metadata_lkp_mac_sa
            print "new mac learnt ", mac_str,
            print "on port ", digests.msg[0].ingress_metadata_ifindex
        finally:
            delete_default_entries(self.client, sess_hdl, device)
            self.client.mac_learn_digest_digest_notify_ack(sess_hdl, digests.msg_ptr)
            self.client.mac_learn_digest_deregister(sess_hdl, 0)

            delete_mac(self.client, sess_hdl, device, dmac_hdl1, smac_hdl1)

            delete_vlan_mapping(self.client, sess_hdl, device, hdl2, mbr_hdl2)
            delete_vlan_mapping(self.client, sess_hdl, device, hdl1, mbr_hdl1)

            delete_bd(self.client, sess_hdl, device, vlan_hdl)

            # delete ports
            delete_ports(self.client, sess_hdl, device, 2, ret_list)

            # delete  init and default entries
            delete_init_entries(self.client, sess_hdl, device, ret_init,
                                tunnel_enabled)

            self.conn_mgr.complete_operations(sess_hdl)
            self.conn_mgr.client_cleanup(sess_hdl)


@group("L2FloodTest")
class L2FloodTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __str__(self):
        return self.id()

    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc")

    def runTest(self):
        sess_hdl = self.conn_mgr.client_init(16)
        mc_sess_hdl = self.mc.mc_create_session()
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        device = 0

        client_init(self.client, sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt, ipv6_enabled,
                                acl_enabled, tunnel_enabled, multicast_enabled,
                                int_enabled)
        ret_init = populate_init_entries(self.client, sess_hdl, dev_tgt,
                                        rewrite_index, rmac, inner_rmac_group,
                                        outer_rmac_group, ipv6_enabled, tunnel_enabled)

        #Create ports
        ret_list = program_ports(self.client, sess_hdl, dev_tgt, 4)

        vlan=10
        port1=1
        port2=2
        port3=3
        port4=4
        v4_enabled=0
        v6_enabled=0
        mgid = 0x100
        rid = 0x200

        # Add bd entry
        vlan_hdl = program_bd(self.client, sess_hdl, dev_tgt, vlan, mgid)

        #Add ports to vlan
        hdl1, mbr_hdl1 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, vlan, port1,
                                              v4_enabled, v6_enabled, 0, 0,
                                              ctag=None, stag=None, rid=rid)
        hdl2, mbr_hdl2 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, vlan, port2,
                                              v4_enabled, v6_enabled, 0, 0,
                                              ctag=None, stag=None, rid=rid)
        hdl3, mbr_hdl3 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, vlan, port3,
                                              v4_enabled, v6_enabled, 0, 0,
                                              ctag=None, stag=None, rid=rid)
        hdl4, mbr_hdl4 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, vlan, port4,
                                              v4_enabled, v6_enabled, 0, 0,
                                              ctag=None, stag=None, rid=rid)

        rid_hdl = program_rid(self.client, sess_hdl, dev_tgt,
                              rid=rid, inner_replica=True,
                              bd=vlan, tunnel_index=0, tunnel_type=0,
                              header_count=0)

        port_map = set_port_or_lag_bitmap(256, [port1, port2, port3, port4])
        lag_map = set_port_or_lag_bitmap(256, [])
        mgrp_hdl = self.mc.mc_mgrp_create(mc_sess_hdl, 0, mgid)
        node_hdl = self.mc.mc_node_create(mc_sess_hdl, 0, rid, port_map, lag_map)
        self.mc.mc_associate_node(mc_sess_hdl, dev_tgt.dev_id, mgrp_hdl, node_hdl)

        self.mc.mc_complete_operations(mc_sess_hdl)
        self.conn_mgr.complete_operations(sess_hdl)

        pkt = simple_tcp_packet(eth_dst='00:44:44:44:44:44',
                                eth_src='00:22:22:22:22:22',
                                ip_dst='10.168.10.1',
                                ip_src='10.168.11.1',
                                ip_id=101,
                                ip_ttl=64)

        try:
            send_packet(self, port1, str(pkt))
            verify_packets(self, pkt, [port2, port3, port4])
        finally:
            delete_default_entries(self.client, sess_hdl, device)
            self.mc.mc_dissociate_node(mc_sess_hdl, device, mgrp_hdl, node_hdl)
            self.mc.mc_node_destroy(mc_sess_hdl, device, node_hdl)
            self.mc.mc_mgrp_destroy(mc_sess_hdl, device, mgrp_hdl)

            # delete port_vlan entries
            delete_vlan_mapping(self.client, sess_hdl, device, hdl4, mbr_hdl4)
            delete_vlan_mapping(self.client, sess_hdl, device, hdl3, mbr_hdl3)
            delete_vlan_mapping(self.client, sess_hdl, device, hdl2, mbr_hdl2)
            delete_vlan_mapping(self.client, sess_hdl, device, hdl1, mbr_hdl1)

            # delete rid
            delete_rid(self.client, sess_hdl, device, rid_hdl)

            # delete BD
            delete_bd(self.client, sess_hdl, device, vlan_hdl)

            # delete ports
            delete_ports(self.client, sess_hdl, device, 4, ret_list)

            # delete  init and default entries
            delete_init_entries(self.client, sess_hdl, device, ret_init,
                                tunnel_enabled)

            self.mc.mc_destroy_session(mc_sess_hdl)
            self.conn_mgr.complete_operations(sess_hdl)
            self.conn_mgr.client_cleanup(sess_hdl)


class L2QinQTest(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, "dc")

    def runTest(self):
        print
        sess_hdl = self.conn_mgr.client_init(16)
        dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        device = 0

        client_init(self.client, sess_hdl, dev_tgt)

        #Add the default entries
        populate_default_entries(self.client, sess_hdl, dev_tgt, ipv6_enabled,
                                acl_enabled, tunnel_enabled, multicast_enabled,
                                int_enabled)
        ret_init = populate_init_entries(self.client, sess_hdl, dev_tgt,
                                        rewrite_index, rmac, inner_rmac_group,
                                        outer_rmac_group, ipv6_enabled, tunnel_enabled)

        #Create two ports
        ret_list = program_ports(self.client, sess_hdl, dev_tgt, 2)

        vlan=10
        port1=1
        port2=2
        v4_enabled=0
        v6_enabled=0

        # Add bd entry
        vlan_hdl = program_bd(self.client, sess_hdl, dev_tgt, vlan, 0)

        #Add ports to vlan
        #port vlan able programs (port, vlan) mapping and derives the bd
        hdl1, mbr_hdl1 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, vlan, port1,
                                              v4_enabled, v6_enabled, 0, 0,
                                              ctag=10, stag=20, rid=0)

        hdl2, mbr_hdl2 = program_vlan_mapping(self.client, sess_hdl, dev_tgt,
                                              vrf, vlan, port2,
                                              v4_enabled, v6_enabled, 0, 0,
                                              ctag=None, stag=None, rid=0)

        xlate_hdl = program_egress_vlan_xlate(self.client, sess_hdl, dev_tgt,
                                              port1, 10, ctag=10, stag=20)

        #Add static macs to ports. (vlan, mac -> port)
        dmac_hdl1, smac_hdl1 = program_mac(self.client, sess_hdl, dev_tgt, vlan, '00:11:11:11:11:11', 1)
        dmac_hdl2, smac_hdl2 = program_mac(self.client, sess_hdl, dev_tgt, vlan, '00:22:22:22:22:22', 2)

        self.conn_mgr.complete_operations(sess_hdl)

        pkt = simple_qinq_tcp_packet(eth_dst='00:22:22:22:22:22',
                              eth_src='00:11:11:11:11:11',
                              dl_vlan_outer=20,
                              dl_vlan_pcp_outer=0,
                              dl_vlan_cfi_outer=0,
                              vlan_vid=10,
                              vlan_pcp=0,
                              dl_vlan_cfi=0,
                              ip_dst='10.0.0.1',
                              ip_src='192.168.0.1',
                              ip_ttl=64,
                              pktlen=100)
        exp_pkt = simple_tcp_packet(eth_dst='00:22:22:22:22:22',
                              eth_src='00:11:11:11:11:11',
                              ip_dst='10.0.0.1',
                              ip_src='192.168.0.1',
                              ip_ttl=64,
                              pktlen=100-8)
        pkt[Ether].type = 0x9100

        pkt2 = simple_tcp_packet(eth_dst='00:11:11:11:11:11',
                              eth_src='00:22:22:22:22:22',
                              ip_dst='10.0.0.1',
                              ip_src='192.168.0.1',
                              ip_ttl=64,
                              pktlen=100-8)
        exp_pkt2 = simple_qinq_tcp_packet(eth_dst='00:11:11:11:11:11',
                              eth_src='00:22:22:22:22:22',
                              dl_vlan_outer=20,
                              dl_vlan_pcp_outer=0,
                              dl_vlan_cfi_outer=0,
                              vlan_vid=10,
                              vlan_pcp=0,
                              dl_vlan_cfi=0,
                              ip_dst='10.0.0.1',
                              ip_src='192.168.0.1',
                              ip_ttl=64,
                              pktlen=100)
        exp_pkt2[Ether].type = 0x9100
        try:
            print "Sending packet port 1 (QinQ) -> port 2 (Untagged)"
            send_packet(self, 1, str(pkt))
            verify_packets(self, exp_pkt, [2])
            print "Sending packet port 2 (Untagged) -> port 2 (QinQ)"
            send_packet(self, 2, str(pkt2))
            verify_packets(self, exp_pkt2, [1])
        finally:
            delete_default_entries(self.client, sess_hdl, device)
            delete_mac(self.client, sess_hdl, device, dmac_hdl2, smac_hdl2)
            delete_mac(self.client, sess_hdl, device, dmac_hdl1, smac_hdl1)

            delete_egress_vlan_xlate(self.client, sess_hdl, device, xlate_hdl)

            delete_vlan_mapping(self.client, sess_hdl, device, hdl2, mbr_hdl2)
            delete_vlan_mapping(self.client, sess_hdl, device, hdl1, mbr_hdl1)

            # delete BD
            delete_bd(self.client, sess_hdl, device, vlan_hdl)

            # delete ports
            delete_ports(self.client, sess_hdl, device, 2, ret_list)

            # delete  init and default entries
            delete_init_entries(self.client, sess_hdl, device, ret_init,
                                tunnel_enabled)

            self.conn_mgr.complete_operations(sess_hdl)
            self.conn_mgr.client_cleanup(sess_hdl)

