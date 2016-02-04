"""
IP multicast tests
"""

import switch_api_thrift

import os
import time
import sys
import logging

import unittest
import random

import api_base_tests

from ptf.testutils import *
from ptf.thriftutils import *

from switch_api_thrift.ttypes import  *

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(this_dir, '..'))
from common.utils import *

device=0
cpu_port=64
swports = [x for x in range(65)]

###############################################################################
@group('mcast')
class L3Multicast(api_base_tests.ThriftInterfaceDataPlane):
    def setUp(self):
        print
        print 'Configuring devices for L3 multicast test cases'

        api_base_tests.ThriftInterfaceDataPlane.setUp(self)
        self.client.switcht_api_init(device)

        self.vrf = self.client.switcht_api_vrf_create(device, 2)
        self.rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, self.rmac,
                                               '00:77:66:55:44:33')

        # vlans: 10, 100, 200
        self.vlan1 = self.client.switcht_api_vlan_create(device, 10)
        self.vlan2 = self.client.switcht_api_vlan_create(device, 100)
        self.vlan3 = self.client.switcht_api_vlan_create(device, 200)

        # disable learning
        self.client.switcht_api_vlan_learning_enabled_set(self.vlan1, 0)
        self.client.switcht_api_vlan_learning_enabled_set(self.vlan2, 0)
        self.client.switcht_api_vlan_learning_enabled_set(self.vlan3, 0)

        # enable igmp snooping on vlan3
        self.client.switcht_api_vlan_igmp_snooping_enabled_set(self.vlan3, 1)

        # port 0: access port in vlan 10
        iu1 = interface_union(port_lag_handle=swports[0])
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1,
                                           mac='00:77:66:55:44:33', label=0)
        self.if1 = self.client.switcht_api_interface_create(device, i_info1)
        self.pv1 = switcht_vlan_port_t(handle=self.if1, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, self.vlan1, self.pv1)

        # port 1: trunk port; allowed vlans: 10, 100, 200
        iu2 = interface_union(port_lag_handle=swports[1])
        i_info2 = switcht_interface_info_t(device=0, type=3, u=iu2,
                                           mac='00:77:66:55:44:33', label=0)
        self.if2 = self.client.switcht_api_interface_create(device, i_info2)
        self.pv2 = switcht_vlan_port_t(handle=self.if2, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, self.vlan1, self.pv2)
        self.client.switcht_api_vlan_ports_add(device, self.vlan2, self.pv2)
        self.client.switcht_api_vlan_ports_add(device, self.vlan3, self.pv2)

        # port 2: access port in vlan 100
        iu3 = interface_union(port_lag_handle=swports[2])
        i_info3 = switcht_interface_info_t(device=0, type=2, u=iu3,
                                           mac='00:77:66:55:44:33', label=0)
        self.if3 = self.client.switcht_api_interface_create(device, i_info3)
        self.pv3 = switcht_vlan_port_t(handle=self.if3, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, self.vlan2, self.pv3)

        # port 3: routed port
        iu4 = interface_union(port_lag_handle = swports[3])
        i_info4 = switcht_interface_info_t(device=0, type=4, u=iu4,
                                           mac='00:77:66:55:44:33', label=0,
                                           vrf_handle=self.vrf,
                                           rmac_handle=self.rmac,
                                           v4_multicast_enabled=1,
                                           v6_multicast_enabled=1)
        self.if4 = self.client.switcht_api_interface_create(device, i_info4)
        self.ip4 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.250.1',
                                     prefix_length=24)
        self.client.switcht_api_l3_interface_address_add(device, self.if4,
                                                         self.vrf, self.ip4)

        # port 4: routed port
        iu5 = interface_union(port_lag_handle = swports[4])
        i_info5 = switcht_interface_info_t(device=0, type=4, u=iu5,
                                           mac='00:77:66:55:44:33', label=0,
                                           vrf_handle=self.vrf,
                                           rmac_handle=self.rmac,
                                           v4_multicast_enabled=1,
                                           v6_multicast_enabled=1)
        self.if5 = self.client.switcht_api_interface_create(device, i_info5)
        self.ip5 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.251.1',
                                     prefix_length=24)
        self.client.switcht_api_l3_interface_address_add(device, self.if5,
                                                         self.vrf, self.ip5)

        # port 5: trunk port; allowed vlans: 10, 100, 200
        iu6 = interface_union(port_lag_handle=swports[5])
        i_info6 = switcht_interface_info_t(device=0, type=3, u=iu6,
                                           mac='00:77:66:55:44:33', label=0)
        self.if6 = self.client.switcht_api_interface_create(device, i_info6)
        self.pv6 = switcht_vlan_port_t(handle=self.if6, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, self.vlan1, self.pv6)
        self.client.switcht_api_vlan_ports_add(device, self.vlan2, self.pv6)
        self.client.switcht_api_vlan_ports_add(device, self.vlan3, self.pv6)

        # port 6: trunk port; allowed vlans: 10, 100, 200
        iu7 = interface_union(port_lag_handle=swports[6])
        i_info7 = switcht_interface_info_t(device=0, type=3, u=iu7,
                                           mac='00:77:66:55:44:33', label=0)
        self.if7 = self.client.switcht_api_interface_create(device, i_info7)
        self.pv7 = switcht_vlan_port_t(handle=self.if7, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, self.vlan1, self.pv7)
        self.client.switcht_api_vlan_ports_add(device, self.vlan2, self.pv7)
        self.client.switcht_api_vlan_ports_add(device, self.vlan3, self.pv7)

        # port 7: trunk port; allowed vlans: 10, 100, 200
        iu8 = interface_union(port_lag_handle=swports[7])
        i_info8 = switcht_interface_info_t(device=0, type=3, u=iu8,
                                           mac='00:77:66:55:44:33', label=0)
        self.if8 = self.client.switcht_api_interface_create(device, i_info8)
        self.pv8 = switcht_vlan_port_t(handle=self.if8, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, self.vlan1, self.pv8)
        self.client.switcht_api_vlan_ports_add(device, self.vlan2, self.pv8)
        self.client.switcht_api_vlan_ports_add(device, self.vlan3, self.pv8)

        # Create L3 virtual interface for vlan 10
        iu = interface_union(vlan_id=10)
        i_info = switcht_interface_info_t(device=0, type=5, u=iu,
                                          mac='00:77:66:55:44:33',
                                          label=0, vrf_handle=self.vrf,
                                          rmac_handle=self.rmac,
                                          v4_unicast_enabled=1,
                                          v6_unicast_enabled=1,
                                          v4_multicast_enabled=1,
                                          v6_multicast_enabled=1)
        self.if20 = self.client.switcht_api_interface_create(device, i_info)
        self.ip20 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.10.1',
                                      prefix_length=24)
        self.client.switcht_api_l3_interface_address_add(device, self.if20,
                                                         self.vrf, self.ip20)

        # Create L3 virtual interface for vlan 100
        iu = interface_union(vlan_id=100)
        i_info = switcht_interface_info_t(device=0, type=5, u=iu,
                                          mac='00:77:66:55:44:33',
                                          label=0, vrf_handle=self.vrf,
                                          rmac_handle=self.rmac,
                                          v4_unicast_enabled=1,
                                          v6_unicast_enabled=1,
                                          v4_multicast_enabled=1,
                                          v6_multicast_enabled=1)
        self.if21 = self.client.switcht_api_interface_create(device, i_info)
        self.ip21 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.100.1',
                                      prefix_length=24)
        self.client.switcht_api_l3_interface_address_add(device, self.if21,
                                                         self.vrf, self.ip21)

        # Create L3 virtual interface for vlan 200
        iu = interface_union(vlan_id=200)
        i_info = switcht_interface_info_t(device=0, type=5, u=iu,
                                          mac='00:77:66:55:44:33',
                                          label=0, vrf_handle=self.vrf,
                                          rmac_handle=self.rmac,
                                          v4_unicast_enabled=1,
                                          v6_unicast_enabled=1,
                                          v4_multicast_enabled=1,
                                          v6_multicast_enabled=1)
        self.if22 = self.client.switcht_api_interface_create(device, i_info)
        self.ip22 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.200.1',
                                      prefix_length=24)
        self.client.switcht_api_l3_interface_address_add(device, self.if22,
                                                         self.vrf, self.ip22)

        # logical network
        ln_flags = switcht_ln_flags(ipv4_unicast_enabled=1,
                                    ipv4_multicast_enabled=1)
        ln_info = switcht_logical_network_t(type=5, age_interval=1800,
                                            vrf=self.vrf,
                                            rmac_handle=self.rmac,
                                            flags=ln_flags)
        self.ln1 = self.client.switcht_api_logical_network_create(device,
                                                                  ln_info)

        # tunnel interface
        udp = switcht_udp_t(src_port=0, dst_port=4789)
        src_ip = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.10.1',
                                   prefix_length=32)
        dst_ip = switcht_ip_addr_t(addr_type=0, ipaddr='235.0.2.2',
                                   prefix_length=32)
        vxlan = switcht_vxlan_id_t(vnid=0x5768)
        bt = switcht_bridge_type(vxlan_info=vxlan)
        encap_info = switcht_encap_info_t(encap_type=3, u=bt)
        udp_tcp = switcht_udp_tcp_t(udp=udp)
        ip_encap =  switcht_ip_encap_t(vrf=self.vrf, src_ip=src_ip,
                                       dst_ip=dst_ip, ttl=60, proto=17,
                                       u=udp_tcp)
        tunnel_encap = switcht_tunnel_encap_t(ip_encap=ip_encap)
        iu = switcht_tunnel_info_t(encap_mode=0, tunnel_encap=tunnel_encap,
                                   encap_info=encap_info, out_if=self.if5)
        self.tif1 = self.client.switcht_api_tunnel_interface_create(device,
                                                                    0, iu)

        # add tunnel to logical network
        self.client.switcht_api_logical_network_member_add(device, self.ln1,
                                                           self.tif1)

        # neighbor on tunnel interface
        neigh_info = switcht_neighbor_info_t(nhop_handle=0,
                                             interface_handle=self.tif1,
                                             mac_addr='01:00:5e:00:02:02',
                                             ip_addr=src_ip)
        self.neigh1 = self.client.switcht_api_neighbor_entry_add(device,
                                                                 neigh_info)

        # create inner multicast tree
        self.mch1 = self.client.switcht_api_multicast_tree_create(device)

        # vlan ports
        self.route_ports = [switcht_vlan_interface_t(vlan_handle=self.vlan1,
                                                     intf_handle=self.if1),
                            switcht_vlan_interface_t(vlan_handle=self.vlan1,
                                                     intf_handle=self.if2),
                            switcht_vlan_interface_t(vlan_handle=self.vlan1,
                                                     intf_handle=self.if6),
                            switcht_vlan_interface_t(vlan_handle=self.vlan1,
                                                     intf_handle=self.if7),
                            switcht_vlan_interface_t(vlan_handle=self.vlan1,
                                                     intf_handle=self.if8),
                            switcht_vlan_interface_t(vlan_handle=self.vlan2,
                                                     intf_handle=self.if2),
                            switcht_vlan_interface_t(vlan_handle=self.vlan2,
                                                     intf_handle=self.if3),
                            switcht_vlan_interface_t(vlan_handle=self.vlan2,
                                                     intf_handle=self.if6),
                            switcht_vlan_interface_t(vlan_handle=self.vlan2,
                                                     intf_handle=self.if7),
                            switcht_vlan_interface_t(vlan_handle=self.vlan2,
                                                     intf_handle=self.if8),
                            switcht_vlan_interface_t(vlan_handle=self.vlan3,
                                                     intf_handle=self.if6),
                            switcht_vlan_interface_t(vlan_handle=self.vlan3,
                                                     intf_handle=self.if7),
                            switcht_vlan_interface_t(vlan_handle=self.vlan3,
                                                     intf_handle=self.if8),
                            switcht_vlan_interface_t(vlan_handle=0,
                                                     intf_handle=self.if4),
                            switcht_vlan_interface_t(vlan_handle=0,
                                                     intf_handle=self.if5),
                            switcht_vlan_interface_t(vlan_handle=self.ln1,
                                                     intf_handle=self.tif1)]
        self.client.switcht_api_multicast_member_add(device, self.mch1,
                                                     self.route_ports)

        # create a ip multicast route (10.0.10.5,230.1.1.5)
        self.msrc_ip1 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.10.5',
                                         prefix_length=32)
        self.mgrp_ip1 = switcht_ip_addr_t(addr_type=0, ipaddr='230.1.1.5',
                                         prefix_length=32)
        rpflist = [ self.vlan1 ]
        self.client.switcht_api_multicast_mroute_add(device, self.mch1,
                                                     self.vrf,
                                                     self.msrc_ip1,
                                                     self.mgrp_ip1, 1,
                                                     rpflist, len(rpflist))

        # create (outer) ip multicast route (*,235.0.2.2)
        self.msrc_ip2 = switcht_ip_addr_t(addr_type=0, ipaddr='0.0.0.0',
                                          prefix_length=0)
        self.mgrp_ip2 = switcht_ip_addr_t(addr_type=0, ipaddr='235.0.2.2',
                                          prefix_length=32)
        rpflist = [ self.if5 ]
        self.client.switcht_api_multicast_mroute_add(device, 0,
                                                     self.vrf,
                                                     self.msrc_ip2,
                                                     self.mgrp_ip2, 1,
                                                     rpflist, len(rpflist))

        # create (inner) ip multicast route (*,230.1.1.6)
        self.msrc_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='0.0.0.0',
                                         prefix_length=0)
        self.mgrp_ip3 = switcht_ip_addr_t(addr_type=0, ipaddr='230.1.1.6',
                                         prefix_length=32)
        rpflist = [ self.ln1 ]
        self.client.switcht_api_multicast_mroute_add(device, self.mch1,
                                                     self.vrf,
                                                     self.msrc_ip3,
                                                     self.mgrp_ip3, 1,
                                                     rpflist, len(rpflist))

        # create a snooping entry for vlan 200
        self.mch2 = self.client.switcht_api_multicast_tree_create(device)
        # vlan 200 ports
        self.snoop_ports = [switcht_vlan_interface_t(vlan_handle=self.vlan3,
                                                     intf_handle=self.if6),
                            switcht_vlan_interface_t(vlan_handle=self.vlan3,
                                                     intf_handle=self.if7),
                            switcht_vlan_interface_t(vlan_handle=self.vlan3,
                                                     intf_handle=self.if8)]
        self.client.switcht_api_multicast_member_add(device, self.mch2,
                                                     self.snoop_ports)
        self.client.switcht_api_multicast_l2route_add(device, self.mch2,
                                                      self.vlan3,
                                                      self.msrc_ip1,
                                                      self.mgrp_ip1)

    def runTest(self):
        print "IPv4 multicast hit (RPF pass)"
        pkt = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                eth_src='00:22:22:22:22:22',
                                ip_src='10.0.10.5',
                                ip_dst='230.1.1.5',
                                ip_ttl=64,
                                pktlen=100)
        pkt1 = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                 eth_src='00:22:22:22:22:22',
                                 dl_vlan_enable=True,
                                 vlan_vid=10,
                                 ip_src='10.0.10.5',
                                 ip_dst='230.1.1.5',
                                 ip_ttl=64,
                                 pktlen=104)
        pkt2 = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                 eth_src='00:77:66:55:44:33',
                                 dl_vlan_enable=True,
                                 vlan_vid=100,
                                 ip_src='10.0.10.5',
                                 ip_dst='230.1.1.5',
                                 ip_ttl=63,
                                 pktlen=104)
        pkt3 = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                 eth_src='00:77:66:55:44:33',
                                 ip_src='10.0.10.5',
                                 ip_dst='230.1.1.5',
                                 ip_ttl=63,
                                pktlen=100)
        pkt4 = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                 eth_src='00:77:66:55:44:33',
                                 dl_vlan_enable=True,
                                 vlan_vid=200,
                                 ip_src='10.0.10.5',
                                 ip_dst='230.1.1.5',
                                 ip_ttl=63,
                                 pktlen=104)
        udp_sport = entropy_hash(pkt)
        vxlan_pkt = simple_vxlan_packet(eth_src='00:77:66:55:44:33',
                                        eth_dst='01:00:5e:00:02:02',
                                        ip_id=0,
                                        ip_dst='235.0.2.2',
                                        ip_src='10.0.10.1',
                                        ip_ttl=64,
                                        udp_sport=udp_sport,
                                        with_udp_chksum=False,
                                        vxlan_vni=0x5768,
                                        inner_frame=pkt3)
        send_packet(self, swports[0], str(pkt))
        p1 = [swports[1], [pkt1, pkt2]]
        p2 = [swports[2], [pkt3]]
        p3 = [swports[3], [pkt3]]
        p4 = [swports[4], [pkt3, vxlan_pkt]]
        p5 = [swports[5], [pkt1, pkt2, pkt4]]
        p6 = [swports[6], [pkt1, pkt2, pkt4]]
        p7 = [swports[7], [pkt1, pkt2, pkt4]]
        verify_multiple_packets_on_ports(self, [p1, p2, p3, p4, p5, p6, p7])

        print "IPv4 multicast hit (RPF fail - flood in ingress vlan)"
        pkt = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                eth_src='00:22:22:22:22:22',
                                ip_src='10.0.10.5',
                                ip_dst='230.1.1.5',
                                ip_ttl=64,
                                pktlen=100)
        pkt1 = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                 eth_src='00:22:22:22:22:22',
                                 dl_vlan_enable=True,
                                 vlan_vid=100,
                                 ip_src='10.0.10.5',
                                 ip_dst='230.1.1.5',
                                 ip_ttl=64,
                                 pktlen=104)
        send_packet(self, swports[2], str(pkt))
        p1 = [swports[1], [pkt1]]
        p5 = [swports[5], [pkt1]]
        p6 = [swports[6], [pkt1]]
        p7 = [swports[7], [pkt1]]
        verify_multiple_packets_on_ports(self, [p1, p5, p6, p7])

        print "IPv4 multicast hit (RPF fail - snooping enabled)"
        pkt = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                eth_src='00:22:22:22:22:22',
                                dl_vlan_enable=True,
                                vlan_vid=200,
                                ip_src='10.0.10.5',
                                ip_dst='230.1.1.5',
                                ip_ttl=64,
                                pktlen=100)
        send_packet(self, swports[6], str(pkt))
        p5 = [swports[5], [pkt]]
        p7 = [swports[7], [pkt]]
        verify_multiple_packets_on_ports(self, [p5, p7])

        print "IPv4 multicast miss (snooping enabled)"
        pkt = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                eth_src='00:22:22:22:22:22',
                                dl_vlan_enable=True,
                                vlan_vid=200,
                                ip_src='10.0.10.5',
                                ip_dst='231.1.1.5',
                                ip_ttl=64,
                                pktlen=100)
        send_packet(self, swports[6], str(pkt))
        verify_multiple_packets_on_ports(self, [])

        print "IPv4 multicast miss (snooping disabled)"
        pkt = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                eth_src='00:22:22:22:22:22',
                                dl_vlan_enable=True,
                                vlan_vid=100,
                                ip_src='10.0.10.5',
                                ip_dst='231.1.1.5',
                                ip_ttl=64,
                                pktlen=100)
        pkt1 = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                 eth_src='00:22:22:22:22:22',
                                 ip_src='10.0.10.5',
                                 ip_dst='231.1.1.5',
                                 ip_ttl=64,
                                 pktlen=96)
        cpu_pkt = simple_cpu_packet(ingress_port=6,
                                    ingress_ifindex=7,
                                    reason_code=0,
                                    ingress_bd=3,
                                    inner_pkt=pkt)
        send_packet(self, swports[6], str(pkt))
        p1 = [swports[1], [pkt]]
        p2 = [swports[2], [pkt1]]
        p5 = [swports[5], [pkt]]
        p7 = [swports[7], [pkt]]
        p64 = [swports[64], [cpu_pkt]]
        verify_multiple_packets_on_ports(self, [p1, p2, p5, p7, p64])

        print "IPv4 multicast (tunneled packet)"
        pkt = simple_udp_packet(eth_dst='01:00:5e:01:01:06',
                                eth_src='00:22:22:22:22:22',
                                ip_src='10.0.10.5',
                                ip_dst='230.1.1.6',
                                ip_ttl=64,
                                pktlen=100)
        udp_sport = entropy_hash(pkt)
        vxlan_pkt = simple_vxlan_packet(eth_src='00:77:66:55:44:33',
                                        eth_dst='01:00:5e:00:02:02',
                                        ip_id=0,
                                        ip_dst='235.0.2.2',
                                        ip_src='10.0.10.1',
                                        ip_ttl=64,
                                        udp_sport=udp_sport,
                                        with_udp_chksum=False,
                                        vxlan_vni=0x5768,
                                        inner_frame=pkt)
        epkt1 = simple_udp_packet(eth_dst='01:00:5e:01:01:06',
                                  eth_src='00:77:66:55:44:33',
                                  ip_src='10.0.10.5',
                                  ip_dst='230.1.1.6',
                                  ip_ttl=63,
                                  pktlen=100)
        epkt2 = simple_udp_packet(eth_dst='01:00:5e:01:01:06',
                                  eth_src='00:77:66:55:44:33',
                                  dl_vlan_enable=True,
                                  vlan_vid=10,
                                  ip_src='10.0.10.5',
                                  ip_dst='230.1.1.6',
                                  ip_ttl=63,
                                  pktlen=104)
        epkt3 = simple_udp_packet(eth_dst='01:00:5e:01:01:06',
                                  eth_src='00:77:66:55:44:33',
                                  dl_vlan_enable=True,
                                  vlan_vid=100,
                                  ip_src='10.0.10.5',
                                  ip_dst='230.1.1.6',
                                  ip_ttl=63,
                                  pktlen=104)
        epkt4 = simple_udp_packet(eth_dst='01:00:5e:01:01:06',
                                  eth_src='00:77:66:55:44:33',
                                  dl_vlan_enable=True,
                                  vlan_vid=200,
                                  ip_src='10.0.10.5',
                                  ip_dst='230.1.1.6',
                                  ip_ttl=63,
                                  pktlen=104)
        send_packet(self, swports[4], str(vxlan_pkt))
        p0 = [swports[0], [epkt1]]
        p1 = [swports[1], [epkt2, epkt3]]
        p2 = [swports[2], [epkt1]]
        p3 = [swports[3], [epkt1]]
        p4 = [swports[4], [epkt1]]
        p5 = [swports[5], [epkt2, epkt3, epkt4]]
        p6 = [swports[6], [epkt2, epkt3, epkt4]]
        p7 = [swports[7], [epkt2, epkt3, epkt4]]
        verify_multiple_packets_on_ports(self, [p0, p1, p2, p3, p4, p5, p6, p7])

    def tearDown(self):
        self.client.switcht_api_mac_table_entries_delete_all(device)
        self.client.switcht_api_neighbor_entry_remove(device, self.neigh1)

        # delete mroute and its tree
        self.client.switcht_api_multicast_mroute_delete(device,
                                                       self.vrf,
                                                       self.msrc_ip1,
                                                       self.mgrp_ip1)
        self.client.switcht_api_multicast_mroute_delete(device,
                                                       self.vrf,
                                                       self.msrc_ip2,
                                                       self.mgrp_ip2)
        self.client.switcht_api_multicast_mroute_delete(device,
                                                       self.vrf,
                                                       self.msrc_ip3,
                                                       self.mgrp_ip3)

        self.client.switcht_api_multicast_member_delete(device, self.mch1,
                                                        self.route_ports)
        self.client.switcht_api_multicast_tree_delete(device, self.mch1)

        # delete snooping entry in vlan 200
        self.client.switcht_api_multicast_l2route_delete(device,
                                                         self.vlan3,
                                                         self.msrc_ip1,
                                                         self.mgrp_ip1)
        self.client.switcht_api_multicast_member_delete(device, self.mch2,
                                                        self.snoop_ports)
        self.client.switcht_api_multicast_tree_delete(device, self.mch2)

        self.client.switcht_api_l3_interface_address_delete(device, self.if4,
                                                            self.vrf,
                                                            self.ip4)
        self.client.switcht_api_l3_interface_address_delete(device, self.if5,
                                                            self.vrf,
                                                            self.ip5)
        self.client.switcht_api_l3_interface_address_delete(device, self.if20,
                                                            self.vrf,
                                                            self.ip20)
        self.client.switcht_api_l3_interface_address_delete(device, self.if21,
                                                            self.vrf,
                                                            self.ip21)
        self.client.switcht_api_l3_interface_address_delete(device, self.if22,
                                                            self.vrf,
                                                            self.ip22)

        self.client.switcht_api_logical_network_member_remove(device, self.ln1,
                                                              self.tif1)
        self.client.switcht_api_logical_network_delete(device, self.ln1)
        self.client.switcht_api_tunnel_interface_delete(device, self.tif1)

        self.client.switcht_api_vlan_ports_remove(device, self.vlan1, self.pv1)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan1, self.pv2)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan2, self.pv2)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan3, self.pv2)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan2, self.pv3)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan1, self.pv6)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan2, self.pv6)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan3, self.pv6)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan1, self.pv7)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan2, self.pv7)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan3, self.pv7)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan1, self.pv8)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan2, self.pv8)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan3, self.pv8)

        self.client.switcht_api_interface_delete(device, self.if1)
        self.client.switcht_api_interface_delete(device, self.if2)
        self.client.switcht_api_interface_delete(device, self.if3)
        self.client.switcht_api_interface_delete(device, self.if4)
        self.client.switcht_api_interface_delete(device, self.if5)
        self.client.switcht_api_interface_delete(device, self.if6)
        self.client.switcht_api_interface_delete(device, self.if7)
        self.client.switcht_api_interface_delete(device, self.if8)
        self.client.switcht_api_interface_delete(device, self.if20)
        self.client.switcht_api_interface_delete(device, self.if21)
        self.client.switcht_api_interface_delete(device, self.if22)

        self.client.switcht_api_vlan_delete(device, self.vlan1)
        self.client.switcht_api_vlan_delete(device, self.vlan2)
        self.client.switcht_api_vlan_delete(device, self.vlan3)

        self.client.switcht_api_router_mac_delete(device, self.rmac,
                                                  '00:77:66:55:44:33')
        self.client.switcht_api_router_mac_group_delete(device, self.rmac)
        self.client.switcht_api_vrf_delete(device, self.vrf)

        api_base_tests.ThriftInterfaceDataPlane.tearDown(self)


@group('mcast')
class L3MulticastBidir(api_base_tests.ThriftInterfaceDataPlane):
    def setUp(self):
        print
        print 'Configuring devices for L3 multicast (Bidir) test cases'

        api_base_tests.ThriftInterfaceDataPlane.setUp(self)
        self.client.switcht_api_init(device)

        self.vrf = self.client.switcht_api_vrf_create(device, 2)
        self.rmac = self.client.switcht_api_router_mac_group_create(device)
        self.client.switcht_api_router_mac_add(device, self.rmac,
                                               '00:77:66:55:44:33')

        # vlans: 10, 100, 200
        self.vlan1 = self.client.switcht_api_vlan_create(device, 10)
        self.vlan2 = self.client.switcht_api_vlan_create(device, 100)
        self.vlan3 = self.client.switcht_api_vlan_create(device, 200)

        # disable learning
        self.client.switcht_api_vlan_learning_enabled_set(self.vlan1, 0)
        self.client.switcht_api_vlan_learning_enabled_set(self.vlan2, 0)
        self.client.switcht_api_vlan_learning_enabled_set(self.vlan3, 0)

        # set RPF group
        self.client.switcht_api_vlan_mrpf_group_set(self.vlan1, 0x0003)
        self.client.switcht_api_vlan_mrpf_group_set(self.vlan2, 0x000A)
        self.client.switcht_api_vlan_mrpf_group_set(self.vlan3, 0x0010)

        # enable igmp snooping on vlan3
        self.client.switcht_api_vlan_igmp_snooping_enabled_set(self.vlan3, 1)

        # port 0: access port in vlan 10
        iu1 = interface_union(port_lag_handle=swports[0])
        i_info1 = switcht_interface_info_t(device=0, type=2, u=iu1,
                                           mac='00:77:66:55:44:33', label=0)
        self.if1 = self.client.switcht_api_interface_create(device, i_info1)
        self.pv1 = switcht_vlan_port_t(handle=self.if1, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, self.vlan1, self.pv1)

        # port 1: trunk port; allowed vlans: 10, 100, 200
        iu2 = interface_union(port_lag_handle=swports[1])
        i_info2 = switcht_interface_info_t(device=0, type=3, u=iu2,
                                           mac='00:77:66:55:44:33', label=0)
        self.if2 = self.client.switcht_api_interface_create(device, i_info2)
        self.pv2 = switcht_vlan_port_t(handle=self.if2, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, self.vlan1, self.pv2)
        self.client.switcht_api_vlan_ports_add(device, self.vlan2, self.pv2)
        self.client.switcht_api_vlan_ports_add(device, self.vlan3, self.pv2)

        # port 2: access port in vlan 100
        iu3 = interface_union(port_lag_handle=swports[2])
        i_info3 = switcht_interface_info_t(device=0, type=2, u=iu3,
                                           mac='00:77:66:55:44:33', label=0)
        self.if3 = self.client.switcht_api_interface_create(device, i_info3)
        self.pv3 = switcht_vlan_port_t(handle=self.if3, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, self.vlan2, self.pv3)

        # port 5: trunk port; allowed vlans: 10, 100, 200
        iu6 = interface_union(port_lag_handle=swports[5])
        i_info6 = switcht_interface_info_t(device=0, type=3, u=iu6,
                                           mac='00:77:66:55:44:33', label=0)
        self.if6 = self.client.switcht_api_interface_create(device, i_info6)
        self.pv6 = switcht_vlan_port_t(handle=self.if6, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, self.vlan1, self.pv6)
        self.client.switcht_api_vlan_ports_add(device, self.vlan2, self.pv6)
        self.client.switcht_api_vlan_ports_add(device, self.vlan3, self.pv6)

        # port 6: trunk port; allowed vlans: 10, 100, 200
        iu7 = interface_union(port_lag_handle=swports[6])
        i_info7 = switcht_interface_info_t(device=0, type=3, u=iu7,
                                           mac='00:77:66:55:44:33', label=0)
        self.if7 = self.client.switcht_api_interface_create(device, i_info7)
        self.pv7 = switcht_vlan_port_t(handle=self.if7, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, self.vlan1, self.pv7)
        self.client.switcht_api_vlan_ports_add(device, self.vlan2, self.pv7)
        self.client.switcht_api_vlan_ports_add(device, self.vlan3, self.pv7)

        # port 7: trunk port; allowed vlans: 10, 100, 200
        iu8 = interface_union(port_lag_handle=swports[7])
        i_info8 = switcht_interface_info_t(device=0, type=3, u=iu8,
                                           mac='00:77:66:55:44:33', label=0)
        self.if8 = self.client.switcht_api_interface_create(device, i_info8)
        self.pv8 = switcht_vlan_port_t(handle=self.if8, tagging_mode=0)
        self.client.switcht_api_vlan_ports_add(device, self.vlan1, self.pv8)
        self.client.switcht_api_vlan_ports_add(device, self.vlan2, self.pv8)
        self.client.switcht_api_vlan_ports_add(device, self.vlan3, self.pv8)

        # Create L3 virtual interface for vlan 10
        iu = interface_union(vlan_id=10)
        i_info = switcht_interface_info_t(device=0, type=5, u=iu,
                                          mac='00:77:66:55:44:33',
                                          label=0, vrf_handle=self.vrf,
                                          rmac_handle=self.rmac,
                                          v4_unicast_enabled=1,
                                          v6_unicast_enabled=1,
                                          v4_multicast_enabled=1,
                                          v6_multicast_enabled=1)
        self.if20 = self.client.switcht_api_interface_create(device, i_info)
        self.ip20 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.10.1',
                                      prefix_length=24)
        self.client.switcht_api_l3_interface_address_add(device, self.if20,
                                                         self.vrf, self.ip20)

        # Create L3 virtual interface for vlan 100
        iu = interface_union(vlan_id=100)
        i_info = switcht_interface_info_t(device=0, type=5, u=iu,
                                          mac='00:77:66:55:44:33',
                                          label=0, vrf_handle=self.vrf,
                                          rmac_handle=self.rmac,
                                          v4_unicast_enabled=1,
                                          v6_unicast_enabled=1,
                                          v4_multicast_enabled=1,
                                          v6_multicast_enabled=1)
        self.if21 = self.client.switcht_api_interface_create(device, i_info)
        self.ip21 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.100.1',
                                      prefix_length=24)
        self.client.switcht_api_l3_interface_address_add(device, self.if21,
                                                         self.vrf, self.ip21)

        # Create L3 virtual interface for vlan 200
        iu = interface_union(vlan_id=200)
        i_info = switcht_interface_info_t(device=0, type=5, u=iu,
                                          mac='00:77:66:55:44:33',
                                          label=0, vrf_handle=self.vrf,
                                          rmac_handle=self.rmac,
                                          v4_unicast_enabled=1,
                                          v6_unicast_enabled=1,
                                          v4_multicast_enabled=1,
                                          v6_multicast_enabled=1)
        self.if22 = self.client.switcht_api_interface_create(device, i_info)
        self.ip22 = switcht_ip_addr_t(addr_type=0, ipaddr='10.0.200.1',
                                      prefix_length=24)
        self.client.switcht_api_l3_interface_address_add(device, self.if22,
                                                         self.vrf, self.ip22)

        # create inner multicast tree
        self.mch1 = self.client.switcht_api_multicast_tree_create(device)

        # vlan ports
        self.route_ports = [switcht_vlan_interface_t(vlan_handle=self.vlan1,
                                                     intf_handle=self.if1),
                            switcht_vlan_interface_t(vlan_handle=self.vlan1,
                                                     intf_handle=self.if2),
                            switcht_vlan_interface_t(vlan_handle=self.vlan1,
                                                     intf_handle=self.if6),
                            switcht_vlan_interface_t(vlan_handle=self.vlan1,
                                                     intf_handle=self.if7),
                            switcht_vlan_interface_t(vlan_handle=self.vlan1,
                                                     intf_handle=self.if8),
                            switcht_vlan_interface_t(vlan_handle=self.vlan2,
                                                     intf_handle=self.if2),
                            switcht_vlan_interface_t(vlan_handle=self.vlan2,
                                                     intf_handle=self.if3),
                            switcht_vlan_interface_t(vlan_handle=self.vlan2,
                                                     intf_handle=self.if6),
                            switcht_vlan_interface_t(vlan_handle=self.vlan2,
                                                     intf_handle=self.if7),
                            switcht_vlan_interface_t(vlan_handle=self.vlan2,
                                                     intf_handle=self.if8),
                            switcht_vlan_interface_t(vlan_handle=self.vlan3,
                                                     intf_handle=self.if6),
                            switcht_vlan_interface_t(vlan_handle=self.vlan3,
                                                     intf_handle=self.if7),
                            switcht_vlan_interface_t(vlan_handle=self.vlan3,
                                                     intf_handle=self.if8)]
        self.client.switcht_api_multicast_member_add(device, self.mch1,
                                                     self.route_ports)

        # create a ip multicast route (*,230.1.1.5)
        self.msrc_ip1 = switcht_ip_addr_t(addr_type=0, ipaddr='0.0.0.0',
                                         prefix_length=0)
        self.mgrp_ip1 = switcht_ip_addr_t(addr_type=0, ipaddr='230.1.1.5',
                                         prefix_length=32)
        rpid = [ ~0x0002 & 0xFFFF ]
        self.client.switcht_api_multicast_mroute_add(device, self.mch1,
                                                     self.vrf,
                                                     self.msrc_ip1,
                                                     self.mgrp_ip1, 2,
                                                     rpid, 1)

        # create a snooping entry for vlan 200
        self.mch2 = self.client.switcht_api_multicast_tree_create(device)
        # vlan 200 ports
        self.snoop_ports = [switcht_vlan_interface_t(vlan_handle=self.vlan3,
                                                     intf_handle=self.if6),
                            switcht_vlan_interface_t(vlan_handle=self.vlan3,
                                                     intf_handle=self.if7),
                            switcht_vlan_interface_t(vlan_handle=self.vlan3,
                                                     intf_handle=self.if8)]
        self.client.switcht_api_multicast_member_add(device, self.mch2,
                                                     self.snoop_ports)
        self.client.switcht_api_multicast_l2route_add(device, self.mch2,
                                                      self.vlan3,
                                                      self.msrc_ip1,
                                                      self.mgrp_ip1)

    def runTest(self):
        print "IPv4 multicast (bidir) hit (RPF pass)"
        pkt = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                eth_src='00:22:22:22:22:22',
                                ip_src='10.0.10.5',
                                ip_dst='230.1.1.5',
                                ip_ttl=64,
                                pktlen=100)
        pkt1 = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                 eth_src='00:22:22:22:22:22',
                                 dl_vlan_enable=True,
                                 vlan_vid=10,
                                 ip_src='10.0.10.5',
                                 ip_dst='230.1.1.5',
                                 ip_ttl=64,
                                 pktlen=104)
        pkt2 = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                 eth_src='00:77:66:55:44:33',
                                 dl_vlan_enable=True,
                                 vlan_vid=100,
                                 ip_src='10.0.10.5',
                                 ip_dst='230.1.1.5',
                                 ip_ttl=63,
                                 pktlen=104)
        pkt3 = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                 eth_src='00:77:66:55:44:33',
                                 ip_src='10.0.10.5',
                                 ip_dst='230.1.1.5',
                                 ip_ttl=63,
                                pktlen=100)
        pkt4 = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                 eth_src='00:77:66:55:44:33',
                                 dl_vlan_enable=True,
                                 vlan_vid=200,
                                 ip_src='10.0.10.5',
                                 ip_dst='230.1.1.5',
                                 ip_ttl=63,
                                 pktlen=104)
        udp_sport = entropy_hash(pkt)
        vxlan_pkt = simple_vxlan_packet(eth_src='00:77:66:55:44:33',
                                        eth_dst='01:00:5e:00:02:02',
                                        ip_id=0,
                                        ip_dst='235.0.2.2',
                                        ip_src='10.0.10.1',
                                        ip_ttl=64,
                                        udp_sport=udp_sport,
                                        with_udp_chksum=False,
                                        vxlan_vni=0x5768,
                                        inner_frame=pkt3)
        send_packet(self, swports[0], str(pkt))
        p1 = [swports[1], [pkt1, pkt2]]
        p2 = [swports[2], [pkt3]]
        p5 = [swports[5], [pkt1, pkt2, pkt4]]
        p6 = [swports[6], [pkt1, pkt2, pkt4]]
        p7 = [swports[7], [pkt1, pkt2, pkt4]]
        verify_multiple_packets_on_ports(self, [p1, p2, p5, p6, p7])

        print "IPv4 multicast (bidir) hit (RPF pass)"
        pkt5 = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                 eth_src='00:22:22:22:22:22',
                                 dl_vlan_enable=True,
                                 vlan_vid=100,
                                 ip_src='10.0.10.5',
                                 ip_dst='230.1.1.5',
                                 ip_ttl=64,
                                 pktlen=104)
        pkt6 = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                 eth_src='00:77:66:55:44:33',
                                 dl_vlan_enable=True,
                                 vlan_vid=10,
                                 ip_src='10.0.10.5',
                                 ip_dst='230.1.1.5',
                                 ip_ttl=63,
                                 pktlen=104)
        send_packet(self, swports[1], str(pkt5))
        p0 = [swports[0], [pkt3]]
        p1 = [swports[1], [pkt6]]
        p2 = [swports[2], [pkt]]
        p5 = [swports[5], [pkt6, pkt5, pkt4]]
        p6 = [swports[6], [pkt6, pkt5, pkt4]]
        p7 = [swports[7], [pkt6, pkt5, pkt4]]
        verify_multiple_packets_on_ports(self, [p0, p1, p2, p5, p6, p7])

        print "IPv4 multicast (bidir) hit (RPF fail - snooping enabled)"
        pkt = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                eth_src='00:22:22:22:22:22',
                                dl_vlan_enable=True,
                                vlan_vid=200,
                                ip_src='10.0.10.5',
                                ip_dst='230.1.1.5',
                                ip_ttl=64,
                                pktlen=100)
        send_packet(self, swports[6], str(pkt))
        p5 = [swports[5], [pkt]]
        p7 = [swports[7], [pkt]]
        verify_multiple_packets_on_ports(self, [p5, p7])

        print "IPv4 multicast (bidir) miss (snooping enabled)"
        pkt = simple_udp_packet(eth_dst='01:00:5e:01:01:05',
                                eth_src='00:22:22:22:22:22',
                                dl_vlan_enable=True,
                                vlan_vid=200,
                                ip_src='10.0.10.5',
                                ip_dst='231.1.1.5',
                                ip_ttl=64,
                                pktlen=100)
        send_packet(self, swports[6], str(pkt))
        verify_multiple_packets_on_ports(self, [])

    def tearDown(self):
        self.client.switcht_api_mac_table_entries_delete_all(device)

        # delete mroute and its tree
        self.client.switcht_api_multicast_mroute_delete(device,
                                                       self.vrf,
                                                       self.msrc_ip1,
                                                       self.mgrp_ip1)

        self.client.switcht_api_multicast_member_delete(device, self.mch1,
                                                        self.route_ports)
        self.client.switcht_api_multicast_tree_delete(device, self.mch1)

        # delete snooping entry in vlan 200
        self.client.switcht_api_multicast_l2route_delete(device,
                                                         self.vlan3,
                                                         self.msrc_ip1,
                                                         self.mgrp_ip1)
        self.client.switcht_api_multicast_member_delete(device, self.mch2,
                                                        self.snoop_ports)
        self.client.switcht_api_multicast_tree_delete(device, self.mch2)

        self.client.switcht_api_vlan_ports_remove(device, self.vlan1, self.pv1)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan1, self.pv2)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan2, self.pv2)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan3, self.pv2)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan2, self.pv3)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan1, self.pv6)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan2, self.pv6)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan3, self.pv6)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan1, self.pv7)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan2, self.pv7)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan3, self.pv7)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan1, self.pv8)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan2, self.pv8)
        self.client.switcht_api_vlan_ports_remove(device, self.vlan3, self.pv8)

        self.client.switcht_api_interface_delete(device, self.if1)
        self.client.switcht_api_interface_delete(device, self.if2)
        self.client.switcht_api_interface_delete(device, self.if3)
        self.client.switcht_api_interface_delete(device, self.if6)
        self.client.switcht_api_interface_delete(device, self.if7)
        self.client.switcht_api_interface_delete(device, self.if8)
        self.client.switcht_api_interface_delete(device, self.if20)
        self.client.switcht_api_interface_delete(device, self.if21)
        self.client.switcht_api_interface_delete(device, self.if22)

        self.client.switcht_api_vlan_delete(device, self.vlan1)
        self.client.switcht_api_vlan_delete(device, self.vlan2)
        self.client.switcht_api_vlan_delete(device, self.vlan3)

        self.client.switcht_api_router_mac_delete(device, self.rmac,
                                                  '00:77:66:55:44:33')
        self.client.switcht_api_router_mac_group_delete(device, self.rmac)
        self.client.switcht_api_vrf_delete(device, self.vrf)

        api_base_tests.ThriftInterfaceDataPlane.tearDown(self)
