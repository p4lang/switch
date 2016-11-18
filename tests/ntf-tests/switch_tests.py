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

from ntf import config
import unittest
from time import sleep
from mininet.cli import CLI

class L2(unittest.TestCase):
    def setUp(self):
        self.net = config['net']
        self.hosts = self.net.hosts
        self.sws = self.net.switches

    def runTest(self):

        result = self.net.ping(self.hosts,30)

        if config['cli']:
            CLI(self.net)

        if result != 0:
            for host in self.hosts:
                print host.cmd('ifconfig')
                print host.cmd('arp -n')

            for sw in self.sws:
                print sw.cmd('arp -n')

    def tearDown(self):
        pass

class STP(unittest.TestCase):
    def setUp(self):
        self.net = config['net']
        self.hosts = self.net.hosts
        self.sws = self.net.switches

    def runTest(self):
        sleep(30)
        result = self.net.ping(self.hosts,30)

        if config['cli']:
            CLI(self.net)

        if result != 0:
            for host in self.hosts:
                print host.cmd('ifconfig')
                print host.cmd('arp -n')

            for sw in self.sws:
                print sw.cmd('arp -n')
        print result

    def tearDown(self):
        pass

class L3Static(unittest.TestCase):
    def setUp(self):
        self.net = config['net']
        self.hosts = self.net.hosts
        self.sws = self.net.switches
        self.h1 = self.net.get('h1')
        self.h2 = self.net.get('h2')
        self.h1.setARP(ip = '172.16.101.1', mac = '00:01:00:00:00:01' )
        self.h2.setARP(ip = '172.16.102.1', mac = '00:02:00:00:00:01' )

        self.h1.setDefaultRoute('via 172.16.101.1' )
        self.h2.setDefaultRoute('via 172.16.102.1' )

    def runTest(self):
        sleep(30)
        result = self.net.ping(self.hosts,30)
        if config['cli']:
            CLI(self.net)

        if result != 0:
            for host in self.hosts:
                print host.cmd('ifconfig')
                print host.cmd('arp -n')

            for sw in self.sws:
                print sw.cmd('arp -n')

    def tearDown(self):
        pass

class L3VI(unittest.TestCase):
    def setUp(self):
        self.net = config['net']
        self.hosts = self.net.hosts
        self.sws = self.net.switches
        self.h1 = self.net.get('h1')
        self.h2 = self.net.get('h2')
        self.h3 = self.net.get('h3')
        self.h4 = self.net.get('h4')

        self.h1.setDefaultRoute('via 172.16.101.1' )
        self.h2.setDefaultRoute('via 172.16.102.1' )
        self.h3.setDefaultRoute('via 172.16.102.1' )
        self.h4.setDefaultRoute('via 172.16.102.1' )

    def runTest(self):
        sleep(30)
        result = self.net.ping(self.hosts,30)
        if config['cli']:
            CLI(self.net)

        if result != 0:
            for host in self.hosts:
                print host.cmd('ifconfig')
                print host.cmd('arp -n')

            for sw in self.sws:
                print sw.cmd('arp -n')

    def tearDown(self):
        pass

class L3BGP(unittest.TestCase):
    def setUp(self):
        self.net = config['net']
        self.hosts = self.net.hosts
        self.sws = self.net.switches
        self.h1 = self.net.get('h1')
        self.h2 = self.net.get('h2')
        self.sw1 = self.net.get('sw1')
        self.sw2 = self.net.get('sw2')

        self.h1.setDefaultRoute('via 172.16.101.1' )
        self.h2.setDefaultRoute('via 172.16.102.1' )
        self.sw1.cmd('service quagga start')
        self.sw2.cmd('service quagga start')

    def runTest(self):
        sleep(60)
        result = self.net.ping(self.hosts,30)
        if config['cli']:
            CLI(self.net)

        if result != 0:
            for host in self.hosts:
                print host.cmd('ifconfig')
                print host.cmd('arp -n')

            for sw in self.sws:
                print sw.cmd('arp -n')

    def tearDown(self):
        pass

class L3OSPF(unittest.TestCase):
    def setUp(self):
        self.net = config['net']
        self.hosts = self.net.hosts
        self.sws = self.net.switches
        self.h1 = self.net.get('h1')
        self.h2 = self.net.get('h2')
        self.sw1 = self.net.get('sw1')
        self.sw2 = self.net.get('sw2')

        self.h1.setDefaultRoute('via 172.16.101.1' )
        self.h2.setDefaultRoute('via 172.16.102.1' )
        self.sw1.cmd('service quagga start')
        self.sw2.cmd('service quagga start')

    def runTest(self):
        sleep(60)
        result = self.net.ping(self.hosts,30)
        if config['cli']:
            CLI(self.net)

        if result != 0:
            for host in self.hosts:
                print host.cmd('ifconfig')
                print host.cmd('arp -n')

            for sw in self.sws:
                print sw.cmd('arp -n')

    def tearDown(self):
        pass
