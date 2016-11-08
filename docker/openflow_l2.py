#!/usr/bin/python

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

########
# README
# 
# This script is for use with the switch target of the behavioral model.
# To run it, first build the behavioral model with an Openflow Agent,
# then start an instance of Ryu running the simple_switch_13.py app. Supply the IP 
# address of the Ryu instance to this script and you should be able to do "h1 ping h2."
########

from mininet.net import Mininet, VERSION
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from p4_mininet import P4DockerSwitch
from distutils.version import StrictVersion

import os
import sys
import time
from subprocess import Popen

import argparse

parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--controller-ip', help='IPv4 address of openflow controller',
                    type=str, action="store", required=True)
parser.add_argument('--cli', help='Run in cli mode',
                    default=False, action="store_true", required=False)

parser_args = parser.parse_args()

def main():
    net = Mininet( controller=None )
    sw1 = net.addSwitch( 'sw1', cls=P4DockerSwitch,
                        target_name="p4openflowswitch",
                        start_program="/bin/bash")

    h1 = net.addHost( 'h1', ip = '10.0.0.1', mac = '00:04:00:00:00:02' )
    h2 = net.addHost( 'h2', ip = '10.0.0.2', mac = '00:05:00:00:00:02' )

    # add links
    if StrictVersion(VERSION) <= StrictVersion('2.2.0') :
        net.addLink( sw1, h1, port1 = 1 )
        net.addLink( sw1, h2, port1 = 2 )
    else:
        net.addLink( sw1, h1, port1 = 1, fast=False )
        net.addLink( sw1, h2, port1 = 2, fast=False )

    sw1.execProgram("/switch/docker/startup.sh", args="--of-ip %s" % parser_args.controller_ip)

    time.sleep(1)

    net.start()

    print "Ready !"

    result = 0
    time.sleep(3)

    if parser_args.cli:
        CLI(net)
    else:
        node_values = net.values()
        print node_values

        hosts = net.hosts
        print hosts

        # ping hosts
        print "PING BETWEEN THE HOSTS"
        result = net.ping(hosts,30)

        if result != 0:
                print "PING FAILED BETWEEN HOSTS %s"  % (hosts)
        else:
            print "PING SUCCESSFUL!!!"

    net.stop()
    return result

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
