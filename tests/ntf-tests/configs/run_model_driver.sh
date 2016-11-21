#!/bin/bash

swname=$1

# start model
LD_LIBRARY_PATH=/install/lib:$LD_LIBRARY_PATH /install/bin/simple_switch --log-console -i 0@${swname}-eth1 -i 1@${swname}-eth2 -i 2@${swname}-eth3 -i 3@${swname}-eth4 -i 64@veth250 --thrift-port 10001 --pcap /install/share/bmpd/switch/switch.json >> /tmp/simple_switch.log 2>&1 &

sleep 10

# start driver
LD_LIBRARY_PATH=/install/lib:/install/lib/bmpd/switch:$LD_LIBRARY_PATH /install/bin/bmswitchp4_drivers >> /tmp/bmswitchp4_drivers.log 2>&1 &

sleep 10

