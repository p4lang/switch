#!/bin/bash

/tools/veth_setup.sh
sleep 10
/configs/start.sh

ip link set dev swp1 address 00:02:00:00:00:01
ip link set dev swp2 address 00:02:00:00:00:02
ip address add 172.16.102.1/24 broadcast + dev swp1
ip address add 172.16.10.2/24 broadcast + dev swp2
ip neigh add 172.16.102.5 lladdr 00:05:00:00:00:02 dev swp1
ip neigh add 172.16.10.1 lladdr 00:01:00:00:00:02 dev swp2
ip route add 172.16.101/24 nexthop via 172.16.10.1

sysctl -q net.ipv6.conf.all.forwarding=1
ip address add 2ffe:0102::1/64 dev swp1
ip address add 2ffe:0010::2/64 dev swp2
ip route add 2ffe:0101::/64 nexthop via 2ffe:0010::1

sleep 15

/configs/run_model_driver.sh sw2
