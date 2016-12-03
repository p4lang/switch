#!/bin/bash

stty -echo; set +m

/tools/veth_setup.sh
sleep 10
/configs/start.sh

ip link set dev swp1 address 00:01:00:00:00:01
ip link set dev swp2 address 00:01:00:00:00:02
ip address add 172.16.101.1/24 broadcast + dev swp1
ip address add 172.16.10.1/24 broadcast + dev swp2

sysctl -q net.ipv6.conf.all.forwarding=1
ip address add 2ffe:0101::1/64 dev swp1
ip address add 2ffe:0010::1/64 dev swp2

cp /configs/sw1/l3_ospf/quagga/* /etc/quagga/
chown quagga.quagga /etc/quagga/*

sleep 10

/configs/run_model_driver.sh sw1
