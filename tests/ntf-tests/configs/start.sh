#!/bin/bash

# Setup CPU port
ip link add name veth250 type veth peer name veth251
ip link set dev veth250 up
ip link set dev veth251 up

# Setup front panel ports
num_ports=16
for i in `seq 1 ${num_ports}`
do
    ip tuntap add dev swp${i} mode tap
    ip link set swp${i} up
done
