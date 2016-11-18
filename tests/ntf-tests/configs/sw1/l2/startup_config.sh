#!/bin/bash

/tools/veth_setup.sh
sleep 10
/configs/start.sh

brctl addbr vlan100
brctl addif vlan100 swp1
brctl addif vlan100 swp2
ip link set vlan100 up

sleep 10

/configs/run_model_driver.sh sw1

