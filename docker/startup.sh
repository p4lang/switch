#!/bin/bash

# set up veths
sudo /switch/tools/veth_setup.sh
sleep 10

# start bm
sudo ./switch/docker/run_bm.sh &>bmlog &
sleep 10
sudo ./switch/docker/run_drivers.sh $@ &>driverlog &
sleep 10

# configure port_vlan_mapping entries
sudo ./switch/docker/configure.sh &>/dev/null &
sleep 2
