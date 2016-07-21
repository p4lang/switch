#!/bin/bash

sudo /switch/tools/veth_setup.sh

# start bm
sudo ./switch/docker/run_bm.sh &>/dev/null &
sleep 10
sudo ./switch/docker/run_drivers.sh $@ &>/dev/null &
sleep 10
