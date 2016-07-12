sudo /switch/tools/veth_setup.sh

# start bm
sudo /switch/bmv2/run_bm.sh > bmlogs &
sleep 10
sudo /switch/bmv2/run_drivers.sh $@ > driverlogs &
sleep 10
