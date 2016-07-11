sudo /switch/tools/veth_setup.sh

# start bm
sudo /switch/bmv2/run_bm.sh &>/dev/null &
sleep 10
sudo /switch/bmv2/run_drivers.sh $@ &>/dev/null &
sleep 10
