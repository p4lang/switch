sudo ./bmv2/run_bm.sh &>/dev/null &
sleep 10
sudo ./bmv2/run_drivers.sh &>/dev/null &
sleep 10
sudo ./bmv2/run_tests.sh --test-dir tests/ptf-tests/api-tests
sudo killall bmswitchp4_drivers lt-bmswitchp4_drivers simple_switch lt-simple_switch; echo 0
sudo ./bmv2/run_bm.sh &>/dev/null &
sleep 10
sudo ./bmv2/run_drivers.sh &>/dev/null &
sleep 10
sudo ./bmv2/run_tests.sh --test-dir tests/ptf-tests/sai-tests
sudo killall bmswitchp4_drivers lt-bmswitchp4_drivers simple_switch lt-simple_switch; echo 0
sudo ./bmv2/run_bm.sh &>/dev/null &
sleep 10
sudo ./bmv2/run_drivers.sh &>/dev/null &
sleep 10
sudo ./bmv2/run_tests.sh
