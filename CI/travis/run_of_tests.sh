sudo ./bmv2/run_bm.sh &>/dev/null &
sleep 10
sudo ./bmv2/run_drivers.sh &>/dev/null &
sleep 10
sudo ./bmv2/run_of_tests.sh --oft-path oftest_tmp/oft
