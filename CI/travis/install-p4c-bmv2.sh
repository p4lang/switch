#!/bin/bash
set -e
git clone https://github.com/p4lang/p4c-bm.git p4c-bmv2
cd p4c-bmv2
git submodule update --init --recursive
sudo pip install -r requirements.txt
./autogen.sh
./configure
make && sudo make install
cd ..
