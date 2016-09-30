#!/bin/bash
set -e
git clone https://github.com/p4lang/ptf.git
cd ptf
sudo python setup.py install
cd ..
