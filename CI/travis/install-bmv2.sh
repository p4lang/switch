#!/bin/bash
set -e
git clone https://github.com/p4lang/behavioral-model.git bmv2_tmp
cd bmv2_tmp
bash travis/install-nanomsg.sh
sudo ldconfig
bash travis/install-nnpy.sh
./autogen.sh
./configure 'CXXFLAGS=-O0' --with-pdfixed
make -j2 && sudo make install
cd ..
rm -rf bmv2_tmp
