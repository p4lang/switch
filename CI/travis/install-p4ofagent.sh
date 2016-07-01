#!/bin/bash
set -e
git clone https://github.com/p4lang/p4ofagent.git p4ofagent_tmp
cd p4ofagent_tmp
git submodule update --init
cd submodules/indigo/
find -name ".gitmodules" -type f -exec sed -i 's/git@github.com:/https:\/\/github.com\//' {} \;
git submodule update --init
cd submodules/bigcode/
find -name ".gitmodules" -type f -exec sed -i 's/git@github.com:/https:\/\/github.com\//' {} \;
cd ../../../../
./autogen.sh
./configure --prefix=$HOME/p4ofagent
make p4ofagent CPPFLAGS="-D_BMV2_ -I$HOME/bmv2/include"
make install
cd ..
rm -rf p4ofagent_tmp
