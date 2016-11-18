BUILD P4 Docker Switch
======================

# Required Repositories

behavioral-model: https://github.com/p4lang/behavioral-model.git
p4c-bm: https://github.com/p4lang/p4c-bm.git
switch: https://github.com/p4lang/switch.git

# Build pre-requisities

behavioral-model, p4c-bm and switch need to be configured with --prefix
pointing to the install directory.

* build and install behavioral-model
    git clone https://github.com/p4lang/behavioral-model.git
    cd behavioral-model
    ./install_deps.sh
    ./autogen.sh
    ./configure --prefix=../install --with-pdfixed
    make
    sudo make install

* build and install p4c-bm
    git clone https://github.com/p4lang/p4c-bm.git
    cd p4c-bm
    sudo pip install -r requirements.txt
    sudo pip install -r requirements_v1_1.txt
    sudo python setup.py install --prefix ../install --single-version-externally-managed --record install_files.txt

* build and install switch
    git clone https://github.com/p4lang/switch.git
    git pull
    git submodule update --init --recursive
    ./autogen.sh
    ./configure --prefix=../install --with-bmv2 CPPFLAGS=-I../install/include LDFLAGS=-I../install/lib --with-switchlink
    make
    sudo make install

# Build P4 Docker Switch

Build the base docker image with the dependencies.

make -f docker.mk base-docker-image
