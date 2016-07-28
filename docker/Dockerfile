FROM ubuntu:14.04

RUN apt-get update
RUN apt-get install -y \
      libjudy-dev \
      libgmp-dev \
      libpcap-dev \
      libboost-dev \
      libboost-test-dev \
      libboost-program-options-dev \
      libboost-system-dev \
      libboost-filesystem-dev \
      libboost-thread-dev \
      libboost-test-dev \
      libevent-dev \
      automake \
      libtool \
      flex \
      bison \
      pkg-config \
      g++ \
      libssl-dev \
      doxygen \
      git \
      libedit-dev \
      libevent-dev \
      libfreetype6-dev \
      libpng-dev \
      libyaml-0-2 \
      libbz2-dev \
      libnl-route-3-dev \
      openssl \
      pkg-config \
      python-dev \
      python-matplotlib \
      python-numpy \
      python-pip \
      python-scipy \
      python-setuptools \
      python-yaml \
      wget \
      ethtool \
      vim

# install scapy
RUN mkdir -p /tmp/scapy ; \
    cd /tmp/scapy ; \
    git clone https://github.com/p4lang/scapy-vxlan.git ; \
    cd scapy-vxlan ; \
    python setup.py install ; \
    rm -fr /tmp/scapy

# install p4-hlir
RUN mkdir -p /tmp/p4-hlir ; \
    cd /tmp/p4-hlir ; \
    git clone https://github.com/p4lang/p4-hlir.git ; \
    cd p4-hlir ; \
    python setup.py install ; \
    rm -fr /tmp/p4-hlir

# install ctypesgen
RUN mkdir -p /tmp/ctypesgen ; \
    cd /tmp/ctypesgen ; \
    git clone https://github.com/davidjamesca/ctypesgen.git ; \
    cd ctypesgen ; \
    python setup.py install ; \
    rm -fr /tmp/ctypesgen

# install bmv2
RUN mkdir -p /tmp/bm ; \
    cd /tmp/bm ; \
    git clone https://github.com/p4lang/behavioral-model ; \
    cd behavioral-model ; \
    ./install_deps.sh ; \
    ./autogen.sh ; \
    ./configure --with-pdfixed ; \
    make ; \
    make install ; ldconfig ; \
    rm -rf /tmp/bm

# install p4c-bm
RUN mkdir /tmp/p4c-bm ; \
    cd /tmp/p4c-bm ; \
    git clone https://github.com/p4lang/p4c-bm ; \
    cd p4c-bm ; \
    sudo python setup.py install ; \
    rm -rf /tmp/p4c-bm

# install p4ofagent
RUN mkdir /tmp/p4ofagent ; \
    cd /tmp/p4ofagent ; \
    git clone https://github.com/p4lang/p4ofagent ; \
    cd p4ofagent ; \
    git submodule update --init ; \
    cd submodules/indigo/ ; \
    find -name ".gitmodules" -type f -exec sed -i 's/git@github.com:/https:\/\/github.com\//' {} \; ; \
    git submodule update --init ; \
    cd submodules/bigcode/ ; \
    find -name ".gitmodules" -type f -exec sed -i 's/git@github.com:/https:\/\/github.com\//' {} \; ; \
    cd ../../../../ ; \
    ./autogen.sh ; \
    ./configure  ; \
    make p4ofagent CPPFLAGS=-D_BMV2_ ; \
    make install CPPFLAGS=-D_BMV2_ ; \
    rm -rf /tmp/p4ofagent

# build switch
RUN git clone https://github.com/p4lang/switch ; \
    cd switch ; \
    git submodule update --init --recursive ; \
    ./autogen.sh ; \
    ./configure --with-bmv2 --with-of ; \
    make
