FROM      ubuntu:14.04

RUN apt-get update
RUN apt-get install -y \
    automake \
    autopoint \
    bison \
    bridge-utils \
    build-essential \
    cmake \
    ethtool \
    flex \
    g++ \
    gdb \
    git \
    libboost-dev \
    libboost-filesystem-dev \
    libboost-program-options-dev \
    libboost-system-dev \
    libboost-test-dev \
    libboost-thread-dev \
    libedit-dev \
    libev-dev \
    libevent-dev \
    libffi-dev \
    libglib2.0-dev \
    libgmp-dev \
    libhiredis-dev \
    libjson0 \
    libjson0-dev \
    libjudy-dev \
    libnl-route-3-dev \
    libpcap0.8 \
    libpcap0.8-dev \
    libpcap-dev \
    libtool \
    libssl-dev \
    mktemp \
    openssh-server \
    packit \
    pkg-config \
    python-dev \
    python-pip \
    python-pygraph \
    python-pygraphviz \
    python-setuptools \
    python-texttable \
    python-thrift \
    python-yaml \
    quagga \
    redis-server \
    redis-tools \
    subversion \
    tcpdump \
    texinfo \
    tshark \
    valgrind \
    vim \
    xterm

RUN mv /usr/sbin/tcpdump /usr/bin/tcpdump

RUN pip install crc16

# install libuio
RUN mkdir -p /tmp/libuio ; \
    cd /tmp/libuio ; \
    git clone https://github.com/Linutronix/libuio ; \
    cd libuio ; \
    ./autogen.sh ; ./configure ; make install ; ldconfig ; \
    rm -fr /tmp/libuio

# install cjson
RUN mkdir -p /tmp/cjson ; \
    cd /tmp/cjson ; \
    git clone https://@github.com/kbranigan/cJSON.git ; \
    cd cJSON ; \
    make ; make install ; ldconfig ; \
    rm -fr /tmp/cjson

# install scapy
RUN mkdir -p /tmp/scapy ; \
    cd /tmp/scapy ; \
    git clone https://github.com/p4lang/scapy-vxlan.git ; \
    cd scapy-vxlan ; \
    python setup.py install ; \
    rm -fr /tmp/scapy

RUN mkdir -p /tmp/libcrafter; \
    cd /tmp/; \
    git clone https://github.com/pellegre/libcrafter ; \
    cd /tmp/libcrafter/libcrafter ; \
    ./autogen.sh ;  \
    make -j 4 ; \
    make install ; \
    ldconfig ; \
    rm -fr /tmp/libcrafter

RUN mkdir -p /tmp/libcli; \
    cd /tmp/; \
	git clone https://github.com/dparrish/libcli.git; \
    cd /tmp/libcli/ ; \
    make -j 4 ; \
    make install ; \
    ldconfig ; \
    rm -fr /tmp/libcli

# install ctypesgen
RUN mkdir -p /tmp/ctypesgen ; \
    cd /tmp/ctypesgen ; \
    git clone https://github.com/davidjamesca/ctypesgen.git ; \
    cd ctypesgen ; \
    python setup.py install ; \
    rm -fr /tmp/ctypesgen

# install mstpd
RUN mkdir -p /third-party/diffs
COPY diffs/mstpd.diff /third-party/diffs/mstpd.diff
RUN cd /third-party; \
    svn checkout svn://svn.code.sf.net/p/mstpd/code/trunk mstpd; \
    cd mstpd; patch -p0 -i /third-party/diffs/mstpd.diff; make -j 4 install


# install p4-hlir
RUN git clone https://github.com/p4lang/p4-hlir.git ; \
    cd p4-hlir ;\
    sudo python setup.py install ; \
    cd ..

RUN pip install tenjin

RUN echo "set nu" >> /root/.vimrc
RUN echo "set hlsearch" >> /root/.vimrc
RUN echo "set et" >> /root/.vimrc
RUN echo "set tabstop=2" >> /root/.vimrc
RUN echo "set shiftwidth=2" >> /root/.vimrc
RUN echo "set autoindent" >> /root/.vimrc
RUN echo "set smartindent" >> /root/.vimrc

RUN mkdir install_tmp ; \
    cd install_tmp ; \
    wget -c http://archive.apache.org/dist/thrift/0.9.2/thrift-0.9.2.tar.gz ; \
    tar zxvf thrift-0.9.2.tar.gz ; \
    cd thrift-0.9.2 ; \
    ./configure --with-cpp=yes --with-c_glib=no --with-java=no --with-ruby=no --with-erlang=no --with-go=no --with-nodejs=no ; \
    make -j4 ; \
    make install ; \
    ldconfig ; \
    cd .. ; \
    wget https://github.com/nanomsg/nanomsg/archive/1.0.0.tar.gz -O nanomsg-1.0.0.tar.gz ; \
    tar -xzvf nanomsg-1.0.0.tar.gz ; \
    cd nanomsg-1.0.0 ; \
    mkdir build ; \
    cd build ; \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr ; \
    cmake --build . ; \
    cmake --build . --target install ; \
    cd ../../ ; \
    git clone https://github.com/nanomsg/nnpy.git ; \
    cd nnpy ; \
    git checkout c7e718a5173447c85182dc45f99e2abcf9cd4065 ; \
    ldconfig ; \
    pip install cffi ; \
    pip install . ; \
    cd ..

ENV VTYSH_PAGER more
