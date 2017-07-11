FROM p4lang/p4c:latest
MAINTAINER Seth Fowler <seth.fowler@barefootnetworks.com>

# Default to using 2 make jobs, which is a good default for CI. If you're
# building locally or you know there are more cores available, you may want to
# override this.
ARG MAKEFLAGS=-j2

# Select the type of image we're building. Use `build` for a normal build, which
# is optimized for image size. Use `test` if this image will be used for
# testing; in this case, the source code and build-only dependencies will not be
# removed from the image.
ARG IMAGE_TYPE=build

# Install dependencies and some useful tools.
ENV NET_TOOLS iputils-arping \
              iputils-ping \
              iputils-tracepath \
              net-tools \
              nmap \
              python-ipaddr \
              python-pypcap \
              tcpdump \
              traceroute \
              tshark
ENV MININET_DEPS automake \
                 build-essential \
                 cgroup-bin \
                 ethtool \
                 gcc \
                 help2man \
                 iperf \
                 iproute \
                 libtool \
                 make \
                 pkg-config \
                 psmisc \
                 socat \
                 ssh \
                 telnet \
                 pep8 \
                 pyflakes \
                 pylint \
                 python-pexpect \
                 python-setuptools
RUN apt-get update && \
    apt-get install -y --no-install-recommends $NET_TOOLS $MININET_DEPS
ENV OTHER_DEPS git
RUN apt-get install -y --no-install-recommends $OTHER_DEPS


# Install our custom version of scapy.
WORKDIR /
RUN git clone --recursive https://github.com/p4lang/scapy-vxlan
WORKDIR /scapy-vxlan
RUN python setup.py install && \
    rm -rf /scapy-vxlan

# Install mininet.
WORKDIR /
RUN git clone --recursive https://github.com/mininet/mininet
WORKDIR /mininet
RUN make install && \
    rm -rf /mininet

# Install PTF.
WORKDIR /
RUN git clone --recursive https://github.com/p4lang/ptf
WORKDIR /ptf
RUN python setup.py install && \
    rm -rf /ptf

ENV CFLAGS -g -O0
ENV CXXFLAGS -g -O0

# Just a placeholder...
ENV SWITCH_DEPS libjudy-dev \
                libpcap-dev \
                python-dev \
                python-pip \
                python-setuptools

COPY . /switch/
WORKDIR /switch/
RUN apt-get update && \
    apt-get install -y --no-install-recommends $SWITCH_DEPS && \
    apt-get purge -y python-scapy && \
    pip install crc16 && \
    pip install ctypesgen && \
    autoreconf -i && \
    ./configure --enable-thrift --with-bmv2 --with-switchapi --with-switchsai && \
    make && \
    make install && \
    ldconfig
