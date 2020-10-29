Switch
=========

**NOTE: This `switch` repository is no longer under active development
or maintenance.  You are welcome to file issues against it, but the
former maintainers are unlikely to respond.  If you are looking for
something similar to this project that is open source, works with the
open source P4 tools [`p4c`](https://github.com/p4lang/p4c) and
[`behavioral-model`](https://github.com/p4lang/behavioral-model)
simple_switch, and actively developed as of 2020, consider instead
looking at ONF's P4 program `fabric.p4` and co-developed ONOS control
plane software.  Relevant links are:**

* ONOS tutorial - https://github.com/opennetworkinglab/ngsdn-tutorial
  * fabric,p4 source code - https://github.com/opennetworkinglab/onos/blob/master/pipelines/fabric/impl/src/main/resources/fabric.p4
* https://wiki.onosproject.org/display/ONOS/fabric.p4%3A+Trellis+support+by+P4+devices

The switch repository contains the switch.p4 sample P4 program along with all the library repos to manipulate the switch using SAI, SwitchAPI and switchlink.

        +-----+   +-----+   +-----+   +-----+
        |App a|   |App j|   |App n|   |App z|
        |     |...|     |...|     |...|     |
        +-----+   +-----+   +-----+   +-----+
           |         |         |         |
           |         |    +----|         |
    +------------+   |    |
    | Switchlink |   |    |
    |            |<-----------------------------+
    +------------------+  |                     |
    |     SAI          |  |                     |
    |                  |  |                     |
    +-----------------------+                   |
    |      Switch API       |                   |
    |                       |                   |
    +-----------------------+---------+         |
    |      Resource Mgmt. API         |         |
    | (auto-gen. from switch.p4)      |         | Netlink events
    +---------------------------------+         |
    |        Soft Switch              |         |
    |  (compiled from switch.p4)      |         |
    +---------------------------------+         |
                                                |
                                                |
    +----------------------------------------------------------------+
    |                             Kernel                             |
    |                                                                |
    +----------------------------------------------------------------+

Directory Structure
------------------
p4src - P4 sources  
switchsai - SAI library  
switchapi - SwitchAPI  
switchlink - Linux netlink listener      
tests/ptf-tests - P4 dependent(PD), SAI and API tests  
tests/of-tests - Openflow tests  


**Make sure you pull the p4-build submodule with `git submodule update --init
  --recursive`.**


Running switch in bmv2 without p4factory
----------------------------------------
You can now run `switch.p4` in bmv2 without cloning `p4factory`. In order to do
this you first need to install [bmv2]
(https://github.com/p4lang/behavioral-model) and its compiler [p4c-bmv2]
(https://github.com/p4lang/p4c-bm) on your system. Note that when running
`./configure` for bmv2, you need to provide the `--with-pdfixed` option, as
switch requires the PD library. Additionally, if you plan on running the tests
for `switch.p4`, please make sure you install [PTF]
(https://github.com/p4lang/ptf) with `sudo python setup.py install`.

Once this is done, you can follow this steps:

     ./autogen.sh
     ./configure --with-bmv2 --with-switchsai
     make

The `--with-switchsai` flag will make sure that the compiled drivers include
`switchapi` and `switchsai`. If you just need `switchapi`, replace the flag will
`--with-switchapi`. Replace the flag with `--with-switchlink` if you need
`switchlink` as well. If you omit these flags, the drivers will only include the
`PD`.

Note that you should be using a fresh clone for this, not the `switch` submodule
that comes with `p4factory`.

Make sure to look at the output of `configure` to spot any missing dependency.

Once everything has compiled, you can run the tests for `switch.p4` (assuming
you have installed [PTF] (https://github.com/p4lang/ptf). Please make sure that
you have all the necessary veth pairs setup (you can use [tools/veth_setup.sh]
(tools/veth_setup.sh)).

First, start the software switch with:

       sudo ./bmv2/run_bm.sh

Then, start the drivers with:

       sudo ./bmv2/run_drivers.sh

You can now run all the tests:

    sudo ./bmv2/run_tests.sh  # for the PD tests
    sudo ./bmv2/run_tests.sh --test-dir tests/ptf-tests/api-tests  # for the switchapi tests
    sudo ./bmv2/run_tests.sh --test-dir tests/ptf-tests/sai-tests  # for the switchsai tests

Running switch with an openflow agent
--------------------------------------
You can now use [p4ofagent](https://github.com/p4lang/p4ofagent) to control switch.p4 on bmv2.
To do this, install p4ofagent with `CPPFLAGS=-D_BMV2_`, then configure switch with `--with-bmv2`
and `--with-of` options. You can run the tests with `sudo ./bmv2/run_of_tests.sh`, and you can also
play with a mininet-based l2-learning example by first building the switch docker image, then running
`sudo ./openflow_l2.py --controller-ip <ip>`, where `<ip>` is the ip address of a [Ryu](https://github.com/osrg/ryu)
instance running the [simple_switch_13](https://github.com/osrg/ryu/blob/master/ryu/app/simple_switch_13.py) app.

Building switch docker image
--------------------------------------

In addition to the setps in "Running switch in bmv2 without p4factory", 
configure bmv2 and p4c-bm with `--prefix` pointing to the install
directory and install. Also configure switch with `--prefix` pointing to
the install directory and `--with-switchlink`.

You can build the base docker image with:

    cd switch/docker/bmv2
    make -f docker.mk base-docker-image

This will build the docker image "p4dockerswitch".

    sudo docker images
    REPOSITORY          TAG                 IMAGE ID            CREATED         SIZE
    p4dockerswitch      latest              8835deb7979e        2 days ago      1.482 GB
    ubuntu              14.04               1e0c3dd64ccd        5 weeks ago     187.9 MB

Running switch ntf-tests
--------------------------------------

Switch NTF tests require NTF (Network Test Framework) and Docker image.

* Clone and install NTF (https://github.com/p4lang/ntf.git).
* Build switch docker image.
* Write topology, configs and tests as in switch/tests/ntf-tests.

You can now use NTF to build the topology required using the docker image and
write tests.

Below are some NTF tests and how to run:

L2: Simple L2 topology with two switches and two hosts. The topology is loop
    free (no spanning tree protocol).

    sudo ntf --topology switch/tests/ntf-tests/topology/l2_topology.json
    --config switch/tests/ntf-tests/topology/config.json --test-dir
    switch/tests/ntf-tests/ --test L2

STP: L2 topology with four switches and two hosts. It runs MSTPD to form a loop
     free topology.

    sudo ntf --topology switch/tests/ntf-tests/topology/stp_topology.json
    --config switch/tests/ntf-tests/topology/config.json --test-dir
    switch/tests/ntf-tests/ --test STP

L3 Static: Simple L3 topology with two switches and two hosts. The setup is
           statically configured.

    sudo ntf --topology switch/tests/ntf-tests/topology/l3_static_topology.json
    --config switch/tests/ntf-tests/topology/config.json --test-dir
    switch/tests/ntf-tests/ --test L3Static

L3 OSPF: Simple L3 topology with two switches and two hosts. The setup runs
         OSPF (Quagga) to learn and advertise networks.

    sudo ntf --topology switch/tests/ntf-tests/topology/l3_ospf_topology.json
    --config switch/tests/ntf-tests/topology/config.json --test-dir
    switch/tests/ntf-tests/ --test L3OSPF

L3 BGP: Simple L3 topology with two switches and two hosts. The setup runs
        EBGP (Quagga) to learn and advertise networks.

    sudo ntf --topology switch/tests/ntf-tests/topology/l3_bgp_topology.json
    --config switch/tests/ntf-tests/topology/config.json --test-dir
    switch/tests/ntf-tests/ --test L3BGP
