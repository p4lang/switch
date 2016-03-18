Switch
=========

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


Running switch in bmv2 without p4factory
----------------------------------------
You can now run `switch.p4` in bmv2 without cloning `p4factory`. In order to do
this you first need to install [bmv2]
(https://github.com/p4lang/behavioral-model) and its compiler [p4c-bmv2]
(https://github.com/p4lang/p4c-bm) on your system. Additionally, if you plan on
running the tests for `switch.p4`, please make sure you install [PTF]
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
