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
