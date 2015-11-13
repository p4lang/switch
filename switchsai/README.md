SwitchSAI
=========

The switchsai library exposes the standard Switch Abstraction Interface (SAI) API on top of the switchapi API library written to program the data plane described in the switch.p4 program in p4factory repository.

Refer to https://github.com/p4lang/p4factory/tree/master/targets/switch for more details on switch.p4 program and https://github.com/p4lang/switchapi for details on switchapi library.

    +-----+   +-----+   +-----+   +-----+
    |App a|   |App j|   |App n|   |App z|
    |     |...|     |...|     |...|     |
    +-----+   +-----+   +-----+   +-----+
       |         |         |         |
       |         |         |         |
    +---------------+      |         |
    |      SAI      |      |         |
    +--------------------------+     |
    |      SwitchAPI           |     |
    |  (higher level API)      |     |
    +-----------------------------------+
    |      Resource Mgmt. API           |
    | (auto-gen. from switch.p4)        |
    +-----------------------------------+
    |        Soft Switch                |
    |  (compiled from switch.p4)        |
    +-----------------------------------+

Supported Features
------------------

1. Basic L2 switching: VLAN flooding and STP
2. Basic L3 Routing: IPv4, IPv6 and VRF
3. LAG
4. ECMP
5. Basic ACL: MAC and IP ACLs
6. Host interface

For the list of supported APIs and attributes, please refer to sai_support.pdf file in the doc directory.
