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

1. Basic L2 switching: VLAN flooding and STP, learning, aging
2. L2 Multicast
3. Basic L3 Routing: IPv4, IPv6 and VRF
4. L3 Multicast
5. LAG
6. ECMP
7. Basic ACL: MAC and IP ACLs
8. Host interface
9. Ingress Policers
10. Statistics: VLAN, ACL
11. Qos (Quality of Service) - Buffers, Queues
12. CoPP (Control Plane Policing)

For the list of supported APIs and attributes, please refer to sai_support.pdf file in the doc directory.
