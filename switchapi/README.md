SwitchAPI
=========

The switchapi library exposes a higher level API on top of lower level resource management API auto-generated from the switch.p4 program in p4factory repository.
Refer to p4factory/targets/switch/README.md for more details on switch.p4 program.

    +-----+    +-----+   +-----+  +-----+
    |App 1|    |App j|   |App n|  |App q|
    |     |... |     |...|     |..|     |
    +-----+    +-----+   +-----+  +-----+
       |        |          |  |     |
    +-----------------------+ |     |
    |      Switch API       | |     |
    |                       | |     |
    +-----------------------+---------+
    |      Resource Mgmt. API         |
    | (auto-gen. from switch.p4)      |
    +---------------------------------+
    |        Soft Switch              |
    |  (compiled from switch.p4)      |
    +---------------------------------+

Supported Features
------------------

1. Basic L2 switching: Flooding, learning and STP
2. Basic L3 Routing: IPv4, IPv6 and VRF
3. LAG
4. ECMP
5. Tunneling: VXLAN and NVGRE (including L2/L3 Gateway), Geneve, and GRE
6. Basic ACL: MAC and IP ACLs
7. Unicast RPF check
8. MPLS: LER, LSR, IPVPN
9. Host interface
10. Mirroring: Ingress and egress mirroring with ERSPAN
11. Counters/Statistics

Upcoming Features
-----------------

1. VPLS

Documentation
-------------

To generate doxygen documentation for switchapi

    make doc

or view a hosted version at http://p4lang.github.io/switchapi
