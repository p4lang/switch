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
2. L2 Multicast (IGMP/MLD snooping)
3. Basic L3 Routing: IPv4, IPv6 and VRF
4. L3 Multicast (Sparse mode, SSM and Bidir)
5. LAG
6. ECMP
7. Tunneling: VXLAN and NVGRE (including L2/L3 Gateway), Geneve, GRE and IPinIP
8. Basic ACL: MAC and IP ACLs
9. Unicast RPF check
10. MPLS: LER, LSR, IPVPN
11. Host interface
12. Mirroring: Ingress and egress mirroring with ERSPAN
13. Counters/Statistics
14. Ingress Policers
15. Lookup bypass in Cpu Tx path
16. Netfilter Rx/Tx support
17. QoS (Quality of Service) - Buffers, Queues
18. Nat
19. CoPP (Control Plance Policing)

Upcoming Features
-----------------

1. VPLS

Documentation
-------------

To generate doxygen documentation for switchapi (from switch directory)

    make doxygen-doc

or view a hosted version at http://p4lang.github.io/switch/
