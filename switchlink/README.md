Switchlink
==========

The switchlink library provides a Netlink listener that listens to kernel
notifications for network events (link, address, neighbor, route, etc.) and
uses the switchsai library to program the data plane described in the
switch.p4 program in the p4factory repository.

    +---------------------------------------------------+
    |                    Switchlink                     |
    |                                                   |
    +-----------------------+---------------------------+
    |          SAI          |                   ^
    |                       |                   |
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


The switchlink library listens to NETLINK messages only on 'swp' interfaces.
The 'swp' interfaces are TUNTAP interfaces that represent the softswitch's
physical ports. Each 'swp' interface is mapped to a physical port (see
src/switchlink_db.c). Applications (bridge-utils, mstpd, iputils, Quagga, etc.)
interact with the softswitch via the 'swp' interfaces. Users can use native
Linux tools to configure the 'swp' interfaces.

The 'swp' interfaces are created as shown below:

    ip tuntap add dev swp1 mode tap
    ip tuntap add dev swp2 mode tap
    ip tuntap add dev swp3 mode tap
    ip tuntap add dev swp4 mode tap
    ip link set swp1 up
    ip link set swp2 up
    ip link set swp3 up
    ip link set swp4 up

Sample L2 configuration:

    # Create a bridge and add two interfaces

    brctl addbr v100
    brctl addif v100 swp1
    brctl addif v100 swp2
    ip link set v100 up

    # Add few static MAC addresses

    bridge fdb add  00:00:00:00:11:02 dev swp1 master temp
    bridge fdb add  00:00:00:00:22:02 dev swp2 master temp

Sample L3 configuration:

    # Add interface IP addresses

    ip address add 172.16.30.1/24 broadcast + dev swp3
    ip address add 172.16.40.1/24 broadcast + dev swp4

    ip address add 2ffe:3::1/70 dev swp3
    ip address add 2ffe:4::1/48 dev swp4

    # Add neighbors

    ip neigh add 172.16.30.2 lladdr 00:00:00:00:33:02 dev swp3
    ip neigh add 172.16.40.2 lladdr 00:00:00:00:44:02 dev swp4
    ip neigh add 172.16.40.3 lladdr 00:00:00:00:44:03 dev swp4

    ip neigh add 2ffe:3::2 lladdr 00:00:00:00:33:02 dev swp3
    ip neigh add 2ffe:4::2 lladdr 00:00:00:00:44:02 dev swp4
    ip neigh add 2ffe:4::3 lladdr 00:00:00:00:44:03 dev swp4

    # Add routes

    ip route add 172.16.101.0/24 nexthop via 172.16.40.2
    ip route add 172.16.102.0/24 nexthop via 172.16.40.2 nexthop via 172.16.40.3

    ip route add 3ffe:2::/64 nexthop via 2ffe:4::2
    ip route add 3ffe:3::/64 nexthop via 2ffe:4::2 nexthop via 2ffe:4::3

Supported Features
------------------

1. Basic L2 switching
2. Basic L3 Routing: IPv4
3. L2 protocol integration (mstpd)
4. L3 protocol integration (Quagga)
5. ECMP

Upcoming Features
-----------------
1. L2: Learning and aging
2. IPv6
3. LAG
