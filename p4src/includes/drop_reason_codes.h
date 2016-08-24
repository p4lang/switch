/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.

 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 * $Id: $
 *
 ******************************************************************************/
#define DROP_UNKNOWN                       0

#define DROP_OUTER_SRC_MAC_ZERO            10
#define DROP_OUTER_SRC_MAC_MULTICAST       11
#define DROP_OUTER_DST_MAC_ZERO            12
#define DROP_OUTER_ETHERNET_MISS           13
#define DROP_SRC_MAC_ZERO                  14
#define DROP_SRC_MAC_MULTICAST             15
#define DROP_DST_MAC_ZERO                  16

#define DROP_OUTER_IP_VERSION_INVALID      25
#define DROP_OUTER_IP_TTL_ZERO             26
#define DROP_OUTER_IP_SRC_MULTICAST        27
#define DROP_OUTER_IP_SRC_LOOPBACK         28
#define DROP_OUTER_IP_MISS                 29
#define DROP_IP_VERSION_INVALID            30
#define DROP_IP_TTL_ZERO                   31
#define DROP_IP_SRC_MULTICAST              32
#define DROP_IP_SRC_LOOPBACK               33

#define DROP_PORT_VLAN_MAPPING_MISS        40
#define DROP_STP_STATE_LEARNING            41
#define DROP_STP_STATE_BLOCKING            42
#define DROP_SAME_IFINDEX                  43
#define DROP_MULTICAST_SNOOPING_ENABLED    44

#define DROP_MTU_CHECK_FAIL                50
#define DROP_TRAFFIC_MANAGER               51

#define DROP_ACL_DENY                      60
#define DROP_RACL_DENY                     61
#define DROP_URPF_CHECK_FAIL               62
#define DROP_IPSG_MISS                     63
#define DROP_IFINDEX                       64

