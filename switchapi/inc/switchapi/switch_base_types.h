/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _switch_base_types_h_
#define _switch_base_types_h_

#include <tommyds/tommyhashtbl.h>
#include <tommyds/tommylist.h>

#include "p4features.h"
#include "drop_reasons.h"
#include "p4features.h"
//#include "model_flags.h"
#ifdef BMV2
#include "pd/pd.h"
#include "pd/pd_pre.h"
#else
#include "p4_sim/pd.h"
#include "p4_sim/pd_pre.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define UNUSED(x) *(&x) = x;

#define TRUE 1
#define FALSE 0

// Enable use of PD wrapper API
#define SWITCH_PD 1

#define ETH_LEN 6

#define switch_malloc(x, c) malloc(x * c)
#define switch_free(x) free(x)
#define switch_realloc(x, sz) realloc(x, sz)

#define HANDLE_TYPE_SHIFT 27

#define handle_to_id(x) (x & 0x3FFFFFF)
#define id_to_handle(t,x) (t << HANDLE_TYPE_SHIFT | x)

typedef int switch_status_t;
typedef uint16_t switch_vlan_t;
typedef uint32_t switch_ifindex_t;
typedef unsigned char uchar;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long switch_port_t;
typedef unsigned char switch_device_t;
typedef uint8_t switch_cos_t;
typedef unsigned int switch_vrf_id_t;

typedef uint16_t switch_rid_t;

/** Direction - ingress, egress or both */
typedef enum {
    SWITCH_API_DIRECTION_BOTH,           /**< Ingress and Egress directions */
    SWITCH_API_DIRECTION_INGRESS,        /**< Ingress Only */
    SWITCH_API_DIRECTION_EGRESS          /**< Egress Only */
} switch_direction_t;

/** 128 bit field */
typedef struct uint128_t {
    union {
        uint8_t  addr8[16];
        uint16_t addr16[8];
        uint16_t addr32[4];
    } u;
} uint128_t;

/** Mac address declaration for use in API */
typedef struct switch_mac_addr {
    uint8_t mac_addr[ETH_LEN];       /**< 6 bytes of mac address */
} switch_mac_addr_t;

/* init */
switch_status_t switch_api_init(switch_device_t device, unsigned int num_ports);
int start_switch_api_packet_driver(void);

/** IP address type v4 or v6 */
typedef enum {
   SWITCH_API_IP_ADDR_V4,                 /**< IPv4 address type */
   SWITCH_API_IP_ADDR_V6                  /**< IPv6 address type */
} switch_ip_addr_type_t;

/** IP address - v4 and v6 with type */
typedef struct switch_ip_addr_ {
    switch_ip_addr_type_t type;          /**< IPv4 or IPv6 */
    union {
        unsigned int v4addr;         /**< IPv4 address */
        uint8_t v6addr[16];          /**< IPv6 address */
    } ip;                            /**< detail based on type */
    unsigned int prefix_len;         /**< prefix length on interface */
} switch_ip_addr_t;

#define SWITCH_IFINDEX_PORT_WIDTH 9

/** Ifindex type */
typedef enum switch_ifindex_type_ {
    SWITCH_IFINDEX_TYPE_VLAN_INTERFACE = 1,
    SWITCH_IFINDEX_TYPE_LAG = 2,
    SWITCH_IFINDEX_TYPE_TUNNEL = 3,
    SWITCH_IFINDEX_TYPE_CPU = 4,
    SWITCH_IFINDEX_TYPE_MAX = 128
} switch_ifinedx_type_t;

/** counter info */
typedef struct switch_counter_ {
    uint64_t num_packets;           /**< number of packets */
    uint64_t num_bytes;             /**< number of bytes */
} switch_counter_t;

typedef enum switch_packet_type_ {
    SWITCH_PACKET_TYPE_UNICAST = 1,
    SWITCH_PACKET_TYPE_MULTICAST = 2,
    SWITCH_PACKET_TYPE_BROADCAST = 4,
    SWITCH_PACKET_TYPE_MAX = SWITCH_PACKET_TYPE_BROADCAST
} switch_packet_type_t;

#ifdef __cplusplus
}
#endif

#endif /* _switch_base_types_h_ */
