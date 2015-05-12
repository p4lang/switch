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

#include <p4utils/tommyhashtbl.h>
#include <p4utils/tommylist.h>

#include "p4features.h"
#include "p4_sim/pd.h"
#include "p4_sim/pre.h"

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

#define handle_to_id(x) (x & 0xFFFF)
#define id_to_handle(t,x) (t << 28 | x)

typedef int switch_status_t;
typedef uint16_t switch_vlan_t;
typedef uint32_t switch_ifindex_t;
typedef unsigned char uchar;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long switch_port_t;
typedef unsigned char switch_device_t;

    
/** Direction - ingress, egress or both */
typedef enum {
    SWITCH_API_DIRECTION_BOTH,           /**< Ingress and Egress directions */
    SWITCH_API_DIRECTION_INGRESS,        /**< Ingress Only */
    SWITCH_API_DIRECTION_EGRESS          /**< Egress Only */
} switch_direction_t;
    
/** 128 bit field */
typedef struct uint128_t {
    uint64_t high;                   /**< higher 64 bits of 128 bit value */
    uint64_t low;                    /**< lower 64 bits of 128 bit value */
} uint128_t;

/** Mac address declaration for use in API */
typedef struct switch_mac_addr {
    uint8_t mac_addr[ETH_LEN];       /**< 6 bytes of mac address */
} switch_mac_addr_t;
    
/* init */
switch_status_t switch_api_init(switch_device_t device);

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

#ifdef __cplusplus
}
#endif

#endif /* _switch_base_types_h_ */
