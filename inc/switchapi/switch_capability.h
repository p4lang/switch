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

//
//  switch_capability.h
//  switch_api
//
//  Created on 7/28/14.
//  Copyright (c) 2014 bn. All rights reserved.
//

#ifndef _switch_capability_h
#define _switch_capability_h

#include "switch_base_types.h"
#include "switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
    
/** @defgroup SWITCH Switch API
 *  @{
 */ // begin of SWITCH API

// Switch

#define SWITCH_API_DEFAULT_VLAN      1                   /**< system default vlan */
#define SWITCH_API_DEFAULT_VRF       1                   /**< system default vrf */

/** switch operational status */
typedef enum switch_oper_status_ {
    SWITCH_OPER_STATUS_UNKNOWN,
    SWITCH_OPER_STATUS_UP,
    SWITCH_OPER_STATUS_DOWN,
    SWITCH_OPER_STATUS_FAILED
} switch_oper_status_t;

/** switch statistics */
typedef enum switch_stat_counter_ {
    SWITCH_STAT_GLOBAL_LOW_DROP_PKTS,
    SWITCH_STAT_GLOBAL_HIGH_DROP_PKTS,
    SWITCH_STAT_GLOBAL_PRIVILEGE_DROP_PKTS,
    SWITCH_STAT_DROP_COUNT_TX,
    SWITCH_STAT_DROP_COUNT_RX
} switch_stat_counter_t;

/** switch hash fields */
typedef enum switch_ecmp_hash_fields_ {
    SWITCH_HASH_SRC_IP        = (1 << 0),
    SWITCH_HASH_DST_IP        = (1 << 1),
    SWITCH_HASH_L4_SRC_PORT   = (1 << 2),
    SWITCH_HASH_L4_DST_PORT   = (1 << 3),
} switch_ecmp_hash_fields_t;

/** switch attributes */
typedef enum switch_capability_attr_ {
    SWITCH_ATTR_PORT_NUMBER,
    SWITCH_ATTR_MAX_VRF,
    SWITCH_ATTR_ON_LINK_ROUTE_SUPPORTED,
    SWITCH_ATTR_OPER_STATUS,
    SWITCH_ATTR_HW_SEQUENCE_ID,
    SWITCH_ATTR_ADMIN_STATE,
    SWITCH_ATTR_BCAST_CPU_FLOOD_ENABLE,
    SWITCH_ATTR_MCAST_CPU_FLOOD_ENABLE,
    SWITCH_ATTR_DEFAULT_VLAN_ID,
    SWITCH_ATTR_MAX_LEARNED_ADDRESSES,
    SWITCH_ATTR_FDB_UNICAST_MISS_ACTION,
    SWITCH_ATTR_FDB_MULTICAST_MISS_ACTION,
    SWITCH_ATTR_FDB_BROADCAST_MISS_ACTION,
    SWITCH_ATTR_ECMP_HASH_TYPE,
    SWITCH_ATTR_ECMP_HASH_FIELDS,

    SWITCH_ATTR_CUSTOM_RANGE_BASE = 0x10000000,
    SWITCH_ATTR_DEFAULT_VRF_ID
} switch_capability_attr_t;

/** switch capability info */
typedef struct switch_api_info_ {
    uint16_t max_ports;                          /**< max ports in the switch */
    uint16_t max_lags;                           /**< max lag supported */
    uint16_t max_port_per_lag;                   /**< max ports per lag */
    uint16_t max_vrf;                            /**< max vrf supported */
    uint16_t max_stp_groups;                     /**< max spanning tree group */
    uint16_t max_tunnels;                        /**< max tunnels */
    uint16_t max_span_sessions;                  /**< max span sessions */
} switch_api_info_t;

/**
 Set switch attribute
 @param attr_type - attribute type
 @param value - value of the attribute
 */
switch_status_t switch_api_capability_attribute_set(switch_capability_attr_t attr_type, uint64_t value);

/**
 Get switch attribute
 @param attr_type - attribute type
 @param value - value of the attribute
 */
switch_status_t switch_api_capability_attribute_get(switch_capability_attr_t attr_type, uint64_t *value);

/**
 Returns switch capabilities - TBD
 @param switch_info struct to hold switch capabilities
 */
switch_status_t switch_api_capability_capabilities_get(switch_api_info_t *switch_info);

/** @} */ // end of switch API

#ifdef __cplusplus
}
#endif

#endif
