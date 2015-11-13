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
#ifndef _switch_hostif_h_
#define _switch_hostif_h_

#include "switch_base_types.h"
#include "switch_handle.h"
#include "switch_acl.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup HostInterface Host Interface API
 *  API functions define and manipulate host interfaces
 *  @{
 */ // begin of Host Interface API

/** switch hostif reason code */
typedef enum switch_hostif_reason_code_ {
    SWITCH_HOSTIF_REASON_CODE_NONE = 0x0,
    SWITCH_HOSTIF_REASON_CODE_STP = 0x1,
    SWITCH_HOSTIF_REASON_CODE_LACP = 0x2,
    SWITCH_HOSTIF_REASON_CODE_EAPOL = 0x3,
    SWITCH_HOSTIF_REASON_CODE_LLDP = 0x4,
    SWITCH_HOSTIF_REASON_CODE_PVRST = 0x5,
    SWITCH_HOSTIF_REASON_CODE_IGMP_TYPE_QUERY = 0x6,
    SWITCH_HOSTIF_REASON_CODE_IGMP_TYPE_LEAVE = 0x7,
    SWITCH_HOSTIF_REASON_CODE_IGMP_TYPE_V1_REPORT = 0x8,
    SWITCH_HOSTIF_REASON_CODE_IGMP_TYPE_V2_REPORT = 0x9,
    SWITCH_HOSTIF_REASON_CODE_IGMP_TYPE_V3_REPORT = 0xa,
    SWITCH_HOSTIF_REASON_CODE_SAMPLEPACKET = 0xb,
    SWITCH_HOSTIF_REASON_CODE_ARP_REQUEST = 0xc,
    SWITCH_HOSTIF_REASON_CODE_ARP_RESPONSE = 0xd,
    SWITCH_HOSTIF_REASON_CODE_DHCP = 0xe,
    SWITCH_HOSTIF_REASON_CODE_OSPF = 0xf,
    SWITCH_HOSTIF_REASON_CODE_PIM = 0x10,
    SWITCH_HOSTIF_REASON_CODE_VRRP = 0x11,
    SWITCH_HOSTIF_REASON_CODE_BGP = 0x12,
    SWITCH_HOSTIF_REASON_CODE_DHCPV6 = 0x13,
    SWITCH_HOSTIF_REASON_CODE_OSPFV6 = 0x14,
    SWITCH_HOSTIF_REASON_CODE_VRRPV6 = 0x15,
    SWITCH_HOSTIF_REASON_CODE_BGPV6 = 0x16,
    SWITCH_HOSTIF_REASON_CODE_IPV6_NEIGHBOR_DISCOVERY = 0x17,
    SWITCH_HOSTIF_REASON_CODE_IPV6_MLD_V1_V2 = 0x18,
    SWITCH_HOSTIF_REASON_CODE_IPV6_MLD_V1_REPORT = 0x19,
    SWITCH_HOSTIF_REASON_CODE_IPV6_MLD_V1_DONE = 0x1a,
    SWITCH_HOSTIF_REASON_CODE_MLD_V2_REPORT = 0x1b,
    SWITCH_HOSTIF_REASON_CODE_L3_MTU_ERROR = 0x1c,
    SWITCH_HOSTIF_REASON_CODE_TTL_ERROR = 0x1d,

    SWITCH_HOSTIF_REASON_CODE_CUSTOM = 0x100,
    SWITCH_HOSTIF_REASON_CODE_GLEAN = 0x101,
    SWITCH_HOSTIF_REASON_CODE_MYIP = 0x102,
    SWITCH_HOSTIF_REASON_CODE_DROP = 0x103,
    SWITCH_HOSTIF_REASON_CODE_NULL_DROP = 0x103,
    SWITCH_HOSTIF_REASON_CODE_ICMP_REDIRECT = 0x104,
    SWITCH_HOSTIF_REASON_CODE_SRC_IS_LINK_LOCAL = 0x105,
    SWITCH_HOSTIF_REASON_CODE_MAX = 0x200,
} switch_hostif_reason_code_t;

/** switch channel */
typedef enum switch_hostif_channel_ {
    SWITCH_HOSTIF_CHANNEL_CB,
    SWITCH_HOSTIF_CHANNEL_FD,
    SWITCH_HOSTIF_CHANNEL_NETDEV,
} switch_hostif_channel_t;

/** switch hostif group */
typedef struct switch_hostif_group_ {
    uint32_t egress_queue;                      /**< egress queue number */
    uint32_t priority;                          /**< priority */
} switch_hostif_group_t;

/** switch hostif reason code info */
typedef struct switch_api_hostif_rcode_info_ {
    switch_hostif_reason_code_t reason_code;    /**< reason code */
    switch_acl_action_t action;                 /**< packet action */
    uint32_t priority;                          /**< priority */
    switch_hostif_channel_t channel;            /**< hostif channel */
    switch_handle_t hostif_group_id;            /**< hostif group id */
} switch_api_hostif_rcode_info_t;

/** hostif tx/rx packet info */
typedef struct switch_hostif_packet_ {
    switch_hostif_reason_code_t reason_code;    /**< reason code */
    bool is_lag;                                /**< handle is lag or port. used in rx */
    switch_handle_t handle;                     /**< port or lag. used in tx/rx */
    bool tx_bypass;                             /**< tx type flag to skip pipeline */
    void *pkt;                                  /**< packet buffer rx/tx */
    uint32_t pkt_size;                          /**< packet buffer size */
} switch_hostif_packet_t;

/** Host interface name size */
#define SWITCH_HOSTIF_NAME_SIZE 16

/** host interface */
typedef struct switch_hostif_ {
    switch_handle_t handle;                     /**< front panel port id */
    char intf_name[SWITCH_HOSTIF_NAME_SIZE];    /**< interface name */
} switch_hostif_t;

/** CPU Rx Callback */
typedef void(*switch_hostif_rx_callback_fn)(switch_hostif_packet_t *hostif_packet);

/**
Register for callback on reception of packets qualified by reason
@param device device to register callback
@param cb_fn callback function pointer
*/
switch_status_t switch_api_hostif_register_rx_callback(switch_device_t device, switch_hostif_rx_callback_fn cb_fn);

/**
Deregister for callback on reception of packets qualified by reason
@param device device to register callback
@param cb_fn callback function pointer
*/
switch_status_t switch_api_hostif_deregister_rx_callback(switch_device_t device, switch_hostif_rx_callback_fn cb_fn);

/**
Allocate packe memory to transmit
@param device device
@param hostif_packet packet info
*/
switch_status_t switch_api_hostif_tx_packet(switch_device_t device, switch_hostif_packet_t *hostif_packet);

/**
 Create a hostif profile to be shared across multiple reason codes
 @param device device
 @param hostif_group hostif group info
 */
switch_handle_t switch_api_hostif_group_create(switch_device_t device, switch_hostif_group_t *hostif_group);

/**
 Delete a hostif profile that is shared across multiple reason codes
 @param device device
 @param hostif_group_id hostif group id
 */
switch_status_t switch_api_hostif_group_delete(switch_device_t device, switch_handle_t hostif_group_id);

/**
 Add a hostif reason code to trap/forward the packet to cpu
 @param device device
 @param rcode_api_info reason code info
 */
switch_status_t switch_api_hostif_reason_code_create(switch_device_t device,
                                                     switch_api_hostif_rcode_info_t *rcode_api_info);

/**
 Update a hostif reason code to trap/forward the packet to cpu
 @param device device
 @param rcode_api_info reason code info
 */
switch_status_t switch_api_hostif_reason_code_update(switch_device_t device,
                                                     switch_api_hostif_rcode_info_t *rcode_api_info);

/**
 Remove a reason code to trap/forward the packet to cpu
 @param device device
 @param reason_code reason code 
 */
switch_status_t switch_api_hostif_reason_code_delete(switch_device_t device,
                                                     switch_hostif_reason_code_t reason_code);

/**
 Create host interface
 @param device device
 @param hostif host interface
 */
switch_handle_t
switch_api_hostif_create(switch_device_t device, switch_hostif_t *hostif);

/**
 Delete host interface
 @param device device
 @param hostif_handle hostif handle
 */
switch_status_t
switch_api_hostif_delete(switch_device_t device, switch_handle_t hostif_handle);

/**
 Return nexthop based on reason code
 @param rcode Reason code
 */
switch_handle_t
switch_api_cpu_nhop_get(switch_hostif_reason_code_t rcode);

/** @} */ // end of Host Interface API

#ifdef __cplusplus
}
#endif

#endif
