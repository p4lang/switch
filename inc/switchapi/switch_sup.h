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
#ifndef _switch_sup_h_
#define _switch_sup_h_

#include "switch_base_types.h"
#include "switch_handle.h"
#include "switch_acl.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** switch sup code */
typedef enum switch_sup_code_ {
    SWITCH_SUP_CODE_NONE = 0x0,
    SWITCH_SUP_CODE_STP = 0x1,
    SWITCH_SUP_CODE_LACP = 0x2,
    SWITCH_SUP_CODE_EAPOL = 0x3,
    SWITCH_SUP_CODE_LLDP = 0x4,
    SWITCH_SUP_CODE_PVRST = 0x5,
    SWITCH_SUP_CODE_IGMP_TYPE_QUERY = 0x6,
    SWITCH_SUP_CODE_IGMP_TYPE_LEAVE = 0x7,
    SWITCH_SUP_CODE_IGMP_TYPE_V1_REPORT = 0x8,
    SWITCH_SUP_CODE_IGMP_TYPE_V2_REPORT = 0x9,
    SWITCH_SUP_CODE_IGMP_TYPE_V3_REPORT = 0xa,
    SWITCH_SUP_CODE_SAMPLEPACKET = 0xb,
    SWITCH_SUP_CODE_ARP_REQUEST = 0xc,
    SWITCH_SUP_CODE_ARP_RESPONSE = 0xd,
    SWITCH_SUP_CODE_DHCP = 0xe,
    SWITCH_SUP_CODE_OSPF = 0xf,
    SWITCH_SUP_CODE_PIM = 0x10,
    SWITCH_SUP_CODE_VRRP = 0x11,
    SWITCH_SUP_CODE_BGP = 0x12,
    SWITCH_SUP_CODE_DHCPV6 = 0x13,
    SWITCH_SUP_CODE_OSPFV6 = 0x14,
    SWITCH_SUP_CODE_VRRPV6 = 0x15,
    SWITCH_SUP_CODE_BGPV6 = 0x16,
    SWITCH_SUP_CODE_IPV6_NEIGHBOR_DISCOVERY = 0x17,
    SWITCH_SUP_CODE_IPV6_MLD_V1_V2 = 0x18,
    SWITCH_SUP_CODE_IPV6_MLD_V1_REPORT = 0x19,
    SWITCH_SUP_CODE_IPV6_MLD_V1_DONE = 0x1a,
    SWITCH_SUP_CODE_MLD_V2_REPORT = 0x1b,
    SWITCH_SUP_CODE_L3_MTU_ERROR = 0x1c,
    SWITCH_SUP_CODE_TTL_ERROR = 0x1d, 
    SWITCH_SUP_CODE_MAX = 0x1e,
} switch_sup_code_t;

/** switch channel */
typedef enum switch_sup_channel_ {
    SWITCH_CHANNEL_CB,
    SWITCH_CHANNEL_FD,
    SWITCH_CHANNEL_NETDEV
} switch_sup_channel_t;

/** switch sup group */
typedef struct switch_sup_group_ {
    uint32_t egress_queue;                      /**< egress queue number */
    uint32_t priority;                          /**< priority */
} switch_sup_group_t;

/** switch sup code info */
typedef struct switch_sup_code_info {
    switch_sup_code_t sup_code;                 /**< sup code */
    switch_acl_action_t action;                 /**< packet action */
    uint32_t priority;                          /**< priority */
    switch_sup_channel_t channel;               /**< sup channel */
    switch_handle_t sup_group_id;               /**< sup group id */
} switch_sup_code_info_t;

/** sup tx/rx packet info */
typedef struct switch_sup_packet_ {
    switch_sup_code_t sup_code;                 /**< sup code */
    bool is_lag;                                /**< handle is lag or port. used in rx */
    switch_handle_t handle;                     /**< port or lag. used in tx/rx */
    bool tx_bypass;                             /**< tx type flag to skip pipeline */
    void *pkt;                                  /**< packet buffer rx/tx */
    uint32_t pkt_size;                          /**< packet buffer size */
} switch_sup_packet_t;

#define SWITCH_INTF_NAME_SIZE 16

/** sup interface */
typedef struct switch_sup_interface_ {
    switch_handle_t handle;                     /**< front panel port id */
    char intf_name[SWITCH_INTF_NAME_SIZE];      /**< interface name */
} switch_sup_interface_t;

/** CPU Rx Callback */
typedef void(*switch_sup_rx_callback_fn)(switch_sup_packet_t *sup_packet);

/**
Register for callback on reception of packets qualified by reason
@param device device to register callback
@param cb_fn callback function pointer
*/
switch_status_t switch_api_sup_register_rx_callback(switch_device_t device, switch_sup_rx_callback_fn cb_fn);

/**
Deregister for callback on reception of packets qualified by reason
@param device device to register callback
@param cb_fn callback function pointer
*/
switch_status_t switch_api_sup_deregister_rx_callback(switch_device_t device, switch_sup_rx_callback_fn cb_fn);

/**
Allocate packe memory to transmit
@param device device
@param sup_packet sup packet info
*/
switch_status_t switch_api_sup_tx_packet_to_hw(switch_device_t device, switch_sup_packet_t *sup_packet);

/**
 Create a sup profile to be shared across multiple sup codes
 @param device device
 @param sup_group sup group info
 */
switch_handle_t switch_api_sup_group_create(switch_device_t device, switch_sup_group_t *sup_group);

/**
 Delete a sup profile that is shared across multiple sup codes
 @param device device
 @param sup_group_id sup group id
 */
switch_status_t switch_api_sup_group_delete(switch_device_t device, switch_handle_t sup_group_id);

/**
 Add a sup code to trap/forward the packet to cpu
 @param device device
 @param sup_code_info sup code info
 */
switch_status_t switch_api_sup_code_create(switch_device_t device, switch_sup_code_info_t *sup_code_info);

/**
 Update a sup code to trap/forward the packet to cpu
 @param device device
 @param sup_code_info sup code info
 */
switch_status_t switch_api_sup_code_update(switch_device_t device, switch_sup_code_info_t *sup_code_info);

/**
 Remove a sup code to trap/forward the packet to cpu
 @param device device
 @param sup_code_info sup code info
 */
switch_status_t switch_api_sup_code_delete(switch_device_t device, switch_sup_code_t sup_code);

/**
 Add a sup code to trap/forward the packet to cpu
 @param device device
 @param sup_code_info sup code info
 */
switch_handle_t
switch_api_sup_interface_create(switch_device_t device, switch_sup_interface_t *sup_interface);

/**
 Add a sup code to trap/forward the packet to cpu
 @param device device
 @param sup_code_info sup code info
 */
switch_status_t
switch_api_sup_interface_delete(switch_device_t device, switch_handle_t sup_intf_handle);
#ifdef __cplusplus
}
#endif

#endif
