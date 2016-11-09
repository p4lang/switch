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
#include "switch_meter.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup HostInterface Host Interface API
 *  API functions define and manipulate host interfaces
 *  @{
 */  // begin of Host Interface API

/** switch hostif reason code */
typedef enum switch_hostif_reason_code_ {
  /*
   * Reason code groups must start on power of 2 boundary since
   * rx_net_filters are setup to use masks
   */
  /* generic reason codes 0x0-0x0FF */
  SWITCH_HOSTIF_REASON_CODE_NONE = 0x0,
  SWITCH_HOSTIF_REASON_CODE_CUSTOM = 0x1,
  SWITCH_HOSTIF_REASON_CODE_DROP = 0x2,
  SWITCH_HOSTIF_REASON_CODE_NULL_DROP = 0x3,
  SWITCH_HOSTIF_REASON_CODE_SFLOW_SAMPLE = 0x4,

  /* L2 reason codes 0x100 - 0x1FF */
  SWITCH_HOSTIF_REASON_CODE_L2_START = 0x100,
  SWITCH_HOSTIF_REASON_CODE_STP = SWITCH_HOSTIF_REASON_CODE_L2_START,
  SWITCH_HOSTIF_REASON_CODE_LACP,                /* 0x101 */
  SWITCH_HOSTIF_REASON_CODE_EAPOL,               /* 0x102 */
  SWITCH_HOSTIF_REASON_CODE_LLDP,                /* 0x103 */
  SWITCH_HOSTIF_REASON_CODE_PVRST,               /* 0x104 */
  SWITCH_HOSTIF_REASON_CODE_IGMP_TYPE_QUERY,     /* 0x105 */
  SWITCH_HOSTIF_REASON_CODE_IGMP_TYPE_LEAVE,     /* 0x106 */
  SWITCH_HOSTIF_REASON_CODE_IGMP_TYPE_V1_REPORT, /* 0x107 */
  SWITCH_HOSTIF_REASON_CODE_IGMP_TYPE_V2_REPORT, /* 0x108 */
  SWITCH_HOSTIF_REASON_CODE_IGMP_TYPE_V3_REPORT, /* 0x109 */

  /* L3 reason codes 0x200-0x2FF */
  SWITCH_HOSTIF_REASON_CODE_L3_START = 0x200,
  SWITCH_HOSTIF_REASON_CODE_SAMPLEPACKET = SWITCH_HOSTIF_REASON_CODE_L3_START,
  SWITCH_HOSTIF_REASON_CODE_ARP_REQUEST,             /* 0x201 */
  SWITCH_HOSTIF_REASON_CODE_ARP_RESPONSE,            /* 0x202 */
  SWITCH_HOSTIF_REASON_CODE_DHCP,                    /* 0x203 */
  SWITCH_HOSTIF_REASON_CODE_OSPF,                    /* 0x204 */
  SWITCH_HOSTIF_REASON_CODE_PIM,                     /* 0x205 */
  SWITCH_HOSTIF_REASON_CODE_VRRP,                    /* 0x206 */
  SWITCH_HOSTIF_REASON_CODE_BGP,                     /* 0x207 */
  SWITCH_HOSTIF_REASON_CODE_DHCPV6,                  /* 0x208 */
  SWITCH_HOSTIF_REASON_CODE_OSPFV6,                  /* 0x209 */
  SWITCH_HOSTIF_REASON_CODE_VRRPV6,                  /* 0x20a */
  SWITCH_HOSTIF_REASON_CODE_BGPV6,                   /* 0x20b */
  SWITCH_HOSTIF_REASON_CODE_IPV6_NEIGHBOR_DISCOVERY, /* 0x20c */
  SWITCH_HOSTIF_REASON_CODE_IPV6_MLD_V1_V2,          /* 0x20d */
  SWITCH_HOSTIF_REASON_CODE_IPV6_MLD_V1_REPORT,      /* 0x20e */
  SWITCH_HOSTIF_REASON_CODE_IPV6_MLD_V1_DONE,        /* 0x20f */
  SWITCH_HOSTIF_REASON_CODE_MLD_V2_REPORT,           /* 0x210 */
  SWITCH_HOSTIF_REASON_CODE_L3_MTU_ERROR,            /* 0x211 */
  SWITCH_HOSTIF_REASON_CODE_TTL_ERROR,               /* 0x212 */
  SWITCH_HOSTIF_REASON_CODE_GLEAN,                   /* 0x213 */
  SWITCH_HOSTIF_REASON_CODE_MYIP,                    /* 0x214 */
  SWITCH_HOSTIF_REASON_CODE_ICMP_REDIRECT,           /* 0x215 */
  SWITCH_HOSTIF_REASON_CODE_SRC_IS_LINK_LOCAL,       /* 0x216 */
  SWITCH_HOSTIF_REASON_CODE_L3_REDIRECT,             /* 0x217 */
  SWITCH_HOSTIF_REASON_CODE_BROADCAST,               /* 0x218 */

  SWITCH_HOSTIF_REASON_CODE_MAX,
} switch_hostif_reason_code_t;

/** switch channel */
typedef enum switch_hostif_channel_ {
  SWITCH_HOSTIF_CHANNEL_CB,
  SWITCH_HOSTIF_CHANNEL_FD,
  SWITCH_HOSTIF_CHANNEL_NETDEV,
} switch_hostif_channel_t;

/** switch hostif group */
typedef struct switch_hostif_group_ {
  switch_qid_t queue_id;          /**< egress queue number */
  uint32_t priority;              /**< priority */
  switch_handle_t policer_handle; /**< policer id */
} switch_hostif_group_t;

/** switch hostif reason code info */
typedef struct switch_api_hostif_rcode_info_ {
  switch_hostif_reason_code_t reason_code; /**< reason code */
  switch_acl_action_t action;              /**< packet action */
  uint32_t priority;                       /**< priority */
  switch_hostif_channel_t channel;         /**< hostif channel */
  switch_handle_t hostif_group_id;         /**< hostif group id */
} switch_api_hostif_rcode_info_t;

/** hostif tx/rx packet info */
typedef struct switch_hostif_packet_ {
  switch_hostif_reason_code_t reason_code; /**< reason code */
  bool is_lag;                     /**< handle is lag or port. used in rx */
  switch_handle_t handle;          /**< port or lag. used in tx/rx */
  switch_ifindex_t egress_ifindex; /**< egress ifindex */
  uint16_t sflow_session_id;       /**< sflow session id */
  bool tx_bypass;                  /**< tx type flag to skip pipeline */
  void *pkt;                       /**< packet buffer rx/tx */
  uint32_t pkt_size;               /**< packet buffer size */
} switch_hostif_packet_t;

/** Host interface name size */
#define SWITCH_HOSTIF_NAME_SIZE 16

/** host interface */
typedef struct switch_hostif_ {
  char intf_name[SWITCH_HOSTIF_NAME_SIZE]; /**< interface name */
} switch_hostif_t;

/** CPU Rx Callback */
typedef void (*switch_hostif_rx_callback_fn)(
    switch_hostif_packet_t *hostif_packet);

/**
Register for callback on reception of packets qualified by reason
@param device device to register callback
@param cb_fn callback function pointer
*/
switch_status_t switch_api_hostif_register_rx_callback(
    switch_device_t device, switch_hostif_rx_callback_fn cb_fn);

/**
Deregister for callback on reception of packets qualified by reason
@param device device to register callback
@param cb_fn callback function pointer
*/
switch_status_t switch_api_hostif_deregister_rx_callback(
    switch_device_t device, switch_hostif_rx_callback_fn cb_fn);

/**
Allocate packe memory to transmit
@param device device
@param hostif_packet packet info
*/
switch_status_t switch_api_hostif_tx_packet(
    switch_device_t device, switch_hostif_packet_t *hostif_packet);

/**
 Create a hostif profile to be shared across multiple reason codes
 @param device device
 @param hostif_group hostif group info
 */
switch_handle_t switch_api_hostif_group_create(
    switch_device_t device, switch_hostif_group_t *hostif_group);

/**
 Delete a hostif profile that is shared across multiple reason codes
 @param device device
 @param hostif_group_id hostif group id
 */
switch_status_t switch_api_hostif_group_delete(switch_device_t device,
                                               switch_handle_t hostif_group_id);

/**
 Add a hostif reason code to trap/forward the packet to cpu
 @param device device
 @param rcode_api_info reason code info
 */
switch_status_t switch_api_hostif_reason_code_create(
    switch_device_t device, switch_api_hostif_rcode_info_t *rcode_api_info);

/**
 Update a hostif reason code to trap/forward the packet to cpu
 @param device device
 @param rcode_api_info reason code info
 */
switch_status_t switch_api_hostif_reason_code_update(
    switch_device_t device, switch_api_hostif_rcode_info_t *rcode_api_info);

/**
 Remove a reason code to trap/forward the packet to cpu
 @param device device
 @param reason_code reason code
 */
switch_status_t switch_api_hostif_reason_code_delete(
    switch_device_t device, switch_hostif_reason_code_t reason_code);

/**
 Create host interface
 @param device device
 @param hostif host interface
 */
switch_handle_t switch_api_hostif_create(switch_device_t device,
                                         switch_hostif_t *hostif);

/**
 Delete host interface
 @param device device
 @param hostif_handle hostif handle
 */
switch_status_t switch_api_hostif_delete(switch_device_t device,
                                         switch_handle_t hostif_handle);

/**
 Return nexthop based on reason code
 @param rcode Reason code
 */
switch_handle_t switch_api_cpu_nhop_get(switch_hostif_reason_code_t rcode);

/** Packet vlan action */
typedef enum switch_packet_vlan_action {
  SWITCH_PACKET_VLAN_NONE = 0x0,
  SWITCH_PACKET_VLAN_ADD = 0x1,
  SWITCH_PACKET_VLAN_REMOVE = 0x2,
  SWITCH_PACKET_VLAN_SWAP = 0x3
} switch_packet_vlan_action_t;

/** Tx bypass flags */
typedef enum switch_tx_bypass_flags_ {
  SWITCH_BYPASS_NONE = 0x0,
  SWITCH_BYPASS_L2 = (1 << 0),
  SWITCH_BYPASS_L3 = (1 << 1),
  SWITCH_BYPASS_ACL = (1 << 2),
  SWITCH_BYPASS_QOS = (1 << 3),
  SWITCH_BYPASS_METER = (1 << 4),
  SWITCH_BYPASS_SYSTEM_ACL = (1 << 5),
  SWITCH_BYPASS_ALL = 0xFFFF
} switch_tx_bypass_flags_t;

/** Rx key for net filter */
typedef struct switch_packet_rx_key_ {
  bool port_valid;                         /**< port handle valid */
  switch_handle_t port_handle;             /**< port handle */
  bool port_lag_valid;                     /**< port lag handle valid */
  switch_handle_t port_lag_handle;         /**< port lag handle */
  bool handle_valid;                       /**< bd or interface handle valid */
  switch_handle_t handle;                  /**< bd or interface handle */
  bool reason_code_valid;                  /**< reascon code valid */
  switch_hostif_reason_code_t reason_code; /**< reason code */
  uint32_t reason_code_mask;               /**< reason code mask */
  uint32_t priority;                       /**< net filter priority */
} switch_packet_rx_key_t;

/** Rx net filter action */
typedef struct switch_packet_rx_action_ {
  switch_handle_t hostif_handle;           /**< hostif handle */
  switch_vlan_t vlan_id;                   /**< vlan id */
  switch_packet_vlan_action_t vlan_action; /**< vlan packet action */
} switch_packet_rx_action_t;

/** Tx key for net filter */
typedef struct switch_packet_tx_key_ {
  bool handle_valid;             /**< hostif handle valid */
  switch_handle_t hostif_handle; /**< hostif handle */
  bool vlan_valid;               /**< vlan valid */
  switch_vlan_t vlan_id;         /**< vlan id */
  uint32_t priority;             /**< net filter priority */
} switch_packet_tx_key_t;

/** Tx net filter ation */
typedef struct switch_packet_tx_action_ {
  switch_handle_t handle;                /**< bd or interface handle */
  switch_tx_bypass_flags_t bypass_flags; /**< bypass flags */
  switch_handle_t port_handle;           /**< egress port */
} switch_packet_tx_action_t;

/**
 Create tx net filter
 @param device device
 @param tx_key tx net filter key
 @param tx_action tx net filter action
 */
switch_status_t switch_api_packet_net_filter_tx_create(
    switch_device_t device,
    switch_packet_tx_key_t *tx_key,
    switch_packet_tx_action_t *tx_action);

/**
 Delete tx net filter
 @param device device
 @param tx_key tx net filter key
 */
switch_status_t switch_api_packet_net_filter_tx_delete(
    switch_device_t device, switch_packet_tx_key_t *tx_key);

/**
 Create rx net filter
 @param device device
 @param rx_key rx net filter key
 @param rx_action rx net filter action
 */
switch_status_t switch_api_packet_net_filter_rx_create(
    switch_device_t device,
    switch_packet_rx_key_t *rx_key,
    switch_packet_rx_action_t *rx_action);

/**
 Delete rx net filter
 @param device device
 @param rx_key rx net filter key
 */
switch_status_t switch_api_packet_net_filter_rx_delete(
    switch_device_t device, switch_packet_rx_key_t *rx_key);

/**
 create a meter for control plane policing
 @param device device
 @param api_meter_info meter struct
 @param meter_handle return meter handle
 */
switch_status_t switch_api_hostif_meter_create(
    switch_device_t device,
    switch_api_meter_t *api_meter_info,
    switch_handle_t *meter_handle);

/**
 delete meter for control plane policing
 @param device device
 @param meter_handle meter handle
*/
switch_status_t switch_api_hostif_meter_delete(switch_device_t device,
                                               switch_handle_t meter_handle);

/** @} */  // end of Host Interface API

#ifdef __cplusplus
}
#endif

#endif
