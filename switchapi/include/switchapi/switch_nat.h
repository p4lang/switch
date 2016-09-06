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
//  switch_nat.h
//  switch_api
//
//  Created on 7/28/14.
//  Copyright (c) 2014 bn. All rights reserved.
//

#ifndef _switch_nat_h
#define _switch_nat_h

#include "switch_base_types.h"
#include "switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup NAT NAT API
 *  API function to add and delete nat rewrites
 *  @{
 */  // begin of NAT API

// NAT
/** Nat mode */
typedef enum switch_nat_mode_ {
  SWITCH_NAT_MODE_NONE,  /**< Nat mode none */
  SWITCH_NAT_MODE_INNER, /**< Nat mode Inner */
  SWITCH_NAT_MODE_OUTER  /**< Nat mode outer */
} switch_nat_mode_t;

/** Nat rewrite type */
typedef enum switch_nat_rw_type_ {
  SWITCH_NAT_RW_TYPE_SRC,         /**< Src IP */
  SWITCH_NAT_RW_TYPE_DST,         /**< Dst IP */
  SWITCH_NAT_RW_TYPE_SRC_DST,     /**< Src and Dst IP */
  SWITCH_NAT_RW_TYPE_SRC_UDP,     /**< Src IP and Udp Port */
  SWITCH_NAT_RW_TYPE_DST_UDP,     /**< Dst IP and Udp Port */
  SWITCH_NAT_RW_TYPE_SRC_DST_UDP, /**< Src IP, Dst IP and Udp Port */
  SWITCH_NAT_RW_TYPE_SRC_TCP,     /**< Src IP and Tcp Port */
  SWITCH_NAT_RW_TYPE_DST_TCP,     /**< Dst IP and Tcp Port */
  SWITCH_NAT_RW_TYPE_SRC_DST_TCP  /**< Src Ip, Dst IP and Tcp Port */
} switch_nat_rw_type_t;

/** Nat info */
typedef struct switch_api_nat_info_ {
  switch_nat_rw_type_t nat_rw_type; /**< Nat rewrite type */
  switch_ip_addr_t src_ip;          /**< Source IP */
  switch_ip_addr_t rw_src_ip;       /**< Source IP rewrite */
  switch_ip_addr_t dst_ip;          /**< Destination IP */
  switch_ip_addr_t rw_dst_ip;       /**< Destination IP rewrite */
  uint16_t src_port;                /**< Source Port */
  uint16_t rw_src_port;             /**< Source Port rewrite */
  uint16_t dst_port;                /**< Destination Port */
  uint16_t rw_dst_port;             /**< Destination Port rewrite */
  uint16_t protocol;                /**< Protocol */

  switch_handle_t vrf_handle;  /**< Vrf ID */
  switch_handle_t nhop_handle; /**< Nexthop handle */
} switch_api_nat_info_t;

/**
 Add an entry to NAT table based on the rewrite type
 @param device - device
 @param api_nat_info - NAT info that contains the rewrite information like
  source ip/dest ip, source port/dest port.
*/
switch_status_t switch_api_nat_add(switch_device_t device,
                                   switch_api_nat_info_t *api_nat_info);

/**
 Delete an entry to NAT table based on the rewrite type
 @param device - device
 @param api_nat_info - NAT info that contains the rewrite information like
  source ip/dest ip, source port/dest port.
*/
switch_status_t switch_api_nat_delete(switch_device_t device,
                                      switch_api_nat_info_t *api_nat_info);

/** @} */  // end of NAT API

#ifdef __cplusplus
}
#endif

#endif
