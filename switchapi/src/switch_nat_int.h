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
//  switch_nat_int.h
//  switch_api
//
//  Created on 7/28/14.
//  Copyright (c) 2014 bn. All rights reserved.
//

#ifndef _switch_nat_int_h_
#define _switch_nat_int_h_

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_nat.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SWITCH_NAT_HASH_KEY_SIZE 24

typedef struct switch_nat_info_ {
  unsigned char key[SWITCH_NAT_HASH_KEY_SIZE];
  switch_api_nat_info_t api_nat_info;
  tommy_hashtable_node node;
#ifdef SWITCH_PD
  uint32_t nat_rw_index;
  p4_pd_entry_hdl_t hw_entry;
  p4_pd_entry_hdl_t rw_hw_entry;
#endif
} switch_nat_info_t;

#define SWITCH_NAT_SRC_IP(info) info->src_ip.ip.v4addr

#define SWITCH_NAT_DST_IP(info) info->dst_ip.ip.v4addr

#define SWITCH_NAT_TYPE_IS_VALID_SRC(info)                  \
  ((info->nat_rw_type == SWITCH_NAT_RW_TYPE_SRC) ||         \
   (info->nat_rw_type == SWITCH_NAT_RW_TYPE_SRC_DST) ||     \
   (info->nat_rw_type == SWITCH_NAT_RW_TYPE_SRC_TCP) ||     \
   (info->nat_rw_type == SWITCH_NAT_RW_TYPE_SRC_UDP) ||     \
   (info->nat_rw_type == SWITCH_NAT_RW_TYPE_SRC_DST_TCP) || \
   (info->nat_rw_type == SWITCH_NAT_RW_TYPE_SRC_DST_UDP))

#define SWITCH_NAT_TYPE_IS_VALID_SRC_PORT(info)             \
  ((info->nat_rw_type == SWITCH_NAT_RW_TYPE_SRC_TCP) ||     \
   (info->nat_rw_type == SWITCH_NAT_RW_TYPE_SRC_UDP) ||     \
   (info->nat_rw_type == SWITCH_NAT_RW_TYPE_SRC_DST_TCP) || \
   (info->nat_rw_type == SWITCH_NAT_RW_TYPE_SRC_DST_UDP))

#define SWITCH_NAT_TYPE_IS_VALID_DST(info)                  \
  ((info->nat_rw_type == SWITCH_NAT_RW_TYPE_DST) ||         \
   (info->nat_rw_type == SWITCH_NAT_RW_TYPE_DST_TCP) ||     \
   (info->nat_rw_type == SWITCH_NAT_RW_TYPE_DST_UDP) ||     \
   (info->nat_rw_type == SWITCH_NAT_RW_TYPE_SRC_DST_TCP) || \
   (info->nat_rw_type == SWITCH_NAT_RW_TYPE_SRC_DST_UDP))

#define SWITCH_NAT_TYPE_IS_VALID_DST_PORT(info)             \
  ((info->nat_rw_type == SWITCH_NAT_RW_TYPE_DST_TCP) ||     \
   (info->nat_rw_type == SWITCH_NAT_RW_TYPE_DST_UDP) ||     \
   (info->nat_rw_type == SWITCH_NAT_RW_TYPE_SRC_DST_TCP) || \
   (info->nat_rw_type == SWITCH_NAT_RW_TYPE_SRC_DST_UDP))

#define SWITCH_NAT_RW_SRC_IP(info) info->rw_src_ip.ip.v4addr

#define SWITCH_NAT_RW_DST_IP(info) info->rw_dst_ip.ip.v4addr

switch_status_t switch_nat_init(switch_device_t device);
switch_status_t switch_nat_free(switch_device_t device);

#ifdef __cplusplus
}
#endif

#endif
