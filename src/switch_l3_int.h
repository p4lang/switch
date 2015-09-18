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

#ifndef _switch_l3_int_h_
#define _switch_l3_int_h_

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SWITCH_L3_HASH_TABLE_SIZE (64*1024)
#define SWITCH_L3_HASH_KEY_SIZE 24

#define SWITCH_IPV4_PREFIX_LENGTH 32
#define SWITCH_IPV6_PREFIX_LENGTH 128

#define SWITCH_IP_TYPE_NONE       0
#define SWITCH_IP_TYPE_IPv4       1
#define SWITCH_IP_TYPE_IPv6       2

typedef struct switch_ip_addr_info_ {
    tommy_node node;
    bool default_ip;
    switch_ip_addr_t ip;
    switch_handle_t vrf_handle;
} switch_ip_addr_info_t;

typedef struct switch_l3_hash_ {
    unsigned char key[SWITCH_L3_HASH_KEY_SIZE];
    switch_handle_t nhop_handle;
    tommy_hashtable_node node;
    tommy_node vrf_route_node;
    unsigned int path_count;
#ifdef SWITCH_PD
    p4_pd_entry_hdl_t hw_entry;
    p4_pd_entry_hdl_t urpf_entry;
#endif
} switch_l3_hash_t;

typedef struct switch_urpf_member_info_ {
    tommy_node node;
    switch_handle_t intf_handle;
    p4_pd_entry_hdl_t hw_entry;
} switch_urpf_member_info_t;

typedef struct switch_urpg_group_info_ {
    tommy_list urpf_member_list;
} switch_urpf_group_info_t;

typedef struct switch_vrf_route_list_ {
    tommy_list routes;
    uint32_t num_entries;
} switch_vrf_route_list_t;

#define SWITCH_L3_IP_TYPE(ip_info) \
    ip_info->ip.type

#define SWITCH_L3_IP_IPV4_ADDRESS(ip_info) \
    ip_info->ip.ip.v4addr

#define SWITCH_L3_IP_IPV6_ADDRESS(ip_info) \
    ip_info->ip.ip.v6addr

switch_status_t switch_l3_init(switch_device_t device);
switch_status_t switch_l3_free(switch_device_t device);
switch_status_t
switch_api_init_default_route_entries(switch_device_t device,
                                      switch_handle_t vrf_handle);

#ifdef __cplusplus
}
#endif

#endif
