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

#include "switch_port_int.h"
#include "switch_lag_int.h"
#include "switchapi/switch_mcast.h"
#include "switchapi/switch_capability.h"

#ifndef switch_mcast_internal_h
#define switch_mcast_internal_h

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


#define SWITCH_MCAST_RID_HASH_KEY_SIZE   24
#define SWITCH_MCAST_GROUP_HASH_KEY_SIZE 64

typedef uint16_t switch_rid_t;
typedef uint32_t mc_mgrp_hdl_t;

#define SWITCH_PORT_ARRAY_SIZE ((SWITCH_API_MAX_PORTS + 7)/8)
typedef uint8_t switch_mc_port_map_t[SWITCH_PORT_ARRAY_SIZE];
#define SWITCH_LAG_ARRAY_SIZE ((SWITCH_API_MAX_LAG + 7)/8)
typedef uint8_t switch_mc_lag_map_t[SWITCH_LAG_ARRAY_SIZE];

#define SWITCH_MC_PORT_MAP_CLEAR_(pm, port)                              \
  do {                                                                   \
      int    _port_p = (port);                                           \
      switch_mc_port_map_t *_port_pm = &(pm);                            \
      if (_port_p >= SWITCH_API_MAX_PORTS) break;                        \
      size_t _port_i = (_port_p)/8;                                      \
      int _port_j = (_port_p) % 8;                                       \
      (*_port_pm)[_port_i] &= ~(1 << _port_j);                           \
  } while (0);

#define SWITCH_MC_PORT_MAP_SET_(pm, port)                                \
  do {                                                                   \
      int    _port_p = (port);                                           \
      switch_mc_port_map_t *_port_pm = &(pm);                            \
      if (_port_p >= SWITCH_API_MAX_PORTS) break;                        \
      size_t _port_i = (_port_p)/8;                                      \
      int _port_j = (_port_p) % 8;                                       \
      (*_port_pm)[_port_i] |= (1 << _port_j);                            \
  } while (0);

#define SWITCH_MC_LAG_MAP_CLEAR_(pm, lag)                                \
  do {                                                                   \
    int    _lag_p = (lag);                                               \
    switch_mc_lag_map_t *_lag_pm = &(pm);                                \
    if (_lag_p >= SWITCH_API_MAX_LAG) break;                             \
    size_t _lag_i = (_lag_p)/8;                                          \
    int    _lag_j = (_lag_p)%8;                                          \
    (*_lag_pm)[_lag_i] &= ~(1 << _lag_j);                                \
  } while (0);

#define SWITCH_MC_LAG_MAP_SET_(pm, lag)                                  \
  do {                                                                   \
    int    _lag_p = (lag);                                               \
    switch_mc_lag_map_t *_lag_pm = &(pm);                                \
    if (_lag_p >= SWITCH_API_MAX_LAG) break;                             \
    size_t _lag_i = (_lag_p)/8;                                          \
    int    _lag_j = (_lag_p)%8;                                          \
    (*_lag_pm)[_lag_i] |= (1 << _lag_j);                                 \
  } while (0);

typedef enum switch_mcast_node_type_ {
    SWITCH_NODE_TYPE_SINGLE = 1,
} switch_mcast_node_type_t;

typedef struct switch_mcast_node_info_ {
    switch_rid_t rid;
    switch_mc_port_map_t port_map;
    switch_mc_lag_map_t lag_map;
    p4_pd_entry_hdl_t hw_entry;
    p4_pd_entry_hdl_t rid_hw_entry;
} switch_mcast_node_info_t;

typedef struct switch_mcast_node_ {
    tommy_node node;
    switch_mcast_node_type_t node_type;
    union {
        switch_mcast_node_info_t node_info;
    } u;
} switch_mcast_node_t;

typedef struct switch_mcast_info_ {
    p4_pd_entry_hdl_t mgrp_hdl;
    tommy_list node_list;
    uint16_t mbr_count_max;
    uint16_t mbr_count;
    switch_vlan_interface_t *mbrs;
} switch_mcast_info_t;

typedef struct switch_mcast_rid_key_ {
    switch_handle_t mgid_handle;
    switch_handle_t bd_handle;
    switch_handle_t intf_handle;
} switch_mcast_rid_key_t;

typedef struct switch_mcast_rid_ {
    switch_mcast_rid_key_t rid_key;
    uint16_t rid;
    tommy_hashtable_node node;
} switch_mcast_rid_t;

typedef struct switch_mcast_group_key_ {
    switch_handle_t bd_vrf_handle;
    switch_ip_addr_t src_ip;
    switch_ip_addr_t grp_ip;
    bool sg_entry;
} switch_mcast_group_key_t;

typedef struct switch_mcast_group_info_ {
    switch_mcast_group_key_t group_key;
    tommy_hashtable_node node;
    switch_handle_t mgid_handle;
    p4_pd_entry_hdl_t outer_hw_entry;
    p4_pd_entry_hdl_t inner_hw_entry;
} switch_mcast_group_info_t;

typedef enum switch_mcast_key_type_ {
    SWITCH_MCAST_KEY_TYPE_BD,
    SWITCH_MCAST_KEY_TYPE_VRF
} switch_mcast_key_type_t;

#define SWITCH_MCAST_NODE_RID(node) \
    node->u.node_info.rid

#define SWITCH_MCAST_NODE_RID_HW_ENTRY(node) \
    node->u.node_info.rid_hw_entry

#define SWITCH_MCAST_GROUP_IPV4_SRC_IP(group_key) \
    group_key->src_ip.ip.v4addr

#define SWITCH_MCAST_GROUP_IPV6_SRC_IP(group_key) \
    group_key->src_ip.ip.v6addr

#define SWITCH_MCAST_GROUP_IPV4_GRP_IP(group_key) \
    group_key->grp_ip.ip.v4addr

#define SWITCH_MCAST_GROUP_IPV6_GRP_IP(group_key) \
    group_key->grp_ip.ip.v6addr

#define SWITCH_MCAST_GROUP_IP_TYPE(group_key) \
    group_key->grp_ip.type

#define SWITCH_MCAST_NODE_INFO_HW_ENTRY(node) \
    node->u.node_info.hw_entry

#define SWITCH_MCAST_NODE_INFO_PORT_MAP(node) \
    node->u.node_info.port_map

#define SWITCH_MCAST_NODE_INFO_LAG_MAP(node) \
    node->u.node_info.lag_map

#define SWITCH_MCAST_ECMP_INFO_HW_ENTRY(node) \
    node->u.ecmp_info.hw_entry

#define SWITCH_MCAST_ECMP_INFO_NODE_LIST(node) \
    node->u.ecmp_info.node_list

#define SWITCH_MCAST_ECMP_INFO_HDL(node) \
    node->u.ecmp_info.handle

/* MCAST Internal API's */
switch_status_t switch_mcast_init(switch_device_t device);
switch_status_t switch_mcast_free(switch_device_t device);
uint16_t switch_mcast_rid_allocate();
void switch_mcast_rid_free(uint16_t rid);
switch_handle_t switch_api_mcast_index_allocate(switch_device_t device);
switch_status_t switch_api_mcast_index_delete(switch_device_t device, switch_handle_t mgid_handle);
switch_mcast_info_t * switch_mcast_tree_get(switch_handle_t mgid_handle);
switch_status_t switch_multicast_update_lag_port_map(switch_device_t device, switch_handle_t lag_handle);

#ifdef __cplusplus
}
#endif

#endif
