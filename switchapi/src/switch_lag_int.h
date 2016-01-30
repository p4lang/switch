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

#include "switchapi/switch_id.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_lag.h"

#ifndef _switch_lag_internal_h_
#define _switch_lag_internal_h_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
// LAG
#define MAX_LAG_GROUP_SIZE (64)

#define SWITCH_API_MAX_LAG 256

/** Lag member is one of the ports that can be a member of LAG */
typedef struct switch_lag_member_ {
    tommy_node ingress_node;               /**< linked list node */
    tommy_node egress_node;                /**< linked list node */
    switch_port_t port;                    /**< physical port */
    uint8_t index;                         /**< Index relative to base */
    switch_handle_t lag_member_handle;     /**< lag member handle */
    switch_handle_t lag_handle;            /**< lag member handle */
    switch_direction_t direction;          /**< direction */
#ifdef SWITCH_PD
    p4_pd_mbr_hdl_t mbr_hdl;         /**< Member handle */
    p4_pd_entry_hdl_t xlate_entry;
#endif
} switch_lag_member_t;
    
/** LAG Information */
typedef struct {
    switch_lag_type_t type;             /**< weighted or otherwise */
    switch_ifindex_t  ifindex;          /**< LAG Ifindex */
    switch_handle_t intf_handle;
    bool lacp;                          /**< LACP enabled? */
    lacp_key_t key;                     /**< LACP key */
    tommy_list ingress;                 /**< Ingress port list */
    tommy_list egress;                  /**< Egress port list */
    switch_api_id_allocator *egr_bmap;  /**< egress bitmap */
    unsigned int count;                 /**< number of members */
    uint16_t base;                      /**< Base of lag select table */
    switch_device_t device;             /**< device on which lag is set */
#ifdef SWITCH_PD
    p4_pd_entry_hdl_t hw_entry;         /**< HW entry */
    p4_pd_grp_hdl_t pd_group_hdl;       /**< HW entry */
#endif
} switch_lag_info_t;
 
/** LAG weighted member information */
typedef struct switch_lag_weighted_member_ {
    tommy_node ingress_node;            /**< house keeping node */
    tommy_node egress_node;             /**< house keeping node */
    switch_lag_member_t port;           /**< port member */
    uint16_t weight;                    /**< weight for port in the group */
    uint8_t index;                      /**< Index of member */
#ifdef SWITCH_PD
    p4_pd_mbr_hdl_t mbr_hdl;            /**< Member handle */
#endif
} switch_lag_weighted_member_t;

#define SWITCH_LAG_ID_FROM_IFINDEX(ifindex)                             \
    (ifindex &                                                          \
    (~(SWITCH_IFINDEX_TYPE_LAG << SWITCH_IFINDEX_PORT_WIDTH)))

#define SWITCH_LAG_COMPUTE_IFINDEX(handle)                              \
    (handle_to_id(handle) |                                             \
    (SWITCH_IFINDEX_TYPE_LAG << SWITCH_IFINDEX_PORT_WIDTH))

#define SWITCH_IS_LAG_IFINDEX(ifindex)                                  \
    ((ifindex >> SWITCH_IFINDEX_PORT_WIDTH) ==                          \
     SWITCH_IFINDEX_TYPE_LAG)

switch_status_t switch_lag_init(switch_device_t device);
switch_status_t switch_lag_free(switch_device_t device);
switch_lag_info_t *switch_api_lag_get_internal(switch_handle_t lag_handle);
switch_status_t switch_lag_update_prune_mask_table(switch_device_t device, switch_lag_info_t *lag_info);

#ifdef __cplusplus
}
#endif

#endif /* switch_lag_internal_h */
