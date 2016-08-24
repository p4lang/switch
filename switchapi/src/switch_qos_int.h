/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.

 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 * $Id: $
 *
 ******************************************************************************/

#ifndef _switch_qos_int_h_
#define _switch_qos_int_h_

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_qos.h"
#include "switch_pd_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SWITCH_QOS_DEFAULT_TC 0

typedef struct switch_qos_map_info_ {
  tommy_node node;
  switch_qos_map_t qos_map;
  p4_pd_entry_hdl_t pd_hdl;
} switch_qos_map_info_t;

typedef struct switch_qos_map_list_ {
  tommy_list qos_map_list;
  switch_qos_group_t qos_group;
  switch_direction_t direction;
  union {
    switch_qos_map_ingress_t ingress_map_type;
    switch_qos_map_egress_t egress_map_type;
  } map_type;
} switch_qos_map_list_t;

switch_status_t switch_qos_init(switch_device_t device);

switch_qos_map_list_t *switch_qos_map_get(switch_handle_t qos_map_handle);

#ifdef __cplusplus
}
#endif

#endif
