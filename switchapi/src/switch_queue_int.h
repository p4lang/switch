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

#ifndef _switch_queue_int_h_
#define _switch_queue_int_h_

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_queue.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct switch_queue_info_ {
  tommy_node node;
  switch_handle_t port_handle;
  switch_handle_t buffer_profile_handle;
  switch_qid_t queue_id;
} switch_queue_info_t;

typedef struct switch_port_queue_info_ {
  tommy_list queue_handles;
  switch_api_id_allocator *queue_id_bmp;
} switch_port_queue_info_t;

switch_queue_info_t *switch_queue_info_get(switch_handle_t queue_handle);

switch_status_t switch_queue_init(switch_device_t device);

#ifdef __cplusplus
}
#endif

#endif
