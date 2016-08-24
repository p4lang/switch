/*
Copyright 2013-present Barefoot Networks, Inc.
*/

#ifndef _switch_buffer_int_h_
#define _switch_buffer_int_h_

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_buffer.h"
#include "switch_pd_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct switch_buffer_pool_info_ {
  uint32_t pool_size;
  switch_direction_t direction;
  switch_pd_pool_id_t pool_id;
  bool in_use;
} switch_buffer_pool_info_t;

#define SWITCH_INGRESS_POOL_COUNT 4
#define SWITCH_EGRESS_POOL_COUNT 4

typedef struct switch_buffer_pool_usage_ {
  switch_buffer_pool_info_t ingress_pool_info[SWITCH_INGRESS_POOL_COUNT];
  switch_buffer_pool_info_t egress_pool_info[SWITCH_EGRESS_POOL_COUNT];
  uint8_t ingress_count;
  uint8_t egress_count;
} switch_buffer_pool_usage_t;

switch_status_t switch_buffer_init(switch_device_t device);

#ifdef __cplusplus
}
#endif

#endif
