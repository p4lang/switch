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
