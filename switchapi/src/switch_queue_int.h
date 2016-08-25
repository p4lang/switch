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
