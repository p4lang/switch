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
#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_utils.h"
#include "switch_pd.h"
#include "switch_log_int.h"
#include "switch_defines.h"
#include "switch_queue_int.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static void *switch_queue_array;

switch_status_t switch_queue_init(switch_device_t device) {
  switch_queue_array = NULL;
  switch_handle_type_init(SWITCH_HANDLE_TYPE_QUEUE, 256 * 32);
  return SWITCH_STATUS_SUCCESS;
}

switch_handle_t switch_queue_handle_create() {
  switch_handle_t queue_handle;
  _switch_handle_create(SWITCH_HANDLE_TYPE_QUEUE,
                        switch_queue_info_t,
                        switch_queue_array,
                        NULL,
                        queue_handle);
  return queue_handle;
}

switch_queue_info_t *switch_queue_info_get(switch_handle_t queue_handle) {
  switch_queue_info_t *queue_info = NULL;
  _switch_handle_get(
      switch_queue_info_t, switch_queue_array, queue_handle, queue_info);
  return queue_info;
}

switch_status_t switch_queue_handle_delete(switch_handle_t queue_handle) {
  _switch_handle_delete(switch_queue_info_t, switch_queue_array, queue_handle);
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_queue_allocate(switch_device_t device,
                                          switch_handle_t port_handle,
                                          uint32_t *num_queues,
                                          switch_handle_t *queue_handles) {
  switch_port_info_t *port_info = NULL;
  switch_queue_info_t *queue_info = NULL;
  switch_handle_t queue_handle = 0;
  uint32_t index = 0;
  uint8_t queue_mapping[SWITCH_MAX_QUEUE];
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  for (index = 0; index < port_info->max_queues; index++) {
    queue_handle = switch_queue_handle_create();
    queue_info = switch_queue_info_get(queue_handle);
    if (!queue_info) {
      SWITCH_API_ERROR("failed to allocate queue");
      return SWITCH_STATUS_NO_MEMORY;
    }
    queue_info->port_handle = port_handle;
    queue_info->queue_id = index;
    queue_handles[index] = queue_handle;
    port_info->queue_handles[index] = queue_handle;
    queue_mapping[index] = queue_info->queue_id;
  }
  *num_queues = port_info->max_queues;
  status = switch_pd_queue_port_mapping(
      device, port_handle, *num_queues, queue_mapping);
  return status;
}

switch_status_t switch_api_queue_deallocate(switch_device_t device,
                                            uint32_t num_queues,
                                            switch_handle_t *queue_handles) {
  switch_port_info_t *port_info = NULL;
  switch_queue_info_t *queue_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  uint32_t index = 0;

  for (index = 0; index < num_queues; index++) {
    queue_info = switch_queue_info_get(queue_handles[index]);
    if (!queue_info) {
      SWITCH_API_ERROR("invalid handle for queue deallocate");
      return SWITCH_STATUS_INVALID_HANDLE;
    }
    port_info = switch_api_port_get_internal(queue_info->port_handle);
    if (!port_info) {
      SWITCH_API_ERROR("invalid port handle");
    }

    port_info->queue_handles[index] = 0;
    status = switch_queue_handle_delete(queue_handles[index]);
  }
  return status;
}

switch_status_t switch_api_queues_get(switch_device_t device,
                                      switch_handle_t port_handle,
                                      uint32_t *num_queues,
                                      switch_handle_t *queue_handles) {
  switch_port_info_t *port_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  uint32_t index = 0;

  port_info = switch_api_port_get_internal(port_handle);
  if (!port_info) {
    SWITCH_API_ERROR("invalid port handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  for (index = 0; index < port_info->max_queues; index++) {
    queue_handles[index] = port_info->queue_handles[index];
  }
  *num_queues = port_info->max_queues;

  return status;
}

switch_status_t switch_api_queue_color_drop_enable(switch_device_t device,
                                                   switch_handle_t port_handle,
                                                   switch_handle_t queue_handle,
                                                   bool enable) {
  switch_queue_info_t *queue_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  queue_info = switch_queue_info_get(queue_handle);
  if (!queue_info) {
    SWITCH_API_ERROR("invalid queue handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status = switch_pd_queue_color_drop_enable(
      device, port_handle, queue_info->queue_id, enable);
  return status;
}

switch_status_t switch_api_queue_color_limit_set(switch_device_t device,
                                                 switch_handle_t port_handle,
                                                 switch_handle_t queue_handle,
                                                 switch_color_t color,
                                                 uint32_t limit) {
  switch_queue_info_t *queue_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  queue_info = switch_queue_info_get(queue_handle);
  if (!queue_info) {
    SWITCH_API_ERROR("invalid queue handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status = switch_pd_queue_color_limit_set(
      device, port_handle, queue_info->queue_id, color, limit);
  return status;
}

switch_status_t switch_api_queue_color_hysteresis_set(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_handle_t queue_handle,
    switch_color_t color,
    uint32_t limit) {
  switch_queue_info_t *queue_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  queue_info = switch_queue_info_get(queue_handle);
  if (!queue_info) {
    SWITCH_API_ERROR("invalid queue handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status = switch_pd_queue_color_hysteresis_set(
      device, port_handle, queue_info->queue_id, color, limit);
  return status;
}

switch_status_t switch_api_queue_pfc_cos_mapping(switch_device_t device,
                                                 switch_handle_t port_handle,
                                                 switch_handle_t queue_handle,
                                                 uint8_t cos) {
  switch_queue_info_t *queue_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  queue_info = switch_queue_info_get(queue_handle);
  if (!queue_info) {
    SWITCH_API_ERROR("invalid queue handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status = switch_pd_queue_pfc_cos_mapping(
      device, port_handle, queue_info->queue_id, cos);
  return status;
}

#ifdef __cplusplus
}
#endif
