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
#include "switch_buffer_int.h"
#include "switch_pd.h"
#include "switch_queue_int.h"
#include "switch_log_int.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static void *switch_buffer_pool_array = NULL;
static void *switch_buffer_profile_array = NULL;
static switch_buffer_pool_usage_t pool_usage;

switch_status_t switch_buffer_init(switch_device_t device) {
  UNUSED(device);
  switch_buffer_pool_array = NULL;
  switch_buffer_profile_array = NULL;
  memset(&pool_usage, 0, sizeof(switch_buffer_pool_usage_t));
  switch_pd_ingress_pool_init(device, pool_usage.ingress_pool_info);
  switch_pd_egress_pool_init(device, pool_usage.egress_pool_info);
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_buffer_free(switch_device_t device) {
  UNUSED(device);
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_buffer_pool_handle_create(switch_device_t device,
                                                 switch_direction_t direction,
                                                 switch_pd_pool_id_t pool_id) {
  switch_handle_t buffer_pool_handle = 0;
  buffer_pool_handle = pool_id;
  buffer_pool_handle |= ((direction & 0x1) << 16);
  buffer_pool_handle |= (SWITCH_HANDLE_TYPE_BUFFER_POOL << HANDLE_TYPE_SHIFT);
  return buffer_pool_handle;
}

switch_status_t switch_buffer_pool_handle_delete(
    switch_device_t device, switch_handle_t buffer_pool_handle) {
  return SWITCH_STATUS_SUCCESS;
}

switch_buffer_pool_info_t *switch_buffer_pool_get(
    switch_handle_t buffer_pool_handle) {
  switch_buffer_pool_info_t *buffer_pool_info = NULL;
  switch_buffer_pool_info_t *buffer_pool_info_tmp = NULL;
  switch_direction_t direction = 0;
  switch_pd_pool_id_t pool_id = 0;
  uint16_t i = 0;
  uint16_t pool_count = 0;

  direction = (buffer_pool_handle >> 16) & 0x1;
  pool_id = buffer_pool_handle & 0xFFFF;

  if (direction == SWITCH_API_DIRECTION_INGRESS) {
    buffer_pool_info = pool_usage.ingress_pool_info;
    pool_count = SWITCH_INGRESS_POOL_COUNT;
  } else {
    buffer_pool_info = pool_usage.egress_pool_info;
    pool_count = SWITCH_EGRESS_POOL_COUNT;
  }

  for (i = 0; i < pool_count; i++) {
    if (buffer_pool_info[i].pool_id == pool_id) {
      buffer_pool_info_tmp = &buffer_pool_info[i];
      break;
    }
  }
  return buffer_pool_info_tmp;
}

static switch_status_t switch_buffer_free_pool_get(
    switch_direction_t direction,
    uint32_t pool_size,
    switch_pd_pool_id_t *pool_id) {
  switch_buffer_pool_info_t *buffer_pool_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  bool free_pool = FALSE;
  uint16_t index = 0;
  uint16_t pool_count = 0;

  *pool_id = 0;

  if ((direction == SWITCH_API_DIRECTION_INGRESS &&
       pool_usage.ingress_count == SWITCH_INGRESS_POOL_COUNT) ||
      (direction == SWITCH_API_DIRECTION_EGRESS &&
       pool_usage.egress_count == SWITCH_EGRESS_POOL_COUNT)) {
    SWITCH_API_ERROR("failed to find free pool");
    return SWITCH_STATUS_INSUFFICIENT_RESOURCES;
  }

  if (direction == SWITCH_API_DIRECTION_INGRESS) {
    buffer_pool_info = pool_usage.ingress_pool_info;
    pool_count = SWITCH_INGRESS_POOL_COUNT;
  } else {
    buffer_pool_info = pool_usage.egress_pool_info;
    pool_count = SWITCH_EGRESS_POOL_COUNT;
  }

  for (index = 0; index < pool_count; index++) {
    if (!buffer_pool_info[index].in_use) {
      free_pool = TRUE;
      *pool_id = buffer_pool_info[index].pool_id;
      break;
    }
  }

  if (!free_pool) {
    SWITCH_API_ERROR("failed to find free pool");
    return SWITCH_STATUS_INSUFFICIENT_RESOURCES;
  }

  return status;
}

switch_handle_t switch_api_buffer_pool_create(switch_device_t device,
                                              switch_direction_t direction,
                                              uint32_t pool_size) {
  switch_handle_t buffer_pool_handle = 0;
  switch_buffer_pool_info_t *buffer_pool_info = NULL;
  switch_pd_pool_id_t pool_id = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  status = switch_buffer_free_pool_get(direction, pool_size, &pool_id);

  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("failed to find pool for pool size %d", pool_size);
    return status;
  }

  buffer_pool_handle =
      switch_buffer_pool_handle_create(device, direction, pool_id);
  if (buffer_pool_handle) {
    SWITCH_API_ERROR("failed to allocate handle!");
    return SWITCH_API_INVALID_HANDLE;
  }

  buffer_pool_info = switch_buffer_pool_get(buffer_pool_handle);
  buffer_pool_info->pool_id = pool_id;
  buffer_pool_info->pool_size = pool_size;
  buffer_pool_info->direction = direction;

  direction == SWITCH_API_DIRECTION_INGRESS ? pool_usage.ingress_count++
                                            : pool_usage.egress_count++;

  status = switch_pd_buffer_pool_set(device, pool_id, pool_size);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("failed to set pool for pool size %d", pool_size);
    return status;
  }

  return buffer_pool_handle;
}

switch_status_t switch_api_buffer_pool_delete(switch_device_t device,
                                              switch_handle_t pool_handle) {
  switch_buffer_pool_info_t *buffer_pool_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  buffer_pool_info = switch_buffer_pool_get(pool_handle);
  if (!buffer_pool_info) {
    SWITCH_API_ERROR("invalid handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  buffer_pool_info->pool_size = 0;
  buffer_pool_info->in_use = FALSE;

  buffer_pool_info->direction == SWITCH_API_DIRECTION_INGRESS
      ? pool_usage.ingress_count--
      : pool_usage.egress_count--;

  status = switch_pd_buffer_pool_set(device, buffer_pool_info->pool_id, 0x0);

  switch_buffer_pool_handle_delete(device, pool_handle);

  return status;
}

switch_status_t switch_api_buffer_pool_color_drop_enable(
    switch_device_t device, switch_handle_t pool_handle, bool enable) {
  switch_buffer_pool_info_t *buffer_pool_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  buffer_pool_info = switch_buffer_pool_get(pool_handle);
  if (!buffer_pool_info) {
    SWITCH_API_ERROR("invalid handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status = switch_pd_buffer_pool_color_drop_enable(
      device, buffer_pool_info->pool_id, enable);
  return status;
}

switch_status_t switch_api_buffer_pool_color_limit_set(
    switch_device_t device,
    switch_handle_t pool_handle,
    switch_color_t color,
    uint32_t num_bytes) {
  switch_buffer_pool_info_t *buffer_pool_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  buffer_pool_info = switch_buffer_pool_get(pool_handle);
  if (!buffer_pool_info) {
    SWITCH_API_ERROR("invalid handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status = switch_pd_buffer_pool_color_limit_set(
      device, buffer_pool_info->pool_id, color, num_bytes);
  return status;
}

switch_status_t switch_api_buffer_pool_color_hysteresis_set(
    switch_device_t device, switch_color_t color, uint32_t num_bytes) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  status = switch_pd_buffer_pool_color_hysteresis_set(device, color, num_bytes);
  return status;
}

switch_handle_t switch_buffer_profile_handle_create() {
  switch_handle_t buffer_profile_handle;
  _switch_handle_create(SWITCH_HANDLE_TYPE_BUFFER_PROFILE,
                        switch_api_buffer_profile_t,
                        switch_buffer_profile_array,
                        NULL,
                        buffer_profile_handle);
  return buffer_profile_handle;
}

switch_api_buffer_profile_t *switch_buffer_profile_info_get(
    switch_handle_t buffer_profile_handle) {
  switch_api_buffer_profile_t *buffer_info = NULL;
  _switch_handle_get(switch_api_buffer_profile_t,
                     switch_buffer_profile_array,
                     buffer_profile_handle,
                     buffer_info);
  return buffer_info;
}

switch_status_t switch_buffer_profile_handle_delete(
    switch_handle_t buffer_profile_handle) {
  _switch_handle_delete(switch_api_buffer_profile_t,
                        switch_buffer_profile_array,
                        buffer_profile_handle);
  return SWITCH_STATUS_SUCCESS;
}

switch_handle_t switch_api_buffer_profile_create(
    switch_device_t device, switch_api_buffer_profile_t *buffer_info) {
  switch_api_buffer_profile_t *buffer_info_tmp = NULL;
  switch_handle_t buffer_profile_handle = 0;

  buffer_profile_handle = switch_buffer_profile_handle_create();
  buffer_info_tmp = switch_buffer_profile_info_get(buffer_profile_handle);
  if (!buffer_info_tmp) {
    SWITCH_API_ERROR("no memory to allocate buffer profile handle");
    return SWITCH_API_INVALID_HANDLE;
  }

  memcpy(buffer_info_tmp, buffer_info, sizeof(switch_api_buffer_profile_t));
  return buffer_profile_handle;
}

switch_status_t switch_api_buffer_profile_delete(
    switch_device_t device, switch_handle_t buffer_profile_handle) {
  switch_buffer_profile_handle_delete(buffer_profile_handle);
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_priority_group_buffer_profile_set(
    switch_device_t device,
    switch_handle_t ppg_handle,
    switch_handle_t buffer_profile_handle) {
  switch_port_priority_group_t *ppg_info = NULL;
  switch_buffer_pool_info_t *pool_info = NULL;
  switch_api_buffer_profile_t *buffer_profile_info = NULL;
  bool enable = true;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  ppg_info = switch_ppg_get(ppg_handle);
  if (!ppg_info) {
    SWITCH_API_ERROR("failed to get port_priority group");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  buffer_profile_info = switch_buffer_profile_info_get(buffer_profile_handle);
  if (!buffer_profile_info) {
    SWITCH_API_ERROR("failed to get buffer profile");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  pool_info = switch_buffer_pool_get(buffer_profile_info->pool_handle);
  if (!pool_info) {
    SWITCH_API_ERROR("failed to get buffer profile");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  ppg_info->buffer_profile_handle = buffer_profile_handle;
  enable = buffer_profile_handle == 0 ? true : false;

  status = switch_pd_ppg_pool_usage_set(device,
                                        ppg_info->tm_ppg_handle,
                                        pool_info->pool_id,
                                        buffer_profile_info,
                                        enable);

  return status;
}

switch_status_t switch_api_buffer_skid_limit_set(switch_device_t device,
                                                 uint32_t num_bytes) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  status = switch_pd_buffer_skid_limit_set(device, num_bytes);
  return status;
}

switch_status_t switch_api_buffer_skid_hysteresis_set(switch_device_t device,
                                                      uint32_t num_bytes) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  status = switch_pd_buffer_skid_hysteresis_set(device, num_bytes);
  return status;
}

switch_status_t switch_api_buffer_pool_pfc_limit(switch_device_t device,
                                                 switch_handle_t pool_handle,
                                                 uint8_t icos,
                                                 uint32_t num_bytes) {
  switch_buffer_pool_info_t *buffer_pool_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  buffer_pool_info = switch_buffer_pool_get(pool_handle);
  if (!buffer_pool_info) {
    SWITCH_API_ERROR("invalid handle");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status = switch_pd_buffer_pool_pfc_limit(
      device, buffer_pool_info->pool_id, icos, num_bytes);

  return status;
}

switch_status_t switch_api_queue_buffer_profile_set(
    switch_device_t device,
    switch_handle_t queue_handle,
    switch_handle_t buffer_profile_handle) {
  switch_queue_info_t *queue_info = NULL;
  switch_buffer_pool_info_t *pool_info = NULL;
  switch_api_buffer_profile_t *buffer_profile_info = NULL;
  bool enable = true;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  queue_info = switch_queue_info_get(queue_handle);
  if (!queue_info) {
    SWITCH_API_ERROR("failed to get queue");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  buffer_profile_info = switch_buffer_profile_info_get(buffer_profile_handle);
  if (!buffer_profile_info) {
    SWITCH_API_ERROR("failed to get buffer profile");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  pool_info = switch_buffer_pool_get(buffer_profile_info->pool_handle);
  if (!pool_info) {
    SWITCH_API_ERROR("failed to get buffer profile");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  queue_info->buffer_profile_handle = buffer_profile_handle;
  enable = buffer_profile_handle == 0 ? true : false;

  status = switch_pd_queue_pool_usage_set(device,
                                          queue_info->port_handle,
                                          queue_info->queue_id,
                                          pool_info->pool_id,
                                          buffer_profile_info,
                                          enable);

  return status;
}

#ifdef __cplusplus
}
#endif
