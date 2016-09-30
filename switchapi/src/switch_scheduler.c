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
#include "switch_scheduler_int.h"
#include "switch_pd.h"
#include "switch_queue_int.h"
#include "switch_log_int.h"
#include "switch_defines.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static void *switch_scheduler_array;

switch_status_t switch_scheduler_init(switch_device_t device) {
  switch_scheduler_array = NULL;
  switch_handle_type_init(SWITCH_HANDLE_TYPE_SCHEDULER, 128);
  return SWITCH_STATUS_SUCCESS;
}

switch_handle_t switch_scheduler_handle_create() {
  switch_handle_t scheduler_handle;
  _switch_handle_create(SWITCH_HANDLE_TYPE_SCHEDULER,
                        switch_scheduler_info_t,
                        switch_scheduler_array,
                        NULL,
                        scheduler_handle);
  return scheduler_handle;
}

switch_scheduler_info_t *switch_scheduler_info_get(
    switch_handle_t scheduler_handle) {
  switch_scheduler_info_t *scheduler_info = NULL;
  _switch_handle_get(switch_scheduler_info_t,
                     switch_scheduler_array,
                     scheduler_handle,
                     scheduler_info);
  return scheduler_info;
}

switch_status_t switch_scheduler_handle_delete(
    switch_handle_t scheduler_handle) {
  _switch_handle_delete(
      switch_scheduler_info_t, switch_scheduler_array, scheduler_handle);
  return SWITCH_STATUS_SUCCESS;
}

switch_handle_t switch_api_scheduler_create(
    switch_device_t device, switch_scheduler_info_t *scheduler_info) {
  switch_handle_t scheduler_handle = 0;
  switch_scheduler_info_t *scheduler_info_tmp = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  scheduler_handle = switch_scheduler_handle_create();
  scheduler_info_tmp = switch_scheduler_info_get(scheduler_handle);
  if (!scheduler_info_tmp) {
    SWITCH_API_ERROR("scheduler create failed");
    return SWITCH_API_INVALID_HANDLE;
  }
  memcpy(scheduler_info_tmp, scheduler_info, sizeof(switch_scheduler_info_t));

  status = switch_api_queue_scheduling_enable(device, scheduler_handle, TRUE);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("scheduler create failed");
    return SWITCH_API_INVALID_HANDLE;
  }

  status = switch_api_queue_scheduling_strict_priority_set(
      device, scheduler_handle, scheduler_info->priority);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("scheduler create failed");
    return SWITCH_API_INVALID_HANDLE;
  }

  status = switch_api_queue_scheduling_remaining_bw_priority_set(
      device, scheduler_handle, scheduler_info->rem_bw_priority);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("scheduler create failed");
    return SWITCH_API_INVALID_HANDLE;
  }

  status = switch_api_queue_scheduling_dwrr_weight_set(
      device, scheduler_handle, scheduler_info->weight);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("scheduler create failed");
    return SWITCH_API_INVALID_HANDLE;
  }

  status = switch_api_queue_scheduling_guaranteed_shaping_set(
      device,
      scheduler_handle,
      scheduler_info->shaper_type == SWITCH_METER_TYPE_PACKETS ? TRUE : FALSE,
      scheduler_info->min_burst_size,
      scheduler_info->min_rate);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("scheduler create failed");
    return SWITCH_API_INVALID_HANDLE;
  }

  status = switch_api_queue_scheduling_dwrr_shaping_set(
      device,
      scheduler_handle,
      scheduler_info->shaper_type == SWITCH_METER_TYPE_PACKETS ? TRUE : FALSE,
      scheduler_info->max_burst_size,
      scheduler_info->max_rate);
  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("scheduler create failed");
    return SWITCH_API_INVALID_HANDLE;
  }

  return scheduler_handle;
}

switch_status_t switch_api_scheduler_update(
    switch_device_t device,
    switch_handle_t scheduler_handle,
    switch_scheduler_info_t *scheduler_info) {
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_scheduler_delete(switch_device_t device,
                                            switch_handle_t scheduler_handle) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_scheduler_info_t *scheduler_info = NULL;

  scheduler_info = switch_scheduler_info_get(scheduler_handle);
  if (!scheduler_info) {
    SWITCH_API_ERROR("scheduler create failed");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status = switch_scheduler_handle_delete(scheduler_handle);
  return status;
}

switch_status_t switch_api_queue_scheduling_enable(
    switch_device_t device, switch_handle_t scheduler_handle, bool enable) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_scheduler_info_t *scheduler_info = NULL;
  switch_queue_info_t *queue_info = NULL;

  scheduler_info = switch_scheduler_info_get(scheduler_handle);
  if (!scheduler_info) {
    SWITCH_API_ERROR("queue scheduling enable failed");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  queue_info = switch_queue_info_get(scheduler_info->queue_handle);
  if (!queue_info) {
    SWITCH_API_ERROR("queue scheduling enable failed");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  status = switch_pd_queue_scheduling_enable(
      device, queue_info->port_handle, queue_info->queue_id, enable);
  return status;
}

switch_status_t switch_api_queue_scheduling_strict_priority_set(
    switch_device_t device,
    switch_handle_t scheduler_handle,
    uint32_t priority) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_scheduler_info_t *scheduler_info = NULL;
  switch_queue_info_t *queue_info = NULL;

  scheduler_info = switch_scheduler_info_get(scheduler_handle);
  if (!scheduler_info) {
    SWITCH_API_ERROR("queue scheduling enable failed");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  queue_info = switch_queue_info_get(scheduler_info->queue_handle);
  if (!queue_info) {
    SWITCH_API_ERROR("queue scheduling enable failed");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  scheduler_info->priority = priority;

  status = switch_pd_queue_scheduling_strict_priority_set(
      device, queue_info->port_handle, queue_info->queue_id, priority);
  return status;
}

switch_status_t switch_api_queue_scheduling_remaining_bw_priority_set(
    switch_device_t device,
    switch_handle_t scheduler_handle,
    uint32_t priority) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_scheduler_info_t *scheduler_info = NULL;
  switch_queue_info_t *queue_info = NULL;

  scheduler_info = switch_scheduler_info_get(scheduler_handle);
  if (!scheduler_info) {
    SWITCH_API_ERROR("queue scheduling enable failed");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  queue_info = switch_queue_info_get(scheduler_info->queue_handle);
  if (!queue_info) {
    SWITCH_API_ERROR("queue scheduling enable failed");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  scheduler_info->rem_bw_priority = priority;

  status = switch_pd_queue_scheduling_remaining_bw_priority_set(
      device, queue_info->port_handle, queue_info->queue_id, priority);
  return status;
}

switch_status_t switch_api_queue_scheduling_dwrr_weight_set(
    switch_device_t device, switch_handle_t scheduler_handle, uint16_t weight) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_scheduler_info_t *scheduler_info = NULL;
  switch_queue_info_t *queue_info = NULL;

  scheduler_info = switch_scheduler_info_get(scheduler_handle);
  if (!scheduler_info) {
    SWITCH_API_ERROR("queue scheduling enable failed");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  queue_info = switch_queue_info_get(scheduler_info->queue_handle);
  if (!queue_info) {
    SWITCH_API_ERROR("queue scheduling enable failed");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  scheduler_info->weight = weight;
  status = switch_pd_queue_scheduling_dwrr_weight_set(
      device, queue_info->port_handle, queue_info->queue_id, weight);
  return status;
}

switch_status_t switch_api_queue_scheduling_guaranteed_shaping_set(
    switch_device_t device,
    switch_handle_t scheduler_handle,
    bool pps,
    uint32_t burst_size,
    uint32_t rate) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_scheduler_info_t *scheduler_info = NULL;
  switch_queue_info_t *queue_info = NULL;

  scheduler_info = switch_scheduler_info_get(scheduler_handle);
  if (!scheduler_info) {
    SWITCH_API_ERROR("queue scheduling enable failed");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  queue_info = switch_queue_info_get(scheduler_info->queue_handle);
  if (!queue_info) {
    SWITCH_API_ERROR("queue scheduling enable failed");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  scheduler_info->min_rate = rate;
  scheduler_info->min_burst_size = burst_size;

  status =
      switch_pd_queue_scheduling_guaranteed_shaping_set(device,
                                                        queue_info->port_handle,
                                                        queue_info->queue_id,
                                                        pps,
                                                        burst_size,
                                                        rate);
  return status;
}

switch_status_t switch_api_queue_scheduling_dwrr_shaping_set(
    switch_device_t device,
    switch_handle_t scheduler_handle,
    bool pps,
    uint32_t burst_size,
    uint32_t rate) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  switch_scheduler_info_t *scheduler_info = NULL;
  switch_queue_info_t *queue_info = NULL;

  scheduler_info = switch_scheduler_info_get(scheduler_handle);
  if (!scheduler_info) {
    SWITCH_API_ERROR("queue scheduling enable failed");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  queue_info = switch_queue_info_get(scheduler_info->queue_handle);
  if (!queue_info) {
    SWITCH_API_ERROR("queue scheduling enable failed");
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  scheduler_info->max_rate = rate;
  scheduler_info->max_burst_size = burst_size;

  status = switch_pd_queue_scheduling_dwrr_shaping_set(device,
                                                       queue_info->port_handle,
                                                       queue_info->queue_id,
                                                       pps,
                                                       burst_size,
                                                       rate);
  return status;
}
#ifdef __cplusplus
}
#endif
