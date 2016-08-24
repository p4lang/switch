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
#ifndef _switch_buffer_h_
#define _switch_buffer_h_

#include "switch_base_types.h"
#include "switch_handle.h"
#include "switch_meter.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup Buffer Buffer API
 *  API functions to create buffers
 *  @{
 */  // begin of Buffer API

// Buffer
/** Buffer information */

typedef enum switch_buffer_threshold_mode_ {
  SWITCH_BUFFER_THRESHOLD_MODE_STATIC = 1,
  SWITCH_BUFFER_THRESHOLD_MODE_DYNAMIC = 2
} switch_buffer_threshold_mode_t;

typedef struct switch_api_buffer_profile_ {
  switch_buffer_threshold_mode_t threshold_mode;
  switch_handle_t pool_handle;
  uint32_t buffer_size;
  uint32_t threshold;
  uint32_t xoff_threshold;
  uint32_t xon_threshold;
} switch_api_buffer_profile_t;

/**
 Create a buffer pool
 NOTE: Maps to tm - bf_tm_set_app_pool_size
 @param device device
 @param direction direction (ingress or egress)
 @param pool_size size of the buffer pool
*/
switch_handle_t switch_api_buffer_pool_create(switch_device_t device,
                                              switch_direction_t direction,
                                              uint32_t pool_size);

/**
 Delete a buffer pool
 NOTE: No api. Setting pool size to 0 will delete ?
 @param device device
 @param pool_handle pool handle
*/
switch_status_t switch_api_buffer_pool_delete(switch_device_t device,
                                              switch_handle_t pool_handle);

/**
 Create switch buffer profile
 NOTE: Maps to bf_tm_set_ppg_app_pool_usage and
       bf_tm_set_q_app_pool_usage
 @param device device
 @param buffer_info buffer profile info
*/
switch_handle_t switch_api_buffer_profile_create(
    switch_device_t device, switch_api_buffer_profile_t *buffer_info);

/**
 Delete switch buffer profile
 NOTE: Maps to bf_tm_disable_ppg_app_pool_usage and
       bf_tm_disable_q_app_pool_usage
 @param device device
 @param buffer_profile_handle buffer profile handle
*/
switch_status_t switch_api_buffer_profile_delete(
    switch_device_t device, switch_handle_t buffer_profile_handle);

/**
 Set buffer profile for a priority group
 NOTE: Maps to bf_tm_set_ppg_app_pool_usage
 @param device device
 @param pg_handle priority group handle
 @param buffer_profile_handle buffer profile handle
*/
switch_status_t switch_api_priority_group_buffer_profile_set(
    switch_device_t device,
    switch_handle_t pg_handle,
    switch_handle_t buffer_profile_handle);

/*
 Set skid buffer size
 @param device device
 @param buffer_size buffer size
*/
switch_status_t switch_api_buffer_skid_limit_set(switch_device_t device,
                                                 uint32_t buffer_size);

switch_status_t switch_api_buffer_skid_hysteresis_set(switch_device_t device,
                                                      uint32_t num_bytes);

switch_status_t switch_api_buffer_pool_pfc_limit(switch_device_t device,
                                                 switch_handle_t pool_handle,
                                                 uint8_t icos,
                                                 uint32_t num_bytes);

/**
 Set buffer profile for a queue
 @param device device
 @param queue_handle queue handle
 @param buffer_profile_handle buffer profile handle
*/
switch_status_t switch_api_queue_buffer_profile_set(
    switch_device_t device,
    switch_handle_t queue_handle,
    switch_handle_t buffer_profile_handle);

switch_status_t switch_api_buffer_pool_color_drop_enable(
    switch_device_t device, switch_handle_t pool_handle, bool enable);

switch_status_t switch_api_buffer_pool_color_limit_set(
    switch_device_t device,
    switch_handle_t pool_handle,
    switch_color_t color,
    uint32_t num_bytes);

switch_status_t switch_api_buffer_pool_color_hysteresis_set(
    switch_device_t device, switch_color_t color, uint32_t num_bytes);

/** @} */  // end of Buffer API
#ifdef __cplusplus
}
#endif

#endif
