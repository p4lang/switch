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

/** Buffer threshold mode */
typedef enum switch_buffer_threshold_mode_ {
  SWITCH_BUFFER_THRESHOLD_MODE_STATIC = 1,
  SWITCH_BUFFER_THRESHOLD_MODE_DYNAMIC = 2
} switch_buffer_threshold_mode_t;

/** Buffer profile struct */
typedef struct switch_api_buffer_profile_ {
  switch_buffer_threshold_mode_t threshold_mode; /**< buffer threshold mode */
  switch_handle_t pool_handle;                   /**< buffer pool handle */
  uint32_t buffer_size;                          /**< buffer size */
  uint32_t threshold;                            /**< threshold limit */
  uint32_t xoff_threshold;                       /**< xoff threshold */
  uint32_t xon_threshold;                        /**< xon threashold */
} switch_api_buffer_profile_t;

/**
 Create a buffer pool
 @param device device
 @param direction direction (ingress or egress)
 @param pool_size size of the buffer pool
*/
switch_handle_t switch_api_buffer_pool_create(switch_device_t device,
                                              switch_direction_t direction,
                                              uint32_t pool_size);

/**
 Delete a buffer pool
 @param device device
 @param pool_handle pool handle
*/
switch_status_t switch_api_buffer_pool_delete(switch_device_t device,
                                              switch_handle_t pool_handle);

/**
 Create switch buffer profile
 @param device device
 @param buffer_info buffer profile info
*/
switch_handle_t switch_api_buffer_profile_create(
    switch_device_t device, switch_api_buffer_profile_t *buffer_info);

/**
 Delete switch buffer profile
 @param device device
 @param buffer_profile_handle buffer profile handle
*/
switch_status_t switch_api_buffer_profile_delete(
    switch_device_t device, switch_handle_t buffer_profile_handle);

/**
 Set buffer profile for a priority group
 @param device device
 @param pg_handle priority group handle
 @param buffer_profile_handle buffer profile handle
*/
switch_status_t switch_api_priority_group_buffer_profile_set(
    switch_device_t device,
    switch_handle_t pg_handle,
    switch_handle_t buffer_profile_handle);

/**
 Set skid buffer size
 @param device device
 @param buffer_size buffer size
*/
switch_status_t switch_api_buffer_skid_limit_set(switch_device_t device,
                                                 uint32_t buffer_size);

/**
 Set skid buffer size
 @param device device
 @param num_bytes number of bytes
*/
switch_status_t switch_api_buffer_skid_hysteresis_set(switch_device_t device,
                                                      uint32_t num_bytes);

/**
 set buffer pool pfc limit for a icos
 @param device device
 @param pool_handle pool handle
 @param icos ingress cos
 @param num_bytes number of bytes
*/
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

/**
 enable color based drop on a pool
 @param device device
 @param pool_handle pool handle
 @param enable enable/disable
*/
switch_status_t switch_api_buffer_pool_color_drop_enable(
    switch_device_t device, switch_handle_t pool_handle, bool enable);

/**
 buffer pool color limit set
 @param device device
 @param pool_handle pool handle
 @param color packet color
 @param num_bytes number of bytes
*/
switch_status_t switch_api_buffer_pool_color_limit_set(
    switch_device_t device,
    switch_handle_t pool_handle,
    switch_color_t color,
    uint32_t num_bytes);

/**
 pool color hystersis set
 @param device device
 @param color packet color
 @param num_bytes number of bytes
*/
switch_status_t switch_api_buffer_pool_color_hysteresis_set(
    switch_device_t device, switch_color_t color, uint32_t num_bytes);

/** @} */  // end of Buffer API
#ifdef __cplusplus
}
#endif

#endif
