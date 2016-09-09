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
#ifndef _switch_scheduler_h_
#define _switch_scheduler_h_

#include "switch_base_types.h"
#include "switch_handle.h"
#include "switch_meter.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup Scheduler Scheduler API
 *  API functions to create Scheduler
 *  @{
 */  // begin of Scheduler API

// Scheduler
/** Scheduler information */

/** scheduler type */
typedef enum switch_scheduler_type_ {
  SWITCH_SCHEDULER_MODE_STRICT = 1,
  SWITCH_SCHEDULER_MODE_DWRR = 2,
  SWITCH_SCHEDULER_MODE_STRICT_AND_DWRR = 3
} switch_scheduler_type_t;

/** scheduler struct */
typedef struct switch_scheduler_info_ {
  switch_scheduler_type_t scheduler_type; /**< scheduler type */
  switch_shaper_type_t shaper_type;       /**< shaper type */
  switch_handle_t queue_handle;           /**< queue handle */
  uint32_t priority;                      /**< priority */
  uint32_t rem_bw_priority;               /**< remaining bandwidth priority */
  uint16_t weight;                        /**< weight */
  uint32_t min_burst_size;                /**< minimum burst size */
  uint32_t min_rate;                      /**< minimum rate */
  uint32_t max_burst_size;                /**< maximum burst size */
  uint32_t max_rate;                      /**< maximum rate */
} switch_scheduler_info_t;

/**
 Create a scheduler
 @param device device
 @param scheduler_info scheduler info
*/
switch_handle_t switch_api_scheduler_create(
    switch_device_t device, switch_scheduler_info_t *scheduler_info);

/**
 Update a scheduler
 @param device device
 @param scheduler_handle scheduler handle
 @param scheduler_info scheduler info
*/
switch_status_t switch_api_scheduler_update(
    switch_device_t device,
    switch_handle_t scheduler_handle,
    switch_scheduler_info_t *scheduler_info);

/**
 Delete a scheduler
 @param device device
 @param scheduler_handle scheduler handle
*/
switch_status_t switch_api_scheduler_delete(switch_device_t device,
                                            switch_handle_t scheduler_handle);

/**
 enable scheduling in queue
 @param device device
 @param scheduler_handle scheduler handle
 @param enable enable
*/
switch_status_t switch_api_queue_scheduling_enable(
    switch_device_t device, switch_handle_t scheduler_handle, bool enable);

/**
 set the priority of queue scheduler
 @param device device
 @param scheduler_handle scheduler handle
 @param priority priority
*/
switch_status_t switch_api_queue_scheduling_strict_priority_set(
    switch_device_t device,
    switch_handle_t scheduler_handle,
    uint32_t priority);

/**
 set the priority of queue scheduler
 @param device device
 @param scheduler_handle scheduler handle
 @param priority priority
*/
switch_status_t switch_api_queue_scheduling_remaining_bw_priority_set(
    switch_device_t device,
    switch_handle_t scheduler_handle,
    uint32_t priority);

/**
 set the weight of queue scheduler
 @param device device
 @param scheduler_handle scheduler handle
 @param weight weight
*/
switch_status_t switch_api_queue_scheduling_dwrr_weight_set(
    switch_device_t device, switch_handle_t scheduler_handle, uint16_t weight);

/**
 configure queue scheduler
 @param device device
 @param scheduler_handle scheduler handle
 @param pps packet per second
 @param burst_size burst size
 @param rate rate
*/
switch_status_t switch_api_queue_scheduling_guaranteed_shaping_set(
    switch_device_t device,
    switch_handle_t scheduler_handle,
    bool pps,
    uint32_t burst_size,
    uint32_t rate);

/**
 configure queue remaining bandwidth scheduler
 @param device device
 @param scheduler_handle scheduler handle
 @param pps packet per second
 @param burst_size burst size
 @param rate rate
*/
switch_status_t switch_api_queue_scheduling_dwrr_shaping_set(
    switch_device_t device,
    switch_handle_t scheduler_handle,
    bool pps,
    uint32_t burst_size,
    uint32_t rate);

/** @} */  // end of Scheduler API

#ifdef __cplusplus
}
#endif

#endif
