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
#ifndef _switch_queue_h_
#define _switch_queue_h_

#include "switch_base_types.h"
#include "switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup QUEUE QUEUE API
 *  API functions to allocate queues
 *  @{
 */  // begin of QUEUE API

// QUEUE
/** QUEUE information */

#define SWITCH_MAX_QUEUE 32

typedef enum switch_qid_type_ {
  SWITCH_QID_TYPE_REASON_CODE = 0,
  SWITCH_QID_TYPE_TC = 1
} switch_qid_type_t;

typedef struct switch_qid_info_ {
  switch_qid_type_t qid_type;
  switch_tc_t tc;
  switch_hostif_reason_code_t reason_code;
} switch_qid_info_t;

/**
 Allocate egress queue for port
 NOTE: Maps to bf_tm_set_port_q_mapping
 @param device device
 @param port_handle port handle
 @param num_queues number of queues
 @param queue_handles list of queue handles
*/
switch_status_t switch_api_queue_allocate(switch_device_t device,
                                          switch_handle_t port_handle,
                                          uint32_t *num_queues,
                                          switch_handle_t *queue_handles);

/**
 Deallocate egress queue for port
 @param device device
 @param num_queues number of queues
 @param queue_handle list of queue handles
*/
switch_status_t switch_api_queue_deallocate(switch_device_t device,
                                            uint32_t num_queues,
                                            switch_handle_t *queue_handle);

/**
 Get port queues
 @param device device
 @param port_handle port handle
 @param num_queues number of queues
 @param queue_handles list of queue handles
*/
switch_status_t switch_api_queues_get(switch_device_t device,
                                      switch_handle_t port_handle,
                                      uint32_t *num_queues,
                                      switch_handle_t *queue_handles);

switch_status_t switch_api_queue_color_drop_enable(switch_device_t device,
                                                   switch_handle_t port_handle,
                                                   switch_handle_t queue_handle,
                                                   bool enable);

switch_status_t switch_api_queue_color_limit_set(switch_device_t device,
                                                 switch_handle_t port_handle,
                                                 switch_handle_t queue_handle,
                                                 switch_color_t color,
                                                 uint32_t limit);

switch_status_t switch_api_queue_color_hysteresis_set(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_handle_t queue_handle,
    switch_color_t color,
    uint32_t limit);

switch_status_t switch_api_queue_pfc_cos_mapping(switch_device_t device,
                                                 switch_handle_t port_handle,
                                                 switch_handle_t queue_handle,
                                                 uint8_t cos);

/** @} */  // end of QUEUE API

#ifdef __cplusplus
}
#endif

#endif
