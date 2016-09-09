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
#include "p4features.h"
#include "switch_pd.h"
#include "switch_defines.h"

extern p4_pd_sess_hdl_t g_sess_hdl;

p4_pd_status_t switch_pd_queue_pool_usage_set(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_qid_t queue_id,
    switch_pd_pool_id_t pool_id,
    switch_api_buffer_profile_t *buffer_profile_info,
    bool enable) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_queue_color_drop_enable(switch_device_t device,
                                                 switch_handle_t port_handle,
                                                 switch_qid_t queue_id,
                                                 bool enable) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_queue_color_limit_set(switch_device_t device,
                                               switch_handle_t port_handle,
                                               switch_qid_t queue_id,
                                               switch_color_t color,
                                               uint32_t limit) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_queue_color_hysteresis_set(switch_device_t device,
                                                    switch_handle_t port_handle,
                                                    switch_qid_t queue_id,
                                                    switch_color_t color,
                                                    uint32_t limit) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_queue_pfc_cos_mapping(switch_device_t device,
                                               switch_handle_t port_handle,
                                               switch_qid_t queue_id,
                                               uint8_t cos) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_queue_port_mapping(switch_device_t device,
                                            switch_handle_t port_handle,
                                            uint8_t queue_count,
                                            uint8_t *queue_mapping) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_queue_scheduling_enable(switch_device_t device,
                                                 switch_handle_t port_handle,
                                                 switch_qid_t queue_id,
                                                 bool enable) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_queue_scheduling_strict_priority_set(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_qid_t queue_id,
    uint32_t priority) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_queue_scheduling_remaining_bw_priority_set(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_qid_t queue_id,
    uint32_t priority) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_queue_scheduling_dwrr_weight_set(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_qid_t queue_id,
    uint16_t weight) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_queue_scheduling_guaranteed_shaping_set(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_qid_t queue_id,
    bool pps,
    uint32_t burst_size,
    uint32_t rate) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_queue_scheduling_dwrr_shaping_set(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_qid_t queue_id,
    bool pps,
    uint32_t burst_size,
    uint32_t rate) {
  p4_pd_status_t status = 0;
  return status;
}
