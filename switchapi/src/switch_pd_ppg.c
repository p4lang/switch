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

p4_pd_status_t switch_pd_port_drop_limit_set(switch_device_t device,
                                             switch_handle_t port_handle,
                                             uint32_t num_bytes) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_port_drop_hysteresis_set(switch_device_t device,
                                                  switch_handle_t port_handle,
                                                  uint32_t num_bytes) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_port_pfc_cos_mapping(switch_device_t device,
                                              switch_handle_t port_handle,
                                              uint8_t *cos_to_icos) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_port_flowcontrol_mode_set(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_flowcontrol_type_t flow_control) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_ppg_create(switch_device_t device,
                                    switch_handle_t port_handle,
                                    switch_tm_ppg_hdl_t *ppg_handle) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_ppg_delete(switch_device_t device,
                                    switch_tm_ppg_hdl_t ppg_handle) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_port_ppg_tc_mapping(switch_device_t device,
                                             switch_tm_ppg_hdl_t tm_ppg_handle,
                                             uint8_t icos_bmp) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_ppg_lossless_enable(switch_device_t device,
                                             switch_tm_ppg_hdl_t tm_ppg_handle,
                                             bool enable) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_ppg_pool_usage_set(
    switch_device_t device,
    switch_tm_ppg_hdl_t tm_ppg_handle,
    switch_pd_pool_id_t pool_id,
    switch_api_buffer_profile_t *buffer_profile_info,
    bool enable) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_ppg_guaranteed_limit_set(
    switch_device_t device,
    switch_tm_ppg_hdl_t tm_ppg_handle,
    uint32_t num_bytes) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_ppg_skid_limit_set(switch_device_t device,
                                            switch_tm_ppg_hdl_t tm_ppg_handle,
                                            uint32_t num_bytes) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_ppg_skid_hysteresis_set(
    switch_device_t device,
    switch_tm_ppg_hdl_t tm_ppg_handle,
    uint32_t num_bytes) {
  p4_pd_status_t status = 0;
  return status;
}
