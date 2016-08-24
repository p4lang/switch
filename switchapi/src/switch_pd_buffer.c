/*
Copyright 2013-present Barefoot Networks, Inc.
*/

#include "p4features.h"
#include "switch_pd.h"
#include "switch_defines.h"

extern p4_pd_sess_hdl_t g_sess_hdl;

switch_status_t switch_pd_ingress_pool_init(
    switch_device_t device, switch_buffer_pool_info_t *pool_info) {
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_pd_egress_pool_init(
    switch_device_t device, switch_buffer_pool_info_t *pool_info) {
  return SWITCH_STATUS_SUCCESS;
}

p4_pd_status_t switch_pd_buffer_pool_set(switch_device_t device,
                                         switch_pd_pool_id_t pool_id,
                                         uint32_t pool_size) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_buffer_pool_color_drop_enable(
    switch_device_t device, switch_pd_pool_id_t pool_id, bool enable) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_buffer_pool_color_limit_set(
    switch_device_t device,
    switch_pd_pool_id_t pool_id,
    switch_color_t color,
    uint32_t num_bytes) {
  p4_pd_status_t status = 0;
  return status;
}

switch_status_t switch_pd_buffer_pool_color_hysteresis_set(
    switch_device_t device, switch_color_t color, uint32_t num_bytes) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_buffer_skid_limit_set(switch_device_t device,
                                               uint32_t num_bytes) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_buffer_skid_hysteresis_set(switch_device_t device,
                                                    uint32_t num_bytes) {
  p4_pd_status_t status = 0;
  return status;
}

p4_pd_status_t switch_pd_buffer_pool_pfc_limit(switch_device_t device,
                                               switch_pd_pool_id_t pool_id,
                                               uint8_t icos,
                                               uint32_t num_bytes) {
  p4_pd_status_t status = 0;
  return status;
}
