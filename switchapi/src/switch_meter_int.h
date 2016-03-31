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

#ifndef _SWITCH_METER_INT_H_
#define _SWITCH_METER_INT_H_

#include <switchapi/switch_meter.h>

typedef uint32_t switch_meter_idx_t;

typedef struct switch_meter_stats_info_ {
    uint16_t stats_idx[SWITCH_METER_STATS_MAX];
    switch_counter_t counters[SWITCH_METER_STATS_MAX];
} switch_meter_stats_info_t;

typedef struct switch_meter_info_ {
    switch_api_meter_t api_meter_info;
    switch_meter_stats_info_t *stats_info;
    p4_pd_entry_hdl_t meter_idx_pd_hdl;
    p4_pd_entry_hdl_t action_pd_hdl[SWITCH_METER_COLOR_MAX];
} switch_meter_info_t;

switch_status_t
switch_meter_init(switch_device_t device);

switch_meter_info_t *
switch_meter_info_get(switch_handle_t meter_handle);
#endif /* _SWITCH_METER_INT_H_ */
