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
#include <Judy.h>
#include "switchapi/switch_meter.h"
#include "switchapi/switch_status.h"
#include "switch_meter_int.h"
#include "switch_pd.h"
#include "switch_log.h"

static void *switch_meter_array = NULL;

switch_status_t
switch_meter_init(switch_device_t device)
{
    switch_meter_array = NULL;
    switch_handle_type_init(SWITCH_HANDLE_TYPE_METER, (1024));
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_meter_create()
{
    switch_handle_t meter_handle;
    _switch_handle_create(SWITCH_HANDLE_TYPE_METER,
                          switch_meter_info_t,
                          switch_meter_array,
                          NULL, meter_handle);
    return meter_handle;
}

switch_meter_info_t *
switch_meter_info_get(switch_handle_t meter_handle)
{
    switch_meter_info_t *meter_info = NULL;
    _switch_handle_get(switch_meter_info_t, switch_meter_array, meter_handle, meter_info);
    return meter_info;
}

switch_status_t
switch_meter_delete(switch_handle_t meter_handle)
{
    _switch_handle_delete(switch_meter_info_t,
                          switch_meter_array,
                          meter_handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_api_meter_create(
        switch_device_t device,
        switch_api_meter_t *api_meter_info)
{
    switch_meter_info_t               *meter_info = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_handle_t                    meter_handle = 0;

    meter_handle = switch_meter_create();
    meter_info = switch_meter_info_get(meter_handle);
    if (!meter_info) {
        return SWITCH_API_INVALID_HANDLE;
    }

    memcpy(&meter_info->api_meter_info, api_meter_info, sizeof(switch_api_meter_t));

    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_API_INVALID_HANDLE;
    }

    meter_info->stats_info = switch_malloc(sizeof(switch_meter_stats_info_t), 1);
    if (!meter_info->stats_info) {
        return SWITCH_API_INVALID_HANDLE;
    }

    memset(meter_info->stats_info, 0, sizeof(switch_meter_stats_info_t));

    if (api_meter_info->meter_mode == SWITCH_METER_MODE_STORM_CONTROL) {
        meter_info->api_meter_info.pbs = meter_info->api_meter_info.cbs;
        meter_info->api_meter_info.pir = meter_info->api_meter_info.cir;
        meter_info->api_meter_info.action[SWITCH_METER_COLOR_YELLOW] =
            meter_info->api_meter_info.action[SWITCH_METER_COLOR_GREEN];
        status = switch_pd_storm_control_meter_add_entry(
                             device,
                             handle_to_id(meter_handle),
                             meter_info);
    } else {
        status = switch_pd_meter_index_table_add_entry(
                             device,
                             handle_to_id(meter_handle),
                             meter_info,
                             &meter_info->meter_idx_pd_hdl);
    }

    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_API_INVALID_HANDLE;
    }

    status = switch_pd_meter_action_table_add_entry(
                             device,
                             handle_to_id(meter_handle),
                             meter_info,
                             meter_info->action_pd_hdl);

    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_API_INVALID_HANDLE;
    }

    return meter_handle;
}

switch_status_t
switch_api_meter_update(
        switch_device_t device,
        switch_handle_t meter_handle,
        switch_api_meter_t *api_meter_info)
{
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_meter_info_t               *meter_info = NULL;

    meter_info = switch_meter_info_get(meter_handle);
    if (!meter_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    memcpy(&meter_info->api_meter_info, api_meter_info, sizeof(switch_api_meter_t));

    if (api_meter_info->meter_mode == SWITCH_METER_MODE_STORM_CONTROL) {
        meter_info->api_meter_info.pbs = meter_info->api_meter_info.cbs;
        meter_info->api_meter_info.pir = meter_info->api_meter_info.cir;
        meter_info->api_meter_info.action[SWITCH_METER_COLOR_YELLOW] =
            meter_info->api_meter_info.action[SWITCH_METER_COLOR_GREEN];
        status = switch_pd_storm_control_meter_add_entry(
                             device,
                             handle_to_id(meter_handle),
                             meter_info);
    } else {
        status = switch_pd_meter_index_table_update_entry(
                             device,
                             handle_to_id(meter_handle),
                             meter_info,
                             meter_info->meter_idx_pd_hdl);
    }

    status = switch_pd_meter_action_table_update_entry(
                             device,
                             handle_to_id(meter_handle),
                             meter_info,
                             meter_info->action_pd_hdl);

    return status;
}

switch_status_t
switch_api_meter_delete(
        switch_device_t device,
        switch_handle_t meter_handle)
{
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_meter_info_t               *meter_info = NULL;

    meter_info = switch_meter_info_get(meter_handle);
    if (!meter_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    if (meter_info->api_meter_info.meter_mode != SWITCH_METER_MODE_STORM_CONTROL) {
        status = switch_pd_meter_index_table_delete_entry(
                             device,
                             meter_info->meter_idx_pd_hdl);
    }

    status = switch_pd_meter_action_table_delete_entry(
                             device,
                             meter_info->action_pd_hdl);

    switch_free(meter_info->stats_info);
    switch_meter_delete(meter_handle);
    return status;
}

switch_status_t
switch_api_meter_stats_get(switch_device_t device,
                          switch_handle_t meter_handle,
                          uint8_t count,
                          switch_meter_stats_t *counter_ids,
                          switch_counter_t *counters)
{
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_meter_info_t               *meter_info = NULL;
    switch_meter_stats_info_t         *stats_info = NULL;
    int                                index = 0;
    switch_vlan_stats_t                counter_id = 0;

    meter_info = switch_meter_info_get(meter_handle);
    if (!meter_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    stats_info = meter_info->stats_info;
    status = switch_pd_meter_stats_get(device, meter_info);
    for (index = 0; index < count; index++) {
        counter_id = counter_ids[index];
        counters[index] = stats_info->counters[counter_id];
    }
    return status;
}
