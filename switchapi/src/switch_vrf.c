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

#include "switchapi/switch_handle.h"
#include "switchapi/switch_vrf.h"
#include "switchapi/switch_status.h"
#include "switch_pd.h"
#include "switch_capability_int.h"
#include "switch_vrf_int.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static void *switch_vrf_array;

switch_status_t
switch_vrf_init(switch_device_t device)
{
    UNUSED(device);
    switch_vrf_array = NULL;
    return switch_handle_type_init(SWITCH_HANDLE_TYPE_VRF, (16*1024));
}

switch_status_t
switch_vrf_free(switch_device_t device)
{
    UNUSED(device);
    switch_handle_type_free(SWITCH_HANDLE_TYPE_VRF);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_vrf_create()
{
    switch_handle_t handle;
    _switch_handle_create(SWITCH_HANDLE_TYPE_VRF, switch_vrf_info_t, switch_vrf_array, NULL, handle);
    return handle;
}

switch_vrf_info_t *
switch_vrf_get(switch_handle_t handle)
{
    switch_vrf_info_t *vrf_info = NULL;
    _switch_handle_get(switch_vrf_info_t, switch_vrf_array, handle, vrf_info);
    return vrf_info;
}

switch_handle_t
switch_api_vrf_create(switch_device_t device, switch_vrf_id_t vrf_id)
{
    switch_vrf_info_t                 *vrf_info = NULL;
    switch_handle_t                    handle;

    UNUSED(device);
    if ((vrf_id == SWITCH_API_DEFAULT_VRF) &&
        (switch_api_default_vrf_internal() != 0)) {
        handle = switch_api_default_vrf_internal();
    } else {
        handle = switch_vrf_create();
        vrf_info = switch_vrf_get(handle);
        vrf_info->vrf_id = vrf_id;
    }
    switch_api_init_default_route_entries(device, handle);

    return handle;
}

switch_status_t
switch_api_vrf_delete(switch_device_t device, switch_handle_t handle)
{
    switch_vrf_info_t *vrf_info = NULL;

    if (!SWITCH_VRF_HANDLE_VALID(handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    UNUSED(device);
    vrf_info = switch_vrf_get(handle);
    if (!vrf_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    if (vrf_info->vrf_id == SWITCH_API_DEFAULT_VRF) {
        return SWITCH_STATUS_SUCCESS;
    }
    _switch_handle_delete(switch_vrf_info_t, switch_vrf_array, handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_vrf_attribute_set(switch_handle_t vrf_handle,
                             switch_vrf_attr_t type,
                             uint64_t value)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    switch(type) {
        case SWITCH_VRF_ATTR_VRF_TYPE:
            status = switch_api_vrf_type_set(vrf_handle, value);
        break;
        default:
            status = SWITCH_STATUS_INVALID_VRID;
    }
    return status;
}

switch_status_t
switch_api_vrf_attribute_get(switch_handle_t vrf_handle,
                             switch_vrf_attr_t type,
                             uint64_t *value)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    switch(type) {
        case SWITCH_VRF_ATTR_VRF_TYPE:
            status = switch_api_vrf_type_get(vrf_handle, value);
        break;
        default:
            status = SWITCH_STATUS_INVALID_VRID;
    }
    return status;
}

switch_status_t
switch_api_vrf_type_set(switch_handle_t vrf_handle, uint64_t value)
{
    switch_vrf_info_t *vrf_info = NULL;

    vrf_info = switch_vrf_get(vrf_handle);
    if (!vrf_info) {
        return SWITCH_STATUS_INVALID_VRID;
    }

    SWITCH_VRF_TYPE(vrf_info) = (uint8_t) value;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_vrf_type_get(switch_handle_t vrf_handle, uint64_t *value)
{
    switch_vrf_info_t *vrf_info = NULL;

    vrf_info = switch_vrf_get(vrf_handle);
    if (!vrf_info) {
        return SWITCH_STATUS_INVALID_VRID;
    }

    *value = SWITCH_VRF_TYPE(vrf_info);
    return SWITCH_STATUS_SUCCESS;
}
