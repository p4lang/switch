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

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_vlan.h"
#include "switchapi/switch_vrf.h"
#include "switchapi/switch_capability.h"
#include "switch_pd.h"
#include "switch_capability_int.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static switch_capability_info_t *switch_info = NULL;

int
switch_capability_init()
{
    switch_device_t device = SWITCH_DEV_ID;

    switch_info = switch_malloc(sizeof(switch_capability_info_t), 1);
    memset(switch_info, 0, sizeof(switch_capability_info_t));

    // Create Default VLAN
    switch_api_capability_attribute_set(SWITCH_ATTR_DEFAULT_VLAN_ID,
                                        SWITCH_API_DEFAULT_VLAN);
    switch_info->default_vlan = switch_api_vlan_create(device, SWITCH_API_DEFAULT_VLAN);

    // Create Default Vrf
    switch_api_capability_attribute_set(SWITCH_ATTR_DEFAULT_VRF_ID,
                                        SWITCH_API_DEFAULT_VRF);
    switch_info->default_vrf = switch_api_vrf_create(device, SWITCH_API_DEFAULT_VRF);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_api_default_vlan_internal()
{
    return switch_info->default_vlan_handle;
}

switch_handle_t
switch_api_default_vrf_internal()
{
    return switch_info->default_vrf_handle;
}

switch_status_t
switch_api_capability_attribute_set(switch_capability_attr_t attr_type, uint64_t value)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    if (!switch_info) {
        return SWITCH_STATUS_SUCCESS;
    }

    switch(attr_type) {
        case SWITCH_ATTR_DEFAULT_VLAN_ID:
            switch_info->default_vlan = value;
        break;

        case SWITCH_ATTR_DEFAULT_VRF_ID:
            switch_info->default_vrf = value;
        break;

        default:
            status = SWITCH_STATUS_SUCCESS;
    }
    return status;
}
    
switch_status_t
switch_api_capability_attribute_get(switch_capability_attr_t attr_type, uint64_t *value)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    *value = 0;
    switch(attr_type) {
        case SWITCH_ATTR_DEFAULT_VLAN_ID:
            *value = switch_info->default_vlan;
        break;

        case SWITCH_ATTR_DEFAULT_VRF_ID:
            *value = switch_info->default_vrf;
        break;

        default:
            status = SWITCH_STATUS_SUCCESS;
    }
    return status;
}

#ifdef __cplusplus
}
#endif
