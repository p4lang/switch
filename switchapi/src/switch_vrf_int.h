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

#ifndef _switch_vrf_int_h_
#define _switch_vrf_int_h_

#include "switchapi/switch_handle.h"
#include "switchapi/switch_vrf.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
#define SWITCH_VRF_V4_ENABLED(info) \
    info->flags.v4_enabled

#define SWITCH_VRF_V6_ENABLED(info) \
    info->flags.v6_enabled

#define SWITCH_VRF_TYPE(info) \
    info->flags.vrf_type

#define SWITCH_VRF_IS_CORE(info) \
    SWITCH_VRF_TYPE(info) == SWITCH_VRF_TYPE_CORE

switch_status_t switch_vrf_init(switch_device_t device);
switch_status_t switch_vrf_free(switch_device_t device);
switch_vrf_info_t * switch_vrf_get(switch_handle_t vrf_handle);

#ifdef __cplusplus
}
#endif

#endif
