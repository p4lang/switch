/*
Copyright 2015-present Barefoot Networks, Inc.

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

#ifndef _SWITCH_INT_H_
#define _SWITCH_INT_H_
#include "switch_base_types.h"
#include "switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
#define INT_INS_MASK_VALID_BITS     0xFF00

switch_status_t
switch_int_transit_enable(switch_device_t device, int32_t switch_id, int32_t enable);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // _SWITCH_INT_H_
