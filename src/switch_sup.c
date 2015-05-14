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
#include "switchapi/switch_sup.h"
#include "switch_pd.h"
#include "switch_nhop_int.h"
#include "switch_sup_int.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

switch_sup_info_t *sup_info = NULL;

switch_status_t
switch_sup_init() {
    sup_info = switch_malloc(sizeof(switch_sup_info_t), 1);
    if (!sup_info) {
        return SWITCH_STATUS_NO_MEMORY;
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_sup_rewrite_init(switch_device_t device, switch_port_t port_id)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    status = switch_pd_sup_rewrite_add_entry(device, port_id);
    return status;
}
    
#ifdef __cplusplus
}
#endif
