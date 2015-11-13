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

#ifndef _switch_acl_int_h_
#define _switch_acl_int_h_

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SWITCH_ACL_HASH_TABLE_SIZE (64*1024)

typedef struct switch_acl_interface_ {
    tommy_node node;
    switch_handle_t interface;
    void *entries;
} switch_acl_interface_t;

typedef struct switch_acl_rule_ {
    switch_handle_t acl_handle;
    int priority;
    unsigned int field_count;
    void *fields;
    switch_acl_action_t action;
    unsigned int action_param_size;
    switch_acl_action_params_t action_params;
} switch_acl_rule_t;

switch_status_t switch_acl_init(switch_device_t device);
switch_status_t switch_acl_free(switch_device_t device);

#ifdef __cplusplus
}
#endif

#endif /* defined(_switch_acl_int_h_) */
