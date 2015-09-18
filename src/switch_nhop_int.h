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
#include "switchapi/switch_nhop.h"

#define MAX_ECMP_GROUP_SIZE     (64)

#define SWITCH_NHOP_HASH_TABLE_SIZE 4096
#define SWITCH_NHOP_HASH_KEY_SIZE  32

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct switch_ecmp_member_ 
{
    tommy_node node;
    switch_handle_t nhop_handle;
#ifdef SWITCH_PD
    p4_pd_entry_hdl_t urpf_hw_entry;
    p4_pd_mbr_hdl_t mbr_hdl;
#endif
} switch_ecmp_member_t;

typedef struct switch_ecmp_info_
{
    unsigned int count;
    tommy_list members;
#ifdef SWITCH_PD
    p4_pd_entry_hdl_t hw_entry;
    p4_pd_grp_hdl_t pd_group_hdl;
#endif
} switch_ecmp_info_t;

typedef struct switch_spath_info_
{
    switch_nhop_key_t nhop_key;
    tommy_node node;
    switch_handle_t nhop_handle;
    switch_handle_t neighbor_handle;
#ifdef SWITCH_PD
    p4_pd_entry_hdl_t hw_entry;
    p4_pd_entry_hdl_t urpf_hw_entry;
#endif
} switch_spath_info_t;

typedef struct switch_nhop_info_
{
    unsigned int ref_count;
    bool valid;
    switch_nhop_index_type_t type;
    union {
        switch_spath_info_t spath;
        switch_ecmp_info_t ecmp;
    } u;
} switch_nhop_info_t;

#define SWITCH_NHOP_ECMP_INFO(nhop) \
    nhop->u.ecmp

#define SWITCH_NHOP_SPATH_INFO(nhop) \
    nhop->u.spath

#define SWITCH_NHOP_TYPE_IS_ECMP(nhop) \
    nhop->type == SWITCH_NHOP_INDEX_TYPE_ECMP

switch_status_t switch_nhop_init(switch_device_t device);
switch_status_t switch_nhop_free(switch_device_t device);
switch_nhop_info_t *switch_nhop_get();
switch_handle_t switch_nhop_create();
switch_status_t
switch_api_nhop_update(switch_device_t device, switch_handle_t nhop_handle);

#ifdef __cplusplus
}
#endif
