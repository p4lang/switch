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

#ifndef _SWITCH_MIRROR_INT_H_
#define _SWITCH_MIRROR_INT_H_

typedef struct switch_mirror_info_ {
    switch_api_mirror_info_t api_mirror_info;
    uint32_t max_pkt_len;
    switch_handle_t intf_handle;
    switch_handle_t vlan_handle;
    switch_handle_t tunnel_intf_handle;
    switch_handle_t inner_neigh_handle;
    switch_handle_t outer_neigh_handle;
    p4_pd_entry_hdl_t pd_hdl;
} switch_mirror_info_t;

switch_status_t
switch_mirror_init(switch_device_t device);

switch_mirror_info_t *
switch_mirror_info_get(switch_handle_t mirror_handle);
#endif /* _SWITCH_MIRROR_INT_H_ */
