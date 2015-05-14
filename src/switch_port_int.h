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

#ifndef __switch_port_int__
#define __switch_port_int__

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_port.h"

#define CPU_PORT_ID                    64

#define SWITCH_API_MAX_PORTS 256

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Port information */
typedef struct switch_port_info_ {
    switch_api_port_info_t api_port_info;
    switch_ifindex_t ifindex;
    switch_handle_t intf_handle;
#ifdef SWITCH_PD
    p4_pd_entry_hdl_t hw_entry;             /* port mapping entry */
    p4_pd_entry_hdl_t lg_entry;             /* Lag group entry */
    p4_pd_entry_hdl_t ls_entry;             /* Lag select entry */
    p4_pd_mbr_hdl_t mbr_hdl;                /* Lag action profile entry */
    p4_pd_entry_hdl_t eg_lag_entry;         /* egress lag entry */
#endif
} switch_port_info_t;

#define SWITCH_PORT_LAG_SELECT_ENTRY(info) \
    info->ls_entry

#define SWITCH_PORT_ID(info) \
    info->api_port_info.port_number

switch_status_t switch_port_init();
switch_port_info_t *switch_api_port_get_internal(switch_port_t port);

#ifdef __cplusplus
}
#endif

#endif /* defined(__switch_port_int__) */
