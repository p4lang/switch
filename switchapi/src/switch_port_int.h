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
#include "switchapi/switch_capability.h"
#include "switchapi/switch_port.h"

#define NULL_PORT_ID                   511
#define CPU_PORT_ID                    64

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum switch_port_type_ {
    SWITCH_PORT_TYPE_NORMAL,
    SWITCH_PORT_TYPE_FABRIC,
    SWITCH_PORT_TYPE_CPU
} switch_port_type_t;

/** Port information */
typedef struct switch_port_info_ {
    switch_api_port_info_t api_port_info;
    switch_ifindex_t ifindex;
    switch_handle_t intf_handle;
    switch_handle_t port_handle;
    switch_handle_t hostif_handle;
    switch_port_type_t port_type;
    switch_handle_t meter_handle[SWITCH_PACKET_TYPE_MAX];
#ifdef SWITCH_PD
    p4_pd_entry_hdl_t hw_entry;             /* port mapping entry */
    p4_pd_entry_hdl_t lg_entry;             /* Lag group entry */
    p4_pd_entry_hdl_t ls_entry;             /* Lag select entry */
    p4_pd_mbr_hdl_t mbr_hdl;                /* Lag action profile entry */
    p4_pd_entry_hdl_t eg_lag_entry;         /* egress lag entry */
    p4_pd_entry_hdl_t rw_entry;             /* fabric rewrite entry */
    p4_pd_entry_hdl_t tunnel_rw_entry;      /* tunnel rewrite entry */
    p4_pd_entry_hdl_t meter_pd_hdl[SWITCH_PACKET_TYPE_MAX];         /* meter pd hdl */
#endif
} switch_port_info_t;

#define SWITCH_PORT_LAG_SELECT_ENTRY(info) \
    info->ls_entry

#define SWITCH_PORT_ID(info) \
    info->api_port_info.port_number

switch_status_t switch_port_init(switch_device_t device);
switch_port_info_t *switch_api_port_get_internal(switch_port_t port);

bool switch_port_is_cpu_port(switch_handle_t port_hdl);
#ifdef __cplusplus
}
#endif

#endif /* defined(__switch_port_int__) */
