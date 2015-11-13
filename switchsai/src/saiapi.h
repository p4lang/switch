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

#if !defined (__SAIAPI_H_)
#define __SAIAPI_H_

#include <sai.h>
#include <saitypes.h>

typedef struct _sai_api_service_t {
    sai_switch_api_t                switch_api;
    sai_port_api_t                  port_api;
    sai_fdb_api_t                   fdb_api;
    sai_vlan_api_t                  vlan_api;
    sai_virtual_router_api_t        vr_api;
    sai_router_interface_api_t      rif_api;
    sai_route_api_t                 route_api;
    sai_neighbor_api_t              neighbor_api;
    sai_next_hop_api_t              nhop_api;
    sai_next_hop_group_api_t        nhop_group_api;
    sai_qos_map_api_t               qos_api;
    sai_acl_api_t                   acl_api;
    sai_lag_api_t                   lag_api;
    sai_stp_api_t                   stp_api;
    sai_hostif_api_t                hostif_api;
    sai_mirror_api_t                mirror_api;
    sai_samplepacket_api_t          samplepacket_api;
} sai_api_service_t;


#endif // __SAIAPI_H_
