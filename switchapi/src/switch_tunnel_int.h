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
#include "switchapi/switch_neighbor.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
#define SWITCH_VTEP_HASH_KEY_SIZE 21

#define SWITCH_SRC_VTEP_HASH_TABLE_SIZE 4096
#define SWITCH_DST_VTEP_HASH_TABLE_SIZE 4096

typedef struct switch_vtep_entry_ {
    unsigned int key[SWITCH_VTEP_HASH_KEY_SIZE];
    tommy_hashtable_node node;
    switch_handle_t vrf;
    switch_ip_addr_t ip_addr;
    uint16_t entry_index;
} switch_vtep_entry_t;

typedef struct switch_mpls_info_ {
    switch_mpls_encap_t mpls_encap;
    p4_pd_entry_hdl_t tunnel_hw_entry;
} switch_mpls_info_t;

switch_status_t switch_tunnel_init(switch_device_t device);
switch_status_t switch_tunnel_free(switch_device_t device);

uint16_t switch_tunnel_src_vtep_index_get(switch_handle_t vrf, switch_ip_addr_t *ip_addr);
uint16_t switch_tunnel_dst_vtep_index_get(switch_handle_t vrf, switch_ip_addr_t *ip_addr);

switch_status_t
switch_api_logical_network_member_add_basic(switch_device_t device,
                                            switch_handle_t bd_handle,
                                            switch_handle_t intf_handle);

switch_status_t
switch_api_logical_network_member_remove_basic(switch_device_t device,
                                               switch_handle_t bd_handle,
                                               switch_handle_t intf_handle);

switch_status_t
switch_api_logical_network_member_add_enhanced(switch_device_t device,
                                               switch_handle_t bd_handle,
                                               switch_handle_t intf_handle);

switch_status_t
switch_api_logical_network_member_remove_enhanced(switch_device_t device,
                                                  switch_handle_t bd_handle,
                                                  switch_handle_t intf_handle);

uint16_t switch_tunnel_get_tunnel_vni(switch_encap_info_t *encap_info); 

switch_tunnel_type_ingress_t
switch_tunnel_get_ingress_tunnel_type(switch_ip_encap_t *ip_encap);

switch_tunnel_type_egress_t
switch_tunnel_get_egress_tunnel_type(switch_encap_type_t encap_type, switch_ip_encap_t *ip_encap);
#ifdef __cplusplus
}
#endif
