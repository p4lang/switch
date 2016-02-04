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

#ifndef _switch_hostif_int_h_
#define _switch_hostif_int_h_

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_hostif.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SWITCH_PACKET_HEADER_OFFSET 12
#define SWITCH_FABRIC_HEADER_ETHTYPE 0x9000

typedef struct switch_hostif_rcode_info_ {
    switch_handle_t acl_handle;
    switch_api_hostif_rcode_info_t rcode_api_info;
} switch_hostif_rcode_info_t;

typedef struct switch_hostif_info_ {
    switch_hostif_t hostif;
    int intf_fd;
} switch_hostif_info_t;

typedef enum switch_fabric_header_type_ {
    SWITCH_FABRIC_HEADER_TYPE_NONE = 0,
    SWITCH_FABRIC_HEADER_TYPE_UNICAST = 1,
    SWITCH_FABRIC_HEADER_TYPE_MULTICAST = 2,
    SWITCH_FABRIC_HEADER_TYPE_MIRROR = 3,
    SWITCH_FABRIC_HEADER_TYPE_CONTROL = 4,
    SWITCH_FABRIC_HEADER_TYPE_CPU = 5
} switch_fabric_header_type_t;

typedef struct __attribute__((__packed__)) switch_fabric_header_ {
    uint16_t ether_type;
    uint8_t pad1 : 1;
    uint8_t packet_version : 2;
    uint8_t header_version : 2;
    uint8_t packet_type : 3;
    uint8_t fabric_color : 3;
    uint8_t fabric_qos : 5;
    uint8_t dst_device;
    uint16_t dst_port_or_group;
} switch_fabric_header_t;

typedef struct __attribute__((__packed__)) switch_cpu_header_ {
    uint16_t reserved : 2;
    uint16_t tx_bypass : 1;
    uint16_t egress_queue : 5;
    uint16_t ingress_port;
    uint16_t ingress_ifindex;
    uint16_t ingress_bd;
    uint16_t reason_code;
} switch_cpu_header_t;

typedef struct __attribute__((__packed__)) switch_packet_header_ {
    switch_fabric_header_t fabric_header;
    switch_cpu_header_t cpu_header;
} switch_packet_header_t;

typedef struct switch_hostif_nhop_ {
    switch_handle_t intf_handle;
    switch_handle_t nhop_handle;
    switch_ifindex_t ifindex;
    p4_pd_entry_hdl_t lag_entry;
    p4_pd_mbr_hdl_t mbr_hdl;
} switch_hostif_nhop_t;

#define SWITCH_HOSTIF_COMPUTE_IFINDEX(index) \
    ((SWITCH_IFINDEX_TYPE_CPU << SWITCH_IFINDEX_PORT_WIDTH) | index)

/*
 * Internal API's
 */
switch_status_t switch_hostif_init(switch_device_t device);
switch_status_t switch_hostif_free(switch_device_t device);
switch_status_t switch_packet_init(switch_device_t device);
switch_status_t
switch_api_hostif_rx_packet_from_hw(switch_packet_header_t *packet_header, char *packet, int packet_size);
switch_status_t
switch_api_hostif_rx_packet_from_host(switch_hostif_info_t *hostif_info, char *packet, int packet_size);
switch_hostif_info_t *
switch_hostif_get(switch_handle_t hostif_handle);
void
switch_packet_tx_to_host(switch_hostif_info_t *hostif_info, char *packet, int packet_size);
switch_status_t
switch_api_cpu_interface_create(switch_device_t device);

switch_ifindex_t switch_api_cpu_glean_ifindex();
switch_ifindex_t switch_api_cpu_myip_ifindex();
switch_ifindex_t switch_api_drop_ifindex();

#ifdef __cplusplus
}
#endif

#endif
