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

#ifndef _switch_packet_int_h_
#define _switch_packet_int_h_

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switch_hostif_int.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SWITCH_PACKET_MAX_BUFFER_SIZE 10000

#define SWITCH_PACKET_TX_HASH_TABLE_SIZE 1024
#define SWITCH_PACKET_RX_HASH_TABLE_SIZE 1024

typedef struct switch_packet_rx_entry_ {
  switch_port_t port;
  bool port_valid;
  switch_ifindex_t ifindex;
  bool ifindex_valid;
  uint16_t bd;
  bool bd_valid;
  switch_hostif_reason_code_t reason_code;
  uint32_t reason_code_mask;
  bool reason_code_valid;
  uint32_t priority;
} switch_packet_rx_entry_t;

typedef struct switch_packet_rx_info_ {
  switch_packet_rx_entry_t rx_entry;
  tommy_node node;
  int intf_fd;
  switch_vlan_t vlan_id;
  switch_packet_vlan_action_t vlan_action;
} switch_packet_rx_info_t;

typedef struct switch_packet_tx_entry_ {
  int32_t intf_fd;
  bool fd_valid;
  switch_vlan_t vlan_id;
  bool vlan_valid;
  uint32_t priority;
} switch_packet_tx_entry_t;

typedef struct switch_packet_tx_info_ {
  switch_packet_tx_entry_t tx_entry;
  tommy_node node;
  uint16_t bd;
  switch_tx_bypass_flags_t bypass_flags;
  switch_port_t port;
} switch_packet_tx_info_t;

typedef struct __attribute__((__packed__)) switch_ethernet_header_ {
  uint8_t dst_mac[ETH_LEN];
  uint8_t src_mac[ETH_LEN];
  uint16_t ether_type;
} switch_ethernet_header_t;

#define SWITCH_ETHERTYPE_DOT1Q 0x8100

typedef struct __attribute__((__packed__)) switch_vlan_header_ {
  uint16_t tpid;
  uint16_t vid : 12;
  uint16_t dei : 1;
  uint16_t pcp : 3;
} switch_vlan_header_t;

#define SWITCH_PACKET_TX_HASH_KEY_SIZE sizeof(switch_packet_tx_hash_entry_t)
#define SWITCH_PACKET_RX_HASH_KEY_SIZE sizeof(switch_packet_rx_hash_entry_t)

void switch_packet_tx_switched(switch_packet_header_t *packet_header,
                               char *packet,
                               int packet_size);
void switch_packet_tx_to_hw(switch_packet_header_t *packet_header,
                            char *packet,
                            int packet_size);
switch_status_t switch_packet_hostif_create(switch_device_t device,
                                            switch_hostif_info_t *hostif_info);
switch_status_t switch_packet_hostif_delete(switch_device_t device,
                                            switch_hostif_info_t *hostif_info);

switch_status_t switch_packet_init(switch_device_t device);

switch_status_t switch_packet_free(switch_device_t device);

switch_status_t switch_packet_rx_info_get(switch_packet_rx_entry_t *rx_entry,
                                          switch_packet_rx_info_t **rx_info);

switch_status_t switch_packet_tx_info_get(switch_packet_tx_entry_t *tx_entry,
                                          switch_packet_tx_info_t **tx_info);
#ifdef __cplusplus
}
#endif

#endif
