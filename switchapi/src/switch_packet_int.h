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

void
switch_packet_tx_to_hw(switch_packet_header_t *packet_header, char *packet, int packet_size);
switch_status_t
switch_packet_hostif_create(switch_device_t device, switch_hostif_info_t *hostif_info);
switch_status_t
switch_packet_hostif_delete(switch_device_t device, switch_hostif_info_t *hostif_info);

#ifdef __cplusplus
}
#endif

#endif
