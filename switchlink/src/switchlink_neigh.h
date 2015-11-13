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

#ifndef __SWITCHLINK_NEIGH_H__
#define __SWITCHLINK_NEIGH_H__

extern void
neigh_create(switchlink_handle_t vrf_h, switchlink_ip_addr_t *ipaddr,
             switchlink_mac_addr_t mac_addr, switchlink_handle_t intf_h);

#endif /* __SWITCHLINK_NEIGH_H__ */
