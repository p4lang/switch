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

#include <saitypes.h>
#include <sai.h>

#include <switchapi/switch_base_types.h>
#include <switchapi/switch_status.h>

#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>

#include <arpa/inet.h>

#ifndef __SAIINTERNAL_H_
#define __SAIINTERNAL_H_

#define SAI_MAX_ENTRY_STRING_LEN 200

#define SAI_LOG_BUFFER_SIZE 1000

#define SAI_API_MAX (SAI_API_SCHEDULER_GROUP + 1)

#define SAI_ASSERT(x) assert(x)

#define SAI_MALLOC(x) malloc(x)

#define SAI_FREE(x) free(x)

void sai_log(int level, sai_api_t api, char *fmt, ...);

#define SAI_LOG(level, api_id, fmt, arg ...) \
    do { \
        sai_log(level, api_id, "[F:%s L:%d Func:%s] " fmt, \
               __FILE__, __LINE__, __func__, ##arg); \
    } while(0);

#define SAI_LOG_ENTER()                    \
    SAI_LOG(SAI_LOG_DEBUG, api_id, "Entering %s\n", __FUNCTION__)

#define SAI_LOG_EXIT()                     \
    SAI_LOG(SAI_LOG_DEBUG, api_id, "Exiting %s\n", __FUNCTION__)

#define SAI_LOG_DEBUG(fmt, arg ...)        \
    SAI_LOG(SAI_LOG_DEBUG, api_id, fmt, ## arg)

#define SAI_LOG_INFO(fmt, arg ...)         \
    SAI_LOG(SAI_LOG_INFO, api_id, fmt, ## arg)

#define SAI_LOG_NOTICE(fmt, arg ...)        \
    SAI_LOG(SAI_LOG_NOTICE, api_id, fmt, ## arg)

#define SAI_LOG_WARN(fmt, arg ...)        \
    SAI_LOG(SAI_LOG_WARN, api_id, fmt, ## arg)

#define SAI_LOG_ERROR(fmt, arg ...)        \
    SAI_LOG(SAI_LOG_ERROR, api_id, fmt, ## arg)

#define SAI_LOG_CRITICAL(fmt, arg ...)        \
    SAI_LOG(SAI_LOG_CRITICAL, api_id, fmt, ## arg)

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

extern switch_device_t device;
extern sai_switch_notification_t sai_switch_notifications;

sai_status_t sai_initialize();
sai_status_t sai_switch_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_port_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_fdb_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_vlan_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_lag_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_router_interface_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_next_hop_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_next_hop_group_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_route_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_virtual_router_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_stp_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_neighbor_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_hostif_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_acl_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_mirror_initialize(sai_api_service_t *sai_api_service);

char *sai_status_to_string(
        _In_ const sai_status_t status);

char * sai_object_type_to_string(
        _In_ sai_object_type_t object_type);

sai_status_t sai_switch_status_to_sai_status(
        _In_ const switch_status_t status);

sai_status_t sai_ipv4_prefix_length(
        _In_ sai_ip4_t ip4,
        _Out_ uint32_t *prefix_length);

sai_status_t sai_ipv6_prefix_length(
        _In_ const sai_ip6_t ip6,
        _Out_ uint32_t *prefix_length);

sai_status_t sai_ipv4_to_string(
        _In_ sai_ip4_t ip4,
        _In_ uint32_t max_length,
        _Out_ char *entry_string,
        _Out_ int *entry_length);

sai_status_t sai_ipv6_to_string(
        _In_ sai_ip6_t ip6,
        _In_ uint32_t max_length,
        _Out_ char *entry_string,
        _Out_ int *entry_length);

sai_status_t sai_ipaddress_to_string(
        _In_ sai_ip_address_t ip_addr,
        _In_ uint32_t max_length,
        _Out_ char *entry_string,
        _Out_ int *entry_length);

sai_status_t sai_ipprefix_to_string(
        _In_ sai_ip_prefix_t ip_prefix,
        _In_ uint32_t max_length,
        _Out_ char *entry_string);

sai_status_t sai_ip_prefix_to_switch_ip_prefix(
        const _In_ sai_ip_prefix_t *sai_ip_addr,
        _Out_ switch_ip_addr_t *ip_addr);

sai_status_t sai_ip_addr_to_switch_ip_addr(
        const _In_ sai_ip_address_t *sai_ip_addr,
        _Out_ switch_ip_addr_t *ip_addr);

#endif  // __SAIINTERNAL_H_
