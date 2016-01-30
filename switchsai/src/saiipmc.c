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

#include <saiipmc.h>
#include "saiinternal.h"
#include <switchapi/switch_interface.h>
#include <switchapi/switch_mcast.h>
#include <switchapi/switch_vlan.h>

static sai_api_t api_id = SAI_API_IPMC;

static void sai_ipmc_entry_to_string(
        _In_ const sai_ipmc_entry_t *ipmc_entry,
        _Out_ char *entry_string) {
    int count = 0;
    int len = 0;
    count = snprintf(entry_string, SAI_MAX_ENTRY_STRING_LEN,
                     "route: vrf %lx (", ipmc_entry->vr_id);
    if (count > SAI_MAX_ENTRY_STRING_LEN) {
        return;
    }
    sai_ipaddress_to_string(ipmc_entry->source,
                            SAI_MAX_ENTRY_STRING_LEN - count,
                            entry_string + count, &len);
    count += len;
    if (count > SAI_MAX_ENTRY_STRING_LEN) {
        return;
    }
    count += snprintf(entry_string + count,
                      SAI_MAX_ENTRY_STRING_LEN - count, ",");
    if (count > SAI_MAX_ENTRY_STRING_LEN) {
        return;
    }
    sai_ipprefix_to_string(ipmc_entry->group,
                           SAI_MAX_ENTRY_STRING_LEN - count,
                           entry_string + count, &len);
    count += len;
    if (count > SAI_MAX_ENTRY_STRING_LEN) {
        return;
    }
    count += snprintf(entry_string + count,
                      SAI_MAX_ENTRY_STRING_LEN - count, ")");
    return;
}

static void sai_ipmc_entry_parse(
        _In_ const sai_ipmc_entry_t *ipmc_entry,
        _Out_ switch_handle_t *vrf_handle,
        _Out_ switch_ip_addr_t *src_addr,
        _Out_ switch_ip_addr_t *grp_addr) {
    SAI_ASSERT(sai_object_type_query(ipmc_entry->vr_id) ==
               SAI_OBJECT_TYPE_VIRTUAL_ROUTER);
    *vrf_handle = (switch_handle_t) ipmc_entry->vr_id;

    memset(src_addr, 0, sizeof(switch_ip_addr_t));
    sai_ip_addr_to_switch_ip_addr(&(ipmc_entry->source), src_addr);
    if (((src_addr->type == SWITCH_API_IP_ADDR_V4) &&
         (src_addr->ip.v4addr == 0)) ||
        ((src_addr->type == SWITCH_API_IP_ADDR_V6) &&
         (memcmp(src_addr->ip.v6addr, &in6addr_any,
                 sizeof(in6addr_any)) == 0))) {
        src_addr->prefix_len = 0;
    }
    sai_ip_prefix_to_switch_ip_addr(&(ipmc_entry->group), grp_addr);
}

static void sai_ipmc_entry_attribute_parse(
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list,
        _Out_ switch_handle_t **oif_list_handle,
        _Out_ int *oif_list_count,
        _Out_ switch_handle_t **rpf_list_handle,
        _Out_ int *rpf_list_count,
        _Out_ int *action,
        _Out_ int *pri) {
    const sai_attribute_t *attribute;
    uint32_t index = 0;

    *action = SAI_PACKET_ACTION_FORWARD;
    for (index = 0; index < attr_count; index++) {
        attribute = &attr_list[index];
        switch (attribute->id) {
            case SAI_IPMC_ATTR_OUTPUT_ROUTER_INTERFACE_LIST:
                *oif_list_handle =
                    (switch_handle_t *) attribute->value.objlist.list;
                *oif_list_count = attribute->value.objlist.count;
                break;
            case SAI_IPMC_ATTR_RPF_ROUTER_INTERFACE_LIST:
                *rpf_list_handle =
                    (switch_handle_t *) attribute->value.objlist.list;
                *rpf_list_count = attribute->value.objlist.count;
            case SAI_ROUTE_ATTR_TRAP_PRIORITY:
                *pri = attribute->value.u8;
                break;
            case SAI_ROUTE_ATTR_PACKET_ACTION:
                *action = attribute->value.s32;
                break;
        }
    }
}

static switch_handle_t sai_ipmc_tree_create (
        _In_ switch_handle_t vrf_handle,
        _In_ switch_ip_addr_t *src_addr,
        _In_ switch_ip_addr_t *grp_addr,
        _In_ int oif_list_count,
        _In_ switch_handle_t *oif_list_handle) {
    switch_handle_t mcast_handle;
    switch_status_t status;

    uint16_t mbr_count_max = oif_list_count;
    uint16_t mbr_count = 0;
    switch_vlan_interface_t *mbrs = NULL;
    mbrs = switch_malloc(sizeof(switch_vlan_interface_t), oif_list_count);

    mcast_handle = switch_api_multicast_tree_create(device);
    for (int i = 0; i < oif_list_count; i++) {
        switch_handle_t intf_handle = oif_list_handle[i];
        switch_interface_type_t type;
        status = switch_api_interface_get_type(intf_handle, &type);
        assert(status == SWITCH_STATUS_SUCCESS);
        if (type == SWITCH_API_INTERFACE_L3) {
            mbrs[mbr_count].vlan_handle = 0;
            mbrs[mbr_count].intf_handle = intf_handle;
            mbr_count++;
        } else {
            uint64_t snooping_enabled = true;
            switch_handle_t vlan_handle;
            status = switch_api_interface_get_vlan_handle(
                intf_handle, &vlan_handle);
            assert(status == SWITCH_STATUS_SUCCESS);
            if (grp_addr->type == SWITCH_API_IP_ADDR_V4) {
                status = switch_api_vlan_igmp_snooping_enabled_get(
                    vlan_handle, &snooping_enabled);
                assert(status == SWITCH_STATUS_SUCCESS);
            } else {
                status = switch_api_vlan_mld_snooping_enabled_get(
                    vlan_handle, &snooping_enabled);
                assert(status == SWITCH_STATUS_SUCCESS);
            }
            if (snooping_enabled) {
                switch_handle_t l2mcast_handle;
                status = switch_api_multicast_l2route_tree_get(
                    device, vlan_handle, src_addr, grp_addr, &l2mcast_handle);
                if (status != SWITCH_STATUS_SUCCESS) {
                    continue;
                }
                uint16_t l2mbr_count = 0;
                switch_vlan_interface_t *l2mbrs = NULL;
                status = switch_api_multicast_member_get(device, l2mcast_handle,
                                                         &l2mbr_count, &l2mbrs);
                if (status != SWITCH_STATUS_SUCCESS) {
                    continue;
                }
                mbr_count_max += l2mbr_count;
                mbrs = switch_realloc(mbrs, (sizeof(switch_vlan_interface_t) *
                                             mbr_count_max));
                memcpy(mbrs + mbr_count, l2mbrs,
                       (sizeof(switch_vlan_interface_t) * l2mbr_count));
                mbr_count += l2mbr_count;

                switch_free(l2mbrs);
            } else {
                uint16_t l2mbr_count = 0;
                switch_vlan_interface_t *l2mbrs = NULL;
                status = switch_api_vlan_interfaces_get(device, vlan_handle,
                                                        &l2mbr_count, &l2mbrs);
                if (status != SWITCH_STATUS_SUCCESS) {
                    continue;
                }

                mbr_count_max += l2mbr_count;
                mbrs = switch_realloc(mbrs, (sizeof(switch_vlan_interface_t) *
                                             mbr_count_max));
                memcpy(mbrs + mbr_count, l2mbrs,
                       (sizeof(switch_vlan_interface_t) * l2mbr_count));
                mbr_count += l2mbr_count;
            }
        }
    }
    status = switch_api_multicast_member_add(device,
                                             mcast_handle, mbr_count, mbrs);
    assert(status == SWITCH_STATUS_SUCCESS);

    switch_free(mbrs);
    return mcast_handle;
}

/*
 * Routine Description:
 *    Create IP multicast entry
 *
 * Arguments:
 *    [in] ipmc_entry - IP multicast entry
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_create_ipmc_entry(
        _In_ const sai_ipmc_entry_t *ipmc_entry,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    switch_ip_addr_t src_addr, grp_addr;
    switch_handle_t vrf_handle = 0;
    switch_handle_t *oif_list_handle = 0;
    switch_handle_t *rpf_list_handle = 0;
    int oif_list_count = 0;
    int rpf_list_count = 0;
    int action=-1, pri=-1;
    switch_handle_t mcast_handle;
    char entry_string[SAI_MAX_ENTRY_STRING_LEN];

    if (!ipmc_entry) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null ipmc entry: %s", sai_status_to_string(status));
        return status;
    }

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s", sai_status_to_string(status));
        return status;
    }

    sai_ipmc_entry_parse(ipmc_entry, &vrf_handle, &src_addr, &grp_addr);
    sai_ipmc_entry_attribute_parse(attr_count, attr_list,
                                   &oif_list_handle, &oif_list_count,
                                   &rpf_list_handle, &rpf_list_count,
                                   &action, &pri);

    sai_ipmc_entry_to_string(ipmc_entry, entry_string);
    mcast_handle = sai_ipmc_tree_create(vrf_handle, &src_addr, &grp_addr,
                                        oif_list_count, oif_list_handle);
    status = sai_switch_status_to_sai_status(switch_status);

    switch_status = switch_api_multicast_mroute_add(
        device, mcast_handle, vrf_handle, &src_addr, &grp_addr, 1,
        rpf_list_handle, rpf_list_count);
    status = sai_switch_status_to_sai_status(switch_status);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/**
 * Routine Description:
 *    Remove IP multicast entry
 *
 * Arguments:
 *    [in] ipmc_entry - IP multicast entry
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_remove_ipmc_entry(
        _In_ const sai_ipmc_entry_t *ipmc_entry) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    switch_ip_addr_t src_addr, grp_addr;
    switch_handle_t vrf_handle = 0;

    if (!ipmc_entry) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null ipmc entry: %s", sai_status_to_string(status));
        return status;
    }

    sai_ipmc_entry_parse(ipmc_entry, &vrf_handle, &src_addr, &grp_addr);

    switch_handle_t mcast_handle;
    switch_status = switch_api_multicast_mroute_tree_get(
        device, vrf_handle, &src_addr, &grp_addr, &mcast_handle);
    if (status == SWITCH_STATUS_SUCCESS) {
        switch_status = switch_api_multicast_tree_delete(device, mcast_handle);
        assert(switch_status == SWITCH_STATUS_SUCCESS);
    }

    switch_status = switch_api_multicast_mroute_delete(
        device, vrf_handle, &src_addr, &grp_addr);
    status = sai_switch_status_to_sai_status(switch_status);

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to remove ipmc entry: %s",
                       sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/**
 * Routine Description:
 *    Set IP multicast entry attribute value
 *
 * Arguments:
 *    [in] IP multicast - IP multicast entry
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_set_ipmc_entry_attribute(
        _In_ const sai_ipmc_entry_t *ipmc_entry,
        _In_ const sai_attribute_t *attr) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    if (!ipmc_entry) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null ipmc entry: %s", sai_status_to_string(status));
        return status;
    }

    if (!attr) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute: %s", sai_status_to_string(status));
        return status;
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/**
 * Routine Description:
 *    Get IP multicast entry attribute value
 *
 * Arguments:
 *    [in] ipmc_entry - IP multicast entry
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_get_ipmc_entry_attribute(
        _In_ const sai_ipmc_entry_t *ipmc_entry,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    if (!ipmc_entry) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null ipmc entry: %s", sai_status_to_string(status));
        return status;
    }

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s", sai_status_to_string(status));
        return status;
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/**
 * IP multicast method table retrieved with sai_api_query()
 */
sai_ipmc_api_t ipmc_api = {
    .create_ipmc_entry             =             sai_create_ipmc_entry,
    .remove_ipmc_entry             =             sai_remove_ipmc_entry,
    .set_ipmc_entry_attribute      =             sai_set_ipmc_entry_attribute,
    .get_ipmc_entry_attribute      =             sai_get_ipmc_entry_attribute,
};

sai_status_t sai_ipmc_initialize(sai_api_service_t *sai_api_service) {
    SAI_LOG_DEBUG("Initializing ipmc");
    sai_api_service->ipmc_api = ipmc_api;
    return SAI_STATUS_SUCCESS;
}
