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

#include <saimirror.h>
#include "saiinternal.h"
#include <switchapi/switch_mirror.h>

static sai_api_t api_id = SAI_API_MIRROR;

static switch_mirror_type_t
sai_session_to_switch_session(
        _In_ sai_mirror_type_t mirror_type) {
    switch (mirror_type) {
        case SAI_MIRROR_TYPE_LOCAL:
            return SWITCH_MIRROR_TYPE_LOCAL;
        case SAI_MIRROR_TYPE_REMOTE:
            return SWITCH_MIRROR_TYPE_REMOTE;
        case SAI_MIRROR_TYPE_ENHANCED_REMOTE:
            return SWITCH_MIRROR_TYPE_ENHANCED_REMOTE;
        default:
            return SWITCH_MIRROR_TYPE_NONE;
    }
}

static switch_encap_type_t
sai_erspan_encap_to_switch_erspan_encap(
        _In_ sai_erspan_encapsulation_type_t encap_type) {
    switch (encap_type) {
        case SAI_MIRROR_L3_GRE_TUNNEL:
            return SWITCH_API_ENCAP_TYPE_ERSPAN_T3;
        default:
            return SWITCH_API_ENCAP_TYPE_NONE;
    }
}

static void sai_mirror_session_attribute_parse(
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list,
        _Out_ switch_api_mirror_info_t *api_mirror_info) {

    const sai_attribute_t *attribute = NULL;
    switch_tunnel_info_t *tunnel_info = NULL;
    uint32_t index = 0;

    memset(api_mirror_info, 0, sizeof(switch_api_mirror_info_t));
    tunnel_info = &api_mirror_info->tunnel_info;

    for (index = 0; index < attr_count; index++) {
        attribute = &attr_list[index];
        switch (attribute->id) {
            case SAI_MIRROR_SESSION_ATTR_TYPE:
                api_mirror_info->mirror_type = 
                            sai_session_to_switch_session(attribute->value.u8);
                break;
            case SAI_MIRROR_SESSION_ATTR_MONITOR_PORT:
                api_mirror_info->egress_port = attribute->value.oid;
                break;
            case SAI_MIRROR_SESSION_ATTR_TC:
                break;
            case SAI_MIRROR_SESSION_ATTR_VLAN_TPID:
                api_mirror_info->vlan_tpid = attribute->value.u16;
                break;
            case SAI_MIRROR_SESSION_ATTR_VLAN_ID:
                api_mirror_info->vlan_id = attribute->value.u16;
                api_mirror_info->vlan_create = TRUE;
                break;
            case SAI_MIRROR_SESSION_ATTR_VLAN_PRI:
                api_mirror_info->vlan_priority = attribute->value.u8;
                break;
            case SAI_MIRROR_SESSION_ATTR_ENCAP_TYPE:
                tunnel_info->encap_info.encap_type = 
                             sai_erspan_encap_to_switch_erspan_encap(attribute->value.u8);
                break;
            case SAI_MIRROR_SESSION_ATTR_IPHDR_VERSION:
                break;
            case SAI_MIRROR_SESSION_ATTR_TOS:
                break;
            case SAI_MIRROR_SESSION_ATTR_TTL:
                break;
            case SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS:
                sai_ip_addr_to_switch_ip_addr(&attribute->value.ipaddr,
                                              &tunnel_info->u.ip_encap.src_ip); 
                break;
            case SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS:
                sai_ip_addr_to_switch_ip_addr(&attribute->value.ipaddr,
                                              &tunnel_info->u.ip_encap.dst_ip); 
                api_mirror_info->tunnel_create = TRUE;
                break;
            case SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS:
                memcpy(&api_mirror_info->src_mac, &attribute->value.mac, 6);
                break;
            case SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS:
                memcpy(&api_mirror_info->dst_mac, &attribute->value.mac, 6);
                break;
            case SAI_MIRROR_SESSION_ATTR_GRE_PROTOCOL_TYPE:
                tunnel_info->u.ip_encap.proto = attribute->value.u16;
                break;
            default:
                break;
        }
    }
}

/**
 * @brief Create mirror session.
 *
 * @param[out] session_id Port mirror session id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Value of attributes
 * @return SAI_STATUS_SUCCESS if operation is successful otherwise a different
 *  error code is returned.
 */
sai_status_t sai_create_mirror_session(
        _Out_ sai_object_id_t *session_id,
        _In_  uint32_t attr_count,
        _In_  const sai_attribute_t *attr_list) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_api_mirror_info_t api_mirror_info;

    SAI_LOG_ENTER();

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                      sai_status_to_string(status));
        return status;
    }

    sai_mirror_session_attribute_parse(attr_count, attr_list, &api_mirror_info);
    *session_id = (sai_object_id_t) switch_api_mirror_session_create(device, &api_mirror_info);
    status = (*session_id == SWITCH_API_INVALID_HANDLE) ?
             SAI_STATUS_FAILURE :
             SAI_STATUS_SUCCESS;

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to create mirror session: %s",
                      sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/**
 * @brief Remove mirror session.
 *
 * @param[in] session_id Port mirror session id
 * @return SAI_STATUS_SUCCESS if operation is successful otherwise a different
 *  error code is returned.
 */
sai_status_t sai_remove_mirror_session(
        _In_ sai_object_id_t session_id) {
    sai_status_t status = SAI_STATUS_SUCCESS;

    SAI_LOG_ENTER();

    SAI_ASSERT(sai_object_type_query(session_id) == SAI_OBJECT_TYPE_MIRROR);

    status = switch_api_mirror_session_delete(device, session_id);
    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to remove mirror session %lx: %s",
                      session_id,
                      sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/**
 * @brief Set mirror session attributes.
 *
 * @param[in] session_id Port mirror session id
 * @param[in] attr Value of attribute
 * @return SAI_STATUS_SUCCESS if operation is successful otherwise a different
 *  error code is returned.
 */
sai_status_t sai_set_mirror_session_attribute(
        _In_ sai_object_id_t session_id,
        _In_ const  sai_attribute_t *attr) {
    sai_status_t status = SAI_STATUS_SUCCESS;

    SAI_LOG_ENTER();

    if (!attr) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute: %s",
                       sai_status_to_string(status));
        return status;
    }

    SAI_ASSERT(sai_object_type_query(session_id) == SAI_OBJECT_TYPE_MIRROR);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/**
 * @brief Get mirror session attributes.
 *
 * @param[in] session_id Port mirror session id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Value of attribute
 * @return SAI_STATUS_SUCCESS if operation is successful otherwise a different
 *  error code is returned.
 */
sai_status_t sai_get_mirror_session_attribute(
        _In_ sai_object_id_t session_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;


    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                       sai_status_to_string(status));
        return status;
    }

    SAI_ASSERT(sai_object_type_query(session_id) == SAI_OBJECT_TYPE_MIRROR);

    SAI_LOG_EXIT();

    return status;
}

/*
*  Mirror API methods table retrieved with sai_api_query()
*/
sai_mirror_api_t mirror_api = {
    .create_mirror_session             =             sai_create_mirror_session,
    .remove_mirror_session             =             sai_remove_mirror_session,
    .set_mirror_session_attribute      =             sai_set_mirror_session_attribute,
    .get_mirror_session_attribute      =             sai_get_mirror_session_attribute,
};

sai_status_t sai_mirror_initialize(sai_api_service_t *sai_api_service) {
    SAI_LOG_DEBUG("Initializing mirror");
    sai_api_service->mirror_api = mirror_api;
    return SAI_STATUS_SUCCESS;
}
