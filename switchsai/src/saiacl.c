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

#include <saiacl.h>
#include "saiinternal.h"
#include <switchapi/switch_handle.h>
#include <switchapi/switch_acl.h>

static sai_api_t api_id = SAI_API_ACL;

/*
Note: SAI ACL action processing implementation changes in the future
This is an interim solution to handling actions for the ACL in a more
static way. In a future implementation a dynamic action composiitng 
scheme will allow for having multiple actions be speicifed in any
combination in response to a match
*/

typedef int sai_acl_table_match_qualifiers[SAI_ACL_TABLE_ATTR_FIELD_END - SAI_ACL_TABLE_ATTR_FIELD_START + 1]; 

typedef struct sai_handle_node_ {
    tommy_node node;
    switch_handle_t handle;
} sai_handle_node_t;


static sai_acl_table_match_qualifiers ip_acl = {
        -1, -1,   // v6
        -1, -1, // MAC
        SWITCH_ACL_IP_FIELD_IPV4_SRC, SWITCH_ACL_IP_FIELD_IPV4_DEST, // v4
        -2, -2, -1, -1, // ports
        -1, -1, -1, -1, -1, -1, // VLAN outer and inner
        SWITCH_ACL_IP_FIELD_L4_SOURCE_PORT, SWITCH_ACL_IP_FIELD_L4_DEST_PORT, // l4 ports
        -1,
        SWITCH_ACL_IP_FIELD_IP_PROTO,
        SWITCH_ACL_IP_FIELD_DSCP,
        -1, // ecn
        SWITCH_ACL_IP_FIELD_TTL, // ttl
        SWITCH_ACL_IP_FIELD_TOS,
        SWITCH_ACL_IP_FIELD_IP_FLAGS,
        SWITCH_ACL_IP_FIELD_TCP_FLAGS, // tcp flags
        -1, // ip type
        -1, // ip frag
        -1, // ipv6 flow
        -1  // tc
        };

static sai_acl_table_match_qualifiers ipv6_acl = {
        SWITCH_ACL_IPV6_FIELD_IPV6_SRC, SWITCH_ACL_IPV6_FIELD_IPV6_DEST,
        -1, -1, // MAC
        -1, -1, // v4
        -2, -2, -1, -1, // ports
        -1, -1, -1, -1, -1, -1, // VLAN outer and inner
        SWITCH_ACL_IPV6_FIELD_L4_SOURCE_PORT, SWITCH_ACL_IPV6_FIELD_L4_DEST_PORT, // l4 ports
        -1,
        SWITCH_ACL_IPV6_FIELD_IP_PROTO,
        -1, // dscp
        -1, // ecn
        SWITCH_ACL_IPV6_FIELD_TTL, // ttl
        SWITCH_ACL_IPV6_FIELD_TOS,
        -1, // ip flags
        SWITCH_ACL_IPV6_FIELD_TCP_FLAGS, // tcp flags
        -1, // ip type
        -1, // ip frag
        SWITCH_ACL_IPV6_FIELD_FLOW_LABEL,
        -1  // tc
        };

static sai_acl_table_match_qualifiers mac_acl = {
        -1, -1,   // v6
        SWITCH_ACL_MAC_FIELD_SOURCE_MAC, SWITCH_ACL_MAC_FIELD_DEST_MAC, // MAC
        -1, -1, // v4
        -2, -2, -1, -1, // ports
        -1, SWITCH_ACL_MAC_FIELD_VLAN_PRI, SWITCH_ACL_MAC_FIELD_VLAN_CFI, -1, -1, -1, // VLAN outer and inner
        -1, -1, // l4 ports
        SWITCH_ACL_MAC_FIELD_ETH_TYPE,
        -1,
        -1,
        -1, // ecn
        -1, // ttl
        -1,
        -1,
        -1, // tcp flags
        -1, // ip type
        -1, // ip frag
        -1, // ipv6 flow
        -1  // tc
        };

static sai_acl_table_match_qualifiers egress_acl = {
        -1, -1, // v6
        -1, -1, // MAC
        -1, -1, // v4
        -2, -2, -1, SWITCH_ACL_EGR_DEST_PORT, // ports
        -1, -1, -1, -1, -1, -1, // VLAN outer and inner
        -1, -1, // l4 ports
        -1,
        -1,
        -1,
        -1, // ecn
        -1, // ttl
        -1,
        -1,
        -1, // tcp flags
        -1, // ip type
        -1, // ip frag
        -1, // ipv6 flow
        -1  // tc
        };


static int * sai_acl_p4_match_table_get(switch_acl_type_t table_type)
{
    switch (table_type) {
        case SWITCH_ACL_TYPE_IP:
            return ip_acl;
        case SWITCH_ACL_TYPE_IPV6:
            return ipv6_acl;
        case SWITCH_ACL_TYPE_MAC:
            return mac_acl;
        case SWITCH_ACL_TYPE_EGRESS_SYSTEM:
            return egress_acl;
        default:
            return NULL;
    }
}

/*
    Ensure that all the fields in the attribute list can be handled by the ACL
*/
static sai_status_t sai_acl_match_table_type_get(
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list,
        _In_ switch_acl_type_t *acl_type) 
{
    uint32_t index1 = 0, index2 = 0;
    int *table;
    bool table_matched = TRUE;

    for (index1 = 0; index1 < SWITCH_ACL_TYPE_MAX; index1++) {
        table = sai_acl_p4_match_table_get(index1);
        if (!table) {
            continue;
        }
        table_matched = TRUE;
        for (index2 = 0; index2 < attr_count; index2++) {
            // skip ports and VLAN attributes on check
            switch(attr_list[index2].id) {
                case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS:
                case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS:
                case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT:
                case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID:
                case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID:
                    break;
                default:
                    if (table[attr_list[index2].id - SAI_ACL_TABLE_ATTR_FIELD_START] == -1) {
                        table_matched = FALSE;
                    }
                    break;
            }
        }
        if (table_matched && index2 == attr_count) {
            *acl_type = index1;
            return SAI_STATUS_SUCCESS;
        }
    }
    return SAI_STATUS_FAILURE;
}

static sai_status_t sai_acl_match_table_field(
        _In_ int table_id, 
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list,
        _Out_ int *match_fields,
        _Out_ int *actions) 
{
    uint32_t index = 0;
    int id = 0;
    int *table;
    
    table = sai_acl_p4_match_table_get(table_id);
    if (!table) {
        return SAI_STATUS_FAILURE;
    }

    for (index = 0; index < attr_count; index++) {
        id = attr_list[index].id;
        if (id >= SAI_ACL_TABLE_ATTR_FIELD_START && id <= SAI_ACL_TABLE_ATTR_FIELD_END) {
           id -= SAI_ACL_TABLE_ATTR_FIELD_START;
           if (table[id] != -1) {
               match_fields[index] = table[id];
           } else {
               return SAI_STATUS_FAILURE;
           }
        }
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t sai_acl_xform_field_value(
        _In_ switch_acl_type_t acl_type,
        _In_ int field,
        _In_ void *dest,
        _In_ const sai_acl_field_data_t *source)
{
    switch(acl_type) {
        case SWITCH_ACL_TYPE_IP:
        {
            switch_acl_ip_key_value_pair_t *kvp = (switch_acl_ip_key_value_pair_t *)dest;
            switch (field) {
                case SWITCH_ACL_IP_FIELD_IPV4_SRC:
                    kvp->value.ipv4_source = ntohl(source->data.ip4);
                    kvp->mask.u.mask = ntohl(source->mask.ip4);
                    break;
                case SWITCH_ACL_IP_FIELD_IPV4_DEST:
                    kvp->value.ipv4_dest = ntohl(source->data.ip4);
                    kvp->mask.u.mask = ntohl(source->mask.ip4);
                    break;
                case SWITCH_ACL_IP_FIELD_IP_PROTO:
                    kvp->value.ip_proto = source->data.u16;
                    kvp->mask.u.mask = source->mask.u16;
                    break;
                case SWITCH_ACL_IP_FIELD_L4_SOURCE_PORT:
                    kvp->value.l4_source_port = source->data.u16;
                    kvp->mask.u.mask = source->mask.u16;
                    break;
                case SWITCH_ACL_IP_FIELD_L4_DEST_PORT:
                    kvp->value.l4_dest_port = source->data.u16;
                    kvp->mask.u.mask = source->mask.u16;
                    break;
                case SWITCH_ACL_IP_FIELD_ICMP_TYPE:
                case SWITCH_ACL_IP_FIELD_ICMP_CODE:
                case SWITCH_ACL_IP_FIELD_TCP_FLAGS:
                    kvp->value.tcp_flags = source->data.u8;
                    kvp->mask.u.mask = source->mask.u8;
                    break;
                case SWITCH_ACL_IP_FIELD_TTL:
                    kvp->value.ttl = source->data.u8;
                    kvp->mask.u.mask = source->mask.u8;
                    break;
                case SWITCH_ACL_IP_FIELD_DSCP:
                    kvp->value.dscp = source->data.u8;
                    kvp->mask.u.mask = source->mask.u8;
                    break;
                case SWITCH_ACL_IP_FIELD_IP_FLAGS:
                    kvp->value.ip_flags = source->data.u8;
                    kvp->mask.u.mask = source->mask.u8;
                    break;
                case SWITCH_ACL_IP_FIELD_TOS:
                    kvp->value.tos = source->data.u8;
                    kvp->mask.u.mask = source->mask.u8;
                    break;
                case SWITCH_ACL_IP_FIELD_IP_FRAGMENT:
                    kvp->value.ip_frag = source->data.u8;
                    kvp->mask.u.mask = source->mask.u8;
                    break;
                default:
                    break;
            }
        }
        break;
        case SWITCH_ACL_TYPE_IPV6:
        {
            switch (field) {
                case SWITCH_ACL_IPV6_FIELD_IPV6_SRC:
                case SWITCH_ACL_IPV6_FIELD_IPV6_DEST:
                case SWITCH_ACL_IPV6_FIELD_IP_PROTO:
                case SWITCH_ACL_IPV6_FIELD_L4_SOURCE_PORT:
                case SWITCH_ACL_IPV6_FIELD_L4_DEST_PORT:
                case SWITCH_ACL_IPV6_FIELD_ICMP_TYPE:
                case SWITCH_ACL_IPV6_FIELD_ICMP_CODE:
                case SWITCH_ACL_IPV6_FIELD_TCP_FLAGS:
                case SWITCH_ACL_IPV6_FIELD_TTL:
                case SWITCH_ACL_IPV6_FIELD_ETH_TYPE:
                case SWITCH_ACL_IPV6_FIELD_FLOW_LABEL:
                    break;
                default:
                    break;
            }
        }
        break;
        case SWITCH_ACL_TYPE_MAC:
        {
            switch_acl_mac_key_value_pair_t *kvp = (switch_acl_mac_key_value_pair_t *)dest;
            switch (field) {
                case SWITCH_ACL_MAC_FIELD_SOURCE_MAC:
                    memcpy(kvp->value.source_mac, source->data.mac, 6);
                    memcpy(kvp->mask.u.mac_mask, source->mask.mac, 6);
                    break;
                case SWITCH_ACL_MAC_FIELD_DEST_MAC:
                    memcpy(kvp->value.dest_mac, source->data.mac, 6);
                    memcpy(kvp->mask.u.mac_mask, source->mask.mac, 6);
                    break;
                case SWITCH_ACL_MAC_FIELD_VLAN_PRI:
                    kvp->value.vlan_pri = source->data.u8;
                    kvp->mask.u.mask16 = source->mask.u8;
                    break;
                case SWITCH_ACL_MAC_FIELD_VLAN_CFI:
                    kvp->value.vlan_cfi = source->data.u8;
                    kvp->mask.u.mask16 = source->mask.u8;
                    break;
                case SWITCH_ACL_MAC_FIELD_ETH_TYPE:
                    kvp->value.eth_type = source->data.u16;
                    kvp->mask.u.mask16 = source->mask.u16;
                    break;
                default:
                    break;
            }
        }
        break;
        case SWITCH_ACL_TYPE_EGRESS_SYSTEM:
        {
            switch_acl_egr_key_value_pair_t *kvp = (switch_acl_egr_key_value_pair_t *)dest;
            switch (field) {
                case SWITCH_ACL_EGR_DEST_PORT:
                    kvp->value.egr_port = source->data.oid;
                    kvp->mask.u.mask = 0xFFFF;
                    break;
                default:
                    break;
            }
        }
        break;
        default:
            break;
    }
    return SAI_STATUS_SUCCESS;
}

/*
* Routine Description:
*   Create an ACL table
*
* Arguments:
*  [out] acl_table_id - the the acl table id
*  [in] attr_count - number of attributes
*  [in] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_create_acl_table(
        _Out_ sai_object_id_t* acl_table_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_acl_type_t acl_type = 0;

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                       sai_status_to_string(status));
        return status;
    }

    status = sai_acl_match_table_type_get(attr_count, attr_list, &acl_type);
    if (status != SAI_STATUS_SUCCESS)  {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("failed to find match table: %s",
                       sai_status_to_string(status));
        return status;
    }

    *acl_table_id = (sai_object_id_t)switch_api_acl_list_create(device, acl_type);

    status = (*acl_table_id == SWITCH_API_INVALID_HANDLE) ?
              SAI_STATUS_FAILURE :
              SAI_STATUS_SUCCESS;
    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to create acl table: %s",
                      sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*   Delete an ACL table
*
* Arguments:
*   [in] acl_table_id - the acl table id
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_delete_acl_table(
        _In_ sai_object_id_t acl_table_id) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

    SAI_ASSERT(sai_object_type_query(acl_table_id) == SAI_OBJECT_TYPE_ACL_TABLE);

    switch_status = switch_api_acl_list_delete(device, (switch_handle_t) acl_table_id);
    status = sai_switch_status_to_sai_status(switch_status);

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to delete acl table%lx : %s",
                       acl_table_id,
                       sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*   Create an ACL entry
*
* Arguments:
*   [out] acl_entry_id - the acl entry id
*   [in] attr_count - number of attributes
*   [in] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_create_acl_entry(
        _Out_ sai_object_id_t *acl_entry_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    sai_object_id_t acl_table_id = 0ULL;
    int *match_fields = NULL;
    switch_acl_ip_key_value_pair_t *kvp=NULL;
    unsigned int field_size;
    switch_acl_action_t acl_action = 0;
    switch_acl_action_params_t         action_params;
    uint32_t priority = 0;
    switch_acl_info_t *acl_info = NULL;
    switch_acl_type_t acl_type;
    tommy_list handle_list;
    sai_handle_node_t *handle_node = NULL;
    uint32_t index1 = 0, index2 = 0;
    sai_object_id_t *objlist = NULL;
    int *actions = NULL;
    tommy_node *node;

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                       sai_status_to_string(status));
        return status;
    }

    *acl_entry_id = 0ULL;
    memset(&action_params, 0, sizeof(switch_acl_action_params_t));
    tommy_list_init(&handle_list);
    // get the table id
    for (index1 = 0; index1 < attr_count; index1++) {
        switch(attr_list[index1].id) {
            case SAI_ACL_ENTRY_ATTR_TABLE_ID:
                // ACL table identifier
                acl_table_id = attr_list[index1].value.aclfield.data.oid;
                SAI_ASSERT(sai_object_type_query(acl_table_id) ==
                           SAI_OBJECT_TYPE_ACL_TABLE);
                break;
            case SAI_ACL_ENTRY_ATTR_PRIORITY:
                // ACL entry priority
                priority = attr_list[index1].value.aclfield.data.u32;
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS:
                // ACL REFERENCE handling
                {
                    objlist = attr_list[index1].value.aclfield.data.objlist.list;
                    for (index2 = 0; index2 < attr_list[index1].value.aclfield.data.objlist.count; index2++) {
                        // accumulate handle mask
                        handle_node = SAI_MALLOC(sizeof(sai_handle_node_t));
                        if (!handle_node) {
                            status = SAI_STATUS_NO_MEMORY;
                            SAI_LOG_ERROR("failed to create acl entry: %s",
                                          sai_status_to_string(status));
                            return status;
                        }
                        memset(handle_node, 0, sizeof(sai_handle_node_t));
                        handle_node->handle = (switch_handle_t) * (objlist + index2);
                        tommy_list_insert_head(&handle_list, &(handle_node->node), handle_node);
                    }
                    SAI_FREE(attr_list[index1].value.aclfield.data.objlist.list);
                }
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT:
            case SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT:
                handle_node = SAI_MALLOC(sizeof(sai_handle_node_t));
                if (!handle_node) {
                    status = SAI_STATUS_NO_MEMORY;
                    SAI_LOG_ERROR("failed to create acl entry: %s",
                                  sai_status_to_string(status));
                    return status;
                }
                memset(handle_node, 0, sizeof(sai_handle_node_t));
                handle_node->handle = (switch_handle_t)attr_list[index1].value.aclfield.data.oid;
                tommy_list_insert_head(&handle_list, &(handle_node->node), handle_node);
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID:
                handle_node = SAI_MALLOC(sizeof(sai_handle_node_t));
                if (!handle_node) {
                    status = SAI_STATUS_NO_MEMORY;
                    SAI_LOG_ERROR("failed to create acl entry: %s",
                                  sai_status_to_string(status));
                    return status;
                }
                memset(handle_node, 0, sizeof(sai_handle_node_t));
                handle_node->handle = (switch_handle_t)attr_list[index1].value.aclfield.data.oid;
                tommy_list_insert_head(&handle_list, &(handle_node->node), handle_node);
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_INNER_VLAN_ID:
                break;
            case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT:
                {
                // ACTION handling
                    switch_handle_t handle = (switch_handle_t)attr_list[index1].value.aclfield.data.oid;
                    /*
                    if (SAI_CPU_PORT(port_handle)) {
                        acl_action = SWITCH_ACL_ACTION_REDIRECT_TO_CPU;
                    } else  {
                    */
                    acl_action = SWITCH_ACL_ACTION_REDIRECT;
                    // set the action params
                    action_params.redirect.handle = handle;
                }
                break;
            case SAI_ACL_ENTRY_ATTR_PACKET_ACTION:
                acl_action = SWITCH_ACL_ACTION_DROP;
                break;
            case SAI_ACL_ENTRY_ATTR_ACTION_FLOOD:
                acl_action = SWITCH_ACL_ACTION_FLOOD_TO_VLAN;
                break;
            case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS:
                {
                    switch_handle_t handle = (switch_handle_t)attr_list[index1].value.aclfield.data.oid;
                    acl_action = SWITCH_ACL_ACTION_SET_MIRROR;
                    action_params.mirror.mirror_handle = handle;
                }
                break;
            case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS:
                {
                    switch_handle_t handle = (switch_handle_t)attr_list[index1].value.aclfield.data.oid;
                    acl_action = SWITCH_ACL_EGR_ACTION_SET_MIRROR;
                    action_params.mirror.mirror_handle = handle;
                }
                break;
        }
    }

    acl_info = switch_acl_get((switch_handle_t) acl_table_id);
    if (!acl_info) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("failed to get acl info: %s",
                      sai_status_to_string(status));
        return status;
    }
    acl_type = acl_info->type;
    
    // switch on type to get more values!
    field_size = SWITCH_ACL_IP_FIELD_MAX;   
    match_fields = SAI_MALLOC(sizeof(int) * field_size);
    if (!match_fields) {
        status = SAI_STATUS_NO_MEMORY;
        SAI_LOG_ERROR("failed to create acl entry: %s",
                       sai_status_to_string(status));
        return status;
    }

    // init the array to unknown
    for (index1 = 0; index1 < field_size; index1++) {
        match_fields[index1] = -1;
    }
    actions = SAI_MALLOC(sizeof(int) * SWITCH_ACL_ACTION_MAX);
    if (!actions) {
        status = SAI_STATUS_NO_MEMORY;
        SAI_LOG_ERROR("failed to create acl entry: %s",
                       sai_status_to_string(status));
        return status;
    }
    // get the match fields
    status = sai_acl_match_table_field(acl_type, attr_count,
                                       attr_list,
                                       match_fields,
                                       actions);
    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to create acl entry: %s",
                       sai_status_to_string(status));
        return status;
    }
    // allocate to store key-value pairs
    kvp = SAI_MALLOC(sizeof(switch_acl_ip_key_value_pair_t) * field_size);
    if (!kvp) {
        status = SAI_STATUS_NO_MEMORY;
        SAI_LOG_ERROR("failed to create acl entry: %s",
                       sai_status_to_string(status));
        return status;
    }
    // Translate the ATTR to field values
    index2 = 0;
    for (index1 = 0; index1 < field_size; index1++) {
        if (match_fields[index1] != -1) {
            if (match_fields[index1] >= 0) {
                kvp[index2].field = match_fields[index1];
                sai_acl_xform_field_value(acl_type,
                                          match_fields[index1],
                                          &kvp[index2],
                                          &(attr_list[index1].value.aclfield));
                index2++;
             }
         }
    }
    // add entry with kvp and j
    if (index2 > 0) {
        // create the rule
        switch_status = switch_api_acl_rule_create(device, acl_table_id,
                                   priority, index2, kvp,
                                   acl_action, &action_params,
                                   acl_entry_id);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
            SAI_LOG_ERROR("failed to create acl entry: %s",
                          sai_status_to_string(status));
            SAI_FREE(kvp);
            SAI_FREE(actions);
            SAI_FREE(match_fields);
            return status;
        }
        // reference the ACL on handle
        node = tommy_list_head(&handle_list);
        while (node) {
            handle_node = node->data;
            if (handle_node) {
                switch_api_acl_reference(device, acl_table_id, handle_node->handle);
            }
            node = node->next;
        }

        // SAI_FREE handle_list
        tommy_list_foreach(&handle_list, free);
    }
    SAI_FREE(kvp);
    SAI_FREE(actions);
    SAI_FREE(match_fields);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*   Delete an ACL entry
*
* Arguments:
*  [in] acl_entry_id - the acl entry id
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_delete_acl_entry( 
        _In_ sai_object_id_t acl_entry_id) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

    SAI_ASSERT(sai_object_type_query(acl_entry_id) == SAI_OBJECT_TYPE_ACL_ENTRY);

    switch_status = switch_api_acl_rule_delete(device,
                                               (switch_handle_t)0,
                                               (switch_handle_t)acl_entry_id);
    status = sai_switch_status_to_sai_status(switch_status);

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to delete acl entry %lx : %s",
                       acl_entry_id,
                       sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
*  ACL methods table retrieved with sai_api_query()
*/
sai_acl_api_t acl_api = {
    .create_acl_table                  =             sai_create_acl_table,
    .delete_acl_table                  =             sai_delete_acl_table,
    .create_acl_entry                  =             sai_create_acl_entry,
    .delete_acl_entry                  =             sai_delete_acl_entry
};

sai_status_t sai_acl_initialize(sai_api_service_t *sai_api_service) {
    SAI_LOG_DEBUG("Initializing acl");
    sai_api_service->acl_api = acl_api;
    return SAI_STATUS_SUCCESS;
}
