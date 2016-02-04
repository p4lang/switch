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

#include <sainexthop.h>
#include "saiinternal.h"
#include <switchapi/switch_nhop.h>

static sai_api_t api_id = SAI_API_NEXT_HOP_GROUP;

sai_status_t sai_create_next_hop_group_entry(
        _Out_ sai_object_id_t* next_hop_group_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

sai_status_t sai_remove_next_hop_group_entry(
        _In_ sai_object_id_t next_hop_group_id);

sai_status_t sai_add_next_hop_to_group(
        _In_ sai_object_id_t next_hop_group_id,
        _In_ uint32_t next_hop_count,
        _In_ const sai_object_id_t* nexthops);

sai_status_t sai_remove_next_hop_from_group(
        _In_ sai_object_id_t next_hop_group_id,
        _In_ uint32_t next_hop_count,
        _In_ const sai_object_id_t* nexthops);


static sai_next_hop_group_type_t
sai_get_next_hop_group_type(sai_object_id_t next_hop_group_id) {
    return SAI_NEXT_HOP_GROUP_ECMP;
}

/*
* Routine Description:
*    Create next hop group
*
* Arguments:
*    [out] next_hop_group_id - next hop group id
*    [in] attr_count - number of attributes
*    [in] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_create_next_hop_group_entry(
        _Out_ sai_object_id_t* next_hop_group_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    sai_attribute_t attribute;
    sai_object_id_t *nhop_list;
    sai_next_hop_group_type_t nhgroup_type;
    uint32_t nhop_count = 0;
    uint32_t index = 0;

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                       sai_status_to_string(status));
        return status;
    }

    for (index = 0; index < attr_count; index++) {
        attribute = attr_list[index];
        switch(attribute.id) {
            case SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_COUNT:
                break;
            case SAI_NEXT_HOP_GROUP_ATTR_TYPE:
                nhgroup_type = attribute.value.u8;
                break;
            case SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_LIST:
                nhop_list = attribute.value.objlist.list;
                nhop_count = attribute.value.objlist.count;
                break;
        }
    }

    assert(nhgroup_type == SAI_NEXT_HOP_GROUP_ECMP);
    *next_hop_group_id = (sai_object_id_t) switch_api_ecmp_create(device);
    status = ((*next_hop_group_id == SWITCH_API_INVALID_HANDLE) ?
              SAI_STATUS_FAILURE : SAI_STATUS_SUCCESS);
    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to create next hop group %s",
                      sai_status_to_string(status));
        return status;
    }

    status = sai_add_next_hop_to_group(*next_hop_group_id,
                                       nhop_count, nhop_list);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Remove next hop group
*
* Arguments:
*    [in] next_hop_group_id - next hop group id
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_remove_next_hop_group_entry(
        _In_ sai_object_id_t next_hop_group_id) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

    SAI_ASSERT(sai_object_type_query(next_hop_group_id) ==
               SAI_OBJECT_TYPE_NEXT_HOP_GROUP);

    sai_next_hop_group_type_t nhgroup_type;
    nhgroup_type = sai_get_next_hop_group_type(next_hop_group_id);
    assert(nhgroup_type == SAI_NEXT_HOP_GROUP_ECMP);
    switch_status = switch_api_ecmp_delete(
        device, (switch_handle_t) next_hop_group_id);
    status = sai_switch_status_to_sai_status(switch_status);
    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to remove next hop group %lx: %s",
                      next_hop_group_id,
                      sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Set Next Hop Group attribute
*
* Arguments:
*    [in] sai_object_id_t - next_hop_group_id
*    [in] attr - attribute
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_set_next_hop_group_entry_attribute(
        _In_ sai_object_id_t next_hop_group_id,
        _In_ const sai_attribute_t *attr) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    if (!attr) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                       sai_status_to_string(status));
        return status;
    }

    SAI_ASSERT(sai_object_type_query(next_hop_group_id) ==
               SAI_OBJECT_TYPE_NEXT_HOP_GROUP);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Get Next Hop Group attribute
*
* Arguments:
*    [in] sai_object_id_t - next_hop_group_id
*    [in] attr_count - number of attributes
*    [inout] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_get_next_hop_group_entry_attribute(
        _In_ sai_object_id_t next_hop_group_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t index = 0;

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                       sai_status_to_string(status));
        return status;
    }

    SAI_ASSERT(sai_object_type_query(next_hop_group_id) ==
               SAI_OBJECT_TYPE_NEXT_HOP_GROUP);

    for (index = 0; index < attr_count; index++) {
        switch(attr_list[index].id) {
            case SAI_NEXT_HOP_GROUP_ATTR_TYPE: {
                attr_list[index].value.u8 =
                    sai_get_next_hop_group_type(next_hop_group_id);
                break;
            }
            default:
                break;
        }
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Add next hop to a group
*
* Arguments:
*    [in] next_hop_group_id - next hop group id
*    [in] next_hop_count - number of next hops
*    [in] nexthops - array of next hops
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_add_next_hop_to_group(
        _In_ sai_object_id_t next_hop_group_id,
        _In_ uint32_t next_hop_count,
        _In_ const sai_object_id_t* nexthops) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

    if (!nexthops) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null nexthops list: %s",
                       sai_status_to_string(status));
        return status;
    }

    SAI_ASSERT(sai_object_type_query(next_hop_group_id) ==
               SAI_OBJECT_TYPE_NEXT_HOP_GROUP);

    switch_status = switch_api_ecmp_member_add(
        device, (switch_handle_t) next_hop_group_id,
        next_hop_count, (switch_handle_t *) nexthops);
    status = sai_switch_status_to_sai_status(switch_status);
    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to add next hop to group %lx : %s",
                      next_hop_group_id,
                      sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Remove next hop from a group
*
* Arguments:
*    [in] next_hop_group_id - next hop group id
*    [in] next_hop_count - number of next hops
*    [in] nexthops - array of next hops
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_remove_next_hop_from_group(
        _In_ sai_object_id_t next_hop_group_id,
        _In_ uint32_t next_hop_count,
        _In_ const sai_object_id_t* nexthops) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

    if (!nexthops) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null nexthops list: %s",
                       sai_status_to_string(status));
        return status;
    }

    SAI_ASSERT(sai_object_type_query(next_hop_group_id) ==
               SAI_OBJECT_TYPE_NEXT_HOP_GROUP);

    switch_status = switch_api_ecmp_member_delete(
        device, (switch_handle_t) next_hop_group_id,
        next_hop_count, (switch_handle_t *) nexthops);
    status = sai_switch_status_to_sai_status(switch_status);
    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to remove next hop from group %lx : %s",
                      next_hop_group_id,
                      sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
*  Next Hop group methods table retrieved with sai_api_query()
*/
sai_next_hop_group_api_t nhop_group_api = {
    .create_next_hop_group                  =             sai_create_next_hop_group_entry,
    .remove_next_hop_group                  =             sai_remove_next_hop_group_entry,
    .set_next_hop_group_attribute           =             sai_set_next_hop_group_entry_attribute,
    .get_next_hop_group_attribute           =             sai_get_next_hop_group_entry_attribute,
    .add_next_hop_to_group                  =             sai_add_next_hop_to_group,
    .remove_next_hop_from_group             =             sai_remove_next_hop_from_group
};

sai_status_t sai_next_hop_group_initialize(sai_api_service_t *sai_api_service) {
    SAI_LOG_DEBUG("Initializing nexthop group");
    sai_api_service->nhop_group_api = nhop_group_api;
    return SAI_STATUS_SUCCESS;
}
