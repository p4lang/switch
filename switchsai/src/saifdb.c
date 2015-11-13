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

#include <saifdb.h>
#include "saiinternal.h"
#include <switchapi/switch_l2.h>
#include <switchapi/switch_vlan.h>

static sai_api_t api_id = SAI_API_FDB;

static void sai_fdb_entry_to_string(
        _In_ const sai_fdb_entry_t *fdb_entry,
        _Out_ char *entry_string)
{
    snprintf(entry_string, SAI_MAX_ENTRY_STRING_LEN,
             "fdb entry mac [%02x:%02x:%02x:%02x:%02x:%02x] vlan %u",
             fdb_entry->mac_address[0],
             fdb_entry->mac_address[1],
             fdb_entry->mac_address[2],
             fdb_entry->mac_address[3],
             fdb_entry->mac_address[4],
             fdb_entry->mac_address[5],
             fdb_entry->vlan_id);
}

static void sai_fdb_entry_parse(
        const sai_fdb_entry_t *fdb_entry,
        switch_api_mac_entry_t *mac_entry) {
    switch_api_vlan_id_to_handle_get(fdb_entry->vlan_id, &mac_entry->vlan_handle);
    memcpy(mac_entry->mac.mac_addr, fdb_entry->mac_address, 6);
}

static void sai_fdb_entry_attribute_parse(
        uint32_t attr_count,
        const sai_attribute_t *attr_list,
        switch_api_mac_entry_t *mac_entry) {

    const sai_attribute_t *attribute;
    uint32_t i = 0;
    sai_packet_action_t action = 0;

    for (i = 0; i < attr_count; i++) {
        attribute = &attr_list[i];
        switch (attribute->id) {
            case SAI_FDB_ENTRY_ATTR_TYPE:
                switch (attribute->value.u8) {
                    case SAI_FDB_ENTRY_DYNAMIC:
                        mac_entry->entry_type = SWITCH_MAC_ENTRY_DYNAMIC;
                        break;

                    case SAI_FDB_ENTRY_STATIC:
                        mac_entry->entry_type = SWITCH_MAC_ENTRY_STATIC;
                        break;
                }
                break;

            case SAI_FDB_ENTRY_ATTR_PORT_ID: 
                mac_entry->handle = (switch_handle_t) attribute->value.oid;
                break;

            case SAI_FDB_ENTRY_ATTR_PACKET_ACTION:
                action = (switch_mac_action_t) attribute->value.u8;
                switch (action) {
                    case SAI_PACKET_ACTION_DROP:
                        mac_entry->mac_action = SWITCH_MAC_ACTION_DROP;
                        break;
                    case SAI_PACKET_ACTION_FORWARD:
                        mac_entry->mac_action = SWITCH_MAC_ACTION_FORWARD;
                        break;
                    default:
                        return;
                }
                break;
        }
    }
}

/*
* Routine Description:
*    Create FDB entry
*
* Arguments:
*    [in] fdb_entry - fdb entry
*    [in] attr_count - number of attributes
*    [in] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_create_fdb_entry(
        _In_ const sai_fdb_entry_t *fdb_entry,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list) {

    switch_api_mac_entry_t mac_entry;
    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    char entry_string[SAI_MAX_ENTRY_STRING_LEN];

    SAI_LOG_ENTER();

    if (!fdb_entry) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null fdb entry: %s",
                       sai_status_to_string(status));
        return status;
    }

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                      sai_status_to_string(status));
        return status;
    }

    memset(&mac_entry, 0, sizeof(mac_entry));
    sai_fdb_entry_parse(fdb_entry, &mac_entry);
    sai_fdb_entry_attribute_parse(attr_count, attr_list, &mac_entry);

    sai_fdb_entry_to_string(fdb_entry, entry_string);
    switch_status = switch_api_mac_table_entry_add(device, &mac_entry);
    status = sai_switch_status_to_sai_status(switch_status);

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to create fdb entry %s : %s",
                       entry_string,
                       sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Remove FDB entry
*
* Arguments:
*    [in] fdb_entry - fdb entry
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_remove_fdb_entry(
        _In_ const sai_fdb_entry_t *fdb_entry) {
    switch_api_mac_entry_t mac_entry;
    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    char entry_string[SAI_MAX_ENTRY_STRING_LEN];

    SAI_LOG_ENTER();

    if (!fdb_entry) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null fdb entry: %s",
                       sai_status_to_string(status));
        return status;
    }

    memset(&mac_entry, 0, sizeof(mac_entry));
    sai_fdb_entry_parse(fdb_entry, &mac_entry);

    sai_fdb_entry_to_string(fdb_entry, entry_string);

    switch_status = switch_api_mac_table_entry_delete(device, &mac_entry);
    status = sai_switch_status_to_sai_status(switch_status);

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to remove fdb entry %s : %s",
                       entry_string,
                       sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Set fdb entry attribute value
*
* Arguments:
*    [in] fdb_entry - fdb entry
*    [in] attr - attribute
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_set_fdb_entry_attribute(
        _In_ const sai_fdb_entry_t *fdb_entry,
        _In_ const sai_attribute_t *attr) {
    switch_api_mac_entry_t mac_entry;
    sai_status_t status = SAI_STATUS_SUCCESS;

    SAI_LOG_ENTER();

    if (!fdb_entry) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null fdb entry: %s",
                       sai_status_to_string(status));
        return status;
    }

    if (!attr) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute: %s",
                       sai_status_to_string(status));
        return status;
    }

    memset(&mac_entry, 0, sizeof(mac_entry));
    sai_fdb_entry_parse(fdb_entry, &mac_entry);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Get fdb entry attribute value
*
* Arguments:
*    [in] fdb_entry - fdb entry
*    [in] attr_count - number of attributes
*    [inout] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_get_fdb_entry_attribute(
        _In_ const sai_fdb_entry_t *fdb_entry,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list) {
    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    if (!fdb_entry) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null fdb entry: %s",
                       sai_status_to_string(status));
        return status;
    }

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                       sai_status_to_string(status));
        return status;
    }
    SAI_LOG_EXIT();
    return status;
}

/*
* Routine Description:
*    Remove all FDB entries by attribute set in sai_fdb_flush_attr
*
* Arguments:
*    [in] attr_count - number of attributes
*    [in] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_flush_fdb_entries(
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    const sai_attribute_t *attribute;
    uint32_t index = 0;
    sai_object_id_t port_id = 0;
    sai_vlan_id_t vlan_id = 0;
    bool flush_all = false;
    bool port_valid = false;
    bool vlan_valid = false;
    switch_handle_t vlan_handle = 0;
    sai_fdb_flush_entry_type_t entry_type = 0;
    sai_status_t status = SAI_STATUS_SUCCESS;

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                       sai_status_to_string(status));
        return status;
    }

    for (index = 0; index < attr_count; index++) {
        attribute = &attr_list[index];
        switch (attribute->id) {
            case SAI_FDB_FLUSH_ATTR_PORT_ID:
                port_id = attribute->value.oid;
                port_valid = true;
                break;
            case SAI_FDB_FLUSH_ATTR_VLAN_ID:
                vlan_id = attribute->value.u16;
                vlan_valid = true;
                break;
            case SAI_FDB_FLUSH_ATTR_ENTRY_TYPE:
                entry_type = attribute->value.u8;
                switch (entry_type) {
                    case SAI_FDB_FLUSH_ENTRY_DYNAMIC:
                    case SAI_FDB_FLUSH_ENTRY_STATIC:
                        break;
                }
                break;
        }
    }
    if (flush_all) {
        status = switch_api_mac_table_entries_delete_all(device);
    } else {
        if (port_valid && vlan_valid) {
            switch_api_vlan_id_to_handle_get(vlan_id, &vlan_handle);
            status = switch_api_mac_table_entries_delete_by_interface_vlan(
                device, (switch_handle_t)port_id, vlan_handle);
        } else if (port_valid) {
            status = switch_api_mac_table_entries_delete_by_interface(
                device, (switch_handle_t)port_id);
        } else if (vlan_valid) {
            switch_api_vlan_id_to_handle_get(vlan_id, &vlan_handle);
            status = switch_api_mac_table_entries_delete_by_vlan(device,
                                                                 vlan_handle);
        } else {
            status = SAI_STATUS_FAILURE;
        }
    }

    SAI_LOG_EXIT();

    return status;
}

/*
*  FDB methods table retrieved with sai_api_query()
*/
sai_fdb_api_t fdb_api = {
    .create_fdb_entry                  =             sai_create_fdb_entry,
    .remove_fdb_entry                  =             sai_remove_fdb_entry,
    .set_fdb_entry_attribute           =             sai_set_fdb_entry_attribute,
    .get_fdb_entry_attribute           =             sai_get_fdb_entry_attribute,
    .flush_fdb_entries                 =             sai_flush_fdb_entries
};

sai_status_t sai_fdb_initialize(sai_api_service_t *sai_api_service) {
    SAI_LOG_DEBUG("initializing fdb");
    sai_api_service->fdb_api = fdb_api;
    return SAI_STATUS_SUCCESS;
}
