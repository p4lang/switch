#include <saibuffer.h>
#include <saistatus.h>
#include "saiinternal.h"

// Unused for now
/* static sai_api_t api_id = SAI_API_BUFFERS; */

sai_status_t sai_create_buffer_pool(
    _Out_ sai_object_id_t* pool_id,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_remove_buffer_pool(
    _In_ sai_object_id_t pool_id
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_set_buffer_pool_attr(
    _In_ sai_object_id_t pool_id,
    _In_ const sai_attribute_t *attr
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_get_buffer_pool_attr(
    _In_ sai_object_id_t pool_id,
    _In_ uint32_t attr_count,
    _Inout_ sai_attribute_t *attr_list
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_set_ingress_priority_group_attr(
    _In_ sai_object_id_t ingress_pg_id,
    _In_ const sai_attribute_t *attr
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_get_ingress_priority_group_attr(
    _In_ sai_object_id_t ingress_pg_id,
    _In_ uint32_t attr_count,
    _Inout_ sai_attribute_t *attr_list
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_create_buffer_profile(
    _Out_ sai_object_id_t* buffer_profile_id,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_remove_buffer_profile(
    _In_ sai_object_id_t buffer_profile_id
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_set_buffer_profile_attr(
    _In_ sai_object_id_t buffer_profile_id,
    _In_ const sai_attribute_t *attr
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_get_buffer_profile_attr(
    _In_ sai_object_id_t buffer_profile_id,
    _In_ uint32_t attr_count,
    _Inout_ sai_attribute_t *attr_list
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_buffer_api_t buffer_api = {
    .create_buffer_pool              = sai_create_buffer_pool,
    .remove_buffer_pool              = sai_remove_buffer_pool,
    .set_buffer_pool_attr            = sai_set_buffer_pool_attr,
    .get_buffer_pool_attr            = sai_get_buffer_pool_attr,
    .set_ingress_priority_group_attr = sai_set_ingress_priority_group_attr,
    .get_ingress_priority_group_attr = sai_get_ingress_priority_group_attr,
    .create_buffer_profile           = sai_create_buffer_profile,
    .remove_buffer_profile           = sai_remove_buffer_profile,
    .set_buffer_profile_attr         = sai_set_buffer_profile_attr,
    .get_buffer_profile_attr         = sai_get_buffer_profile_attr
};

sai_status_t sai_buffer_initialize(sai_api_service_t *sai_api_service) {
    sai_api_service->buffer_api = buffer_api;
    return SAI_STATUS_SUCCESS;
}
