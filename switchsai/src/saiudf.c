#include <saiudf.h>
#include <saistatus.h>
#include <sai.h>

#include "saiinternal.h"

static sai_api_t api_id = SAI_API_UDF;

sai_status_t sai_create_udf(
    _Out_ sai_object_id_t* udf_id,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_remove_udf(
    _In_ sai_object_id_t udf_id
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_set_udf_attribute(
    _In_ sai_object_id_t udf_id,
    _In_ const sai_attribute_t *attr
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_get_udf_attribute(
    _In_ sai_object_id_t udf_id,
    _In_ uint32_t attr_count,
    _Inout_ sai_attribute_t *attr_list
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_create_udf_match(
    _Out_ sai_object_id_t* udf_match_id,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_remove_udf_match(
    _In_ sai_object_id_t udf_match_id
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_set_udf_match_attribute(
    _In_ sai_object_id_t udf_match_id,
    _In_ const sai_attribute_t *attr
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_get_udf_match_attribute(
    _In_ sai_object_id_t udf_match_id,
    _In_ uint32_t attr_count,
    _Inout_ sai_attribute_t *attr_list
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_create_udf_group(
    _Out_ sai_object_id_t* udf_group_id,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_remove_udf_group(
    _In_ sai_object_id_t udf_group_id
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_set_udf_group_attribute(
    _In_ sai_object_id_t udf_group_id,
    _In_ const sai_attribute_t *attr
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_get_udf_group_attribute(
    _In_ sai_object_id_t udf_group_id,
    _In_ uint32_t attr_count,
    _Inout_ sai_attribute_t *attr_list
    ) {
    return SAI_STATUS_SUCCESS;
}

sai_udf_api_t udf_api = {
    .create_udf              = sai_create_udf,
    .remove_udf              = sai_remove_udf,
    .set_udf_attribute       = sai_set_udf_attribute,
    .get_udf_attribute       = sai_get_udf_attribute,
    .create_udf_match        = sai_create_udf_match,
    .remove_udf_match        = sai_remove_udf_match,
    .set_udf_match_attribute = sai_set_udf_match_attribute,
    .get_udf_match_attribute = sai_get_udf_match_attribute,
    .create_udf_group        = sai_create_udf_group,
    .remove_udf_group        = sai_remove_udf_group,
    .set_udf_group_attribute = sai_set_udf_group_attribute,
    .get_udf_group_attribute = sai_get_udf_group_attribute,
};

sai_status_t sai_udf_initialize(sai_api_service_t *sai_api_service) {
    sai_api_service->udf_api = udf_api;
    return SAI_STATUS_SUCCESS;
}

