#include <saihash.h>
#include <saistatus.h>

#include "saiinternal.h"

// Unused for now
/* static sai_api_t api_id = SAI_API_HASH; */

sai_status_t sai_create_hash(_Out_ sai_object_id_t *hash_id,
                             _In_ uint32_t attr_count,
                             _In_ const sai_attribute_t *attr_list) {
  return SAI_STATUS_SUCCESS;
}

sai_status_t sai_remove_hash(_In_ sai_object_id_t hash_id) {
  return SAI_STATUS_SUCCESS;
}

sai_status_t sai_set_hash_attribute(_In_ sai_object_id_t hash_id,
                                    _In_ const sai_attribute_t *attr) {
  return SAI_STATUS_SUCCESS;
}

sai_status_t sai_get_hash_attribute(_In_ sai_object_id_t hash_id,
                                    _In_ uint32_t attr_count,
                                    _Inout_ sai_attribute_t *attr_list) {
  return SAI_STATUS_SUCCESS;
}

sai_hash_api_t hash_api = {
    .create_hash = sai_create_hash,
    .remove_hash = sai_remove_hash,
    .set_hash_attribute = sai_set_hash_attribute,
    .get_hash_attribute = sai_get_hash_attribute,
};

sai_status_t sai_hash_initialize(sai_api_service_t *sai_api_service) {
  sai_api_service->hash_api = hash_api;
  return SAI_STATUS_SUCCESS;
}
