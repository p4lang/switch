#include <saiobject.h>
#include <saistatus.h>

sai_status_t sai_get_maximum_attribute_count(_In_ sai_object_type_t object_type,
                                             _Inout_ uint32_t *count) {
  return SAI_STATUS_SUCCESS;
}

sai_status_t sai_get_object_count(_In_ sai_object_type_t object_type,
                                  _Inout_ uint32_t *count) {
  return SAI_STATUS_SUCCESS;
}

sai_status_t sai_get_object_key(_In_ sai_object_type_t object_type,
                                _In_ uint32_t object_count,
                                _Inout_ sai_object_key_t *object_list) {
  return SAI_STATUS_SUCCESS;
}

sai_status_t sai_bulk_get_attribute(_In_ sai_object_type_t object_type,
                                    _In_ uint32_t object_count,
                                    _In_ sai_object_key_t *object_key,
                                    _Inout_ uint32_t *attr_count,
                                    _Inout_ sai_attribute_t **attrs,
                                    _Inout_ sai_status_t *object_statuses) {
  return SAI_STATUS_SUCCESS;
}
