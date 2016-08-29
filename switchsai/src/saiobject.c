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
