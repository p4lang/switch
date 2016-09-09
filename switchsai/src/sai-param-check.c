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

/*
 sai-param-check.c
*/

/*
Each function has the following attribute parameter check rule
--------------------------------------------------------------
1. Create:
    Mandatory attribute list
    Possible attribute list
    For each attribute:
        Type:
            RW, RO, WO
        Default Specified
            Boolean
            Value
        Range Specified
            Boolean
            Min, Max

2. Set: (some attributes can only be set @ create)
    Possible attribute list
    For each attribute:
        Type:
            RW, WO
        Range Specified
            Boolean
            Min, Max

3. Get:
    Possible attribute list
    For each attribute:
        Type:
            RW, RO
        Range Specified
            Boolean
            Min, Max

4. Destroy/Delete:
    No applicable parameter check
*/

#include "sai.h"
#include "saiinternal.h"

typedef enum {
  SAI_ATTRIBUTE_PARAM_API_TYPE_MIN,
  SAI_ATTRIBUTE_PARAM_API_TYPE_CREATE = SAI_ATTRIBUTE_PARAM_API_TYPE_MIN,
  SAI_ATTRIBUTE_PARAM_API_TYPE_SET,
  SAI_ATTRIBUTE_PARAM_API_TYPE_GET,
  SAI_ATTRIBUTE_PARAM_API_TYPE_MAX
} sai_attribute_param_api_type_t;

typedef enum {
  SAI_ATTRIBUTE_PARAM_TYPE_MIN,
  SAI_ATTRIBUTE_PARAM_TYPE_RW = SAI_ATTRIBUTE_PARAM_TYPE_MIN,
  SAI_ATTRIBUTE_PARAM_TYPE_RO,
  SAI_ATTRIBUTE_PARAM_TYPE_WO,
  SAI_ATTRIBUTE_PARAM_TYPE_MAX
} sai_attribute_param_type_e;

typedef struct sat_attribute_param_type_s sat_attribute_param_type_t;

struct sai_attribute_param_default_s {
  bool enable;
  sai_attr_id_t id;
  sai_attribute_value_t value;
};

typedef struct sai_attribute_param_default_s sai_attribute_param_default_t;

struct sai_attribute_param_range_s {
  bool enable;
  sai_attr_id_t id;
  sai_attribute_value_t min, max;
};

typedef struct sai_attribute_param_range_s sai_attribute_param_range_t;

struct sai_attribute_param_create_s {
  sai_attribute_param_type_e type;
  sai_attribute_param_default_t def;
  sai_attribute_param_range_t range;
};

typedef struct sai_attribute_param_create_s sai_attribute_param_create_t;

struct sai_attribute_param_set_s {
  sai_attribute_param_type_e type;
  sai_attribute_param_range_t range;
};

typedef struct sai_attribute_param_set_s sai_attribute_param_set_t;

typedef struct {
  tommy_node node;
  union {
    sai_attr_id_t id;
    sai_attribute_param_create_t create;
    sai_attribute_param_set_t set;
  } u;
} sai_attribute_param_desc_t;

/*
    create functions
*/
struct sai_attribute_param_check_create_s {
  unsigned int mandatory_count;
  //    sai_attr_id_t *mandatory_list;
  tommy_list mandatory_list;
  unsigned int possible_count;
  //    sai_attribute_param_create_t *possible_list;
  tommy_list possible_list;
};

typedef struct sai_attribute_param_check_create_s
    sai_attribute_param_check_create_t;

/*
    set functions
*/
struct sai_attribute_param_check_set_s {
  unsigned int possible_count;
  //    sai_attribute_param_create_t *possible_list;
  tommy_list possible_list;
};

typedef struct sai_attribute_param_check_set_s sai_attribute_param_check_set_t;

typedef struct {
  tommy_node node;
  int api;
  sai_attribute_param_check_create_t create;
  sai_attribute_param_check_set_t set;
} sai_attribute_param_t;

sai_attribute_param_t sai_param_validation[SAI_API_MAX];

int sai_param_check_init(void) {
  for (unsigned int i = 0; i < SAI_API_MAX; i++) {
    // init
    memset(&sai_param_validation[i], 0, sizeof(sai_attribute_param_t));
    sai_param_validation[i].api = i;
    tommy_list_init(&(sai_param_validation[i].create.mandatory_list));
    tommy_list_init(&(sai_param_validation[i].create.possible_list));
    tommy_list_init(&(sai_param_validation[i].set.possible_list));
  }
  return 0;
}

int sai_param_check_insert(int api,
                           sai_attribute_param_api_type_t api_type,
                           sai_attr_id_t id,
                           sai_attribute_value_t *def,
                           sai_attribute_value_t *min,
                           sai_attribute_value_t *max,
                           sai_attribute_param_type_e type,
                           bool mandatory) {
  sai_attribute_param_desc_t *p = NULL;
  // create a tommy node to hold the values
  p = switch_malloc(sizeof(*p), 1);
  if (p) {
    memset(p, 0, sizeof(*p));
    if (api_type == SAI_ATTRIBUTE_PARAM_API_TYPE_CREATE) {
      if (def) {
        // default value extract
        p->u.create.type = type;
        p->u.create.def.id = id;
        p->u.create.def.value = *def;
        p->u.create.def.enable = TRUE;
      } else if (mandatory) {
        p->u.id = id;
      }
      if (min || max) {
        // range is valid
        // set the defaults to ignore min & max?
        if (min) {
          p->u.create.range.min = *min;
        }
        if (max) {
          p->u.create.range.min = *max;
        }
        p->u.create.range.id = id;
        p->u.create.type = type;
        p->u.create.range.enable = TRUE;
      }
      // insert into list
      if (mandatory) {
        tommy_list_insert_tail(
            &(sai_param_validation[api].create.mandatory_list), &(p->node), p);
      } else {
        tommy_list_insert_tail(
            &(sai_param_validation[api].create.possible_list), &(p->node), p);
      }
    } else if (api_type == SAI_ATTRIBUTE_PARAM_API_TYPE_SET) {
    }
  }
  return 0;
}

int sai_param_check(int api,
                    sai_attribute_param_api_type_t api_type,
                    unsigned int attr_count,
                    sai_attribute_t *attr_list) {
  return 0;
}

typedef enum sai_param_rw_type_ {
  SAI_ATTRIBUTE_RW_NONE = 0,
  SAI_ATTRIBUTE_RW_READ_ONLY = 1,
  SAI_ATTRIBUTE_RW_READ_WRITE = 2,
  SAI_ATTRIBUTE_RW_WRITE_ONLY = 3
} sai_param_rw_type_t;

typedef enum sai_param_data_type_ {
  SAI_ATTRIBUTE_DATA_TYPE_NONE = 0,
  SAI_ATTRIBUTE_DATA_TYPE_BOOL = 1,
  SAI_ATTRIBUTE_DATA_TYPE_CHAR = 2,
  SAI_ATTRIBUTE_DATA_TYPE_U8 = 3,
  SAI_ATTRIBUTE_DATA_TYPE_S8 = 4,
  SAI_ATTRIBUTE_DATA_TYPE_U16 = 5,
  SAI_ATTRIBUTE_DATA_TYPE_S16 = 6,
  SAI_ATTRIBUTE_DATA_TYPE_U32 = 7,
  SAI_ATTRIBUTE_DATA_TYPE_S32 = 8,
  SAI_ATTRIBUTE_DATA_TYPE_U64 = 9,
  SAI_ATTRIBUTE_DATA_TYPE_S64 = 10,
  SAI_ATTRIBUTE_DATA_TYPE_MAC = 11,
  SAI_ATTRIBUTE_DATA_TYPE_IP4 = 12,
  SAI_ATTRIBUTE_DATA_TYPE_IP6 = 13,
  SAI_ATTRIBUTE_DATA_TYPE_IP_ADDRESS = 14,
  SAI_ATTRIBUTE_DATA_TYPE_OID = 15,
  SAI_ATTRIBUTE_DATA_TYPE_OID_LIST = 16,
  SAI_ATTRIBUTE_DATA_TYPE_U32_LIST = 17,
  SAI_ATTRIBUTE_DATA_TYPE_S32_LIST = 18,
  SAI_ATTRIBUTE_DATA_TYPE_U32_RANGE = 19,
  SAI_ATTRIBUTE_DATA_TYPE_S32_RANGE = 20,
  SAI_ATTRIBUTE_DATA_TYPE_VLAN_LIST = 21,
  SAI_ATTRIBUTE_DATA_TYPE_VLAN_PORT_LIST = 22,
  SAI_ATTRIBUTE_DATA_TYPE_ACL_FIELD = 23,
  SAI_ATTRIBUTE_DATA_TYPE_ACL_ACTION = 24,
  SAI_ATTRIBUTE_DATA_TYPE_PORT_BREAKOUT = 25
} sai_param_data_type_t;

typedef struct sai_param_attribute_ {
  tommy_node node;
  sai_attr_id_t id;
  bool mandatory;
  bool create;
  bool set;
  bool get;
  sai_param_data_type_t data_type;
  sai_param_rw_type_t rw_type;
  sai_attribute_value_t default_value;
} sai_param_attribute_t;

typedef struct sai_param_attribute_info_ {
  tommy_node node;
  char attribute_desc[20];
  bool match_one;
  tommy_list attribute_list;
} sai_param_attribute_info_t;

typedef struct sai_param_module_info_ {
  char module_name[20];
  tommy_list attribute_info_list;
} sai_param_module_info_t;

sai_param_module_info_t param_module_info[SAI_API_MAX];

static char *sai_param_json_file_get(sai_api_id_t api_id) {
  switch (api_id) {
    case SAI_API_SWITCH:
      return "saiswitch.json" case SAI_API_PORT
          : return "saiport.json" case SAI_API_FDB
            : return "saifdb.json" case SAI_API_VLAN
              : return "saivlan.json" case SAI_API_VIRTUAL_ROUTER
                : return "sairouter.json" case SAI_API_ROUTE
                  : return "sairoute.json" case SAI_API_NEXT_HOP
                    : return "sainextop.json" case SAI_API_NEXT_HOP_GROUP
                      : return "sainexthopgroup."
                               "json" case SAI_API_ROUTER_INTERFACE
                        : return "sairouterinterface.json" case SAI_API_NEIGHBOR
                          : return "saineighbor.json" case SAI_API_ACL
                            : return "saiacl.json" case SAI_API_HOST_INTERFACE
                              : return "saihostintf.json" case SAI_API_MIRROR
                                : return "saimirror.json" case SAI_API_STP
                                  : return "saistp.json" case SAI_API_LAG
                                    : return "sailag.json" default
                                      : return NULL;
  }
}

static sai_param_rw_type_t sai_param_rw_type_get(_In_ char *rw_type) {
  if (!strcmp(rw_type, "READ_ONLY")) {
    return SAI_ATTRIBUTE_RW_READ_ONLY;
  } else if (!strcmp(rw_type, "READ_WRITE")) {
    return SAI_ATTRIBUTE_RW_READ_WRITE;
  } else if (!strcmp(rw_type, "WRITE_ONLY")) {
    return SAI_ATTRIBUTE_RW_WRITE_ONLY;
  } else {
    return SAI_ATTRIBUTE_RW_TYPE_NONE;
  }

  static sai_param_data_type_t sai_param_data_type_get(_In_ char *data_type) {
    if (!strcmp(data_type, "bool")) {
      return SAI_ATTRIBUTE_DATA_TYPE_BOOL;
    } else if (!strcmp(data_type, "chardata")) {
      return SAI_ATTRIBUTE_DATA_TYPE_CHAR;
    } else if (!strcmp(data_type, "u8")) {
      return SAI_ATTRIBUTE_DATA_TYPE_U8;
    } else if (!strcmp(data_type, "s8")) {
      return SAI_ATTRIBUTE_DATA_TYPE_S8;
    } else if (!strcmp(data_type, "u16")) {
      return SAI_ATTRIBUTE_DATA_TYPE_U16;
    } else if (!strcmp(data_type, "s16")) {
      return SAI_ATTRIBUTE_DATA_TYPE_S16;
    } else if (!strcmp(data_type, "u32")) {
      return SAI_ATTRIBUTE_DATA_TYPE_U32;
    } else if (!strcmp(data_type, "s32")) {
      return SAI_ATTRIBUTE_DATA_TYPE_S32;
    } else if (!strcmp(data_type, "u64")) {
      return SAI_ATTRIBUTE_DATA_TYPE_U64;
    } else if (!strcmp(data_type, "s64")) {
      return SAI_ATTRIBUTE_DATA_TYPE_S64;
    } else if (!strcmp(data_type, "mac")) {
      return SAI_ATTRIBUTE_DATA_TYPE_MAC;
    } else if (!strcmp(data_type, "ip4")) {
      return SAI_ATTRIBUTE_DATA_TYPE_IP4;
    } else if (!strcmp(data_type, "ip6")) {
      return SAI_ATTRIBUTE_DATA_TYPE_IP6;
    } else if (!strcmp(data_type, "ip_address")) {
      return SAI_ATTRIBUTE_DATA_TYPE_IP_ADDRESS;
    } else if (!strcmp(data_type, "oid")) {
      return SAI_ATTRIBUTE_DATA_TYPE_OID;
    } else if (!strcmp(data_type, "oid_list")) {
      return SAI_ATTRIBUTE_DATA_TYPE_OID_LIST;
    } else if (!strcmp(data_type, "u32_list")) {
      return SAI_ATTRIBUTE_DATA_TYPE_U32_LIST;
    } else if (!strcmp(data_type, "s32_list")) {
      return SAI_ATTRIBUTE_DATA_TYPE_S32_LIST;
    } else if (!strcmp(data_type, "u32_range")) {
      return SAI_ATTRIBUTE_DATA_TYPE_U32_RANGE;
    } else if (!strcmp(data_type, "s32_range")) {
      return SAI_ATTRIBUTE_DATA_TYPE_S32_RANGE;
    } else if (!strcmp(data_type, "vlan_list")) {
      return SAI_ATTRIBUTE_DATA_TYPE_VLAN_LIST;
    } else if (!strcmp(data_type, "vlan_port_list")) {
      return SAI_ATTRIBUTE_DATA_TYPE_VLAN_PORT_LIST;
    } else if (!strcmp(data_type, "acl_field")) {
      return SAI_ATTRIBUTE_DATA_TYPE_ACL_FIELD;
    } else if (!strcmp(data_type, "acl_action")) {
      return SAI_ATTRIBUTE_DATA_TYPE_ACL_ACTION;
    } else if (!strcmp(data_type, "port_breakout")) {
      return SAI_ATTRIBUTE_DATA_TYPE_PORT_BREAKOUT;
    } else {
      return SAI_ATTRIBUTE_DATA_TYPE_NONE;
    }

    sai_status_t sai_param_parse_attributes(
        _In_ cJSON * attr_object _In_ sai_param_attribute_info_t * attr_info) {
      sai_param_attribute_t *attr = NULL;

      while (attr_object) {
        attr = SAI_MALLOC(sizeof(sai_param_attribute_t));
        if (!attr) {
          return SAI_STATUS_NO_MEMORY;
        }
        attr->mandatory = FALSE;
        attr->create = FALSE;
        attr->set = FALSE;
        attr->get = FALSE;
        if (!strcmp(attr_object->string, "name")) {
          // convert string to enum
        } else if (!strcmp(attr_object->string, "mandatory")) {
          if (!strcmp(attr_object->valueString, "true")) {
            attr->mandatory = TRUE;
          }
        } else if (!strcmp(attr_object->string, "create")) {
          if (!strcmp(attr_object->valueString, "true")) {
            attr->create = TRUE;
          }
        } else if (!strcmp(attr_object->string, "set")) {
          if (!strcmp(attr_object->valueString, "true")) {
            attr->set = TRUE;
          }
        } else if (!strcmp(attr_object->string, "get")) {
          if (!strcmp(attr_object->valueString, "true")) {
            attr->get = TRUE;
          }
        } else if (!strcmp(attr_object->string, "rw_type")) {
          attr->rw_type = sai_param_rw_type_get(attr_object->valueString);
        } else if (!strcmp(attr_object->string, "data_type")) {
          attr->data_type = sai_param_data_type_get(attr_object->valueString);
        }
        tommy_list_insert_tail(
            &(attr_info->attributes_list), &(attr->node), attr);
        attr_object = attr_object->next;
      }
    }

    sai_status_t sai_param_parse_atttibute_info(
        _In_ cJSON * attributes_object,
        _Out_ sai_param_module_info_t * module_info) {
      sai_param_attribute_info_t *attr_info = NULL;
      cJSON *attr_info_object = NULL;

      while (attributes_object) {
        attr_info = SAI_MALLOC(sizeof(sai_param_attribute_info_t));
        if (!attr_info) {
          return SAI_STATUS_NO_MEMORY;
        }

        tommy_list_init(&(attr_info->attributes_list));
        attr_info_object = attributes_object->child;
        while (attr_info_object) {
          if (attr_info_object->type == cJSON_String) {
            if (!strcmp(attr_info_object->string, "attribute_desc")) {
              strcpy(attr_info->attribute_desc, attr_info_object->valueString);
            } else if (!strcmp(attr_info_object->string, "match_one")) {
              attr_info->match_one = TRUE;
            }
          } else if (attr_info_object->type == cJSON_Object) {
            if (!strcmp(attr_info_object->string, "attribute_list")) {
              status = sai_param_parse_attributes(attr_info_object->child,
                                                  attr_info);
              if (status != SAI_STATUS_SUCCESS) {
                SAI_FREE(attr_info);
                return status;
              }
            }
          }
          attr_info_object = attr_info_object->next;
        }
        tommy_list_insert_tail(
            &(module_info->attribute_info_list), &(attr_info->node), attr_info);
        attributes_object = attributes_object->next;
      }
      return SAI_STATUS_SUCCESS;
    }

    sai_status_t sai_param_parse_json(_In_ sai_api_id_t api_id,
                                      _In_ char *file_name) {
      cJSON *module_object = NULL;
      cJSON *attr_info_object = NULL;
      cJSON *attr_object = NULL;
      sai_param_module_info_t *module_info = NULL;
      sai_param_atribute_info_t *attr_info = NULL;
      sai_param_attribute_t *attr = NULL;

      object = cJSON_Parse(file_name);
      module_info = param_module_info[api_id];
      tommy_list_init(&(module_info->attribute_info_list));

      while (module_object) {
        if (module_object->type == cJSON_String) {
          if (!strcmp(module_object->string, "module_info")) {
            strcpy(module_info->module_name, module_object->valueString);
          }
        } else if (module_object->type == cJSON_Object) {
          if (!strcmp(module_object->string, "attributes")) {
            sai_param_parse_attribute_info(module_object->child, module_info);
          }
        }
        module_object = module_object->next;
      }
    }

    sai_status_t sai_param_load_modules_json() {
      sai_api_id_t api_id;
      char *filename = NULL;

      for (api_id = 0; api_id < SAI_API_MAX; api_id++) {
        filename = sai_param_json_file_get(api_id);
        if (file_name) {
          status = sai_param_parse_json(api_id, filename);
          if (status != SAI_STATUS_SUCCESS) {
            SAI_LOG_ERROR("failed to load json");
          }
        }
      }
    }
