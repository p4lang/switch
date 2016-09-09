/*
Copyright 2016-present Barefoot Networks, Inc.

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
#ifndef _SWITCH_LOG_H_
#define _SWITCH_LOG_H_

#include "p4features.h"
#include "switch_status.h"

typedef enum switch_api_log_levels_ {
  SWITCH_API_LOG_NONE = 0,
  SWITCH_API_LOG_ERROR,
  SWITCH_API_LOG_WARN,
  SWITCH_API_LOG_INFO,
  SWITCH_API_LOG_VERBOSE,
  SWITCH_API_LOG_TRACE,
} switch_api_log_level_t;

typedef int(switch_api_log_fn_t)(switch_api_log_level_t level, char *fmt, ...);
void switch_api_log_function_set(switch_api_log_fn_t *log_fn);

#endif /* _SWITCH_LOG_H_ */
