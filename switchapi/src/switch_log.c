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

#include "p4features.h"
#include "switch_log_int.h"
#include <stdarg.h>
#include <stdio.h>

switch_api_log_fn_t *switch_api_client_log_fn = NULL;
switch_api_log_level_t switch_api_default_log_level = SWITCH_API_LOG_INFO;

char *switch_print_error(switch_status_t status) {
  switch (status) {
    case SWITCH_STATUS_INVALID_HANDLE:
      return "err: invalid handle";
      break;
    case SWITCH_STATUS_ITEM_NOT_FOUND:
      return "err: entry not found";
      break;
    case SWITCH_STATUS_FAILURE:
      return "err: general failure";
      break;
    default:
      return "err: unknown failure";
      break;
  }
}

int switch_default_logger(switch_api_log_level_t level, char *fmt, ...) {
  va_list args;

  if ((switch_api_default_log_level == SWITCH_API_LOG_NONE) ||
      (level > switch_api_default_log_level)) {
    return 0;
  }
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);

  return 1;
}

void switch_api_log_function_set(switch_api_log_fn_t *log_fn) {
  switch_api_client_log_fn = log_fn;
}

void switch_log_init() {
  switch_api_default_log_level = SWITCH_API_LOG_INFO;
  switch_api_client_log_fn = switch_default_logger;
}
