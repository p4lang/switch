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

#ifndef _switch_config_int_
#define _switch_config_int_

/* Global configuration parameters for a switch */
typedef struct switch_config_param_ {
    bool    enable_dod;         /* Enable Deflect-on-drop feature */
    /* Add more global information - such as switch-id etc in future */
} switch_config_param_t;

switch_config_param_t *
switch_config_params_get (switch_device_t device);
void
switch_config_params_init (switch_device_t device);
void
switch_config_action_populate(switch_device_t device,
                    p4_pd_dc_set_config_parameters_action_spec_t *action_sw_cfg);
#endif // _switch_config_int_
