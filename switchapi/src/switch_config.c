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
#include "switch_pd.h"
#include "switch_log.h"
#include "switch_lag_int.h"
#include "switch_nhop_int.h"
#include "switch_defines.h"
#include "switch_mirror_int.h"
#include "switch_tunnel_int.h"
#include "switch_config_int.h"
#include <string.h>

/* switch global configuration parameters */
static switch_config_param_t switch_config[SWITCH_MAX_DEVICE];

switch_config_param_t *
switch_config_params_get(switch_device_t device)
{
    return &switch_config[device];
}

void
switch_config_params_init (switch_device_t device)
{
    memset(switch_config_params_get(device), 0, sizeof(switch_config_param_t));
    /* Add default configuration parameters here */
    /* each config parameters becomes an action routine parameter so these are
     * limited
     */
    return;
}

void
switch_config_param_set_dod(switch_device_t device, bool dod)
{
    switch_config_params_get(device)->enable_dod = dod;
    return;
}


void
switch_config_action_populate(switch_device_t device,
                    p4_pd_dc_set_config_parameters_action_spec_t *action_sw_cfg)
{
    action_sw_cfg->action_enable_dod = switch_config_params_get(device)->enable_dod;
    /* Add more parameters here */
    return;
}

/* exported APIs */
switch_status_t
switch_api_set_deflect_on_drop(switch_device_t device, bool dod)
{
    switch_config_param_set_dod(device, dod);
    return  switch_pd_switch_config_params_update(device);
}
