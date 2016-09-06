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
#ifndef _switch_pd_types_h_
#define _switch_pd_types_h_

#ifdef BMV2
#include "bmpd/switch/pd/pd.h"
#include "bm/pdfixed/pd_pre.h"
#include "bm/pdfixed/pd_mirroring.h"
#else
#include "p4_sim/pd.h"
#include "p4_sim/pd_pre.h"
#include "p4_sim/mirroring.h"
#endif /* BMV2 */

typedef uint16_t switch_pd_pool_id_t;
typedef uint16_t switch_tm_ppg_hdl_t;

#endif /* _switch_pd_types_h_ */
