/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.

 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 * $Id: $
 *
 ******************************************************************************/
#ifndef _switch_pd_types_h_
#define _switch_pd_types_h_

#ifdef BMV2
#include "bmpd/switch/pd/pd.h"
#include "bm/pdfixed/pd_pre.h"
#else
#include "p4_sim/pd.h"
#include "p4_sim/pd_pre.h"
#endif /* BMV2 */

typedef uint16_t switch_pd_pool_id_t;
typedef uint16_t switch_tm_ppg_hdl_t;

#endif /* _switch_pd_types_h_ */
