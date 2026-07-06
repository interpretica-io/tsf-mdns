/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief mDNS TAPI: RPC client wrappers
 *
 * Client wrappers of the mdns_* RPCs, see mdns_rpc.x.m4. Tests use
 * tapi_mdns.h; these are the calls behind it, one per RPC.
 */

#ifndef __TAPI_MDNS_RPC_H__
#define __TAPI_MDNS_RPC_H__

#include "te_errno.h"
#include "te_string.h"
#include "rcf_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Browse services (raw record text). */
extern te_errno rpc_mdns_browse(rcf_rpc_server *rpcs, int seconds,
                                int *count, te_string *result);

/** Resolve one instance (raw record text). */
extern te_errno rpc_mdns_resolve(rcf_rpc_server *rpcs, const char *type,
                                 const char *name, const char *domain,
                                 te_string *result);

/** Send one raw mDNS query and measure the answer. */
extern te_errno rpc_mdns_probe(rcf_rpc_server *rpcs, const char *query,
                               int seconds, int *responders, int *records,
                               te_string *detail);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_MDNS_RPC_H__ */
