/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief mDNS TAPI: RPC client wrappers
 *
 * The rcf_rpc_call() boilerplate behind tapi_mdns. The RPCs return
 * te_errno; an RPC transport failure is mapped to TE_ECORRUPTED.
 */

#define TE_LGR_USER     "TAPI MDNS RPC"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "logger_api.h"
#include "tapi_rpc_internal.h"
#include "tarpc.h"

#include "tapi_mdns_rpc.h"

#define CHECK_RPC_ERRNO_UNCHANGED(_func, _var) \
    CHECK_RETVAL_VAR_ERR_COND(_func, _var, false,                    \
                              TE_RC(TE_TAPI, TE_ECORRUPTED), false)

static void
take_string(te_string *dst, const char *src)
{
    if (dst != NULL && src != NULL)
        te_string_append(dst, "%s", src);
}

/* See description in tapi_mdns_rpc.h */
te_errno
rpc_mdns_browse(rcf_rpc_server *rpcs, int seconds, int *count,
                te_string *result)
{
    tarpc_mdns_browse_in in;
    tarpc_mdns_browse_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.seconds = seconds;

    rcf_rpc_call(rpcs, "mdns_browse", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(mdns_browse, out.retval);
    TAPI_RPC_LOG(rpcs, mdns_browse, "%ds", "%r count=%d", seconds,
                 out.retval, out.count);

    if (out.retval == 0)
    {
        if (count != NULL)
            *count = out.count;
        take_string(result, out.result);
    }
    RETVAL_TE_ERRNO(mdns_browse, out.retval);
}

/* See description in tapi_mdns_rpc.h */
te_errno
rpc_mdns_resolve(rcf_rpc_server *rpcs, const char *type, const char *name,
                 const char *domain, te_string *result)
{
    tarpc_mdns_resolve_in in;
    tarpc_mdns_resolve_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.type = (char *)(type != NULL ? type : "");
    in.name = (char *)(name != NULL ? name : "");
    in.domain = (char *)(domain != NULL ? domain : "");

    rcf_rpc_call(rpcs, "mdns_resolve", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(mdns_resolve, out.retval);
    TAPI_RPC_LOG(rpcs, mdns_resolve, "%s/%s", "%r",
                 name != NULL ? name : "", type != NULL ? type : "",
                 out.retval);

    if (out.retval == 0)
        take_string(result, out.result);
    RETVAL_TE_ERRNO(mdns_resolve, out.retval);
}

/* See description in tapi_mdns_rpc.h */
te_errno
rpc_mdns_probe(rcf_rpc_server *rpcs, const char *query, int seconds,
               int *responders, int *records, te_string *detail)
{
    tarpc_mdns_probe_in in;
    tarpc_mdns_probe_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.query = (char *)(query != NULL ? query : "");
    in.seconds = seconds;

    rcf_rpc_call(rpcs, "mdns_probe", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(mdns_probe, out.retval);
    TAPI_RPC_LOG(rpcs, mdns_probe, "%s %ds", "%r resp=%d rec=%d",
                 query != NULL ? query : "(default)", seconds, out.retval,
                 out.responders, out.records);

    if (out.retval == 0)
    {
        if (responders != NULL)
            *responders = out.responders;
        if (records != NULL)
            *records = out.records;
        take_string(detail, out.detail);
    }
    RETVAL_TE_ERRNO(mdns_probe, out.retval);
}
