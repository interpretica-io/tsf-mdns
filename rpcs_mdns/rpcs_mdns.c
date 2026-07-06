/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief mDNS RPC server library
 *
 * The mdns_* RPCs (see mdns_rpc.x.m4) on top of ta_mdns.
 * TARPC_FUNC_STATIC() binds an RPC to the function of the same name,
 * so each RPC has a plain C function first and the wrapper after it.
 */

#define TE_LGR_USER     "RPC MDNS"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "rpc_server.h"

#include "ta_mdns.h"

/* Hand a te_string result over to an RPC string field (never NULL). */
static char *
take(te_string *str)
{
    return str->ptr != NULL ? str->ptr : TE_STRDUP("");
}

static te_errno
mdns_browse(int seconds, int *count, char **result)
{
    te_string r = TE_STRING_INIT;
    te_errno rc = ta_mdns_browse(seconds, count, &r);

    *result = take(&r);
    return rc;
}

TARPC_FUNC_STATIC(mdns_browse, {},
{
    int count = 0;

    MAKE_CALL(out->retval = func(in->seconds, &count, &out->result));
    out->count = count;
    out->common.errno_changed = false;
})

static te_errno
mdns_resolve(const char *type, const char *name, const char *domain,
             char **result)
{
    te_string r = TE_STRING_INIT;
    te_errno rc = ta_mdns_resolve(type, name, domain, &r);

    *result = take(&r);
    return rc;
}

TARPC_FUNC_STATIC(mdns_resolve, {},
{
    MAKE_CALL(out->retval = func(in->type, in->name, in->domain,
                                 &out->result));
    out->common.errno_changed = false;
})

static te_errno
mdns_probe(const char *query, int seconds, int *responders, int *records,
           char **detail)
{
    te_string d = TE_STRING_INIT;
    te_errno rc = ta_mdns_probe(query, seconds, responders, records, &d);

    *detail = take(&d);
    return rc;
}

TARPC_FUNC_STATIC(mdns_probe, {},
{
    int responders = 0;
    int records = 0;

    MAKE_CALL(out->retval = func(in->query, in->seconds, &responders,
                                 &records, &out->detail));
    out->responders = responders;
    out->records = records;
    out->common.errno_changed = false;
})
