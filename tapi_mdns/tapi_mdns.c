/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Discovering mDNS / DNS-SD services on an agent from a test
 *
 * The engine-side layer over the mdns_* RPCs: it asks the agent to
 * browse/resolve and parses the newline/tab record text into the
 * #tapi_mdns_service / #tapi_mdns_resolved shapes.
 */

#define TE_LGR_USER     "TAPI MDNS"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"
#include "logger_api.h"

#include "tapi_mdns.h"
#include "tapi_mdns_rpc.h"

/** The nth tab-separated field of @p line[0..len), or @c NULL. */
static char *
mdns_field(const char *line, size_t len, size_t idx)
{
    const char *p = line;
    const char *end = line + len;
    size_t i;

    for (i = 0; i < idx; i++)
    {
        const char *tab = memchr(p, '\t', (size_t)(end - p));

        if (tab == NULL)
            return NULL;
        p = tab + 1;
    }
    {
        const char *tab = memchr(p, '\t', (size_t)(end - p));
        size_t flen = tab != NULL ? (size_t)(tab - p) : (size_t)(end - p);

        return TE_STRNDUP(p, flen);
    }
}

/* See description in tapi_mdns.h */
te_errno
tapi_mdns_browse(rcf_rpc_server *rpcs, int seconds, te_vec *services)
{
    te_string raw = TE_STRING_INIT;
    const char *line;
    te_errno rc;

    *services = (te_vec)TE_VEC_INIT(tapi_mdns_service);

    rc = rpc_mdns_browse(rpcs, seconds, NULL, &raw);
    if (rc != 0)
    {
        te_string_free(&raw);
        return rc;
    }

    line = te_string_value(&raw);
    while (line != NULL && *line != '\0')
    {
        const char *nl = strchr(line, '\n');
        size_t len = nl != NULL ? (size_t)(nl - line) : strlen(line);

        if (len != 0)
        {
            tapi_mdns_service s;

            s.type = mdns_field(line, len, 0);
            s.name = mdns_field(line, len, 1);
            s.domain = mdns_field(line, len, 2);
            if (s.type != NULL)
                TE_VEC_APPEND(services, s);
            else
            {
                free(s.name);
                free(s.domain);
            }
        }
        line = nl != NULL ? nl + 1 : NULL;
    }

    te_string_free(&raw);

    return 0;
}

/* See description in tapi_mdns.h */
te_errno
tapi_mdns_resolve(rcf_rpc_server *rpcs, const char *type, const char *name,
                  const char *domain, tapi_mdns_resolved *resolved)
{
    te_string raw = TE_STRING_INIT;
    const char *line;
    size_t len;
    char *port;
    te_errno rc;

    memset(resolved, 0, sizeof(*resolved));

    rc = rpc_mdns_resolve(rpcs, type, name, domain, &raw);
    if (rc != 0)
    {
        te_string_free(&raw);
        return rc;
    }

    line = te_string_value(&raw);
    len = strcspn(line, "\n");
    if (len == 0)
    {
        te_string_free(&raw);
        return TE_RC(TE_TAPI, TE_ENODATA);
    }

    resolved->host = mdns_field(line, len, 0);
    resolved->address = mdns_field(line, len, 1);
    port = mdns_field(line, len, 2);
    resolved->port = port != NULL ? (int)strtol(port, NULL, 10) : 0;
    free(port);
    resolved->txt = mdns_field(line, len, 3);

    te_string_free(&raw);

    return 0;
}

/* See description in tapi_mdns.h */
te_errno
tapi_mdns_probe(rcf_rpc_server *rpcs, const char *query, int seconds,
                int *responders, int *records, te_string *detail)
{
    return rpc_mdns_probe(rpcs, query, seconds, responders, records, detail);
}

/* See description in tapi_mdns.h */
const tapi_mdns_service *
tapi_mdns_find(const te_vec *services, const char *type)
{
    const tapi_mdns_service *s;

    TE_VEC_FOREACH((te_vec *)services, s)
    {
        if (s->type != NULL && strcmp(s->type, type) == 0)
            return s;
    }

    return NULL;
}

/* See description in tapi_mdns.h */
void
tapi_mdns_resolved_free(tapi_mdns_resolved *resolved)
{
    free(resolved->host);
    free(resolved->address);
    free(resolved->txt);
    memset(resolved, 0, sizeof(*resolved));
}

/* See description in tapi_mdns.h */
void
tapi_mdns_services_free(te_vec *services)
{
    tapi_mdns_service *s;

    TE_VEC_FOREACH(services, s)
    {
        free(s->type);
        free(s->name);
        free(s->domain);
    }
    te_vec_free(services);
}
