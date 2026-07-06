/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Discovering mDNS / DNS-SD services on an agent from a test
 *
 * @defgroup tapi_mdns mDNS / DNS-SD (tapi_mdns)
 * @{
 *
 * What the agent's link-local network advertises over mDNS / DNS-SD
 * (RFC 6762 / 6763), read in the agent's RPC server over avahi-client,
 * plus a daemon-less raw mDNS probe. Read-only.
 *
 * - tapi_mdns_browse() snapshots the advertised service instances;
 * - tapi_mdns_resolve() turns one into a host, address, port and TXT;
 * - tapi_mdns_probe() sends one raw mDNS query and measures the answer;
 * - @ref tapi_mdns_audit (tapi_mdns_audit.h) reads what is advertised
 *   as a light security posture through tsf-cybersec.
 */

#ifndef __TAPI_MDNS_H__
#define __TAPI_MDNS_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "rcf_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** One advertised service instance. */
typedef struct tapi_mdns_service {
    /** Service type, e.g. @c "_http._tcp". */
    char *type;
    /** Instance name. */
    char *name;
    /** Domain, usually @c "local". */
    char *domain;
} tapi_mdns_service;

/** A resolved instance. */
typedef struct tapi_mdns_resolved {
    /** Host name. */
    char *host;
    /** Address, as the agent printed it. */
    char *address;
    /** Port. */
    int port;
    /** TXT records, as @c "key=val;key=val;" (empty when none). */
    char *txt;
} tapi_mdns_resolved;

/**
 * Snapshot the services advertised on the agent's link.
 *
 * @param[in]  rpcs     RPC server on the agent.
 * @param[in]  seconds  How long to collect.
 * @param[out] services Vector of #tapi_mdns_service; release with
 *                      tapi_mdns_services_free().
 *
 * @return Status code.
 */
extern te_errno tapi_mdns_browse(rcf_rpc_server *rpcs, int seconds,
                                 te_vec *services);

/**
 * Resolve one service instance.
 *
 * @param[in]  rpcs     RPC server on the agent.
 * @param[in]  type     Service type.
 * @param[in]  name     Instance name.
 * @param[in]  domain   Domain, or @c NULL for @c "local".
 * @param[out] resolved Filled in; release with tapi_mdns_resolved_free().
 *
 * @return Status code.
 */
extern te_errno tapi_mdns_resolve(rcf_rpc_server *rpcs, const char *type,
                                  const char *name, const char *domain,
                                  tapi_mdns_resolved *resolved);

/**
 * Send one raw mDNS query from the agent and measure the answer.
 *
 * @param[in]  rpcs         RPC server on the agent.
 * @param[in]  query        Name to query, or @c NULL for the DNS-SD
 *                          service enumeration name.
 * @param[in]  seconds      How long to collect answers.
 * @param[out] responders   Distinct responders, or @c NULL.
 * @param[out] records      Total answer records, or @c NULL.
 * @param[out] detail       One @c "address\\tbytes" line per responder,
 *                          or @c NULL.
 *
 * @return Status code.
 */
extern te_errno tapi_mdns_probe(rcf_rpc_server *rpcs, const char *query,
                                int seconds, int *responders, int *records,
                                te_string *detail);

/**
 * Find the first service of a given type in a snapshot.
 *
 * @param services      A snapshot from tapi_mdns_browse().
 * @param type          Service type, e.g. @c "_http._tcp".
 *
 * @return The service, or @c NULL. Owned by @p services.
 */
extern const tapi_mdns_service *tapi_mdns_find(const te_vec *services,
                                               const char *type);

/** Release a resolved instance. */
extern void tapi_mdns_resolved_free(tapi_mdns_resolved *resolved);

/** Release a service snapshot. */
extern void tapi_mdns_services_free(te_vec *services);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_MDNS_H__ */

/**@} <!-- END tapi_mdns --> */
