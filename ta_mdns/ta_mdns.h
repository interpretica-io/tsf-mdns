/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Agent-side mDNS / DNS-SD discovery
 *
 * Discovering the services an agent's link-local network advertises
 * over mDNS / DNS-SD (RFC 6762 / 6763). Two ways, both in-process and
 * neither scraping @c avahi-browse:
 *
 * - over **avahi-client** (the Avahi daemon's library API): browse the
 *   service types, browse a type for its instances, and resolve an
 *   instance to a host, port and its TXT records. Needs a running
 *   @c avahi-daemon on the agent.
 * - a raw mDNS query over a UDP socket to @c 224.0.0.251:5353 and the
 *   answers measured, the way tsf-upnp sends a raw SSDP M-SEARCH - so
 *   the bytes counted are the real ones on the wire, and no daemon is
 *   needed.
 *
 * Read-only: it asks the network what it advertises and listens. The
 * agent and its RPC server both link this; the RPCs (see
 * mdns_rpc.x.m4) are thin wrappers over these functions. Results that
 * are lists come back as newline-separated text, one record per line
 * with tab-separated fields - the engine side parses them.
 */

#ifndef __TA_MDNS_H__
#define __TA_MDNS_H__

#include "te_errno.h"
#include "te_string.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Browse the services advertised on the link, over avahi-client.
 *
 * Enumerates the service types (@c _services._dns-sd._udp) and, for
 * each, its instances, collecting for @p seconds.
 *
 * @param[in]  seconds  How long to collect.
 * @param[out] count    Number of instances found.
 * @param[out] result   One instance per line, tab-separated:
 *                      @c "type\\tname\\tdomain".
 *
 * @return Status code.
 * @retval TE_ECONNREFUSED  The Avahi daemon is not reachable.
 */
extern te_errno ta_mdns_browse(int seconds, int *count, te_string *result);

/**
 * Resolve one service instance to a host, port and TXT, over avahi-client.
 *
 * @param[in]  type     Service type, e.g. @c "_http._tcp".
 * @param[in]  name     Instance name from ta_mdns_browse().
 * @param[in]  domain   Domain (usually @c "local"), or @c NULL / @c "".
 * @param[out] result   One line, tab-separated:
 *                      @c "host\\taddress\\tport\\tkey=val;key=val...".
 *
 * @return Status code.
 */
extern te_errno ta_mdns_resolve(const char *type, const char *name,
                                const char *domain, te_string *result);

/**
 * Send one raw mDNS query and measure the answers, daemon-less.
 *
 * Builds a standard mDNS PTR query for @p query, sends it to
 * @c 224.0.0.251:5353 over a UDP socket, and collects responses for
 * @p seconds. Uses no library - the bytes in and out are the real UDP
 * ones.
 *
 * @param[in]  query        Name to query, or @c NULL for
 *                          @c "_services._dns-sd._udp.local".
 * @param[in]  seconds      How long to collect answers.
 * @param[out] responders   Number of distinct responders.
 * @param[out] records      Total answer records across responses.
 * @param[out] detail       One @c "address\\tbytes" line per responder.
 *
 * @return Status code.
 */
extern te_errno ta_mdns_probe(const char *query, int seconds,
                              int *responders, int *records,
                              te_string *detail);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TA_MDNS_H__ */
