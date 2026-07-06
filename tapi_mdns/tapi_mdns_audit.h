/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief What an agent's mDNS advertising is worth as a posture
 *
 * @defgroup tapi_mdns_audit mDNS security posture
 * @ingroup tapi_mdns
 * @{
 *
 * The services advertised on an agent's link read as a light security
 * posture and reported through tsf-cybersec. mDNS is meant to announce
 * things on a trusted LAN, so the findings are about what that
 * announcement gives away rather than about a break-in: that a host is
 * advertising at all, and that an instance name or TXT record leaks a
 * hostname, model or version an attacker would otherwise have to probe
 * for.
 *
 * | Finding | Severity | Raised when |
 * |---|---|---|
 * | @c mdns.service-advertised | info | a service is advertised (one per service) |
 * | @c mdns.info-leak | low | an instance name or TXT record exposes a host/model/version |
 * | @c mdns.none | info | nothing is advertised (or nothing could be read) |
 *
 * A finding's subject is the service type or instance name, stable
 * between runs.
 */

#ifndef __TAPI_MDNS_AUDIT_H__
#define __TAPI_MDNS_AUDIT_H__

#include "te_errno.h"
#include "rcf_rpc.h"

#include "tapi_cybersec.h"

#ifdef __cplusplus
extern "C" {
#endif

/** What the advertising is expected to be. */
typedef struct tapi_mdns_audit_policy {
    /** How long the browse collects, seconds (0 for a default of 3). */
    int seconds;
    /** Resolve each instance to inspect its TXT for leaks. */
    bool inspect_txt;
} tapi_mdns_audit_policy;

/** The default: a 3-second browse, TXT inspected. */
extern const tapi_mdns_audit_policy tapi_mdns_default_audit_policy;

/**
 * Read the agent's mDNS posture into @p report.
 *
 * @param[in]  rpcs     RPC server on the agent.
 * @param[in]  policy   What is expected, or @c NULL for the default.
 * @param[out] report   Report to append findings to.
 *
 * @return Status code of reading the posture, not its verdict.
 */
extern te_errno tapi_mdns_audit(rcf_rpc_server *rpcs,
                                const tapi_mdns_audit_policy *policy,
                                tapi_cybersec_report *report);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_MDNS_AUDIT_H__ */

/**@} <!-- END tapi_mdns_audit --> */
