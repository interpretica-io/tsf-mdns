/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief What an agent's mDNS advertising is worth as a posture
 *
 * Browses with tapi_mdns_browse(), optionally resolves each instance,
 * and classifies what is advertised into tsf-cybersec findings.
 */

#define TE_LGR_USER     "TAPI MDNS AUDIT"

#include "te_config.h"

#include <string.h>
#include <strings.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "logger_api.h"

#include "tapi_mdns.h"
#include "tapi_mdns_audit.h"

/* See description in tapi_mdns_audit.h */
const tapi_mdns_audit_policy tapi_mdns_default_audit_policy = {
    .seconds = 3,
    .inspect_txt = true,
};

/** Does @p text hint at a host/model/version worth flagging as a leak? */
static bool
mdns_looks_like_leak(const char *text)
{
    static const char *const needles[] = {
        "model", "version", "ver=", "os=", "osxvers", "fw", "serial",
        "macaddress", "deviceid",
    };
    size_t i;

    if (text == NULL)
        return false;
    for (i = 0; i < TE_ARRAY_LEN(needles); i++)
    {
        if (strcasestr(text, needles[i]) != NULL)
            return true;
    }
    return false;
}

/* See description in tapi_mdns_audit.h */
te_errno
tapi_mdns_audit(rcf_rpc_server *rpcs, const tapi_mdns_audit_policy *policy,
                tapi_cybersec_report *report)
{
    te_vec services = TE_VEC_INIT(tapi_mdns_service);
    const tapi_mdns_service *s;
    int seconds;
    te_errno rc;

    if (policy == NULL)
        policy = &tapi_mdns_default_audit_policy;
    seconds = policy->seconds > 0 ? policy->seconds : 3;

    rc = tapi_mdns_browse(rpcs, seconds, &services);
    if (rc != 0)
        return rc;

    if (te_vec_size(&services) == 0)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
            "mdns.none", "-", "no mDNS/DNS-SD services are advertised (or "
            "none could be read)");
    }

    TE_VEC_FOREACH(&services, s)
    {
        const char *name = s->name != NULL ? s->name : "";

        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
            "mdns.service-advertised", s->type != NULL ? s->type : "?",
            "%s advertised as '%s'", s->type != NULL ? s->type : "?", name);

        if (mdns_looks_like_leak(name))
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
                "mdns.info-leak", name,
                "the instance name exposes a host/model/version");
        }

        if (policy->inspect_txt)
        {
            tapi_mdns_resolved r;

            if (tapi_mdns_resolve(rpcs, s->type, s->name, s->domain,
                                  &r) == 0)
            {
                if (mdns_looks_like_leak(r.txt))
                {
                    tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
                        "mdns.info-leak", name,
                        "a TXT record exposes a host/model/version");
                }
                tapi_mdns_resolved_free(&r);
            }
        }
    }

    tapi_mdns_services_free(&services);

    return 0;
}
