/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Agent-side mDNS / DNS-SD discovery
 *
 * Browse and resolve over avahi-client (the Avahi daemon's library),
 * and a raw mDNS query over a UDP socket for the daemon-less path.
 * Avahi's browsing is event-driven: a browser hands results to a
 * callback on the poll loop, so ta_mdns_browse() runs the loop for
 * @a seconds and collects under the callbacks, the way tsf-upnp
 * collects SSDP responses. The raw probe uses no library at all.
 */

#define TE_LGR_USER     "TA MDNS"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/error.h>
#include <avahi-common/malloc.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "logger_api.h"

#include "ta_mdns.h"

/** Milliseconds one poll iteration blocks for. */
#define TA_MDNS_TICK_MS 100

/** Upper bound on the per-type service browsers kept alive at once. */
#define TA_MDNS_MAX_BROWSERS 256

/** Shared state threaded through the Avahi callbacks of one browse. */
typedef struct ta_mdns_browse_ctx {
    AvahiClient *client;
    AvahiSimplePoll *poll;
    te_string *result;
    int count;
    AvahiServiceBrowser *browsers[TA_MDNS_MAX_BROWSERS];
    size_t n_browsers;
} ta_mdns_browse_ctx;

/** Seconds elapsed since @p start. */
static double
ta_mdns_elapsed(const struct timeval *start)
{
    struct timeval now;

    gettimeofday(&now, NULL);
    return (now.tv_sec - start->tv_sec) +
           (now.tv_usec - start->tv_usec) / 1000000.0;
}

/** An Avahi instance showed up: record it as "type\tname\tdomain". */
static void
ta_mdns_service_cb(AvahiServiceBrowser *b, AvahiIfIndex iface,
                   AvahiProtocol proto, AvahiBrowserEvent event,
                   const char *name, const char *type, const char *domain,
                   AvahiLookupResultFlags flags, void *userdata)
{
    ta_mdns_browse_ctx *ctx = userdata;

    UNUSED(b);
    UNUSED(iface);
    UNUSED(proto);
    UNUSED(flags);

    if (event == AVAHI_BROWSER_NEW)
    {
        te_string_append(ctx->result, "%s\t%s\t%s\n",
                         type != NULL ? type : "",
                         name != NULL ? name : "",
                         domain != NULL ? domain : "");
        ctx->count++;
    }
}

/** A new service type showed up: open a browser for its instances. */
static void
ta_mdns_type_cb(AvahiServiceTypeBrowser *b, AvahiIfIndex iface,
                AvahiProtocol proto, AvahiBrowserEvent event,
                const char *type, const char *domain,
                AvahiLookupResultFlags flags, void *userdata)
{
    ta_mdns_browse_ctx *ctx = userdata;
    AvahiServiceBrowser *sb;

    UNUSED(b);
    UNUSED(flags);

    if (event != AVAHI_BROWSER_NEW || type == NULL)
        return;
    if (ctx->n_browsers >= TA_MDNS_MAX_BROWSERS)
        return;

    sb = avahi_service_browser_new(ctx->client, iface, proto, type, domain,
                                   0, ta_mdns_service_cb, ctx);
    if (sb != NULL)
        ctx->browsers[ctx->n_browsers++] = sb;
}

/* See description in ta_mdns.h */
te_errno
ta_mdns_browse(int seconds, int *count, te_string *result)
{
    ta_mdns_browse_ctx ctx;
    AvahiServiceTypeBrowser *types = NULL;
    struct timeval start;
    int error = 0;
    size_t i;
    te_errno rc = 0;

    *count = 0;
    memset(&ctx, 0, sizeof(ctx));
    ctx.result = result;

    ctx.poll = avahi_simple_poll_new();
    if (ctx.poll == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOMEM);

    ctx.client = avahi_client_new(avahi_simple_poll_get(ctx.poll), 0, NULL,
                                  NULL, &error);
    if (ctx.client == NULL)
    {
        ERROR("Cannot reach the Avahi daemon: %s", avahi_strerror(error));
        avahi_simple_poll_free(ctx.poll);
        return TE_RC(TE_TA_UNIX, TE_ECONNREFUSED);
    }

    types = avahi_service_type_browser_new(ctx.client, AVAHI_IF_UNSPEC,
                                           AVAHI_PROTO_UNSPEC, "local", 0,
                                           ta_mdns_type_cb, &ctx);
    if (types == NULL)
    {
        ERROR("Cannot start the service-type browser: %s",
              avahi_strerror(avahi_client_errno(ctx.client)));
        rc = TE_RC(TE_TA_UNIX, TE_EFAIL);
        goto out;
    }

    gettimeofday(&start, NULL);
    while (ta_mdns_elapsed(&start) < seconds)
    {
        if (avahi_simple_poll_iterate(ctx.poll, TA_MDNS_TICK_MS) != 0)
            break;  /* quit requested or error */
    }

    *count = ctx.count;

out:
    for (i = 0; i < ctx.n_browsers; i++)
        avahi_service_browser_free(ctx.browsers[i]);
    if (types != NULL)
        avahi_service_type_browser_free(types);
    avahi_client_free(ctx.client);
    avahi_simple_poll_free(ctx.poll);

    return rc;
}

/** Shared state for one resolve. */
typedef struct ta_mdns_resolve_ctx {
    AvahiSimplePoll *poll;
    te_string *result;
    bool done;
} ta_mdns_resolve_ctx;

static void
ta_mdns_resolve_cb(AvahiServiceResolver *r, AvahiIfIndex iface,
                   AvahiProtocol proto, AvahiResolverEvent event,
                   const char *name, const char *type, const char *domain,
                   const char *host_name, const AvahiAddress *address,
                   uint16_t port, AvahiStringList *txt,
                   AvahiLookupResultFlags flags, void *userdata)
{
    ta_mdns_resolve_ctx *ctx = userdata;

    UNUSED(r);
    UNUSED(iface);
    UNUSED(proto);
    UNUSED(name);
    UNUSED(type);
    UNUSED(domain);
    UNUSED(flags);

    if (event == AVAHI_RESOLVER_FOUND)
    {
        char addr[AVAHI_ADDRESS_STR_MAX] = "";
        AvahiStringList *e;

        if (address != NULL)
            avahi_address_snprint(addr, sizeof(addr), address);

        te_string_append(ctx->result, "%s\t%s\t%u\t",
                         host_name != NULL ? host_name : "", addr,
                         (unsigned)port);
        for (e = txt; e != NULL; e = avahi_string_list_get_next(e))
        {
            te_string_append(ctx->result, "%s;",
                             (const char *)avahi_string_list_get_text(e));
        }
        te_string_append(ctx->result, "\n");
    }

    ctx->done = true;
    avahi_simple_poll_quit(ctx->poll);
}

/* See description in ta_mdns.h */
te_errno
ta_mdns_resolve(const char *type, const char *name, const char *domain,
                te_string *result)
{
    ta_mdns_resolve_ctx ctx;
    AvahiClient *client = NULL;
    AvahiServiceResolver *resolver = NULL;
    struct timeval start;
    int error = 0;
    te_errno rc = 0;

    memset(&ctx, 0, sizeof(ctx));
    ctx.result = result;

    ctx.poll = avahi_simple_poll_new();
    if (ctx.poll == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOMEM);

    client = avahi_client_new(avahi_simple_poll_get(ctx.poll), 0, NULL, NULL,
                              &error);
    if (client == NULL)
    {
        ERROR("Cannot reach the Avahi daemon: %s", avahi_strerror(error));
        avahi_simple_poll_free(ctx.poll);
        return TE_RC(TE_TA_UNIX, TE_ECONNREFUSED);
    }

    resolver = avahi_service_resolver_new(client, AVAHI_IF_UNSPEC,
                   AVAHI_PROTO_UNSPEC, name, type,
                   (domain != NULL && domain[0] != '\0') ? domain : "local",
                   AVAHI_PROTO_UNSPEC, 0, ta_mdns_resolve_cb, &ctx);
    if (resolver == NULL)
    {
        ERROR("Cannot start the resolver: %s",
              avahi_strerror(avahi_client_errno(client)));
        rc = TE_RC(TE_TA_UNIX, TE_EFAIL);
        goto out;
    }

    gettimeofday(&start, NULL);
    while (!ctx.done && ta_mdns_elapsed(&start) < 5)
    {
        if (avahi_simple_poll_iterate(ctx.poll, TA_MDNS_TICK_MS) != 0)
            break;
    }
    if (!ctx.done)
        rc = TE_RC(TE_TA_UNIX, TE_ETIMEDOUT);

out:
    if (resolver != NULL)
        avahi_service_resolver_free(resolver);
    avahi_client_free(client);
    avahi_simple_poll_free(ctx.poll);

    return rc;
}

/*
 * ---- raw mDNS probe (no library) -----------------------------------
 */

/** Encode @p name ("a.b.local") as DNS labels into @p buf; return length. */
static size_t
ta_mdns_encode_qname(const char *name, uint8_t *buf, size_t len)
{
    size_t pos = 0;
    const char *label = name;

    while (label != NULL && *label != '\0')
    {
        const char *dot = strchr(label, '.');
        size_t llen = dot != NULL ? (size_t)(dot - label) : strlen(label);

        if (llen == 0 || llen > 63 || pos + llen + 1 >= len)
            break;
        buf[pos++] = (uint8_t)llen;
        memcpy(buf + pos, label, llen);
        pos += llen;
        label = dot != NULL ? dot + 1 : NULL;
    }
    if (pos < len)
        buf[pos++] = 0;  /* root label */

    return pos;
}

/* See description in ta_mdns.h */
te_errno
ta_mdns_probe(const char *query, int seconds, int *responders, int *records,
              te_string *detail)
{
    static const char default_query[] = "_services._dns-sd._udp.local";
    uint8_t packet[512];
    size_t qn;
    size_t plen = 0;
    int sock;
    struct sockaddr_in dst;
    struct timeval start;
    char seen[64][INET_ADDRSTRLEN];
    size_t n_seen = 0;
    te_errno rc = 0;

    *responders = 0;
    *records = 0;

    /* DNS header: id 0, standard query, QDCOUNT 1. */
    memset(packet, 0, 12);
    packet[5] = 1;  /* QDCOUNT low byte */
    plen = 12;

    qn = ta_mdns_encode_qname(query != NULL ? query : default_query,
                              packet + plen, sizeof(packet) - plen - 4);
    plen += qn;
    packet[plen++] = 0; packet[plen++] = 12;  /* QTYPE  = PTR  */
    packet[plen++] = 0; packet[plen++] = 1;   /* QCLASS = IN   */

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return TE_OS_RC(TE_TA_UNIX, errno);

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(5353);
    dst.sin_addr.s_addr = inet_addr("224.0.0.251");

    if (sendto(sock, packet, plen, 0, (struct sockaddr *)&dst,
               sizeof(dst)) < 0)
    {
        rc = TE_OS_RC(TE_TA_UNIX, errno);
        close(sock);
        return rc;
    }

    gettimeofday(&start, NULL);
    while (ta_mdns_elapsed(&start) < seconds)
    {
        uint8_t resp[2048];
        struct sockaddr_in src;
        socklen_t srclen = sizeof(src);
        struct timeval tv = { .tv_sec = 0, .tv_usec = TA_MDNS_TICK_MS * 1000 };
        fd_set rfds;
        ssize_t n;
        const char *addr;
        size_t i;
        bool known = false;

        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        if (select(sock + 1, &rfds, NULL, NULL, &tv) <= 0)
            continue;

        n = recvfrom(sock, resp, sizeof(resp), 0, (struct sockaddr *)&src,
                     &srclen);
        if (n < 12)
            continue;

        *records += (resp[6] << 8) | resp[7];  /* ANCOUNT */
        addr = inet_ntoa(src.sin_addr);
        for (i = 0; i < n_seen; i++)
        {
            if (strcmp(seen[i], addr) == 0)
            {
                known = true;
                break;
            }
        }
        if (!known && n_seen < TE_ARRAY_LEN(seen))
        {
            te_strlcpy(seen[n_seen], addr, sizeof(seen[n_seen]));
            n_seen++;
            te_string_append(detail, "%s\t%zd\n", addr, n);
        }
    }

    *responders = (int)n_seen;
    close(sock);

    return rc;
}
