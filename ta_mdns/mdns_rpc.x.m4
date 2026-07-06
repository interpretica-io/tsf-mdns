/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief RPC for mDNS / DNS-SD discovery
 *
 * The RPCs of rpcs_mdns, a thin layer over ta_mdns, which browses and
 * resolves mDNS/DNS-SD in the RPC server process over avahi-client, and
 * sends a raw mDNS query over a UDP socket. Add this file to the rpcxdr
 * definitions of the engine platform and of the agent platform:
 *
 *   TE_LIB_PARMS([rpcxdr], [<platform>], [],
 *                [--with-rpcdefs=tarpc_job.x.m4,../ta_mdns/mdns_rpc.x.m4])
 *
 * No handle survives between calls. Results that are lists come back as
 * newline-separated text, one record per line with tab-separated fields
 * - the engine side parses them, the same shape tsf-upnp uses.
 */

/* mdns_browse(): instances found over @a seconds, "type\tname\tdomain". */
struct tarpc_mdns_browse_in {
    struct tarpc_in_arg common;

    tarpc_int       seconds;
};

struct tarpc_mdns_browse_out {
    struct tarpc_out_arg common;

    tarpc_int       retval;
    tarpc_int       count;
    string          result<>;
};

/* mdns_resolve(): one instance to "host\taddress\tport\ttxt...". */
struct tarpc_mdns_resolve_in {
    struct tarpc_in_arg common;

    string          type<>;
    string          name<>;
    string          domain<>;
};

struct tarpc_mdns_resolve_out {
    struct tarpc_out_arg common;

    tarpc_int       retval;
    string          result<>;
};

/*
 * mdns_probe(): one raw mDNS PTR query, answers measured. detail is one
 * "address\tbytes" line per distinct responder.
 */
struct tarpc_mdns_probe_in {
    struct tarpc_in_arg common;

    string          query<>;
    tarpc_int       seconds;
};

struct tarpc_mdns_probe_out {
    struct tarpc_out_arg common;

    tarpc_int       retval;
    tarpc_int       responders;
    tarpc_int       records;
    string          detail<>;
};

program mdns
{
    version ver0
    {
        RPC_DEF(mdns_browse)
        RPC_DEF(mdns_resolve)
        RPC_DEF(mdns_probe)
    } = 1;
} = 36;
