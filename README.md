# tsf-mdns

Discovering mDNS / DNS-SD services on a Test Agent, packaged as an
external Test Environment (TE) repository (consumed with the
`TE_EXT_REPO` builder directive). It reads what the link-local network
advertises over a low-level library — **avahi-client, no Python** — plus
a daemon-less raw mDNS probe, for both an inventory and a light security
posture.

Three libraries:

- `ta_mdns` — agent side. Browse and resolve over **avahi-client**
  (`avahi-client/*.h`, `-lavahi-client -lavahi-common`), and a raw mDNS
  query over a UDP socket to `224.0.0.251:5353` (no library, no daemon —
  the bytes counted are the real ones on the wire, the way tsf-upnp
  probes SSDP). Read-only. The agent and its RPC server both link it.
- `rpcs_mdns` — the `mdns_*` RPCs for the agent's RPC server, thin
  wrappers over `ta_mdns`. Discovery happens on the agent, on its link.
- `tapi_mdns` — engine side. `tapi_mdns.h` browses into a
  `tapi_mdns_service` vector, resolves an instance, and runs the raw
  probe; `tapi_mdns_audit.h` reads the advertising as a light posture
  through tsf-cybersec; `tapi_mdns_rpc.h` is the one-per-RPC layer.

TE has no mDNS/DNS-SD of its own (tsf-upnp covers SSDP, the other
discovery protocol).

## What it reads

```c
te_vec services = TE_VEC_INIT(tapi_mdns_service);
const tapi_mdns_service *s;

CHECK_RC(tapi_mdns_browse(rpcs, 3, &services));
TE_VEC_FOREACH(&services, s)
    RING("%s  %s.%s", s->type, s->name, s->domain);
tapi_mdns_services_free(&services);
```

`tapi_mdns_resolve()` turns one instance into a host, address, port and
its TXT records. `tapi_mdns_probe()` sends one raw mDNS PTR query and
reports how many distinct responders answered and how many records they
carried — the measurement behind an mDNS reflection posture, and the
path that works when there is no `avahi-daemon`.

## Security posture

`tapi_mdns_audit()` reports through tsf-cybersec. mDNS announces things
on a trusted LAN, so the posture is light — it is about what the
announcement gives away:

| Finding | Severity | Raised when |
|---|---|---|
| `mdns.service-advertised` | info | a service is advertised (one per service) |
| `mdns.info-leak` | low | an instance name or TXT record exposes a host/model/version |
| `mdns.none` | info | nothing is advertised (or nothing could be read) |

## Agent host requirements

- **avahi** with its client development headers (Debian:
  `apt install libavahi-client-dev`) for the browse/resolve path, and a
  running **`avahi-daemon`** — avahi-client talks to that daemon.
- The raw probe (`tapi_mdns_probe`) needs neither: it is a plain UDP
  socket to the mDNS multicast group, so it works on a host without
  Avahi, and is the honest "what is actually on the wire" measurement.

## Usage

Declare the repository in an external libraries catalog and pass it to
`dispatcher.sh --external=<catalog.yml>`:

```yaml
repositories:
  - name: tsf_mdns
    url: https://github.com/interpretica-io/tsf-mdns.git
    ref: <tag>
    libs:
      - ta_mdns
      - rpcs_mdns
      - tapi_mdns
```

In `builder.conf`, bind `tapi_mdns` to the engine, list `ta_mdns` and
`rpcs_mdns` among the RPC server's libraries, and add the RPC
definitions to both platforms:

```
TE_EXT_REPO_USE([tsf_mdns], [ta_mdns rpcs_mdns], [tapi_mdns])

TE_LIB_PARMS([rpcxdr], [${TE_HOST}], [],
             [--with-rpcdefs=tarpc_job.x.m4,../ta_mdns/mdns_rpc.x.m4])
TE_LIB_PARMS([rpcxdr], [${TE_TA_TYPE}], [],
             [--with-rpcdefs=tarpc_job.x.m4,../ta_mdns/mdns_rpc.x.m4])
```

`tapi_mdns_audit` reports through tsf-cybersec, so that repository (and
its prerequisites tsf-kernel and tsf-devtool) must be built too. The RPC
program number is **36** (20–35 are taken by the other tsf agent RPCs);
change it in `mdns_rpc.x.m4` if it ever collides.

## What was verified, and what was not

**The avahi-client path was not compiled here.** Avahi is Linux-only —
macOS uses its own `mDNSResponder`, and the `avahi-client`/`avahi-common`
headers are absent on this host — so `ta_mdns.c`'s browse/resolve was
written against the documented avahi-client API (the `AvahiSimplePoll`
loop, `avahi_service_type_browser_new` / `avahi_service_browser_new` /
`avahi_service_resolver_new`) and was **not** syntax-checked. The first
build on Linux is the place to confirm the avahi callback signatures.

**The raw mDNS probe path is portable and was syntax-checked** against
this host's system headers (`-fsyntax-only`): the socket setup, the DNS
query builder (`ta_mdns_encode_qname`), the multicast `sendto`, and the
`select`/`recvfrom` collection loop with the ANCOUNT accounting all
type-check.

**Not verified either way:** the TE engine-side C, the RPC marshalling,
and any live discovery. The engine-side record parsing follows the
tsf-usb template unbuilt.

## Scope

- **Read-only.** tsf-mdns asks the network what it advertises and
  listens; it announces nothing of its own and changes no device.
- **Link-local.** mDNS is multicast to `224.0.0.251`, so the agent only
  sees what is on its own L2 segment — which is the point.
