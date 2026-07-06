# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved.
#
# External TE library (see TE_EXT_REPO): agent-side mDNS / DNS-SD
# discovery over avahi-client, plus a daemon-less raw mDNS probe over a
# UDP socket. The agent and its RPC server both link it.

headers += files(
    'ta_mdns.h',
)

sources += files(
    'ta_mdns.c',
)

te_libs += [
    'logger_core',
    'tools',
]

cc = meson.get_compiler('c')

avahi_client = dependency('avahi-client', required: false)
if not avahi_client.found()
    avahi_client = cc.find_library('avahi-client',
                                   has_headers: 'avahi-client/client.h')
endif

avahi_common = dependency('avahi-common', required: false)
if not avahi_common.found()
    avahi_common = cc.find_library('avahi-common', required: false)
endif

deps += [ avahi_client ]
if avahi_common.found()
    deps += [ avahi_common ]
endif
