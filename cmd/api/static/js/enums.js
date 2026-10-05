// Mirror of internal/normalize/enums.go — the smallint vocabularies of the
// normalized event model (class / activity / action / interface role /
// direction). Hand-maintained; TestEnumsJSMirror (internal/normalize) parses
// this file and fails CI when a name or value differs from the Go maps, so
// edit both or neither. Exposed on window for the pages that will render
// net_events / sec_events (S-3 / S-4); nothing loads it yet.
(function () {
    'use strict';
    window.FwmonEnums = {
        CLASS: {
            network: 4001, finding: 2004, auth: 3002,
            config_change: 5019, vpn_session: 4014, device_health: 5001
        },
        ACTIVITY: {
            unknown: 0,
            open: 1, close: 2, traffic: 3, http: 4, dns: 5, packet: 6, dhcp: 7,
            detect: 10,
            logon: 20, logoff: 21, connect: 22, disconnect: 23, roam: 24,
            create: 30, update: 31, delete: 32,
            tunnel_up: 40, tunnel_down: 41, client_connect: 42, client_disconnect: 43, tunnel_stats: 44,
            wan_down: 50, wan_up: 51, latency: 52, packet_loss: 53, ha_state: 54,
            device_offline: 55, device_online: 56, resource: 57, failover: 58, software: 59
        },
        ACTION: { unknown: 0, allow: 1, deny: 2, reject: 3, timeout_close: 4, other: 99 },
        ROLE: { unknown: 0, wan: 1, lan: 2, dmz: 3, undefined: 4 },
        DIRECTION: { unknown: 0, inbound: 1, outbound: 2, internal: 3, external: 4 }
    };
})();
