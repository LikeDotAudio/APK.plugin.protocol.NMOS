// Part of the APK.audio project — http://APK.audio — made by Anthony Kuzub
// MIT Licence. Free, for everyone, for ever. Full text in LICENSE at the root.
//! `apk-nmos` — the `nmos` container: mDNS browse AND the IS-04 registry agent.
//!
//! Hand-written rather than `main!` because it is two MODULES, not two entry
//! points of one. `apkaudio-nmos` finds the APIs; `apkaudio-nmos-control` finds
//! what is registered inside them; both publish into the same table with `role`
//! separating them (the comment that stood in `workers/discovery.rs` until
//! PLAN-3316.01). They share a restart domain because a registry agent with no
//! browse beside it has nothing to query — and they keep two tokens, two
//! configs, two wills and two self tests because the bus already knows them as
//! `nmos` and `nmos-control`.

fn main() {
    apk_plugin_runner::serve_group(
        vec![
            apk_plugin_runner::Plugin {
                token: "nmos",
                config_ini: include_str!("../../config.ini"),
                self_test: apkaudio_nmos::self_test::self_test_json,
            },
            apk_plugin_runner::Plugin {
                token: "nmos-control",
                config_ini: include_str!("../../../../APK:plugin:NMOS_CONTROL/SRC/config.ini"),
                self_test: apkaudio_nmos_control::self_test::self_test_json,
            },
        ],
        vec![
            (
                "run_browse_agent",
                Box::new(|host: String, port: u16| apkaudio_nmos::run_browse_agent(&host, port)),
            ),
            (
                "run_registry_agent",
                Box::new(|host: String, port: u16| {
                    apkaudio_nmos_control::run_registry_agent(&host, port)
                }),
            ),
        ],
    )
}
