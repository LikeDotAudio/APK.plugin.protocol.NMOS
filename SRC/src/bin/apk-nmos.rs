// Part of the APK.audio project — http://APK.audio — made by Anthony Kuzub
// MIT Licence. Free, for everyone, for ever. Full text in LICENSE at the root.
//! `apk-nmos` — the `nmos` container: the mDNS browse agent.
//!
//! It was hand-written around `serve_group` while it also carried the IS-04
//! registry agent (two MODULES, one process). That agent is its own stack and
//! container now, `apk-nmos-control` in APK:plugin:NMOS_CONTROL; the two meet
//! in the bus table, where `role` separates their rows, and nowhere else.
//!
//! `manifest = "agent.toml"` (ROAD-3472): the manifest is compiled in, and the
//! runner serves `GET /status` / `GET /telemetry` on 127.0.0.1:8206 — `running`
//! until the first mDNS answer, `serving` after.

// `panels = [nmos]`: every NMOS registry/node this plugin finds presents its
// own panel, retained at `APK.audio/System/Gui/Panels/nmos-<device>`; the
// manifest's `device_depth: 1` because the tree is `Device/<device>/<field>`.
apk_plugin_runner::main!(token = "nmos", lib = apkaudio_nmos, run = [run_browse_agent], panels = [nmos], manifest = "agent.toml");
