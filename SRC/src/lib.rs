// Part of the APK.audio project — http://APK.audio — made by Anthony Kuzub
// MIT Licence. Free, for everyone, for ever. Full text in LICENSE at the root.
//! `apkaudio-nmos` — AMWA NMOS discovery (IS-04 / IS-09).
//!
//! NMOS is how professional media-over-IP gear finds itself. Unlike the printer
//! or AirPlay case — many services, one device — each NMOS service is a distinct
//! **API role**, and one host commonly runs several:
//!
//! | Service | Typical port | Role |
//! |---|---|---|
//! | `_nmos-node._tcp` | 3212 | Node API — a device offering senders/receivers |
//! | `_nmos-query._tcp` | 3211 | Query API — what clients ask to find things |
//! | `_nmos-register._tcp` | 3210 | Registration API (current name) |
//! | `_nmos-registration._tcp` | 3210 | Registration API (legacy name, same service) |
//! | `_nmos-system._tcp` | 10641 | System API (IS-09) — global config, PTP domain |
//!
//! # Grouping: by host **and port**, not by host
//!
//! Two Node APIs on one host (`:3212` and `:3300`) are genuinely two nodes and
//! must stay separate rows — collapsing by hostname would hide one.
//!
//! But `_nmos-register` and `_nmos-registration` on `:3210` are **one service
//! under two names**: the spec renamed it and implementations advertise both for
//! compatibility. Those must merge, or every registry appears twice.
//!
//! Host+port separates the first case and merges the second, which is why it is
//! the key.
//!
//! # `api_auth` gets its own column
//!
//! The TXT record states whether the API requires authorisation. `api_auth=false`
//! means an unauthenticated HTTP API is controlling media routing — worth seeing
//! at a glance rather than buried in a TXT blob.
//!
//! # Scope
//!
//! Discovery only, BY DESIGN and not by omission: nothing here is enumerated,
//! registered or connected, and this paragraph is a contract rather than a
//! to-do. The controller is the sibling crate `apkaudio-nmos-control` — the
//! HTTP client went there so this one stays what it says. PLAN-319.01.
//!
//! Discovery has TWO transports and this crate owns both. [`run_browse_agent`]
//! is the multicast half — `_nmos-query._tcp.local.` shouted at the link, which
//! is the only domain multicast can name. [`unicast`] is the other half: the
//! same PTR/SRV/TXT walk asked of a named resolver, in a domain DHCP handed the
//! host, which is how a registry on another subnet is found at all. Both are
//! discovery, so neither breaks the contract above. PLAN-975.01.

use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::collections::{BTreeSet, HashMap};
use std::time::Duration;
use apkaudio_contracts::presence;
use apk_plugin_runner::session::Session;
use apk_plugin_runner::unkept::{forget, publications_of, say};

/// Implementation state. Discovery is real; the IS-04/IS-05 HTTP APIs are not
/// implemented, so this is deliberately not the word "complete".
pub const STATUS: &str = "discovery-only";

/// NMOS service types, with the role label shown in the table.
///
/// `_nmos-register` and `_nmos-registration` share a label deliberately — see
/// the grouping note above.
const NMOS_SERVICES: [(&str, &str); 5] = [
    ("_nmos-node._tcp.local.", "Node"),
    ("_nmos-query._tcp.local.", "Query"),
    ("_nmos-register._tcp.local.", "Registration"),
    ("_nmos-registration._tcp.local.", "Registration"),
    ("_nmos-system._tcp.local.", "System"),
];

/// The row's keys — the contract's, not this crate's: the `nmos` table is
/// written by two crates (this one and PLUGIN.NMOS_CONTROL), and
/// `apkaudio_contracts::nmos_rows` is the one schema both test against.
/// `mac`/`vendor` are recovered from the SLAAC IPv6 address (blank `-` for a
/// privacy-addressed host); `last_online` is `-1` while advertising (see
/// `apkaudio_contracts::presence`).
use apkaudio_contracts::nmos_rows::{self, ENDPOINT_KEYS as DEVICE_KEYS};


/// The compiled-in config.ini — the runner publishes it and the agent reads its
/// tunables out of the same text.
pub const CONFIG_INI: &str = include_str!("../config.ini");

/// Every tunable this agent reads, from `[nmos]` in config.ini.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    /// How often every row still being advertised is said again (`restate_s`).
    ///
    /// The rows are UNKEPT (QoS 0, retain clear), like AVB, PRINTERS, PTP and
    /// RAVENNA: a discovery row describes what is advertising *now*, and
    /// retained it went on describing a node that had stopped, with nothing to
    /// correct it once this agent was gone. Unkept, a row leaves the bus by not
    /// being restated — which is why this clock is load-bearing. mdns-sd
    /// resolves a node again only when its records change, so without the
    /// restate a subscriber that connected after the first resolution would
    /// never see a settled registry at all.
    pub restate: Duration,
}

impl Settings {
    /// Parse `[nmos]` out of an ini text. A missing or malformed key is named,
    /// and the error says which, rather than a value guessed.
    pub fn from_ini(text: &str) -> Result<Settings, String> {
        let mut in_section = false;
        let mut restate_s = None;
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                in_section = line == format!("[{}]", self_test::MODULE);
                continue;
            }
            if !in_section || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=')
                && key.trim() == "restate_s"
            {
                let value = value.trim();
                restate_s = Some(value.parse::<u64>().map_err(|_| format!("restate_s = {value} is not whole seconds"))?);
            }
        }
        let restate_s = restate_s.ok_or("config.ini declares no restate_s")?;
        if restate_s == 0 {
            return Err("restate_s = 0 would restate in a busy loop".into());
        }
        Ok(Settings { restate: Duration::from_secs(restate_s) })
    }
}

/// The longest the receive loop waits before it ticks again, whatever
/// `restate_s` says — so a long restate never reads as a stalled agent to the
/// runner's watchdog (APK_PLUGIN_STALL_SECS, 120 s by default).
const TICK_AT_LEAST: Duration = Duration::from_secs(30);

/// Say the agent cannot hunt, through the shared `agent_state` vocabulary.
/// Its retain flag is not honoured: like the rows, the statement is unkept
/// (`unkept::say`) and lives one restate at a time, so it leaves the bus once
/// the daemon starts.
fn say_unavailable(mqtt_client: &rumqttc::Client, reason: &str) {
    let account = apkaudio_contracts::agent_state::AgentReport::unavailable(self_test::MODULE, reason);
    // `publications_of` logs and yields nothing on a bad token — `nmos` is a
    // literal this crate owns, so that would be a bug here.
    for (topic, payload) in publications_of("NMOS", account) {
        say(mqtt_client, topic, payload);
    }
}

/// Start the mDNS daemon, or say why not and try again, for ever.
///
/// A host whose mDNS daemon cannot start (no multicast socket yet, port 5353
/// refused) is a standing condition, not a crash: returning hands the runner a
/// finished hunter, which it exits 70 on, and Docker restarts the container
/// into the same refusal forever. So each refusal goes to `unavailable` (which
/// says it on the bus and waits one restate) and the start is tried again.
/// Generic over the daemon so a test can drive the refusals.
fn until_started<D, E: std::fmt::Display>(
    mut start: impl FnMut() -> Result<D, E>,
    mut unavailable: impl FnMut(&str),
) -> D {
    loop {
        match start() {
            Ok(daemon) => return daemon,
            Err(e) => unavailable(&format!("could not start mDNS daemon: {e}")),
        }
    }
}

/// `APK.audio/System/Protocols/nmos/Device/{host}_{port}`, built by the
/// contract (`topics::protocols`), never hand-concatenated.
fn device_prefix(host: &str, port: u16) -> String {
    // `endpoint_id` is `{sanitize_segment(host)}_{port}`, a legal level for any
    // input (an empty host included), so this cannot refuse.
    nmos_rows::device_prefix(&nmos_rows::endpoint_id(host, port))
        .expect("a sanitised host and a port always make a legal topic level")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Human-readable authorisation state.
///
/// `api_auth` is a documented boolean, but absence is not the same as `false`:
/// a registry that never advertises the key has not told us it is open. `?`
/// preserves that distinction instead of asserting a security property.
pub fn auth_label(api_auth: Option<&String>) -> &'static str {
    match api_auth.map(|v| v.trim().to_ascii_lowercase()) {
        Some(v) if v == "true" => "required",
        Some(v) if v == "false" => "NONE",
        _ => "?",
    }
}

/// Numeric sort key for `vMAJOR.MINOR`, so v1.10 ranks above v1.9.
///
/// `pub(crate)` for `unicast.rs`, which ranks the `api_ver` list a registry
/// advertises over unicast DNS-SD by the same rule the mDNS browse uses. One
/// copy, because two would drift and only one of them would be tested.
pub(crate) fn version_key(v: &str) -> (u32, u32) {
    let t = v.trim_start_matches('v');
    let mut it = t.split('.');
    (
        it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
        it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
    )
}

/// Summarise advertised API versions, newest first.
///
/// A client negotiates to the highest common version, so that is the number
/// that matters; the full list stays visible behind it.
pub fn summarise_versions(api_ver: &str) -> String {
    let mut versions: Vec<&str> = api_ver
        .split(',')
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .collect();
    if versions.is_empty() {
        return "-".to_string();
    }
    versions.sort_by_key(|v| version_key(v));
    let newest = versions.last().copied().unwrap_or("-");
    if versions.len() == 1 {
        newest.to_string()
    } else {
        format!("{newest} (of {})", versions.join(", "))
    }
}

#[derive(Default, Clone)]
struct NmosService {
    instance: String,
    role: String,
    txt: HashMap<String, String>,
    addresses: BTreeSet<String>,
    host: String,
    port: u16,
}

impl NmosService {
    /// Fold one resolution of `fullname` (`role`, on `host:port`) into the row.
    /// Addresses and TXT keys accumulate: a node that resolves on two
    /// interfaces, or advertises a key once, keeps both.
    fn absorb(
        &mut self,
        role: &str,
        host: &str,
        port: u16,
        fullname: &str,
        addresses: impl IntoIterator<Item = String>,
        txt: impl IntoIterator<Item = (String, String)>,
    ) {
        self.host = host.to_string();
        self.port = port;
        self.role = role.to_string();
        self.instance = fullname
            .split_once("._")
            .map(|(s, _)| s.to_string())
            .unwrap_or_else(|| fullname.to_string());
        for s in addresses {
            // nmos-cpp advertises every interface including loopback and IPv6
            // link-local; neither helps anyone reach the API.
            if s.contains('.') && !s.starts_with("127.") {
                self.addresses.insert(s);
            }
        }
        for (key, value) in txt {
            if !value.is_empty() {
                self.txt.insert(key.to_ascii_lowercase(), value);
            }
        }
    }

    fn get(&self, key: &str) -> String {
        self.txt.get(key).cloned().unwrap_or_default()
    }

    /// The row exactly as a subscriber sees it: one `(topic, value)` per
    /// [`DEVICE_KEYS`] leaf under `Device/{host}_{port}/`. `mac` / `vendor`
    /// are what LIB.MAC_LOOKUP recovered from the addresses (`-` when not);
    /// `since` is the presence clock's `online_since`. Every value is non-empty
    /// — an empty unkept payload would read as nothing, and an empty RETAINED
    /// one is MQTT's delete.
    fn row(&self, mac: &str, vendor: &str, since: u64) -> Vec<(String, String)> {
        let or_dash = |v: String| if v.is_empty() { "-".to_string() } else { v };
        let values = [
            or_dash(self.instance.clone()),
            or_dash(self.role.clone()),
            summarise_versions(&self.get("api_ver")),
            or_dash(self.get("api_proto")),
            auth_label(self.txt.get("api_auth")).to_string(),
            or_dash(self.get("pri")),
            or_dash(self.host.clone()),
            self.port.to_string(),
            or_dash(self.addresses.iter().cloned().collect::<Vec<_>>().join(", ")),
            or_dash(mac.to_string()),
            or_dash(vendor.to_string()),
            presence::ONLINE_NOW.to_string(),
            since.to_string(),
        ];
        let prefix = device_prefix(&self.host, self.port);
        DEVICE_KEYS.iter().zip(values).map(|(k, v)| (format!("{prefix}/{k}"), v)).collect()
    }
}

/// The topics a departed endpoint's row occupied — every one is cleared.
fn row_topics(prefix: &str) -> Vec<String> {
    DEVICE_KEYS.iter().map(|k| format!("{prefix}/{k}")).collect()
}

/// Blocking browse loop — run on a dedicated thread.
pub fn run_browse_agent(mqtt_host: &str, mqtt_port: u16) {
    // The session — client id unique per node and process, credentials,
    // keep-alive and the backoff-paced drain — is the runner's (audit
    // 2026-10-30): this crate decides only WHAT it says, through
    // `unkept::say` / `unkept::forget`.
    let mqtt_client = Session::new(self_test::MODULE, "browse").to(mqtt_host, mqtt_port).capacity(32).spawn_drained();
    let vendors = apkaudio_maclookup::MacVendors::start();

    // A compiled-in config.ini without a usable `restate_s` is a build defect.
    // Said on the bus as `unavailable` and held, not returned on: a returned
    // hunter exits the runner 70 and Docker restart-loops the same image.
    let restate = match Settings::from_ini(CONFIG_INI) {
        Ok(settings) => settings.restate,
        Err(why) => loop {
            // Held, not returned on — but a fault it cannot serve past: the
            // loopback reads `failed` for as long as it holds (ROAD-3472).
            apk_plugin_runner::loopback::fatal(format!("config.ini: {why}"));
            eprintln!("🛑 [NMOS] config.ini: {why}");
            say_unavailable(&mqtt_client, &format!("config.ini: {why}"));
            std::thread::sleep(TICK_AT_LEAST);
        },
    };

    // Said unavailable (unkept, so restated on the restate cadence) and
    // retried — never returned on; see `until_started`.
    let mdns = until_started(ServiceDaemon::new, |reason| {
        eprintln!("🛑 [NMOS] {reason} — saying so, retrying in {}s", restate.as_secs());
        say_unavailable(&mqtt_client, reason);
        std::thread::sleep(restate);
    });

    let (tx, rx) = std::sync::mpsc::channel::<(String, ServiceEvent)>();
    for (stype, role) in NMOS_SERVICES {
        match mdns.browse(stype) {
            Ok(receiver) => {
                let tx = tx.clone();
                let role = role.to_string();
                std::thread::spawn(move || {
                    while let Ok(ev) = receiver.recv() {
                        from_the_wire(&ev);
                        if tx.send((role.clone(), ev)).is_err() {
                            break;
                        }
                    }
                });
            }
            Err(e) => eprintln!("   ⚠️  [NMOS] cannot browse {stype}: {e}"),
        }
    }
    drop(tx);

    println!("🚀 [NMOS] browsing IS-04 Node/Query/Registration + IS-09 System");

    // Key: host:port — see the grouping note in the module docs.
    let mut services: HashMap<String, NmosService> = HashMap::new();
    // What was last said per topic — and so what the restate says again. A
    // re-resolution that changes nothing writes nothing and prints nothing (an
    // IS-04 registry that had not changed since Tuesday used to narrate itself);
    // the restate timer alone keeps an unchanged node on the bus.
    let mut published: HashMap<String, String> = HashMap::new();
    let mut last_restate = std::time::Instant::now();
    let mut arrived = presence::Presence::new();
    // PRESENCE (PLAN-3318.01), one status document per API endpoint — the same
    // host:port this agent already merges on. Departures-only (`config.ini`):
    // mdns-sd resolves an endpoint again only when its record changes, and
    // removes it on a goodbye or a lapsed TTL. A removal carries only the
    // instance's full name, so `announced` maps it back to the endpoint.
    let mut announced: HashMap<String, String> = HashMap::new();

    loop {
        // STALL DETECTION (RP-09): one tick per turn of the receive loop arms
        // the runner's per-agent clock. The receive times out at least every
        // TICK_AT_LEAST, so a silent bench still ticks.
        apk_plugin_runner::tick();
        let next = match rx.recv_timeout(restate.min(TICK_AT_LEAST)) {
            Ok(next) => Some(next),
            // Idle — the normal state of a settled bench, and exactly when the
            // restate matters most.
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
            // Every browse thread has gone; there is nothing left to hear.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!("🛑 [NMOS] every mDNS browse ended");
                apk_plugin_runner::loopback::fatal("every mDNS browse ended");
                break;
            }
        };
        // Checked on the event path too, so a chatty bench that keeps
        // `recv_timeout` from expiring still restates on schedule.
        if last_restate.elapsed() >= restate {
            last_restate = std::time::Instant::now();
            apk_plugin_runner::unkept::restate(&mqtt_client, &published);
        }
        let Some((role, event)) = next else { continue };
        let info = match event {
            ServiceEvent::ServiceResolved(info) => info,
            ServiceEvent::ServiceRemoved(_, fullname) => {
                if let Some(key) = announced.remove(&fullname) {
                    if !announced.values().any(|k| *k == key) {
                        println!("   👋 [NMOS] {key} stopped advertising");
                        apk_plugin_runner::presence::gone(&nmos_sighting(&key).device_id());
                        // UNREACHABLE IS DEAD: the row leaves the bus. Dropped
                        // from `published` it is not restated; the empty
                        // retained write also clears a copy an older build of
                        // this agent left KEPT on the broker.
                        if let Some(gone) = services.remove(&key) {
                            let prefix = device_prefix(&gone.host, gone.port);
                            for topic in row_topics(&prefix) {
                                published.remove(&topic);
                                forget(&mqtt_client, topic);
                            }
                            arrived.forget(&prefix);
                            // The runner's retained leaves under the same
                            // prefix — `presence_topic` and the identity
                            // beside it (name, device_class…) — go with the
                            // row; clearing DEVICE_KEYS alone left them as a
                            // leaf-only ghost under `Device/+`
                            // (LOOSE-plugin-nmos-when-a-node).
                            apk_plugin_runner::presence::unlink(&prefix);
                        }
                    }
                }
                continue;
            }
            _ => continue,
        };
        let host = info.get_hostname().trim_end_matches('.').to_string();
        let port = info.get_port();
        let key = format!("{host}:{port}");
        announced.insert(info.get_fullname().to_string(), key.clone());
        apk_plugin_runner::presence::seen(&nmos_sighting(&key), Some(&device_prefix(&host, port)));

        let entry = services.entry(key).or_default();
        entry.absorb(
            &role,
            &host,
            port,
            info.get_fullname(),
            info.get_addresses().iter().map(|a| a.to_string()),
            info.get_properties().iter().map(|p| (p.key().to_string(), p.val_str().to_string())),
        );
        let s = entry.clone();
        let prefix = device_prefix(&s.host, s.port);
        let addrs: Vec<String> = s.addresses.iter().cloned().collect();
        let mac = vendors.mac_of_any(addrs.iter().map(String::as_str)).map(|m| m.to_string()).unwrap_or_default();
        let vendor = vendors.vendor_of_any(addrs.iter().map(String::as_str)).unwrap_or_default();
        let row = s.row(&mac, &vendor, arrived.since(&prefix, now_secs()));

        let mut wrote = 0usize;
        for (topic, value) in row {
            if published.get(&topic).is_some_and(|p| *p == value) {
                continue;
            }
            published.insert(topic.clone(), value.clone());
            wrote += 1;
            say(&mqtt_client, topic, value.into_bytes());
        }
        // Only when it is news — a node re-resolving is not an event.
        if wrote > 0 {
            println!(
                "   ✅ [NMOS] {} @ {}:{} — API {} auth:{}",
                s.role,
                s.host,
                s.port,
                summarise_versions(&s.get("api_ver")),
                auth_label(s.txt.get("api_auth"))
            );
        }
    }
}

/// TRAFFIC, counted for the loopback telemetry (ROAD-3472): the one fact that
/// moves this agent from `running` to `serving`. A found, resolved or removed
/// NMOS service is something the LAN said in mDNS; the daemon's search
/// start/stop events are its own timers and are not packets.
fn from_the_wire(event: &ServiceEvent) {
    if matches!(
        event,
        ServiceEvent::ServiceFound(..) | ServiceEvent::ServiceResolved(..) | ServiceEvent::ServiceRemoved(..)
    ) {
        apk_plugin_runner::loopback::packet_received();
    }
}

/// One API endpoint, as a presence sighting. PLAN-3318.01.
///
/// IDENTITY IS `host:port`, the key this agent merges every role on. Nothing of
/// the sighting but its id reaches the wire — identity stays on the
/// `System/Protocols/nmos/Device/…` topics above.
fn nmos_sighting(endpoint: &str) -> apkaudio_contracts::device_publish::Sighting {
    apkaudio_contracts::device_publish::Sighting::new("nmos", endpoint).class("Media Node")
}

#[cfg(test)]
mod tests {
    /// The manifest the binary compiles in parses, declares the loopback port
    /// and lists every key of config.ini's [nmos] that code reads (ROAD-3472).
    #[test]
    fn the_compiled_in_manifest_parses_and_reads_every_config_key() {
        let manifest = apkaudio_contracts::embedded_manifest!().expect("agent.toml parses");
        assert_eq!(manifest.name, "nmos");
        assert_eq!(manifest.telemetry_port, 8206);
        let config = apk_plugin_runner::ini_to_json(include_str!("../config.ini"));
        let keys: Vec<&str> = config["nmos"].as_object().unwrap().keys().map(String::as_str).collect();
        // 1 = `enabled`, which nothing reads (see agent.toml [config]).
        assert_eq!(manifest.unread_config_keys(keys), Some(1), "an [nmos] key nothing reads");
    }

    use super::*;
    use apkaudio_contracts::topics;

    /// This crate is no longer a stub, and the marker must say so — the old test
    /// asserted `STATUS == "stub"` precisely so implementing it could not pass
    /// silently while the README still called it unimplemented.
    #[test]
    fn status_reflects_that_discovery_is_implemented() {
        assert_eq!(STATUS, "discovery-only");
    }

    /// Absence must not be reported as "open" — that would be a security claim
    /// the announcement never made.
    #[test]
    fn auth_distinguishes_absent_from_false() {
        assert_eq!(auth_label(Some(&"false".to_string())), "NONE");
        assert_eq!(auth_label(Some(&"true".to_string())), "required");
        assert_eq!(auth_label(None), "?");
        assert_eq!(auth_label(Some(&"".to_string())), "?");
    }

    /// The real advertisement from the bench.
    #[test]
    fn summarises_versions_newest_first() {
        assert_eq!(
            summarise_versions("v1.0,v1.1,v1.2,v1.3"),
            "v1.3 (of v1.0, v1.1, v1.2, v1.3)"
        );
        // The System API advertises a single version.
        assert_eq!(summarise_versions("v1.0"), "v1.0");
        assert_eq!(summarise_versions(""), "-");
    }

    /// A bench registry as it resolves: nmos-cpp's Registration API on two
    /// interfaces (loopback and link-local dropped), advertised under both
    /// service names.
    fn fixture() -> NmosService {
        let mut s = NmosService::default();
        let txt = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<Vec<_>>();
        s.absorb(
            "Registration",
            "nmos-cpp.local",
            3210,
            "nmos-cpp_registry._nmos-register._tcp.local.",
            ["10.0.0.5".to_string(), "127.0.0.1".to_string(), "fe80::1".to_string()],
            txt(&[("API_VER", "v1.2,v1.3"), ("api_proto", "http"), ("api_auth", "false"), ("pri", "100")]),
        );
        s.absorb(
            "Registration",
            "nmos-cpp.local",
            3210,
            "nmos-cpp_registry._nmos-registration._tcp.local.",
            ["192.168.1.5".to_string()],
            txt(&[("pri", ""), ("api_auth", "false")]),
        );
        s
    }

    /// THE ROW CONTRACT (audit 2026-10-30, replacing two `include_str!` source
    /// greps): exactly the DEVICE_KEYS leaves under `Device/{host}_{port}/`,
    /// with the values a subscriber (Device Console, NMOS panel) reads.
    #[test]
    fn the_row_is_exactly_the_published_leaves() {
        let row = fixture().row("AA:BB:CC:DD:EE:FF", "", 1_700_000_000);
        let p = "APK.audio/System/Protocols/nmos/Device/nmos-cpp_local_3210";
        let expected: Vec<(String, String)> = [
            ("service", "nmos-cpp_registry"),
            ("role", "Registration"),
            ("api_versions", "v1.3 (of v1.2, v1.3)"),
            ("api_proto", "http"),
            ("api_auth", "NONE"),
            ("priority", "100"), // an empty re-advertisement does not erase it
            ("host", "nmos-cpp.local"),
            ("port", "3210"),
            ("addresses", "10.0.0.5, 192.168.1.5"),
            ("mac", "AA:BB:CC:DD:EE:FF"),
            ("vendor", "-"),
            ("last_online", "-1"),
            ("online_since", "1700000000"),
        ]
        .iter()
        .map(|(k, v)| (format!("{p}/{k}"), v.to_string()))
        .collect();
        assert_eq!(row, expected);
        assert_eq!(presence::ONLINE_NOW.to_string(), "-1");
        for (topic, _) in &row {
            assert!(matches!(topics::parse(topic), topics::ParsedTopic::Protocols { .. }), "{topic}");
        }
    }

    /// Unkept means nothing a subscriber reads is ever EMPTY (an empty payload
    /// is the delete), and a departure clears exactly the topics the row held
    /// — no fewer (a ghost leaf) and no more (someone else's leaf).
    #[test]
    fn a_departure_clears_exactly_the_row() {
        let s = fixture();
        let row = s.row("", "", 0);
        assert!(row.iter().all(|(_, v)| !v.is_empty()), "{row:?}");
        let said: Vec<String> = row.into_iter().map(|(t, _)| t).collect();
        assert_eq!(said, row_topics(&device_prefix(&s.host, s.port)));
    }

    /// The contract's row schema (`apkaudio_contracts::nmos_rows`, vectors
    /// `contracts/vectors/nmos_rows.json`): every role this agent writes, with
    /// the key set it publishes, is a valid `nmos` table row.
    #[test]
    fn the_row_is_a_contract_nmos_row() {
        let s = fixture();
        let row = s.row("", "", 0);
        let prefix = format!("{}/", device_prefix(&s.host, s.port));
        let keys: Vec<&str> = row.iter().map(|(t, _)| t.strip_prefix(&prefix).unwrap()).collect();
        for (_, role) in NMOS_SERVICES {
            assert_eq!(nmos_rows::row_problems(role, keys.iter().copied()), Vec::<String>::new(), "{role}");
        }
        assert_eq!(device_prefix("nmos-node.local.", 3210), nmos_rows::device_prefix(&nmos_rows::endpoint_id("nmos-node.local.", 3210)).unwrap());
    }

    /// A daemon that cannot start is said unavailable and retried, not
    /// returned on (LOOSE-plugin-nmos-runbrowseagent-still-prints): a returned
    /// hunter exits the runner 70 and Docker restart-loops it.
    #[test]
    fn mdns_failure_is_retried_not_returned() {
        let mut attempts = 0;
        let mut said = Vec::new();
        let daemon = until_started(
            || {
                attempts += 1;
                if attempts < 3 { Err("port 5353 refused") } else { Ok("daemon") }
            },
            |reason| said.push(reason.to_string()),
        );
        assert_eq!(daemon, "daemon");
        assert_eq!(said, vec!["could not start mDNS daemon: port 5353 refused"; 2]);
    }

    /// The restate interval is config, not source (RP-14): the compiled-in
    /// file names it, and a missing or broken key is refused by name.
    #[test]
    fn the_restate_interval_comes_from_config_ini() {
        assert_eq!(Settings::from_ini(CONFIG_INI).map(|s| s.restate), Ok(Duration::from_secs(30)));
        assert!(Settings::from_ini("[nmos]\n").unwrap_err().contains("restate_s"));
        assert!(Settings::from_ini("[nmos]\nrestate_s = soon\n").unwrap_err().contains("restate_s"));
        assert!(Settings::from_ini("[nmos]\nrestate_s = 0\n").is_err());
    }

    /// The device prefix is the contract's Protocols family (RP-07).
    #[test]
    fn the_device_prefix_is_built_by_the_contract() {
        let prefix = device_prefix("nmos-cpp.local", 3212);
        assert_eq!(prefix, "APK.audio/System/Protocols/nmos/Device/nmos-cpp_local_3212");
        assert!(matches!(
            apkaudio_contracts::topics::parse(&format!("{prefix}/role")),
            apkaudio_contracts::topics::ParsedTopic::Protocols { .. }
        ));
        // A nameless host still makes a legal level rather than a panic.
        let _ = device_prefix("", 3210);
    }

    /// Lexical sorting would rank v1.9 above v1.10.
    #[test]
    fn version_sort_is_numeric_not_lexical() {
        let s = summarise_versions("v1.9,v1.10");
        assert!(s.starts_with("v1.10"), "got {s}");
    }
}

/// Unicast DNS-SD — the same discovery through a resolver instead of the link,
/// which is what finds a registry that is not on this subnet and what AMWA
/// `IS-04-04 test_01` grades. Its module header owns the decision to put it in
/// this crate rather than in the controller, and the precedence a caller holding
/// both a configured URL and a resolved one must apply. PLAN-975.01.
pub mod unicast;

/// This crate's own self test — what it can prove about itself with nothing
/// plugged in. Reached from the bus through `outgoing/selftest_run`; see
/// `apkaudio_contracts::self_test` for the two inputs and the withdrawal the
/// first of them performs. PLAN-459.01.
pub mod self_test;
