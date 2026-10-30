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
use apkaudio_contracts::topics::sanitize_segment;

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

const DEVICE_KEYS: [&str; 13] = [
    "service",
    "role",
    "api_versions",
    "api_proto",
    "api_auth",
    "priority",
    "host",
    "port",
    "addresses",
    // Neither is advertised. Both are recovered from the SLAAC IPv6 address,
    // which carries the host's MAC in its low 64 bits — `mac` is the address
    // itself, `vendor` is who holds that IEEE block. Blank for a host using
    // privacy addressing, where the interface ID is genuinely random.
    "mac",
    "vendor",
    // `-1` while the node is advertising — see `apkaudio_contracts::presence`.
    "last_online",
    "online_since",
];


/// How often every row still being advertised is said again.
///
/// The rows are UNKEPT (QoS 0, retain clear), like AVB, PRINTERS, PTP and
/// RAVENNA: a discovery row describes what is advertising *now*, and retained it
/// went on describing a node that had stopped, with nothing to correct it once
/// this agent was gone. Unkept, a row leaves the bus by not being restated —
/// which is why this clock is load-bearing. mdns-sd resolves a node again only
/// when its records change, so without the restate a subscriber that connected
/// after the first resolution would never see a settled registry at all.
const RESTATE: Duration = Duration::from_secs(30);

/// Publish one row field, unkept. The only publish in this agent.
fn say(mqtt_client: &rumqttc::Client, topic: impl Into<String>, payload: impl Into<Vec<u8>>) {
    let _ = mqtt_client.publish(topic.into(), rumqttc::QoS::AtMostOnce, false, payload.into());
}

/// Say the agent cannot hunt, through the shared `agent_state` vocabulary.
/// Its retain flag is not honoured: like the rows, the statement is unkept and
/// lives one RESTATE at a time, so it leaves the bus once the daemon starts.
fn say_unavailable(mqtt_client: &rumqttc::Client, reason: &str) {
    match apkaudio_contracts::agent_state::AgentReport::unavailable("nmos", reason)
        .and_then(|a| a.publications())
    {
        Ok(entries) => {
            for (topic, payload, _retain) in entries {
                say(mqtt_client, topic, payload);
            }
        }
        // `nmos` is a literal this crate owns — a failure is a bug here.
        Err(e) => eprintln!("⚠️  [NMOS] agent state not published: {e}"),
    }
}

fn device_prefix(host: &str, port: u16) -> String {
    format!("APK.audio/System/Protocols/nmos/Device/{}_{}", sanitize_segment(host), port)
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

/// Blocking browse loop — run on a dedicated thread.
pub fn run_browse_agent(mqtt_host: &str, mqtt_port: u16) {
    let mut opts = rumqttc::MqttOptions::new("apkaudio-nmos", mqtt_host, mqtt_port);
    opts.set_keep_alive(Duration::from_secs(30));
    if let Some((username, password)) = apkaudio_contracts::broker_auth::credentials() {
        opts.set_credentials(username, password);
    }
    let (mqtt_client, mut connection) = rumqttc::Client::new(opts, 32);
    let vendors = apkaudio_maclookup::MacVendors::start();
    std::thread::spawn(move || {
        apkaudio_contracts::broker_backoff::drain(
            "nmos",
            connection.iter(),
            |e| matches!(e, rumqttc::ConnectionError::ConnectionRefused(_)),
            |_| {},
        );
    });

    // A host whose mDNS daemon cannot start (no multicast socket yet, port
    // 5353 refused) is a standing condition, not a crash: returning here hands
    // the runner a finished hunter, which it exits 70 on, and Docker restarts
    // the container into the same refusal forever. So the agent stays up, SAYS
    // it is unavailable — unkept like every row here, so restated on the
    // RESTATE cadence — and tries the daemon again each time (the same shape as
    // AVB-Milan's capture loop).
    let mdns = loop {
        match ServiceDaemon::new() {
            Ok(d) => break d,
            Err(e) => {
                let reason = format!("could not start mDNS daemon: {e}");
                eprintln!("🛑 [NMOS] {reason} — saying so, retrying in {}s", RESTATE.as_secs());
                say_unavailable(&mqtt_client, &reason);
                std::thread::sleep(RESTATE);
            }
        }
    };

    let (tx, rx) = std::sync::mpsc::channel::<(String, ServiceEvent)>();
    for (stype, role) in NMOS_SERVICES {
        match mdns.browse(stype) {
            Ok(receiver) => {
                let tx = tx.clone();
                let role = role.to_string();
                std::thread::spawn(move || {
                    while let Ok(ev) = receiver.recv() {
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
        let next = match rx.recv_timeout(RESTATE) {
            Ok(next) => Some(next),
            // Idle — the normal state of a settled bench, and exactly when the
            // restate matters most.
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
            // Every browse thread has gone; there is nothing left to hear.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        // Checked on the event path too, so a chatty bench that keeps
        // `recv_timeout` from expiring still restates on schedule.
        if last_restate.elapsed() >= RESTATE {
            last_restate = std::time::Instant::now();
            for (topic, value) in &published {
                say(&mqtt_client, topic.clone(), value.clone().into_bytes());
            }
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
                            for k in DEVICE_KEYS {
                                let topic = format!("{prefix}/{k}");
                                published.remove(&topic);
                                let _ = mqtt_client.publish(topic, rumqttc::QoS::AtLeastOnce, true, Vec::new());
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
        entry.host = host.clone();
        entry.port = port;
        entry.role = role.clone();
        let fullname = info.get_fullname().to_string();
        entry.instance = fullname
            .split_once("._")
            .map(|(s, _)| s.to_string())
            .unwrap_or(fullname);
        for a in info.get_addresses() {
            let s = a.to_string();
            // nmos-cpp advertises every interface including loopback and IPv6
            // link-local; neither helps anyone reach the API.
            if s.contains('.') && !s.starts_with("127.") {
                entry.addresses.insert(s);
            }
        }
        for prop in info.get_properties().iter() {
            let v = prop.val_str().to_string();
            if !v.is_empty() {
                entry.txt.insert(prop.key().to_ascii_lowercase(), v);
            }
        }

        let s = entry.clone();
        let get = |k: &str| s.txt.get(k).cloned().unwrap_or_default();
        let prefix = device_prefix(&s.host, s.port);

        let values = [
            s.instance.clone(),
            s.role.clone(),
            summarise_versions(&get("api_ver")),
            { let p = get("api_proto"); if p.is_empty() { "-".into() } else { p } },
            auth_label(s.txt.get("api_auth")).to_string(),
            { let p = get("pri"); if p.is_empty() { "-".into() } else { p } },
            s.host.clone(),
            s.port.to_string(),
            s.addresses.iter().cloned().collect::<Vec<_>>().join(", "),
            {
                let addrs: Vec<String> = s.addresses.iter().cloned().collect();
                vendors
                    .mac_of_any(addrs.iter().map(String::as_str))
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "-".to_string())
            },
            {
                let addrs: Vec<String> = s.addresses.iter().cloned().collect();
                vendors
                    .vendor_of_any(addrs.iter().map(String::as_str))
                    .unwrap_or_else(|| "-".to_string())
            },
            presence::ONLINE_NOW.to_string(),
            arrived.since(&prefix, now_secs()).to_string(),
        ];

        let mut wrote = 0usize;
        for (k, value) in DEVICE_KEYS.iter().zip(values) {
            let topic = format!("{prefix}/{k}");
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
                summarise_versions(&get("api_ver")),
                auth_label(s.txt.get("api_auth"))
            );
        }
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
    use super::*;

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

    /// Rows are unkept (LOOSE-nmos-run-browse-agent). The only retained write
    /// in the browse agent is the EMPTY one that clears a departed row, so a
    /// retain flag of `true` beside a non-empty payload is a regression.
    #[test]
    fn nothing_the_browse_agent_says_is_kept() {
        let src = include_str!("lib.rs");
        let agent = &src[src.find("pub fn run_browse_agent").unwrap()..src.find("fn nmos_sighting").unwrap()];
        let kept: Vec<&str> = agent.lines().filter(|l| l.contains(".publish(")).collect();
        assert_eq!(kept.len(), 1, "one publish call besides `say`: {kept:?}");
        assert!(kept[0].contains("true, Vec::new()"), "the kept write must be the clear: {kept:?}");
        assert!(src.contains("rumqttc::QoS::AtMostOnce, false, payload.into()"));
    }

    /// A daemon that cannot start is restated as unavailable and retried, not
    /// returned on (LOOSE-plugin-nmos-runbrowseagent-still-prints): a returned
    /// hunter exits the runner 70 and Docker restart-loops it.
    #[test]
    fn mdns_failure_is_retried_not_returned() {
        let src = include_str!("lib.rs");
        let start = src.find("pub fn run_browse_agent").unwrap();
        let agent = &src[start..start + src[start..].find("let (tx, rx)").unwrap()];
        assert!(!agent.contains("return;"), "the agent must not return before browsing");
        assert!(agent.contains("say_unavailable("));
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
