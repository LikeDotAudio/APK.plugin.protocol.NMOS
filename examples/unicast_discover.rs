// Part of the APK.audio project — http://APK.audio — made by Anthony Kuzub
// MIT Licence. Free, for everyone, for ever. Full text in LICENSE at the root.
//! Find an NMOS registry by **unicast** DNS-SD, from a terminal.
//!
//! Owns: turning `apkaudio_nmos::unicast` into something a person can run and
//! read. It resolves, prints, and exits; it opens no HTTP connection and
//! publishes nothing to the broker — see the module header on why this crate is
//! allowed to do neither.
//!
//!     cargo run -p apkaudio-nmos --example unicast_discover
//!     cargo run -p apkaudio-nmos --example unicast_discover -- 127.0.0.1:5100 testsuite.nmos.tv
//!
//! With no arguments it browses every search domain in `/etc/resolv.conf`
//! against every nameserver there. With arguments it asks ONE resolver about
//! ONE domain — which is the shape the AMWA suite's `IS-04-04 test_01` needs,
//! because that test stands its DNS server up on `PORT_BASE + 100` and serves
//! `testsuite.nmos.tv`, neither of which a host's resolv.conf will ever name.
//!
//! EXIT CODE. Non-zero when nothing was found, so a lane can gate on it. An
//! empty browse is a real answer and it is still a failure for a caller that
//! needed a registry — the message says which of the two happened.
//! PLAN-975.01.

use apkaudio_nmos::unicast::{
    browse, browse_host_domains, host_resolvers, query_api_url, select_registry, Resolver,
    ServiceInstance, QUERY_SERVICE,
};
use std::net::SocketAddr;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let timeout = Duration::from_secs(2);

    let found: Vec<(String, ServiceInstance)> = match args.as_slice() {
        [] => {
            let hosts = host_resolvers();
            if hosts.servers.is_empty() {
                eprintln!("❌ [NMOS] /etc/resolv.conf names no nameserver — nothing to ask");
                std::process::exit(2);
            }
            if hosts.domains.is_empty() {
                // The systemd-resolved stub case. Saying so beats browsing
                // `local` and reporting that unicast found nothing.
                eprintln!(
                    "❌ [NMOS] /etc/resolv.conf names no search domain — unicast DNS-SD has \
                     nothing to browse. Pass a resolver and a domain explicitly."
                );
                std::process::exit(2);
            }
            println!(
                "🚀 [NMOS] unicast DNS-SD: {} in {:?} via {:?}",
                QUERY_SERVICE, hosts.domains, hosts.servers
            );
            browse_host_domains(QUERY_SERVICE, &hosts, timeout)
        }
        [server, domain] => {
            let address: SocketAddr = match server.parse() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("❌ [NMOS] '{server}' is not a host:port — {e}");
                    std::process::exit(2);
                }
            };
            println!("🚀 [NMOS] unicast DNS-SD: {QUERY_SERVICE} in {domain} via {address}");
            match browse(&Resolver { server: address, timeout }, QUERY_SERVICE, domain) {
                Ok(instances) => instances.into_iter().map(|i| (domain.clone(), i)).collect(),
                Err(e) => {
                    eprintln!("❌ [NMOS] {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("usage: unicast_discover [<resolver-host:port> <domain>]");
            std::process::exit(2);
        }
    };

    if found.is_empty() {
        eprintln!("⚠️  [NMOS] the resolver answered and advertised no Query API");
        std::process::exit(1);
    }

    for (domain, instance) in &found {
        println!(
            "   ✅ [NMOS] {} in {domain} — pri {} srv {} — {}",
            instance.name.instance(),
            instance.priority(),
            instance.srv_priority,
            query_api_url(instance)
        );
    }

    let candidates: Vec<ServiceInstance> = found.into_iter().map(|(_, i)| i).collect();
    match select_registry(&candidates) {
        Some(chosen) => println!("🎯 [NMOS] selected {}", query_api_url(chosen)),
        None => {
            // Everything advertised pri >= 100, or advertised no pri at all.
            eprintln!("⚠️  [NMOS] every registry found says do-not-use (pri >= 100 or absent)");
            std::process::exit(1);
        }
    }
}
