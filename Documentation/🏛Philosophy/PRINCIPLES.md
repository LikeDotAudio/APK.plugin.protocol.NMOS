# Principles PLUGIN.NMOS keeps

Each rule is pointed at the code that keeps it; where the code bends one, it says so. Ecosystem
rules live in the root: [Refusal over fabrication](../../../../../../Documentation/%F0%9F%8F%9BPhilosophy/Doctrine/readme.Refusal%20over%20fabrication.md),
[Doctrine](../../../../../../Documentation/%F0%9F%8F%9BPhilosophy/Doctrine/readme.Doctrine.md).

← [Philosophy](INDEX.md) · [Repo README](../../README.md)

| Principle | Kept by |
|---|---|
| **Discovery only, and the boundary is a contract.** This crate finds; `apkaudio-nmos-control` calls APIs. The unicast DNS walk lives here because it is discovery, and it builds a URL without fetching it. | crate header, [`lib.rs:35-48`](../../SRC/src/lib.rs); [`unicast.rs`](../../SRC/src/unicast.rs) header, "Scope". |
| **Group by what is really one thing.** Rows key on `host:port`: two Node APIs on one host stay two rows; `_nmos-register` and `_nmos-registration` on one port merge. | `NMOS_SERVICES`, [`lib.rs:63`](../../SRC/src/lib.rs); "Grouping" in the header. |
| **Refusal over fabrication.** An absent `api_auth` is `?`, never `false`; a privacy-addressed host gets `-` for MAC, not a guess; an unadvertised registry `pri` is "do not use", not 0. | `auth_label`, `lib.rs:125`; `ServiceInstance::priority` and `PRIORITY_DO_NOT_USE`, [`unicast.rs:112`](../../SRC/src/unicast.rs). |
| **Unreachable is dead.** Device rows are unkept (QoS 0, retain clear) and restated every `restate_s` (config.ini, 30 s); a node that stops advertising leaves the restate, and its rows are cleared. | `say`, `lib.rs:148`; `Settings::from_ini`, `lib.rs:99`; `ServiceRemoved` arm, `lib.rs:355`; test `nothing_the_browse_agent_says_is_kept`, `lib.rs:518`. |
| **A supplied URL wins over a resolved one.** Unicast discovery is a fallback, never an override; the precedence is written where the walk lives so the caller in another crate cannot quietly change it. | [`unicast.rs`](../../SRC/src/unicast.rs) header, "Precedence"; kept by `apkaudio_nmos_control::registry_agent::query_base_with`. |
| **No half-implemented security.** No DNSSEC validation rather than one that accepts everything. | `unicast.rs:53`. |
| **A host that cannot hunt says so and stays up.** If the mDNS daemon cannot start, the agent restates `Agent/state = unavailable` (unkept, every `restate_s`) and retries, instead of returning into a Docker restart loop. | `say_unavailable` and the daemon loop in `run_browse_agent`; test `mdns_failure_is_retried_not_returned`. |
| **Quiet when nothing changed.** A re-resolve that changes nothing writes and prints nothing; only the restate repeats it. | the `published` map in `run_browse_agent`. |
| **Numbers sort as numbers.** `v1.10` ranks above `v1.9`. | `version_key` / `summarise_versions`, `lib.rs:151`; shared with `unicast.rs`. |

## Where the code bends a rule

* There is no `domain` key in [`SRC/config.ini`](../../SRC/config.ini) (it was read by nothing and is
  gone): the browse names `local.` in `NMOS_SERVICES`, and the unicast walk takes its domains from
  `/etc/resolv.conf` or its caller.
