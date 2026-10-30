// Part of the APK.audio project — http://APK.audio — made by Anthony Kuzub
// MIT Licence. Free, for everyone, for ever. Full text in LICENSE at the root.
//! nmos's self test — the API version summariser still reads a node's version list.
//!
//! Owns: the checks THIS crate can make about itself, and nothing about how
//! they are asked for. The contract in `apkaudio_contracts::self_test` owns the
//! two inputs, the withdrawal they perform and the words the answer may carry;
//! this file owns what is actually true.
//!
//! WHY IT IS A PLAIN FUNCTION AND NOT A BUS LOOP
//!
//! The check does not own the bus: since PLAN-3316.01 the plugin's own
//! container answers `selftest_run` for this module through apk-plugin-runner
//! (DISCOVERY.Engine/SRC/RUNNER), which calls the door below. A function over
//! the crate's own machinery is runnable by that runner, by `cargo test`, and
//! by a person at a terminal, and none of the three needs a broker to be up.
//! PLAN-459.01.
//!
//! WHAT A CHECK HERE MAY DO
//!
//! At [`Depth::Own`], nothing that leaves the process: no socket, no file
//! outside what is baked in at compile time, no clock it does not control.
//! Anything that reaches the host or the network is [`Depth::Device`], and the
//! contract records it as `skipped` when the run did not ask for it — so a
//! check filed at the wrong depth is caught rather than quietly performed.

use apkaudio_contracts::self_test::{Check, Depth, Report};

/// The topic segment this crate owns — the `{proto}` in
/// `APK.audio/System/Protocols/{proto}/…`, and the name its report is filed
/// under. It must match the section in `config.ini`, which is what
/// `config_section_still_names_this_module` below asserts.
pub const MODULE: &str = "nmos";

/// This crate's `config.ini`, baked in at compile time.
///
/// Read from the binary rather than from disk because a self test must not
/// depend on the working directory it was launched from — the plugin image
/// holds binaries, not this source tree, and a check that passed at a terminal
/// and failed in the container would be worse than no check.
const CONFIG_INI: &str = include_str!("../config.ini");

/// Everything this crate can prove about itself at `depth`.
pub fn self_test(depth: Depth) -> Report {
    let mut report = Report::new(MODULE, depth);

    // Every crate answers these two. The first proves this crate can address
    // its own mailbox at all; the second proves the name it addresses it with
    // is the one the config walk publishes it under.
    report.record(Check::from_result(
        "landing_spots_build",
        Depth::Own,
        "both inputs and all three readbacks address a legal topic",
        landing_spots(),
    ));
    report.record(Check::from_result(
        "config_section_still_names_this_module",
        Depth::Own,
        "config.ini declares this module under the name the bus knows it by",
        config_declares_module(),
    ));

    report.record(Check::from_result(
        "a_version_list_is_summarised",
        Depth::Own,
        "v1.2 and v1.3 are both named",
        {
            let summary = crate::summarise_versions("v1.2,v1.3");
            if summary.contains("1.3") {
                Ok(())
            } else {
                Err(format!("{summary:?} does not name the newest version"))
            }
        },
    ));
    report.record(Check::from_result(
        "an_unauthenticated_node_is_labelled_as_one",
        Depth::Own,
        "absent and present auth labels differ",
        {
            let absent = crate::auth_label(None);
            let present = crate::auth_label(Some(&"true".to_string()));
            if absent != present {
                Ok(())
            } else {
                Err(format!("both render {absent:?}"))
            }
        },
    ));

    report
}

/// The four self-test topics, built. An error here is a module name that
/// stopped being a legal topic segment — which would silently detach this
/// crate from its own mailbox rather than fail anywhere visible.
fn landing_spots() -> Result<(), String> {
    use apkaudio_contracts::self_test as st;
    st::engage_topic(MODULE).map_err(|e| format!("{e:?}"))?;
    st::run_topic(MODULE).map_err(|e| format!("{e:?}"))?;
    apkaudio_contracts::baremetal_io::module_incoming(MODULE, st::LEAF_RESULT)
        .map_err(|e| format!("{e:?}"))?;
    apkaudio_contracts::baremetal_io::module_incoming(MODULE, st::LEAF_REPORT)
        .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

/// Does `config.ini` open with `[nmos]`?
///
/// The drift this catches is quiet and total: apk-plugin-runner publishes this
/// crate's compiled-in `config.ini` retained under the section's own name
/// (`publish_config` in DISCOVERY.Engine/SRC/RUNNER/src/lib.rs). A section renamed without its crate puts this agent's
/// configuration on the bus under a name nothing reads, and every display goes
/// on showing the last good copy.
fn config_declares_module() -> Result<(), String> {
    let wanted = format!("[{MODULE}]");
    if CONFIG_INI.lines().any(|line| line.trim() == wanted) {
        Ok(())
    } else {
        Err(format!("config.ini does not declare {wanted}"))
    }
}

/// The same self test, across a workspace boundary.
///
/// The supervisor that collects these lives in the `Core` workspace, which has
/// its OWN lockfile and shares one `target/` with this one. A `Report` handed
/// across that line is only the same type while the two locks agree everywhere
/// below `apkaudio-contracts`, and when they stop agreeing the compiler says so
/// in a message that names neither the lockfile nor the workspace. So the
/// boundary is a serialization boundary and this is the only door through it:
/// a depth word in, JSON out, nothing but `&str` and `String` crossing.
pub fn self_test_json(depth_word: &str) -> String {
    apkaudio_contracts::self_test::run_as_json(MODULE, depth_word, self_test)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apkaudio_contracts::self_test::Verdict;

    /// The self test passes against the crate it is part of. If this fails,
    /// the crate is broken — which is the entire point of it existing.
    #[test]
    fn the_self_test_passes_against_this_build() {
        let report = self_test(Depth::Own);
        assert_eq!(report.verdict(), Verdict::Pass, "{}", report.headline());
    }

    /// A run that did not ask for the hardware does not touch it. Every check
    /// filed at `Depth::Device` comes back `skipped`, by the contract rather
    /// than by this crate remembering to skip it.
    #[test]
    fn a_self_depth_run_reaches_no_hardware() {
        let report = self_test(Depth::Own);
        for check in report.checks() {
            if check.depth == Depth::Device {
                assert_eq!(
                    check.outcome,
                    apkaudio_contracts::self_test::Outcome::Skipped,
                    "{} ran at self depth",
                    check.name
                );
            }
        }
    }

    /// The name this crate files its report under is the name the bus knows it
    /// by. A crate reporting under a name nothing subscribes to is a self test
    /// that passes into the void.
    #[test]
    fn the_module_name_is_a_legal_topic_segment() {
        assert!(apkaudio_contracts::topics::is_segment(MODULE));
        assert_eq!(landing_spots(), Ok(()));
    }

    /// The door the supervisor uses answers the same thing the typed function
    /// does. Two answers to one question is the failure a second entry point
    /// invites, so the two are tied together here rather than trusted.
    #[test]
    fn the_json_door_answers_what_the_typed_one_does() {
        let typed = self_test(Depth::Own);
        let parsed = apkaudio_contracts::self_test::Report::from_json(&self_test_json("self"))
            .expect("the door emits a report this crate can read back");
        assert_eq!(parsed.verdict(), typed.verdict());
        assert_eq!(parsed.counts(), typed.counts());
        assert_eq!(parsed.headline(), typed.headline());
    }
}
