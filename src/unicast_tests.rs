// Part of the APK.audio project — http://APK.audio — made by Anthony Kuzub
// MIT Licence. Free, for everyone, for ever. Full text in LICENSE at the root.
//! Tests for the unicast DNS-SD walk.
//!
//! Owns: proving the wire format is read and written correctly, and proving the
//! PTR → SRV → TXT walk completes **over a real socket** against a server that
//! answers in real DNS bytes.
//!
//! WHY THERE IS A SERVER IN HERE. A parser tested only against fixtures its own
//! author encoded proves that two functions in one file agree with each other.
//! [`Authority`] below is a UDP DNS responder built by hand from the RFC 1035
//! field layout — header, question echo, answer section, compression pointers —
//! and the client walks it through `UdpSocket`, `send_to`, `recv_from`. It binds
//! `127.0.0.1:0`, so the kernel picks the port, nothing is left listening, and
//! the test needs no network, no root and no docker.
//!
//! It is deliberately NOT a re-use of the encoder: the responder writes its
//! bytes with `push` and `extend_from_slice`, so a mistake in `encode_query`
//! cannot cancel out against a matching mistake in the reader.

use super::*;
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::thread;

// ── the fixture authority ───────────────────────────────────────────────────

/// A one-shot-per-question UDP DNS server, speaking real bytes.
struct Authority {
    socket: UdpSocket,
}

/// Encode a presentation-form name the long way round, without the encoder
/// under test. `\.` is honoured so an escaped instance label can be built.
fn wire_name(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut label: Vec<u8> = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if i + 1 < bytes.len() => {
                label.push(bytes[i + 1]);
                i += 2;
            }
            b'.' => {
                if !label.is_empty() {
                    out.push(label.len() as u8);
                    out.extend_from_slice(&label);
                    label.clear();
                }
                i += 1;
            }
            b => {
                label.push(b);
                i += 1;
            }
        }
    }
    if !label.is_empty() {
        out.push(label.len() as u8);
        out.extend_from_slice(&label);
    }
    out.push(0);
    out
}

fn rr(name: &str, rtype: u16, rdata: &[u8]) -> Vec<u8> {
    let mut out = wire_name(name);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out.extend_from_slice(&120u32.to_be_bytes()); // TTL
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

fn srv_rdata(priority: u16, weight: u16, port: u16, target: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&priority.to_be_bytes());
    out.extend_from_slice(&weight.to_be_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&wire_name(target));
    out
}

fn txt_rdata(pairs: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in pairs {
        out.push(p.len() as u8);
        out.extend_from_slice(p.as_bytes());
    }
    out
}

impl Authority {
    fn bind() -> Authority {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        Authority { socket }
    }

    fn address(&self) -> SocketAddr {
        self.socket.local_addr().expect("local addr")
    }

    /// Answer `count` questions with an error RCODE and no records — how a
    /// resolver says NXDOMAIN (3) or SERVFAIL (2).
    fn serve_rcode(self, count: usize, rcode: u16) {
        thread::spawn(move || {
            let mut buf = [0u8; 1500];
            for _ in 0..count {
                let Ok((n, from)) = self.socket.recv_from(&mut buf) else {
                    return;
                };
                let request = &buf[..n];
                let (_, after) = read_name(request, 12).expect("question name");
                let mut out = Vec::new();
                out.extend_from_slice(&request[0..2]);
                out.extend_from_slice(&(0x8580u16 | rcode).to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&request[12..after + 4]);
                let _ = self.socket.send_to(&out, from);
            }
        });
    }

    /// Serve `count` questions, answering each from `answer`, which is handed
    /// the question name and qtype and returns (answer records, additional
    /// records). Runs on its own thread; the receiver reports what was asked so
    /// a test can assert the walk actually made the queries it claims to.
    fn serve(self, count: usize, answer: fn(&str, u16) -> (Vec<Vec<u8>>, Vec<Vec<u8>>)) -> mpsc::Receiver<(String, u16)> {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut buf = [0u8; 1500];
            for _ in 0..count {
                let Ok((n, from)) = self.socket.recv_from(&mut buf) else {
                    return;
                };
                let request = &buf[..n];
                let id = u16::from_be_bytes([request[0], request[1]]);
                // Decode the question with the module's own reader — the point
                // of the fixture is the ANSWER bytes, and re-implementing the
                // reader here would prove nothing about the client.
                let (qname, after) = read_name(request, 12).expect("question name");
                let qtype = u16::from_be_bytes([request[after], request[after + 1]]);
                let qtext = qname.to_string();
                let _ = tx.send((qtext.clone(), qtype));

                let (answers, additional) = answer(&qtext, qtype);
                let mut out = Vec::new();
                out.extend_from_slice(&id.to_be_bytes());
                // QR + AA + RD/RA.
                out.extend_from_slice(&0x8580u16.to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&(additional.len() as u16).to_be_bytes());
                out.extend_from_slice(&request[12..after + 4]); // echo the question
                for r in answers.iter().chain(additional.iter()) {
                    out.extend_from_slice(r);
                }
                let _ = self.socket.send_to(&out, from);
            }
        });
        rx
    }
}

const PTR_NAME: &str = "_nmos-query._tcp.testsuite.nmos.tv.";
const INSTANCE: &str = "mocks\\.registry 00._nmos-query._tcp.testsuite.nmos.tv.";
const TARGET: &str = "mocks.testsuite.nmos.tv.";

/// One resolver, one browse, one instance — answered in Additional, which is
/// what a real DNS-SD server does and what saves the walk two round trips.
fn one_shot(qname: &str, qtype: u16) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    if qname == PTR_NAME && qtype == T_PTR {
        return (
            vec![rr(PTR_NAME, T_PTR, &wire_name(INSTANCE))],
            vec![
                rr(INSTANCE, T_SRV, &srv_rdata(0, 0, 5102, TARGET)),
                rr(
                    INSTANCE,
                    T_TXT,
                    &txt_rdata(&["api_ver=v1.0,v1.1,v1.2,v1.3", "api_proto=http", "api_auth=false", "pri=0"]),
                ),
                rr(TARGET, T_A, &[127, 0, 0, 1]),
            ],
        );
    }
    (Vec::new(), Vec::new())
}

const INSTANCE_A: &str = "mocks-registry-0._nmos-query._tcp.testsuite.nmos.tv.";
const INSTANCE_B: &str = "mocks-registry-1._nmos-query._tcp.testsuite.nmos.tv.";

/// Two advertised registries with their SRV, TXT and the target's address, all
/// in one datagram. Uncompressed, which is what the Python responder that found
/// the buffer bug emitted, and 717 bytes on the wire.
fn two_registries(qname: &str, qtype: u16) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    if qname != PTR_NAME || qtype != T_PTR {
        return (Vec::new(), Vec::new());
    }
    (
        vec![
            rr(PTR_NAME, T_PTR, &wire_name(INSTANCE_A)),
            rr(PTR_NAME, T_PTR, &wire_name(INSTANCE_B)),
        ],
        vec![
            rr(INSTANCE_A, T_SRV, &srv_rdata(0, 0, 5102, TARGET)),
            rr(
                INSTANCE_A,
                T_TXT,
                &txt_rdata(&["api_ver=v1.0,v1.1,v1.2,v1.3", "api_proto=http", "api_auth=false", "pri=20"]),
            ),
            rr(INSTANCE_B, T_SRV, &srv_rdata(0, 0, 5202, TARGET)),
            rr(
                INSTANCE_B,
                T_TXT,
                &txt_rdata(&["api_ver=v1.3", "api_proto=http", "api_auth=false", "pri=5"]),
            ),
            rr(TARGET, T_A, &[127, 0, 0, 1]),
        ],
    )
}

// ── the walk, over a socket ─────────────────────────────────────────────────

/// THE MEASUREMENT. A real UDP exchange: the client asks a real server for the
/// PTR and reads a registry out of the answer, endpoint and all.
#[test]
fn a_registry_is_found_over_a_real_socket() {
    let authority = Authority::bind();
    let server = authority.address();
    let asked = authority.serve(1, one_shot);

    let resolver = Resolver { server, timeout: Duration::from_secs(5) };
    let found = browse(&resolver, QUERY_SERVICE, "testsuite.nmos.tv").expect("browse");

    assert_eq!(found.len(), 1, "one instance was advertised");
    let registry = &found[0];
    assert_eq!(registry.port, 5102);
    assert_eq!(registry.priority(), 0);
    assert_eq!(registry.proto(), "http");
    assert_eq!(registry.newest_version(), "v1.3");
    assert_eq!(
        query_api_url(registry),
        "http://127.0.0.1:5102/x-nmos/query/v1.3"
    );

    // The question that went out is the one IS-04-04 test_01 grades.
    let (qname, qtype) = asked.recv_timeout(Duration::from_secs(5)).expect("a question was asked");
    assert_eq!(qname, PTR_NAME);
    assert_eq!(qtype, T_PTR);
    // And exactly one: everything else was in Additional.
    assert!(asked.recv_timeout(Duration::from_millis(200)).is_err());
}

/// A dot inside an instance label survives the round trip. The SRV question the
/// walk asks must be the label bytes, not the six labels a `split('.')` would
/// have made of them.
#[test]
fn an_instance_label_containing_a_dot_stays_one_label() {
    let authority = Authority::bind();
    let server = authority.address();
    authority.serve(1, one_shot);

    let resolver = Resolver { server, timeout: Duration::from_secs(5) };
    let found = browse(&resolver, QUERY_SERVICE, "testsuite.nmos.tv").expect("browse");
    let name = &found[0].name;
    assert_eq!(name.labels().len(), 6, "instance + _nmos-query + _tcp + 3 domain labels");
    assert_eq!(name.instance(), "mocks.registry 00");
}

/// A domain the server knows and has nothing in is an empty browse.
#[test]
fn a_domain_with_no_instances_is_an_empty_browse() {
    let authority = Authority::bind();
    let server = authority.address();
    authority.serve(1, |_, _| (Vec::new(), Vec::new()));

    let resolver = Resolver { server, timeout: Duration::from_secs(5) };
    let found = browse(&resolver, QUERY_SERVICE, "empty.example").expect("browse");
    assert!(found.is_empty());
}

/// NXDOMAIN — the domain does not exist — is ALSO an empty browse and not a
/// fault. A controller that treated it as one would refuse to fall back to the
/// next search domain, which is the whole point of having a list.
#[test]
fn nxdomain_is_an_empty_browse_and_not_a_fault() {
    let authority = Authority::bind();
    let server = authority.address();
    authority.serve_rcode(1, 3);

    let resolver = Resolver { server, timeout: Duration::from_secs(5) };
    let found = browse(&resolver, QUERY_SERVICE, "nowhere.example").expect("browse");
    assert!(found.is_empty());
}

/// SERVFAIL is NOT an empty browse. "The resolver broke" and "there is no
/// registry here" are different facts and the caller has to be able to tell
/// them apart — that distinction is the reason `browse` returns a Result at all.
#[test]
fn servfail_is_reported_rather_than_read_as_no_registry() {
    let authority = Authority::bind();
    let server = authority.address();
    authority.serve_rcode(1, 2);

    let resolver = Resolver { server, timeout: Duration::from_secs(5) };
    assert!(matches!(
        browse(&resolver, QUERY_SERVICE, "broken.example"),
        Err(DnsError::Rcode(2))
    ));
}

/// THE REGRESSION. Two registries, their SRV, TXT and address, is **over 512
/// bytes** — measured at 717 for the pair below — and the first out-of-process
/// run of this walk read it as a malformed message because the receive buffer
/// was 512. `recvfrom` keeps what fits and drops the rest without saying so, so
/// the failure was a parse error rather than the TCP retry, and it would have
/// appeared exactly when a bench had more than one registry on it.
#[test]
fn a_udp_answer_over_five_hundred_and_twelve_bytes_is_read_whole() {
    let authority = Authority::bind();
    let server = authority.address();
    authority.serve(1, two_registries);

    let resolver = Resolver { server, timeout: Duration::from_secs(5) };
    let found = browse(&resolver, QUERY_SERVICE, "testsuite.nmos.tv").expect("browse");
    assert_eq!(found.len(), 2, "both registries survived the datagram");

    // And the selection rule then picks the lower `pri`, which is the second.
    let chosen = select_registry(&found).expect("one is usable");
    assert_eq!(chosen.port, 5202);
    assert_eq!(chosen.priority(), 5);
}

// ── the wire format ─────────────────────────────────────────────────────────

#[test]
fn a_query_carries_its_id_name_and_type() {
    let name = Name::service_in(QUERY_SERVICE, "testsuite.nmos.tv").expect("name");
    let packet = encode_query(&name, T_PTR, 0xbeef).expect("encode");
    assert_eq!(&packet[0..2], &[0xbe, 0xef]);
    assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 1, "one question");
    let (read_back, after) = read_name(&packet, 12).expect("name reads back");
    assert_eq!(read_back, name);
    assert_eq!(u16::from_be_bytes([packet[after], packet[after + 1]]), T_PTR);
}

/// A compression pointer must be followed, and the cursor must resume after the
/// POINTER rather than after the name it led to. Getting this wrong reads the
/// rest of the message as garbage without erroring.
#[test]
fn a_compression_pointer_is_followed_and_the_cursor_resumes_after_it() {
    let mut buf = vec![0u8; 12];
    buf.extend_from_slice(&wire_name("example.com."));
    let at = buf.len();
    buf.extend_from_slice(&[0x03, b'a', b'p', b'i', 0xc0, 12]);
    buf.push(0x99); // a byte that must be where the cursor lands

    let (name, after) = read_name(&buf, at).expect("compressed name");
    assert_eq!(name.to_string(), "api.example.com.");
    assert_eq!(after, buf.len() - 1);
    assert_eq!(buf[after], 0x99);
}

/// A message can encode a pointer that points at itself. The reader refuses it
/// instead of spinning — this arrives off a socket, from anyone.
#[test]
fn a_pointer_loop_is_refused_rather_than_looped() {
    let mut buf = vec![0u8; 12];
    buf.extend_from_slice(&[0xc0, 12]); // points at offset 12 — itself
    assert!(matches!(read_name(&buf, 12), Err(DnsError::PointerLoop)));
}

/// TXT is a list of length-prefixed strings, and a key with no `=` is present
/// with an empty value rather than absent.
#[test]
fn txt_strings_become_a_lowercased_map_and_a_bare_key_is_not_dropped() {
    let map = txt_map(&[
        b"API_VER=v1.3".to_vec(),
        b"api_proto=https".to_vec(),
        b"beta".to_vec(),
    ]);
    assert_eq!(map.get("api_ver").map(String::as_str), Some("v1.3"));
    assert_eq!(map.get("api_proto").map(String::as_str), Some("https"));
    assert_eq!(map.get("beta").map(String::as_str), Some(""));
}

/// A name too long for the wire is refused at encode time, not truncated into a
/// different name that would silently resolve to somebody else.
#[test]
fn an_over_long_label_cannot_be_encoded() {
    let long = "x".repeat(64);
    assert!(matches!(Name::parse(&long), Err(DnsError::BadName(_))));
}

#[test]
fn a_short_message_is_truncated_not_a_panic() {
    assert!(matches!(parse_message(&[0u8; 4]), Err(DnsError::Truncated)));
}

// ── selection ───────────────────────────────────────────────────────────────

fn candidate(instance: &str, pri: Option<&str>, srv_priority: u16) -> ServiceInstance {
    let mut txt = HashMap::new();
    if let Some(p) = pri {
        txt.insert("pri".to_string(), p.to_string());
    }
    ServiceInstance {
        name: Name::parse(instance).expect("name"),
        target: Name::parse("host.example.").expect("name"),
        port: 3211,
        srv_priority,
        srv_weight: 0,
        txt,
        addresses: Vec::new(),
    }
}

/// BCP-002-01: lowest `pri` wins, and 100+ means "up, but not for you".
#[test]
fn the_lowest_priority_registry_wins_and_a_hundred_is_excluded() {
    let all = vec![
        candidate("c._nmos-query._tcp.example.", Some("100"), 0),
        candidate("b._nmos-query._tcp.example.", Some("10"), 0),
        candidate("a._nmos-query._tcp.example.", Some("50"), 0),
    ];
    let chosen = select_registry(&all).expect("one is usable");
    assert_eq!(chosen.name.instance(), "b");

    let only_reserved = vec![candidate("c._nmos-query._tcp.example.", Some("100"), 0)];
    assert!(select_registry(&only_reserved).is_none(), "100+ is never chosen");
}

/// A registry that never advertised `pri` has not said it is usable. Defaulting
/// silence to zero would let an unconfigured box win the election.
#[test]
fn an_unadvertised_priority_is_not_zero() {
    let silent = candidate("q._nmos-query._tcp.example.", None, 0);
    assert_eq!(silent.priority(), PRIORITY_DO_NOT_USE);
    assert!(select_registry(&[silent]).is_none());
}

/// Equal `pri` falls through to the SRV priority, then to the name, so two runs
/// against the same registries pick the same one.
#[test]
fn ties_break_on_srv_priority_then_on_the_name() {
    let all = vec![
        candidate("z._nmos-query._tcp.example.", Some("0"), 10),
        candidate("y._nmos-query._tcp.example.", Some("0"), 5),
        candidate("x._nmos-query._tcp.example.", Some("0"), 5),
    ];
    assert_eq!(select_registry(&all).expect("chosen").name.instance(), "x");
}

// ── the host's configuration ────────────────────────────────────────────────

/// `search` wins over `domain`, comments are stripped, and a nameserver that is
/// not an address is skipped rather than becoming a hostname lookup.
#[test]
fn resolv_conf_yields_the_servers_and_the_browsing_domains() {
    let parsed = parse_resolv_conf(
        "# generated\n\
         domain corp.example\n\
         search testsuite.nmos.tv nmos.local.\n\
         nameserver 10.0.0.53\n\
         nameserver not-an-address\n\
         nameserver ::1  ; the v6 stub\n",
    );
    assert_eq!(
        parsed.servers,
        vec!["10.0.0.53".parse::<IpAddr>().unwrap(), "::1".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(parsed.domains, vec!["testsuite.nmos.tv", "nmos.local"]);
}

/// With no `search`, `domain` is the browsing domain.
#[test]
fn a_bare_domain_line_is_the_browsing_domain() {
    let parsed = parse_resolv_conf("nameserver 127.0.0.53\ndomain testsuite.nmos.tv.\n");
    assert_eq!(parsed.domains, vec!["testsuite.nmos.tv"]);
}

/// A systemd-resolved stub file lists a loopback server and NO search domain.
/// The honest answer is an empty domain list, so a caller can report "there is
/// nothing to browse" rather than being handed `local` and told it tried.
#[test]
fn a_stub_resolv_conf_has_nothing_to_browse() {
    let parsed = parse_resolv_conf("nameserver 127.0.0.53\noptions edns0 trust-ad\n");
    assert_eq!(parsed.servers.len(), 1);
    assert!(parsed.domains.is_empty());
    assert!(browse_host_domains(QUERY_SERVICE, &parsed, Duration::from_millis(50)).is_empty());
}
