// Part of the APK.audio project — http://APK.audio — made by Anthony Kuzub
// MIT Licence. Free, for everyone, for ever. Full text in LICENSE at the root.
//! Unicast DNS-SD — finding an NMOS registry through a **resolver**, not the link.
//!
//! # Why this exists, and why it is not the browse next door
//!
//! [`crate::run_browse_agent`] browses **multicast** DNS: it shouts
//! `_nmos-query._tcp.local.` at 224.0.0.251 and listens. That reaches exactly
//! one link and no further, and `local.` is the only domain it can ever name.
//!
//! AMWA IS-04 requires the other half as well (BCP-002 / IS-04 §Discovery): a
//! controller must be able to find a registry by asking a **named resolver**
//! for `_nmos-query._tcp.<domain>` — a normal DNS PTR, then SRV, then TXT —
//! where `<domain>` came from DHCP option 15 or the host's search list. That is
//! how a registry two subnets away is found, and no amount of multicast gets
//! there. The AMWA test suite's `IS-04-04 test_01`
//! (*"Ensure NCuT uses unicast DNS-SD to find registry"*) grades precisely this
//! walk: it stands up its own DNS server and passes when the controller under
//! test queries it. PLAN-975.01.
//!
//! # Why it lives HERE and not in the controller crate
//!
//! `apkaudio-nmos-control` is the HTTP client — Node, Query, Registration,
//! Connection. A DNS walk is not an NMOS API call; it is discovery, and this
//! crate's header already declares itself the discovery half by design. Putting
//! the resolver here keeps both contracts literally true: the controller still
//! calls APIs and nothing else, and this crate still discovers and connects to
//! nothing. The alternative — a DNS client inside the controller — would have
//! made two crates that both discover, which is the shape PLAN-319.01 was
//! carved to end. PLAN-975.01 step 2, decided and recorded rather than implied.
//!
//! # Precedence when a caller has two answers
//!
//! A controller can be **told** where the registry is (the AMWA suite's
//! pre-test question carries a URL in its prose) and can **resolve** one here.
//! The rule is: **an explicitly supplied Query API URL always wins.** Discovery
//! is a fallback, never an override — a bench that names a registry has said
//! which one it means, and silently preferring a DNS answer would grade a
//! different device from the one the operator pointed at. This module therefore
//! never reads a configured URL and never writes one; it answers "what is out
//! there", and the caller decides. Stated here because the caller is in another
//! crate and a precedence that lives only in a call site is not a rule.
//! That caller is `apkaudio_nmos_control::registry_agent::discover_query_base`,
//! the fallback behind both its `query_base` and its AMWA facade
//! (LOOSE-nmos-unicast); `examples/unicast_discover.rs` is the terminal one.
//!
//! # Scope
//!
//! Query only. Nothing here opens an HTTP connection, and
//! [`query_api_url`] builds a string rather than fetching it — the moment this
//! module speaks HTTP, the paragraph above stops being true.
//!
//! No DNSSEC validation: RFC 6763 §11 unicast DNS-SD does not require it, the
//! AMWA suite's DNS server does not sign, and a half-implemented validator that
//! accepts everything is worse than a stated absence.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

/// The service a controller browses for to find a registry.
pub const QUERY_SERVICE: &str = "_nmos-query._tcp";

/// The other three IS-04 / IS-09 service types, for a caller that wants them.
pub const REGISTRATION_SERVICE: &str = "_nmos-register._tcp";
/// The pre-rename spelling of the Registration API. Registries advertise both.
pub const REGISTRATION_SERVICE_LEGACY: &str = "_nmos-registration._tcp";
/// The Node API — what a registry browses for.
pub const NODE_SERVICE: &str = "_nmos-node._tcp";
/// IS-09 System API.
pub const SYSTEM_SERVICE: &str = "_nmos-system._tcp";

/// DNS RR types this module can read. Anything else is kept as bytes.
pub const T_A: u16 = 1;
/// Canonical name — followed when a PTR target is aliased.
pub const T_CNAME: u16 = 5;
/// Service instance pointer — the first step of the walk.
pub const T_PTR: u16 = 12;
/// The key/value blob: `api_ver`, `api_proto`, `api_auth`, `pri`.
pub const T_TXT: u16 = 16;
/// IPv6 address.
pub const T_AAAA: u16 = 28;
/// Target host, port, priority and weight for one instance.
pub const T_SRV: u16 = 33;

/// `IN` — the only class anything here asks for.
const CLASS_IN: u16 = 1;

/// The receive buffer for a UDP answer.
///
/// **NOT 512, and the difference is a measured bug.** 512 is the RFC 1035
/// payload a resolver may assume without EDNS0, and this module does not
/// advertise EDNS0 — so a *conforming* server truncates at 512, sets TC, and
/// [`Resolver::query_tcp`] re-asks. But `recvfrom` on a datagram larger than the
/// buffer keeps the first N bytes and **silently discards the rest**, and a
/// server that sends the big answer anyway is common enough that the first
/// out-of-process run of this walk hit it immediately: two registries with
/// realistic instance names, their SRV, TXT and one A record came to **717
/// bytes**, and a 512-byte buffer read them as `DnsError::Truncated` — a parse
/// failure, not a retry, because the TC bit was never set to trigger one.
///
/// The buffer is what this can RECEIVE; it is not a claim about what was asked
/// for. Sizing it past any answer a registry browse produces costs one page of
/// stack and removes a whole class of "found some of the registries".
const RECV_MAX: usize = 4096;

/// NMOS registries advertise a priority in TXT. **100 and above means "do not
/// use me"** — BCP-002-01 reserves that range for registries that are up but
/// must not be selected, which is not the same as absent. A candidate at or
/// above this is discovered, reported, and never chosen.
pub const PRIORITY_DO_NOT_USE: u32 = 100;

// ── errors ──────────────────────────────────────────────────────────────────

/// Everything that can go wrong between "ask a resolver" and "read an answer".
#[derive(Debug)]
pub enum DnsError {
    /// The socket failed, or the resolver did not answer inside the timeout.
    Io(std::io::Error),
    /// The message ended in the middle of a field. Never a panic: a malformed
    /// answer from a resolver on an untrusted network is an expected input.
    Truncated,
    /// Compression pointers that chase each other. A message can encode this,
    /// so the reader has to refuse it rather than loop.
    PointerLoop,
    /// A name that cannot go on the wire — a label over 63 bytes, or a name
    /// over 255.
    BadName(String),
    /// The resolver answered with a non-zero RCODE. 3 is NXDOMAIN, which for a
    /// browse means "no registry in that domain" rather than a fault.
    Rcode(u8),
    /// The answer's ID did not match the question's — an off-path reply, or a
    /// stale datagram from a previous query on the same socket.
    IdMismatch,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::Io(e) => write!(f, "dns transport: {e}"),
            DnsError::Truncated => write!(f, "dns message ended mid-field"),
            DnsError::PointerLoop => write!(f, "dns name compression pointer loop"),
            DnsError::BadName(n) => write!(f, "name cannot be encoded: {n}"),
            DnsError::Rcode(3) => write!(f, "dns NXDOMAIN — nothing advertised in that domain"),
            DnsError::Rcode(c) => write!(f, "dns rcode {c}"),
            DnsError::IdMismatch => write!(f, "dns answer did not match the question id"),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<std::io::Error> for DnsError {
    fn from(e: std::io::Error) -> Self {
        DnsError::Io(e)
    }
}

// ── names ───────────────────────────────────────────────────────────────────

/// A DNS name held as its **labels**, not as a dotted string.
///
/// THIS IS NOT PEDANTRY. A DNS-SD instance label is allowed to contain a dot —
/// `apk.audio (Cam)._nmos-query._tcp.example.com.` is four labels, not six —
/// and the presentation form escapes it as `apk\.audio`. Every implementation
/// that stores a name as a `String` and re-splits it on `'.'` to ask the next
/// question therefore asks the wrong question about exactly the instances whose
/// names read best. Keeping the labels means the SRV lookup for a PTR answer is
/// the bytes that came back, unparsed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Name {
    labels: Vec<Vec<u8>>,
}

impl Name {
    /// Parse a presentation-form name — `_nmos-query._tcp.example.com` — into
    /// labels, honouring `\.` and `\032` escapes so a round trip is lossless.
    pub fn parse(text: &str) -> Result<Name, DnsError> {
        let bytes = text.as_bytes();
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut label: Vec<u8> = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' if i + 3 < bytes.len() && bytes[i + 1..i + 4].iter().all(u8::is_ascii_digit) => {
                    let n: u32 = std::str::from_utf8(&bytes[i + 1..i + 4])
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(|| DnsError::BadName(text.to_string()))?;
                    if n > 255 {
                        return Err(DnsError::BadName(text.to_string()));
                    }
                    label.push(n as u8);
                    i += 4;
                }
                b'\\' if i + 1 < bytes.len() => {
                    label.push(bytes[i + 1]);
                    i += 2;
                }
                b'.' => {
                    // A trailing dot is the root and adds no label.
                    if !(label.is_empty() && i + 1 == bytes.len()) {
                        labels.push(std::mem::take(&mut label));
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
            labels.push(label);
        }
        let name = Name { labels };
        name.check()?;
        Ok(name)
    }

    /// Build a name by putting labels in front of an existing one — how
    /// `_nmos-query._tcp` plus `example.com` becomes the PTR question.
    pub fn service_in(service: &str, domain: &str) -> Result<Name, DnsError> {
        let mut name = Name::parse(service)?;
        name.labels.extend(Name::parse(domain)?.labels);
        name.check()?;
        Ok(name)
    }

    /// Refuse a name the wire cannot carry, rather than truncating it into a
    /// different name.
    fn check(&self) -> Result<(), DnsError> {
        let mut total = 1usize; // the root label
        for l in &self.labels {
            if l.is_empty() || l.len() > 63 {
                return Err(DnsError::BadName(self.to_string()));
            }
            total += 1 + l.len();
        }
        if total > 255 {
            return Err(DnsError::BadName(self.to_string()));
        }
        Ok(())
    }

    /// The labels, in order. `_nmos-query`, `_tcp`, `example`, `com`.
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// The first label as text — for a DNS-SD instance name, the human part.
    /// Escapes are undone, so this is for display and never for re-querying.
    pub fn instance(&self) -> String {
        self.labels
            .first()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .unwrap_or_default()
    }

    /// True when this name sits under `parent` — used to tell a PTR answer for
    /// the service we asked about from one we did not.
    pub fn is_under(&self, parent: &Name) -> bool {
        self.labels.len() > parent.labels.len()
            && self.labels[self.labels.len() - parent.labels.len()..] == parent.labels[..]
    }

    fn encode(&self, out: &mut Vec<u8>) {
        for l in &self.labels {
            out.push(l.len() as u8);
            out.extend_from_slice(l);
        }
        out.push(0);
    }
}

impl std::fmt::Display for Name {
    /// Presentation form, with the escapes put back, and always fully
    /// qualified — the trailing dot is part of the name.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for l in &self.labels {
            for &b in l {
                match b {
                    b'.' | b'\\' => write!(f, "\\{}", b as char)?,
                    0x21..=0x7e => write!(f, "{}", b as char)?,
                    other => write!(f, "\\{other:03}")?,
                }
            }
            write!(f, ".")?;
        }
        if self.labels.is_empty() {
            write!(f, ".")?;
        }
        Ok(())
    }
}

/// Read a name at `pos`, following compression pointers.
///
/// Returns the name and the offset **immediately after the name as it appeared
/// at `pos`** — which for a compressed name is two bytes on, not wherever the
/// pointer led. Getting that wrong walks the rest of the message off a cliff.
fn read_name(buf: &[u8], pos: usize) -> Result<(Name, usize), DnsError> {
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut at = pos;
    let mut after: Option<usize> = None;
    // A message can encode a pointer cycle. Bounding the hops by the message
    // length is the cheap proof that this terminates for any input at all.
    let mut hops = 0usize;
    loop {
        let len = *buf.get(at).ok_or(DnsError::Truncated)? as usize;
        if len & 0xc0 == 0xc0 {
            let lo = *buf.get(at + 1).ok_or(DnsError::Truncated)? as usize;
            let target = ((len & 0x3f) << 8) | lo;
            after.get_or_insert(at + 2);
            hops += 1;
            if hops > buf.len() || target >= buf.len() {
                return Err(DnsError::PointerLoop);
            }
            at = target;
            continue;
        }
        if len & 0xc0 != 0 {
            // 0b01 and 0b10 are reserved and have never been assigned.
            return Err(DnsError::Truncated);
        }
        if len == 0 {
            after.get_or_insert(at + 1);
            break;
        }
        let start = at + 1;
        let end = start + len;
        if end > buf.len() {
            return Err(DnsError::Truncated);
        }
        labels.push(buf[start..end].to_vec());
        at = end;
    }
    Ok((Name { labels }, after.unwrap_or(at)))
}

// ── messages ────────────────────────────────────────────────────────────────

/// One resource record, decoded as far as this module understands it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The owner name.
    pub name: Name,
    /// The RR type, as it appeared. Kept even for [`RData::Other`].
    pub rtype: u16,
    /// Seconds. Reported, never enforced — nothing here caches.
    pub ttl: u32,
    /// The decoded payload.
    pub data: RData,
}

/// The record payloads the walk needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    /// A service instance name — the answer to the browse.
    Ptr(Name),
    /// An alias. Followed once when a PTR target turns out to be one.
    Cname(Name),
    /// `priority`, `weight`, `port`, `target`.
    Srv {
        /// Lower is preferred, per RFC 2782.
        priority: u16,
        /// Relative share among equal priorities. Reported, not implemented —
        /// a controller picking a registry is not load balancing.
        weight: u16,
        /// TCP port of the API.
        port: u16,
        /// The host that answers.
        target: Name,
    },
    /// The character-strings, each already stripped of its length byte.
    Txt(Vec<Vec<u8>>),
    /// An IPv4 address.
    A(Ipv4Addr),
    /// An IPv6 address.
    Aaaa(Ipv6Addr),
    /// A type this module does not decode. Kept so a caller can see it was
    /// there rather than believing the answer was empty.
    Other(Vec<u8>),
}

/// A parsed DNS response. Only the fields the walk reads are kept.
#[derive(Debug, Clone, Default)]
pub struct Message {
    /// The transaction id, checked against the question's.
    pub id: u16,
    /// The TC bit — the answer did not fit in a datagram and must be re-asked
    /// over TCP.
    pub truncated: bool,
    /// The Answer section.
    pub answers: Vec<Record>,
    /// Additional — a resolver commonly puts the SRV target's A/AAAA and the
    /// instance's TXT here, which saves the walk a round trip.
    pub additional: Vec<Record>,
}

impl Message {
    /// Every record in the message, whichever section it arrived in.
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.answers.iter().chain(self.additional.iter())
    }
}

/// Build a query for one name and type.
pub fn encode_query(name: &Name, qtype: u16, id: u16) -> Result<Vec<u8>, DnsError> {
    name.check()?;
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&id.to_be_bytes());
    // RD (recursion desired). A stub asking a caching resolver needs it, and an
    // authoritative server that does not recurse simply ignores it.
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    name.encode(&mut out);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

fn be16(buf: &[u8], at: usize) -> Result<u16, DnsError> {
    let b = buf.get(at..at + 2).ok_or(DnsError::Truncated)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn be32(buf: &[u8], at: usize) -> Result<u32, DnsError> {
    let b = buf.get(at..at + 4).ok_or(DnsError::Truncated)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Decode a response. Never panics on a malformed message — every field read is
/// bounds-checked, because the input comes off a socket.
pub fn parse_message(buf: &[u8]) -> Result<Message, DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::Truncated);
    }
    let id = be16(buf, 0)?;
    let flags = be16(buf, 2)?;
    let rcode = (flags & 0x000f) as u8;
    let qd = be16(buf, 4)? as usize;
    let an = be16(buf, 6)? as usize;
    let ns = be16(buf, 8)? as usize;
    let ar = be16(buf, 10)? as usize;
    let truncated = flags & 0x0200 != 0;

    let mut at = 12usize;
    for _ in 0..qd {
        let (_, next) = read_name(buf, at)?;
        at = next + 4; // QTYPE + QCLASS
    }

    // The RCODE is read AFTER the header parses and BEFORE the sections, so a
    // NXDOMAIN is reported as itself rather than as a truncation of an empty
    // Answer section.
    if rcode != 0 {
        return Err(DnsError::Rcode(rcode));
    }

    let read_section = |count: usize, at: &mut usize| -> Result<Vec<Record>, DnsError> {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let (name, next) = read_name(buf, *at)?;
            let rtype = be16(buf, next)?;
            let _class = be16(buf, next + 2)?;
            let ttl = be32(buf, next + 4)?;
            let rdlen = be16(buf, next + 8)? as usize;
            let rstart = next + 10;
            let rend = rstart + rdlen;
            if rend > buf.len() {
                return Err(DnsError::Truncated);
            }
            let data = decode_rdata(buf, rtype, rstart, rend)?;
            out.push(Record { name, rtype, ttl, data });
            *at = rend;
        }
        Ok(out)
    };

    let answers = read_section(an, &mut at)?;
    let _authority = read_section(ns, &mut at)?;
    let additional = read_section(ar, &mut at)?;

    Ok(Message { id, truncated, answers, additional })
}

fn decode_rdata(buf: &[u8], rtype: u16, start: usize, end: usize) -> Result<RData, DnsError> {
    match rtype {
        T_PTR => Ok(RData::Ptr(read_name(buf, start)?.0)),
        T_CNAME => Ok(RData::Cname(read_name(buf, start)?.0)),
        T_SRV => {
            let priority = be16(buf, start)?;
            let weight = be16(buf, start + 2)?;
            let port = be16(buf, start + 4)?;
            // The target is read against the WHOLE message, not against the
            // RDATA slice: RFC 2782 targets are not compressed, but resolvers
            // in the wild compress them anyway and a slice-local reader would
            // decode a pointer as a length byte.
            let target = read_name(buf, start + 6)?.0;
            Ok(RData::Srv { priority, weight, port, target })
        }
        T_TXT => {
            let mut strings = Vec::new();
            let mut at = start;
            while at < end {
                let len = buf[at] as usize;
                let s = at + 1;
                let e = s + len;
                if e > end {
                    return Err(DnsError::Truncated);
                }
                strings.push(buf[s..e].to_vec());
                at = e;
            }
            Ok(RData::Txt(strings))
        }
        T_A if end - start == 4 => Ok(RData::A(Ipv4Addr::new(
            buf[start],
            buf[start + 1],
            buf[start + 2],
            buf[start + 3],
        ))),
        T_AAAA if end - start == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[start..end]);
            Ok(RData::Aaaa(Ipv6Addr::from(octets)))
        }
        _ => Ok(RData::Other(buf[start..end].to_vec())),
    }
}

/// Split TXT character-strings into the `key=value` map DNS-SD defines.
///
/// A string with no `=` is a key present with no value — RFC 6763 §6.4 — which
/// is NOT the same as absent, so it maps to an empty string rather than being
/// dropped. Keys are lowercased because the RFC says they are case-insensitive
/// and nmos-cpp, the AMWA mock registry and Avahi do not agree on the case.
pub fn txt_map(strings: &[Vec<u8>]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for s in strings {
        if s.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(s);
        let (k, v) = match text.split_once('=') {
            Some((k, v)) => (k, v.to_string()),
            None => (text.as_ref(), String::new()),
        };
        out.insert(k.trim().to_ascii_lowercase(), v);
    }
    out
}

// ── transport ───────────────────────────────────────────────────────────────

/// One resolver, and how long to wait for it.
#[derive(Debug, Clone)]
pub struct Resolver {
    /// Where the questions go. Port 53 unless a caller says otherwise — the
    /// AMWA suite runs its DNS server on `PORT_BASE + 100`, so this is not
    /// hard-coded anywhere.
    pub server: SocketAddr,
    /// Per-query wall clock. Applied to both UDP and the TCP retry.
    pub timeout: Duration,
}

impl Resolver {
    /// A resolver at `server` with the default two-second budget.
    pub fn new(server: SocketAddr) -> Resolver {
        Resolver { server, timeout: Duration::from_secs(2) }
    }

    /// Ask one question. Retries over TCP when the answer comes back with the
    /// TC bit — a registry advertising several instances overflows 512 bytes
    /// routinely, and a walk that read only the truncated datagram would find
    /// some of the registries some of the time.
    pub fn query(&self, name: &Name, qtype: u16) -> Result<Message, DnsError> {
        let id = query_id();
        let packet = encode_query(name, qtype, id)?;

        let bind: SocketAddr = match self.server {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().expect("literal"),
            SocketAddr::V6(_) => "[::]:0".parse().expect("literal"),
        };
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(self.timeout))?;
        socket.set_write_timeout(Some(self.timeout))?;
        socket.send_to(&packet, self.server)?;

        let mut buf = [0u8; RECV_MAX];
        let (n, from) = socket.recv_from(&mut buf)?;
        // A datagram from anywhere else is not the answer. Cheap, and the only
        // off-path check a stub resolver can make without DNSSEC.
        if from.ip() != self.server.ip() {
            return Err(DnsError::IdMismatch);
        }
        let message = parse_message(&buf[..n])?;
        if message.id != id {
            return Err(DnsError::IdMismatch);
        }
        if message.truncated {
            return self.query_tcp(&packet, id);
        }
        Ok(message)
    }

    fn query_tcp(&self, packet: &[u8], id: u16) -> Result<Message, DnsError> {
        let mut stream = TcpStream::connect_timeout(&self.server, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let len = u16::try_from(packet.len())
            .map_err(|_| DnsError::BadName("query too long for TCP framing".into()))?;
        stream.write_all(&len.to_be_bytes())?;
        stream.write_all(packet)?;
        stream.flush()?;

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf)?;
        let expect = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; expect];
        stream.read_exact(&mut body)?;
        let message = parse_message(&body)?;
        if message.id != id {
            return Err(DnsError::IdMismatch);
        }
        Ok(message)
    }
}

/// A per-query id.
///
/// Not a CSPRNG, and it does not need to be: this is a stub asking a resolver
/// it was configured with, over a socket bound to an ephemeral port, and the id
/// is here to match answers to questions rather than to resist an attacker who
/// can already see the port. `SystemTime` nanoseconds mixed with the address of
/// a stack local gives a different id per query in one process and across two.
fn query_id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let local = 0u8;
    let addr = std::ptr::addr_of!(local) as usize;
    ((nanos as usize ^ addr) & 0xffff) as u16
}

// ── the host's own configuration ────────────────────────────────────────────

/// The nameservers and search domains a `resolv.conf` declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostResolvers {
    /// In file order. The first is asked first.
    pub servers: Vec<IpAddr>,
    /// `search` if present, otherwise `domain`. These are the unicast browsing
    /// domains — RFC 6763 §11 says a host browses the domains it would append
    /// to an unqualified name, and DHCP option 15 is what puts them here.
    pub domains: Vec<String>,
}

/// Parse a `resolv.conf`. Takes the text rather than the path so it is testable
/// without a file, and so a caller inside a container can hand over the host's.
pub fn parse_resolv_conf(text: &str) -> HostResolvers {
    let mut out = HostResolvers::default();
    let mut domain_fallback: Option<String> = None;
    for raw in text.lines() {
        let line = raw.split(['#', ';']).next().unwrap_or("").trim();
        let mut words = line.split_whitespace();
        match words.next() {
            Some("nameserver") => {
                if let Some(ip) = words.next().and_then(|w| w.parse::<IpAddr>().ok()) {
                    out.servers.push(ip);
                }
            }
            // `search` wins over `domain` when both are present, and a later
            // `search` replaces an earlier one — that is resolv.conf's own rule,
            // not a simplification.
            Some("search") => out.domains = words.map(|w| w.trim_end_matches('.').to_string()).collect(),
            Some("domain") => {
                domain_fallback = words.next().map(|w| w.trim_end_matches('.').to_string())
            }
            _ => {}
        }
    }
    if out.domains.is_empty() {
        out.domains.extend(domain_fallback);
    }
    out
}

/// Read `/etc/resolv.conf`.
///
/// Empty when the file is unreadable, which is the honest answer: on a
/// systemd-resolved host the stub file lists `127.0.0.53` and no search domain
/// at all, so a caller must be able to see "nothing to browse" and say so
/// rather than be handed a guess.
pub fn host_resolvers() -> HostResolvers {
    std::fs::read_to_string("/etc/resolv.conf")
        .map(|t| parse_resolv_conf(&t))
        .unwrap_or_default()
}

// ── the walk ────────────────────────────────────────────────────────────────

/// One service instance, as the PTR/SRV/TXT walk found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInstance {
    /// The full instance name, labels intact.
    pub name: Name,
    /// The host the SRV names.
    pub target: Name,
    /// The TCP port.
    pub port: u16,
    /// SRV priority — lower is preferred.
    pub srv_priority: u16,
    /// SRV weight, reported only.
    pub srv_weight: u16,
    /// The TXT key/value pairs, keys lowercased.
    pub txt: HashMap<String, String>,
    /// Addresses for `target`, when the resolver volunteered them in
    /// Additional or answered the A/AAAA lookup.
    pub addresses: Vec<IpAddr>,
}

impl ServiceInstance {
    /// The NMOS advertised priority — TXT `pri`.
    ///
    /// Absent is [`PRIORITY_DO_NOT_USE`] and not zero: a registry that never
    /// said it was usable has not said it, and defaulting silence to "most
    /// preferred" is how an unconfigured box wins an election.
    pub fn priority(&self) -> u32 {
        self.txt
            .get("pri")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(PRIORITY_DO_NOT_USE)
    }

    /// `http` or `https`, from TXT `api_proto`. Defaults to `http`, which is
    /// what IS-04 says an absent key means.
    pub fn proto(&self) -> &str {
        match self.txt.get("api_proto").map(|s| s.trim()) {
            Some("https") => "https",
            _ => "http",
        }
    }

    /// The highest advertised API version, or `v1.3` when nothing was
    /// advertised — the version the AMWA suite defaults to.
    pub fn newest_version(&self) -> String {
        let raw = self.txt.get("api_ver").cloned().unwrap_or_default();
        let mut versions: Vec<&str> =
            raw.split(',').map(str::trim).filter(|v| !v.is_empty()).collect();
        if versions.is_empty() {
            return "v1.3".to_string();
        }
        versions.sort_by_key(|v| crate::version_key(v));
        versions.last().map(|s| s.to_string()).unwrap_or_else(|| "v1.3".into())
    }

    /// The host part of a URL: an address when one was resolved, otherwise the
    /// SRV target name with its trailing dot removed.
    pub fn host(&self) -> String {
        match self.addresses.first() {
            Some(IpAddr::V6(a)) => format!("[{a}]"),
            Some(IpAddr::V4(a)) => a.to_string(),
            None => self.target.to_string().trim_end_matches('.').to_string(),
        }
    }
}

/// The Query API base URL for an instance — what a controller would call.
///
/// A string, deliberately: this crate discovers and does not connect. See the
/// module header on precedence — a URL the caller was given always beats this.
pub fn query_api_url(instance: &ServiceInstance) -> String {
    format!(
        "{}://{}:{}/x-nmos/query/{}",
        instance.proto(),
        instance.host(),
        instance.port,
        instance.newest_version()
    )
}

/// Browse one service type in one domain over unicast DNS: PTR, then SRV and
/// TXT for each instance.
///
/// An instance whose SRV cannot be read is dropped and the others are kept — a
/// registry that is half-advertised must not take the working ones down with
/// it. `Ok(vec![])` means the domain answered and had nothing, which is a
/// different fact from an error and the caller can tell them apart.
pub fn browse(resolver: &Resolver, service: &str, domain: &str) -> Result<Vec<ServiceInstance>, DnsError> {
    let question = Name::service_in(service, domain)?;
    let ptr = match resolver.query(&question, T_PTR) {
        Ok(m) => m,
        // NXDOMAIN is "no such service in this domain", which is an empty
        // browse rather than a fault. Every other rcode is a fault.
        Err(DnsError::Rcode(3)) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut instances: Vec<Name> = Vec::new();
    for record in ptr.records() {
        if let RData::Ptr(target) = &record.data {
            if record.name == question && !instances.contains(target) {
                instances.push(target.clone());
            }
        }
    }

    let mut out = Vec::new();
    for name in instances {
        // A resolver that put the SRV and TXT in Additional has already
        // answered; only ask again for what is missing.
        if let Some(built) = build_instance(&name, &ptr, resolver) {
            out.push(built);
        }
    }
    Ok(out)
}

fn build_instance(name: &Name, hint: &Message, resolver: &Resolver) -> Option<ServiceInstance> {
    let mut srv = find_srv(name, hint);
    if srv.is_none() {
        srv = resolver.query(name, T_SRV).ok().and_then(|m| find_srv(name, &m));
    }
    let (srv_priority, srv_weight, port, target) = srv?;

    let mut txt = find_txt(name, hint);
    if txt.is_none() {
        txt = resolver.query(name, T_TXT).ok().and_then(|m| find_txt(name, &m));
    }
    let txt = txt.unwrap_or_default();

    let mut addresses = find_addresses(&target, hint);
    if addresses.is_empty() {
        for qtype in [T_A, T_AAAA] {
            if let Ok(m) = resolver.query(&target, qtype) {
                addresses.extend(find_addresses(&target, &m));
            }
        }
    }
    addresses.dedup();

    Some(ServiceInstance {
        name: name.clone(),
        target,
        port,
        srv_priority,
        srv_weight,
        txt,
        addresses,
    })
}

fn find_srv(name: &Name, message: &Message) -> Option<(u16, u16, u16, Name)> {
    message.records().find_map(|r| match &r.data {
        RData::Srv { priority, weight, port, target } if &r.name == name => {
            Some((*priority, *weight, *port, target.clone()))
        }
        _ => None,
    })
}

fn find_txt(name: &Name, message: &Message) -> Option<HashMap<String, String>> {
    message.records().find_map(|r| match &r.data {
        RData::Txt(strings) if &r.name == name => Some(txt_map(strings)),
        _ => None,
    })
}

fn find_addresses(target: &Name, message: &Message) -> Vec<IpAddr> {
    message
        .records()
        .filter(|r| &r.name == target)
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(*a)),
            RData::Aaaa(a) => Some(IpAddr::V6(*a)),
            _ => None,
        })
        .collect()
}

/// Browse every domain the host would search, newest answer last.
///
/// Returns the domain alongside each instance so a caller can say *where* it
/// found the registry — "found by unicast DNS-SD in `testsuite.nmos.tv`" is a
/// sentence an operator can act on; "found a registry" is not.
pub fn browse_host_domains(
    service: &str,
    hosts: &HostResolvers,
    timeout: Duration,
) -> Vec<(String, ServiceInstance)> {
    let mut found = Vec::new();
    for server in &hosts.servers {
        let resolver = Resolver { server: SocketAddr::new(*server, 53), timeout };
        for domain in &hosts.domains {
            if let Ok(instances) = browse(&resolver, service, domain) {
                for i in instances {
                    found.push((domain.clone(), i));
                }
            }
        }
    }
    found
}

/// Pick the registry a controller should use.
///
/// BCP-002-01's rule, and it is three comparisons rather than one:
/// lowest TXT `pri` first, then lowest SRV priority, then the name, so the
/// choice is stable across runs rather than dependent on answer order. Anything
/// at or above [`PRIORITY_DO_NOT_USE`] is excluded entirely — that range means
/// "up, but not for you".
pub fn select_registry(candidates: &[ServiceInstance]) -> Option<&ServiceInstance> {
    candidates
        .iter()
        .filter(|c| c.priority() < PRIORITY_DO_NOT_USE)
        .min_by(|a, b| {
            a.priority()
                .cmp(&b.priority())
                .then(a.srv_priority.cmp(&b.srv_priority))
                .then(a.name.to_string().cmp(&b.name.to_string()))
        })
}

#[cfg(test)]
#[path = "unicast_tests.rs"]
mod unicast_tests;
