//! Maintainer-only allocation-request harness for generic assignment
//! classification (issue #1121). Counts `alloc`/`realloc` requests (not peak
//! memory) of one whole-input `scan` over synthetic assignment fixtures, and
//! with `--attribute` aggregates requests by the innermost `redact_secret::`
//! frame of a captured backtrace (build with line tables for names).
//!
//! `cargo run --release -p redact-secret --example alloc_attribution -- [--attribute] [--time]`
//!
//! Synthetic data only; values are never printed.

#![allow(unsafe_code, clippy::pedantic, clippy::restriction, clippy::nursery)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use redact_secret::{DefaultPolicy, DetectorRegistry, scan};

static CALLS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static REENTRANT: Cell<bool> = const { Cell::new(false) };
    static CAPTURE: Cell<bool> = const { Cell::new(false) };
    static SITES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

struct Counting;

fn record(size: usize) {
    let capturing = CAPTURE.try_with(Cell::get).unwrap_or(false);
    let reentrant = REENTRANT.try_with(Cell::get).unwrap_or(true);
    if reentrant {
        return;
    }
    CALLS.fetch_add(1, Ordering::Relaxed);
    BYTES.fetch_add(size as u64, Ordering::Relaxed);
    if capturing {
        let _ = REENTRANT.try_with(|r| r.set(true));
        let bt = std::backtrace::Backtrace::force_capture().to_string();
        // Innermost crate frames (symbol + file:line), skipping this harness.
        let lines: Vec<&str> = bt.lines().map(str::trim).collect();
        let mut own: Vec<String> = Vec::new();
        for pair in lines.windows(2) {
            if let Some(loc) = pair[1].strip_prefix("at ./crates/secret-scan-core/src/") {
                let sym = pair[0].split_once(": ").map_or(pair[0], |(_, s)| s);
                let sym = sym.split('<').next().unwrap_or(sym);
                own.push(format!("{sym}@{loc}"));
                if own.len() == 2 {
                    break;
                }
            }
        }
        let site = own.join(" < ");
        let _ = SITES.try_with(|s| s.borrow_mut().push(site));
        let _ = REENTRANT.try_with(|r| r.set(false));
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        record(l.size());
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        record(n);
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Counting = Counting;

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn pick<'a>(&mut self, s: &'a [&'a str]) -> &'a str {
        s[self.next() as usize % s.len()]
    }
    fn string(&mut self, alphabet: &[u8], len: usize) -> String {
        (0..len)
            .map(|_| alphabet[self.next() as usize % alphabet.len()] as char)
            .collect()
    }
}

const B62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX: &[u8] = b"0123456789abcdef";
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const KEYS: &[&str] = &[
    "api_key",
    "secret",
    "password",
    "auth_token",
    "client_secret",
];

fn ordinary(n: usize) -> String {
    let mut r = Lcg(1);
    let mut s = String::new();
    for _ in 0..n {
        let v = r.string(B62, 32);
        s.push_str(&format!("api_key = \"{v}\"\n"));
    }
    s
}

fn diverse(n: usize) -> String {
    let mut r = Lcg(7);
    let mut s = String::new();
    for i in 0..n {
        let key = r.pick(KEYS);
        let v = match i % 5 {
            0 => {
                let len = 20 + (r.next() % 30) as usize;
                r.string(B62, len)
            }
            1 => r.string(HEX, 40),
            2 => format!("{}-{}", r.string(B62, 8), r.string(B62, 24)),
            3 => r.string(B64, 44),
            _ => format!("{}_{}", r.string(b"abcdefghijklmnop", 6), r.string(B62, 28)),
        };
        s.push_str(&format!("{key}: \"{v}\"\n"));
    }
    s
}

fn references(n: usize) -> String {
    let mut r = Lcg(11);
    let mut s = String::new();
    for i in 0..n {
        let a = r.string(b"abcdefghij", 8);
        let b = r.string(b"klmnopqrst", 9);
        let v = match i % 9 {
            0 => format!("projects/{a}-proj/secrets/{b}/versions/3"),
            1 => format!("arn:aws:secretsmanager:us-east-1:123456789012:secret:{a}/{b}-AbCdEf"),
            2 => format!("https://{a}.vault.azure.net/secrets/{b}"),
            3 => format!("ref+vault://secret/data/{a}#/{b}"),
            4 => format!("vault:secret/data/{a}#{b}"),
            5 => format!("{a}-key:your-{b}-key"),
            6 => format!("prod:{a}|super-secret-key"),
            7 => "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-us1".to_string(),
            _ => format!("projects/{a}/locations/x/secrets/{b}"),
        };
        s.push_str(&format!("api_key = \"{v}\"\n"));
    }
    s
}

fn main() {
    let attribute = std::env::args().any(|a| a == "--attribute");
    let timing = std::env::args().any(|a| a == "--time");
    let n = 1000;
    for (name, text) in [
        ("ordinary", ordinary(n)),
        ("diverse", diverse(n)),
        ("references", references(n)),
        ("otp-dense", otp_dense(n)),
        ("otp-sparse", otp_sparse()),
    ] {
        let registry = DetectorRegistry::with_built_in([]).unwrap();
        let policy = DefaultPolicy;
        let _ = scan(&text, &registry, &policy); // warm lazily-initialised statics
        let c0 = CALLS.load(Ordering::Relaxed);
        let b0 = BYTES.load(Ordering::Relaxed);
        if attribute {
            SITES.with(|s| s.borrow_mut().clear());
            CAPTURE.with(|c| c.set(true));
        }
        let found = scan(&text, &registry, &policy).unwrap();
        CAPTURE.with(|c| c.set(false));
        let calls = CALLS.load(Ordering::Relaxed) - c0;
        let bytes = BYTES.load(Ordering::Relaxed) - b0;
        // Digest of the full finding list (spans, types, confidence, order),
        // so two builds can be compared without printing any value.
        let digest = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            format!("{found:?}").hash(&mut hasher);
            hasher.finish()
        };
        println!(
            "{name}: findings={} alloc_calls={calls} requested_bytes={bytes} digest={digest:016x}",
            found.len()
        );
        if timing {
            let mut samples: Vec<u128> = (0..41)
                .map(|_| {
                    let start = std::time::Instant::now();
                    std::hint::black_box(scan(&text, &registry, &policy).unwrap());
                    start.elapsed().as_nanos()
                })
                .collect();
            samples.sort_unstable();
            println!(
                "    median {:.3} ms, min {:.3} ms",
                samples[20] as f64 / 1e6,
                samples[0] as f64 / 1e6
            );
        }
        if attribute {
            let mut agg: BTreeMap<String, u64> = BTreeMap::new();
            SITES.with(|s| {
                for site in s.borrow().iter() {
                    *agg.entry(site.clone()).or_default() += 1;
                }
            });
            let mut v: Vec<_> = agg.into_iter().collect();
            v.sort_by_key(|a| std::cmp::Reverse(a.1));
            for (k, c) in v.iter().take(16) {
                println!("    {c:>7}  {k}");
            }
        }
    }
}

/// Synthetic `otpauth://` URIs, one per line (issues #1145 and #1146).
fn otp_dense(n: usize) -> String {
    let mut r = Lcg(13);
    let mut s = String::new();
    for i in 0..n {
        let kind = if i % 2 == 0 { "totp" } else { "hotp" };
        let secret = r.string(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 24);
        s.push_str(&format!(
            "otpauth://{kind}/Example:user{i}@example.com?secret={secret}&issuer=Example\n"
        ));
    }
    s
}

/// One synthetic `otpauth://` URI inside about 74 KB of ordinary log text.
fn otp_sparse() -> String {
    let mut s = String::new();
    while s.len() < 74_000 {
        s.push_str("The quick brown fox, request id 12345, status ok; path /var/log/app.log\n");
    }
    s.push_str("otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example\n");
    s
}
