//! A shared literal prefilter for built-in and ruleset detectors (issues
//! #983, #1057).
//!
//! Most built-in detectors can only propose a candidate when the scan copy
//! contains one of a few case-sensitive literals: a provider prefix
//! (`ghp_`), a marker (`.atlasv1.`) or a separator pair. Each such detector
//! declares those literals when it is registered ([`RequiredLiterals`]).
//! A built-in registry compiles every declaration once into one
//! [`LiteralMatcher`], and the pipeline makes one pass over each scan copy
//! with it: the pass reports exactly which declaring detectors have a
//! literal in the input. A detector none of whose literals occurs is
//! skipped: it would have searched the whole input and returned nothing.
//!
//! The test is exact. The matcher compares every literal byte for byte at
//! every offset whose two bytes begin one, so a detector is skipped exactly
//! when none of its literals occurs anywhere in the scan copy. (The #983
//! version tested a hashed 1,024-bit set of byte pairs instead; beyond a few
//! KB of text the set filled up and almost nothing was skipped.)
//!
//! The declaration is private to the registry. It is never read from the
//! public `Detector` trait, so custom detectors, and the built-ins that
//! cannot name such a literal (`generic-token`, keyword-gated detectors,
//! bare-shape detectors such as `discord`), always run.
//!
//! A ruleset detector (`super::ruleset_adapter`) is registered through that
//! public trait like any custom detector, so the registry cannot tell it
//! from one and it declares nothing there. It filters itself instead, with
//! [`ruleset_literal_may_occur`]: the pipeline marks the scan copy it is
//! scanning ([`ScanScope`]), and a ruleset detector handed exactly that copy
//! asks the byte pairs of the copy, built once per call and shared by every
//! ruleset detector, whether its prefix can occur.

use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

use super::pattern::PrefixShape;

/// Bits in a [`PairSet`]. A power of two, so the hash keeps its top bits.
const PAIR_SET_BITS: usize = 1024;

/// How far [`pair_slot`] shifts its product to keep `log2(PAIR_SET_BITS)`
/// bits.
const PAIR_SLOT_SHIFT: u32 = u32::BITS - PAIR_SET_BITS.trailing_zeros();

/// Every 16-bit byte pair, one bit each: an exact [`PairTable`] and the
/// [`LiteralMatcher`]'s lead set.
const PAIR_TABLE_WORDS: usize = (1 << 16) / 64;

/// Scan copies at least this long get an exact [`PairTable`] instead of a
/// hashed [`PairSet`]: past a few KB of text the 1,024-bit set is mostly
/// full, while the table's 8 KiB is cheap next to the text itself.
const EXACT_PAIRS_FROM: usize = 4 * 1024;

/// The bitset slot of the byte pair `(first, second)`: a multiplicative
/// hash of the pair's 16-bit value.
fn pair_slot(first: u8, second: u8) -> usize {
    let pair = u32::from(u16::from_le_bytes([first, second]));
    // The top bits of a product by an odd constant (Fibonacci hashing).
    (pair.wrapping_mul(0x9E37_79B1) >> PAIR_SLOT_SHIFT) as usize
}

/// The 16-bit value of the byte pair `(first, second)`, the index of its
/// bit in a [`PairTable`] or a [`LiteralMatcher`]'s lead set.
const fn pair_index(first: u8, second: u8) -> usize {
    ((first as usize) << 8) | second as usize
}

/// Which adjacent byte pairs occur in one short scan copy, as a hashed
/// bitset.
///
/// A 1024-bit set costs 128 bytes to clear, which matters because an
/// incremental session scans one closed line at a time; an exact
/// 65,536-bit [`PairTable`] would cost 8 KiB per line.
pub(crate) struct PairSet {
    bits: [u64; PAIR_SET_BITS / 64],
}

impl PairSet {
    /// The pairs of `text`.
    pub(crate) fn of(text: &[u8]) -> Self {
        let mut bits = [0u64; PAIR_SET_BITS / 64];
        for pair in text.windows(2) {
            let slot = pair_slot(pair[0], pair[1]);
            bits[slot / 64] |= 1 << (slot % 64);
        }
        Self { bits }
    }

    /// `false` only when the pair `(first, second)` occurs nowhere in the
    /// text.
    fn may_contain(&self, first: u8, second: u8) -> bool {
        let slot = pair_slot(first, second);
        self.bits[slot / 64] & (1 << (slot % 64)) != 0
    }

    /// `false` only when `literal` cannot occur in the text: one of its
    /// consecutive pairs occurs nowhere.
    fn may_contain_literal(&self, literal: &[u8]) -> bool {
        literal
            .windows(2)
            .all(|pair| self.may_contain(pair[0], pair[1]))
    }
}

/// Which adjacent byte pairs occur in one scan copy, exactly: one bit per
/// 16-bit pair, so it never fills up however long the text is.
struct PairTable {
    bits: [u64; PAIR_TABLE_WORDS],
}

impl PairTable {
    /// The pairs of `text`.
    fn of(text: &[u8]) -> Box<Self> {
        let mut table = Box::new(Self {
            bits: [0; PAIR_TABLE_WORDS],
        });
        for pair in text.windows(2) {
            let index = pair_index(pair[0], pair[1]);
            table.bits[index / 64] |= 1 << (index % 64);
        }
        table
    }

    /// `false` exactly when the pair `(first, second)` occurs nowhere in
    /// the text.
    const fn contains(&self, first: u8, second: u8) -> bool {
        let index = pair_index(first, second);
        self.bits[index / 64] & (1 << (index % 64)) != 0
    }

    /// `false` only when `literal` cannot occur in the text: one of its
    /// consecutive pairs occurs nowhere. Two pairs from different places
    /// still pass, so this is conservative, never exact.
    fn may_contain_literal(&self, literal: &[u8]) -> bool {
        literal
            .windows(2)
            .all(|pair| self.contains(pair[0], pair[1]))
    }
}

/// The byte pairs of a scan copy, sized to it: a hashed [`PairSet`] for a
/// short copy, an exact [`PairTable`] for a long one.
enum Pairs {
    Hashed(PairSet),
    Exact(Box<PairTable>),
}

impl Pairs {
    fn of(text: &[u8]) -> Self {
        if text.len() < EXACT_PAIRS_FROM {
            Self::Hashed(PairSet::of(text))
        } else {
            Self::Exact(PairTable::of(text))
        }
    }

    fn may_contain_literal(&self, literal: &[u8]) -> bool {
        match self {
            Self::Hashed(pairs) => pairs.may_contain_literal(literal),
            Self::Exact(pairs) => pairs.may_contain_literal(literal),
        }
    }
}

/// One group of a detector's declared literals, named the way its grammar
/// already holds them, so a declaration reuses the scan's own constants
/// instead of retyping them. Plain data: a declaration is a `const`, and
/// walking it is one non-generic function, which keeps the declarations
/// out of the WebAssembly code size.
#[derive(Clone, Copy)]
pub(super) enum Literals {
    /// Byte-string constants (`b"SG."`).
    Bytes(&'static [&'static [u8]]),
    /// String constants (`"ghp_"`).
    Strs(&'static [&'static str]),
    /// The first string of each pair of a `(prefix, finding type)` table.
    Prefixes(&'static [(&'static str, &'static str)]),
    /// The prefix of each shape of a [`PrefixShape`] table.
    Shapes(&'static [PrefixShape<'static>]),
}

impl Literals {
    fn for_each(self, visit: &mut dyn FnMut(&'static [u8])) {
        match self {
            Self::Bytes(literals) => literals.iter().for_each(|literal| visit(literal)),
            Self::Strs(literals) => literals
                .iter()
                .for_each(|literal| visit(literal.as_bytes())),
            Self::Prefixes(pairs) => pairs
                .iter()
                .for_each(|(prefix, _)| visit(prefix.as_bytes())),
            Self::Shapes(shapes) => shapes
                .iter()
                .for_each(|shape| visit(shape.prefix.as_bytes())),
        }
    }
}

/// The case-sensitive literals at least one of which occurs in the scan
/// copy whenever a detector proposes any candidate.
///
/// Every literal has at least two bytes, so the [`LiteralMatcher`] can key
/// it by its first byte pair. [`Self::any_of`] refuses a list with a
/// shorter one, and the detector then always runs. The declaration borrows
/// the detector's own `'static` grammar tables, so registering a built-in
/// allocates nothing for it.
#[derive(Clone, Copy)]
pub(crate) struct RequiredLiterals {
    groups: &'static [Literals],
}

impl std::fmt::Debug for RequiredLiterals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequiredLiterals").finish_non_exhaustive()
    }
}

impl RequiredLiterals {
    /// A declaration from every literal in `groups`, or `None` (always run
    /// the detector) when there is none or one is shorter than two bytes.
    pub(super) fn any_of(groups: &'static [Literals]) -> Option<Self> {
        let mut count = 0usize;
        let mut too_short = false;
        for group in groups {
            group.for_each(&mut |literal| {
                count += 1;
                too_short |= literal.len() < 2;
            });
        }
        (count > 0 && !too_short).then_some(Self { groups })
    }

    /// Calls `visit` with every declared literal, in declaration order.
    fn for_each(self, visit: &mut dyn FnMut(&'static [u8])) {
        for group in self.groups {
            group.for_each(visit);
        }
    }

    /// Every declared literal, in declaration order.
    #[cfg(test)]
    pub(crate) fn literals(self) -> Vec<&'static [u8]> {
        let mut literals = Vec::new();
        self.for_each(&mut |literal| literals.push(literal));
        literals
    }
}

/// Words in a [`SlotSet`].
const SLOT_WORDS: usize = 4;

/// Detectors one [`LiteralMatcher`] can cover: registry positions
/// `0..MAX_SLOTS`. A registry with a declaration past it gets no matcher,
/// and every detector then runs.
const MAX_SLOTS: usize = SLOT_WORDS * 64;

/// A set of registry positions, one bit each.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SlotSet {
    bits: [u64; SLOT_WORDS],
}

impl SlotSet {
    fn insert(&mut self, slot: usize) {
        self.bits[slot / 64] |= 1 << (slot % 64);
    }

    /// `true` when `slot` is in the set.
    pub(crate) fn contains(&self, slot: usize) -> bool {
        slot < MAX_SLOTS && self.bits[slot / 64] & (1 << (slot % 64)) != 0
    }

    fn len(&self) -> u32 {
        self.bits.iter().map(|word| word.count_ones()).sum()
    }
}

/// One declared literal and the registry position of the detector that
/// declared it.
#[derive(Clone, Copy)]
struct Entry {
    literal: &'static [u8],
    slot: u16,
}

/// Every literal a registry's detectors declared, compiled once so that one
/// pass over a scan copy finds exactly which detectors have one.
///
/// The pass tests each offset's two bytes against a 65,536-bit lead set;
/// only an offset where some literal begins goes on to compare the
/// literals with that first pair. The matcher is built from `'static`
/// declarations and reused by every registry of the same profile.
pub(crate) struct LiteralMatcher {
    /// Bit `pair_index(a, b)` is set when some literal begins with `a b`.
    leads: Box<[u64; PAIR_TABLE_WORDS]>,
    /// Every declared literal, sorted by its first pair (then by slot).
    entries: Box<[Entry]>,
    /// `(first pair, start, end)`: the `entries` beginning with each lead
    /// pair, sorted by pair.
    groups: Box<[(u16, u32, u32)]>,
    /// The slots that declared anything.
    declared: SlotSet,
}

impl std::fmt::Debug for LiteralMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiteralMatcher").finish_non_exhaustive()
    }
}

impl LiteralMatcher {
    /// Compiles the declarations of a registry's detectors, given in
    /// registry order: the `n`th item is the declaration of the detector at
    /// position `n`, if any. `None` when a declaring detector sits past
    /// [`MAX_SLOTS`], so no detector could be skipped safely.
    pub(crate) fn compile<'a>(
        declarations: impl IntoIterator<Item = Option<&'a RequiredLiterals>>,
    ) -> Option<Self> {
        let mut entries = Vec::new();
        let mut declared = SlotSet::default();
        for (slot, required) in declarations.into_iter().enumerate() {
            let Some(required) = required else {
                continue;
            };
            let Ok(slot_id) = u16::try_from(slot) else {
                return None;
            };
            if slot >= MAX_SLOTS {
                return None;
            }
            declared.insert(slot);
            required.for_each(&mut |literal| {
                entries.push(Entry {
                    literal,
                    slot: slot_id,
                });
            });
        }
        let lead = |entry: &Entry| pair_index(entry.literal[0], entry.literal[1]);
        entries.sort_by_key(|entry| (lead(entry), entry.slot));
        let mut leads = Box::new([0u64; PAIR_TABLE_WORDS]);
        let mut groups: Vec<(u16, u32, u32)> = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            let pair = lead(entry);
            leads[pair / 64] |= 1 << (pair % 64);
            let index = u32::try_from(index).ok()?;
            match groups.last_mut() {
                Some((last, _, end)) if usize::from(*last) == pair => *end = index + 1,
                _ => groups.push((u16::try_from(pair).ok()?, index, index + 1)),
            }
        }
        Some(Self {
            leads,
            entries: entries.into_boxed_slice(),
            groups: groups.into_boxed_slice(),
            declared,
        })
    }

    /// The literals whose first pair is `pair`, which is in the lead set.
    fn group(&self, pair: usize) -> &[Entry] {
        self.groups
            .binary_search_by_key(&pair, |&(lead, _, _)| usize::from(lead))
            .map_or(&[], |found| {
                let (_, start, end) = self.groups[found];
                &self.entries[start as usize..end as usize]
            })
    }

    /// The registry positions whose detector declared a literal that occurs
    /// in `text`. The pass stops early once every declaring detector has
    /// one.
    pub(crate) fn present(&self, text: &[u8]) -> SlotSet {
        let mut present = SlotSet::default();
        let mut remaining = self.declared.len();
        if remaining == 0 {
            return present;
        }
        for (offset, pair) in text.windows(2).enumerate() {
            let lead = pair_index(pair[0], pair[1]);
            if self.leads[lead / 64] & (1 << (lead % 64)) == 0 {
                continue;
            }
            let rest = &text[offset..];
            for entry in self.group(lead) {
                let slot = usize::from(entry.slot);
                if !present.contains(slot) && rest.starts_with(entry.literal) {
                    present.insert(slot);
                    remaining -= 1;
                    if remaining == 0 {
                        return present;
                    }
                }
            }
        }
        present
    }
}

/// The scan copy the pipeline is scanning on this thread, and its byte
/// pairs once a ruleset detector has asked for them.
struct ActiveScan {
    /// Address and length of the scan copy: a detector handed a `&str` with
    /// both is handed the very same, still borrowed, bytes.
    start: usize,
    len: usize,
    pairs: Option<Pairs>,
    /// The lines holding a long alphabet run, as byte ranges, once a
    /// bare-shape detector has asked (issue #1075). Never text.
    long_run_lines: Option<Rc<[(usize, usize)]>>,
}

thread_local! {
    static ACTIVE_SCAN: RefCell<Option<ActiveScan>> = const { RefCell::new(None) };
}

/// Marks `scanned` as the scan copy the pipeline is running detectors on,
/// for [`ruleset_literal_may_occur`], until dropped. Scopes nest: a detector
/// that itself scans restores the outer scan's mark when its scan returns.
pub(crate) struct ScanScope {
    previous: Option<ActiveScan>,
    /// A scope restores this thread's mark, so it must stay on it.
    _not_send: PhantomData<*const ()>,
}

impl ScanScope {
    pub(crate) fn enter(scanned: &str) -> Self {
        let active = ActiveScan {
            start: scanned.as_ptr() as usize,
            len: scanned.len(),
            pairs: None,
            long_run_lines: None,
        };
        let previous = ACTIVE_SCAN
            .try_with(|cell| {
                cell.try_borrow_mut()
                    .ok()
                    .and_then(|mut current| current.replace(active))
            })
            .ok()
            .flatten();
        Self {
            previous,
            _not_send: PhantomData,
        }
    }
}

impl Drop for ScanScope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        let _ = ACTIVE_SCAN.try_with(|cell| {
            if let Ok(mut current) = cell.try_borrow_mut() {
                *current = previous;
            }
        });
    }
}

/// `false` only when `literal` provably occurs nowhere in `input`: `input`
/// is the scan copy of the innermost [`ScanScope`] on this thread, and one
/// of `literal`'s byte pairs occurs nowhere in it. Every other case —
/// outside a scan, a different or partial input, a literal shorter than two
/// bytes — answers `true`, so a caller only ever skips work that would have
/// found nothing.
pub(crate) fn ruleset_literal_may_occur(input: &str, literal: &[u8]) -> bool {
    if literal.len() < 2 {
        return true;
    }
    ACTIVE_SCAN
        .try_with(|cell| {
            let Ok(mut current) = cell.try_borrow_mut() else {
                return true;
            };
            match current.as_mut() {
                Some(active)
                    if active.start == input.as_ptr() as usize && active.len == input.len() =>
                {
                    active
                        .pairs
                        .get_or_insert_with(|| Pairs::of(input.as_bytes()))
                        .may_contain_literal(literal)
                }
                _ => true,
            }
        })
        .unwrap_or(true)
}

/// The lines of `input` that hold a run of 32 or more `[A-Za-z0-9+/=_-]`
/// bytes ([`super::text::long_run_line_spans`]), when `input` is the scan
/// copy of the innermost [`ScanScope`] on this thread; built once per scan
/// copy and shared by every bare-shape detector. `None` in every other case
/// (outside a scan, a different or partial input), where the caller walks
/// every line as before.
pub(super) fn long_run_lines(input: &str) -> Option<Rc<[(usize, usize)]>> {
    ACTIVE_SCAN
        .try_with(|cell| {
            let mut current = cell.try_borrow_mut().ok()?;
            let active = current.as_mut()?;
            if active.start != input.as_ptr() as usize || active.len != input.len() {
                return None;
            }
            let spans = active.long_run_lines.get_or_insert_with(|| {
                let spans = super::text::long_run_line_spans(input);
                // Every skipped line must hold no long run, so a detector
                // skipping it would have found nothing.
                #[cfg(debug_assertions)]
                assert_eq!(spans, super::text::long_run_line_spans_by_line(input));
                spans.into()
            });
            Some(Rc::clone(spans))
        })
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_literal_is_possible_exactly_when_all_its_pairs_occur() {
        let pairs = PairSet::of(b"xx re_ yy");
        assert!(pairs.may_contain_literal(b"re_"));
        // `re` alone occurs, `e_` alone occurs, but `ab` does not.
        assert!(!pairs.may_contain_literal(b"ab"));
        let split = PairSet::of(b"re e_");
        // Both pairs occur, apart: a false positive the prefilter allows.
        assert!(split.may_contain_literal(b"re_"));
        let neither = PairSet::of(b"r e _");
        assert!(!neither.may_contain_literal(b"re_"));
    }

    #[test]
    fn every_occurring_literal_is_reported_possible() {
        let text = b"prefix ghp_ AKIA sk-proj- xoxb- .atlasv1. 0: \xff\x00 end";
        let pairs = PairSet::of(text);
        let table = PairTable::of(text);
        for start in 0..text.len() {
            for end in start + 2..=text.len() {
                assert!(pairs.may_contain_literal(&text[start..end]));
                assert!(table.may_contain_literal(&text[start..end]));
            }
        }
    }

    #[test]
    fn the_pair_table_is_exact_for_every_pair() {
        let text = b"ab\xff\x00zz";
        let table = PairTable::of(text);
        for first in 0..=u8::MAX {
            for second in 0..=u8::MAX {
                let occurs = text.windows(2).any(|pair| pair == [first, second]);
                assert_eq!(table.contains(first, second), occurs);
            }
        }
    }

    #[test]
    fn declarations_refuse_short_or_empty_literal_lists() {
        assert!(RequiredLiterals::any_of(&[]).is_none());
        assert!(RequiredLiterals::any_of(&[Literals::Strs(&[])]).is_none());
        assert!(RequiredLiterals::any_of(&[Literals::Strs(&["ghp_", "x"])]).is_none());
        assert!(
            RequiredLiterals::any_of(&[Literals::Strs(&["ghp_"]), Literals::Bytes(&[b"x"])])
                .is_none()
        );
        assert!(RequiredLiterals::any_of(&[Literals::Strs(&["ghp_", "gho_"])]).is_some());
    }

    #[test]
    fn a_declaration_matches_exactly_when_a_literal_occurs() {
        let github = RequiredLiterals::any_of(&[
            Literals::Prefixes(&[("ghp_", "github_token")]),
            Literals::Bytes(&[b"glpat-"]),
        ])
        .unwrap();
        let separator = RequiredLiterals::any_of(&[Literals::Strs(&["0:", "==", "re_"])]).unwrap();
        let matcher =
            LiteralMatcher::compile([None, Some(&github), None, Some(&separator)]).unwrap();
        let present = |text: &[u8]| {
            let found = matcher.present(text);
            (0..4)
                .filter(|&slot| found.contains(slot))
                .collect::<Vec<_>>()
        };
        assert_eq!(present(b"token glpat-abc"), [1]);
        assert_eq!(present(b"plain prose only"), [] as [usize; 0]);
        assert_eq!(present(b""), [] as [usize; 0]);
        assert_eq!(present(b"g"), [] as [usize; 0]);
        // Every pair of `re_` occurs, apart: the pair tests would pass it,
        // the matcher does not.
        assert_eq!(present(b"re e_ glpat"), [] as [usize; 0]);
        assert_eq!(present(b"x==ghp_"), [1, 3]);
        assert_eq!(present(b"ghp"), [] as [usize; 0]);
        assert_eq!(present(b"10:"), [3]);
    }

    #[test]
    fn a_declaration_past_the_slot_limit_compiles_no_matcher() {
        let github = RequiredLiterals::any_of(&[Literals::Strs(&["ghp_"])]).unwrap();
        let mut declarations = vec![None; MAX_SLOTS];
        declarations.push(Some(&github));
        assert!(LiteralMatcher::compile(declarations).is_none());
        let mut within = vec![None; MAX_SLOTS - 1];
        within.push(Some(&github));
        let matcher = LiteralMatcher::compile(within).unwrap();
        assert!(matcher.present(b"ghp_").contains(MAX_SLOTS - 1));
    }

    #[test]
    fn a_ruleset_literal_is_ruled_out_only_for_the_marked_scan_copy() {
        let scanned = String::from("prose with no prefix at all");
        // Outside any scan, nothing is ruled out.
        assert!(ruleset_literal_may_occur(&scanned, b"ACME_"));
        {
            let _scope = ScanScope::enter(&scanned);
            assert!(!ruleset_literal_may_occur(&scanned, b"ACME_"));
            assert!(ruleset_literal_may_occur(&scanned, b"prefix"));
            // A part of the copy, or another string, is not the copy.
            assert!(ruleset_literal_may_occur(&scanned[1..], b"ACME_"));
            assert!(ruleset_literal_may_occur(&scanned[..4], b"ACME_"));
            let other = String::from("prose with no prefix at all");
            assert!(ruleset_literal_may_occur(&other, b"ACME_"));
            {
                // A nested scan marks its own copy, then restores the outer.
                let inner = String::from("ACME_ inner");
                let _inner = ScanScope::enter(&inner);
                assert!(ruleset_literal_may_occur(&inner, b"ACME_"));
                assert!(ruleset_literal_may_occur(&scanned, b"ACME_"));
            }
            assert!(!ruleset_literal_may_occur(&scanned, b"ACME_"));
        }
        assert!(ruleset_literal_may_occur(&scanned, b"ACME_"));
    }

    use crate::detectors::{built_in_entries, common_built_in_entries};
    use crate::registry::DetectorRegistry;
    use crate::types::DetectorContext;
    use crate::{DefaultPolicy, scan};

    /// Short text mixing prose, non-ASCII and invisible code points.
    const SHORT_BASE: &str = "config: value é 漢字 🙂 \u{200B}x\u{FEFF}y end\n";

    /// Over [`EXACT_PAIRS_FROM`] bytes of mixed log, JSON, source and
    /// non-ASCII lines; ASCII digits and colons are common in it, as in
    /// real logs.
    fn long_base() -> String {
        let line = "2026-09-30T12:34:56Z INFO request id=42 path=/v1/items status=200 \
                    {\"name\":\"value\",\"list\":[1,2,3]} fn main() { let x = y; } \
                    naïve café 東京 🙂 \u{200B}zero\u{2060}width\n";
        let text = line.repeat(EXACT_PAIRS_FROM / line.len() + 2);
        assert!(text.len() > EXACT_PAIRS_FROM);
        text
    }

    /// `text` with `inserted` placed at the char boundary at or after
    /// `at`.
    fn insert_at(text: &str, at: usize, inserted: &str) -> String {
        let mut at = at.min(text.len());
        while !text.is_char_boundary(at) {
            at += 1;
        }
        format!("{}{inserted}{}", &text[..at], &text[at..])
    }

    /// Inputs that contain `literal`, lack it by one byte, or split it with
    /// an invisible code point, at the start, middle and end of `base`.
    fn variants(base: &str, literal: &str) -> Vec<String> {
        let value = format!("{literal}SYNTHETIC0123456789abcdefREVOKED0000");
        let mut split = literal.to_owned();
        let second = literal
            .char_indices()
            .nth(1)
            .map_or(literal.len(), |(at, _)| at);
        split.insert(second, '\u{200B}');
        let truncated = &literal[..literal.len() - 1];
        vec![
            format!("{value}{base}"),
            insert_at(base, base.len() / 2, &format!(" {value} ")),
            format!("{base}{literal}"),
            insert_at(base, base.len() / 3, truncated),
            insert_at(base, base.len() / 3, &format!("{split}SYNTHETIC0123456789")),
            format!("{base}{truncated}"),
        ]
    }

    /// Checks one registry's matcher on `text` against a substring oracle,
    /// and that every detector it would skip proposes nothing; then scans
    /// `text`, whose debug-build check covers the normalized scan copy.
    fn check_exact(registry: &DetectorRegistry, text: &str) {
        let matcher = registry.prefilter().unwrap();
        let present = matcher.present(text.as_bytes());
        let context = DetectorContext::new(text.len());
        for (slot, registered) in registry.detectors().iter().enumerate() {
            let Some(required) = registered.required_literals() else {
                assert!(!present.contains(slot));
                continue;
            };
            let occurs = required.literals().iter().any(|literal| {
                text.as_bytes()
                    .windows(literal.len())
                    .any(|window| window == *literal)
            });
            assert_eq!(present.contains(slot), occurs, "{}", registered.id());
            if !occurs {
                assert!(
                    registered
                        .detector()
                        .detect(text, &context)
                        .is_ok_and(|candidates| candidates.is_empty()),
                    "{} would be skipped but proposes a candidate",
                    registered.id()
                );
            }
        }
        let _ = scan(text, registry, &DefaultPolicy);
    }

    /// The compiled matcher finds exactly the detectors with a literal in
    /// the input — never fewer, which would skip an emitting detector, and
    /// never more — on short and long (exact-table-sized) inputs that
    /// contain, lack, truncate, or invisibly split each declared literal.
    #[test]
    fn the_matcher_is_exact_and_never_skips_an_emitting_detector() {
        let long = long_base();
        for registry in [
            DetectorRegistry::with_built_in([]).unwrap(),
            DetectorRegistry::with_common_built_in([]).unwrap(),
        ] {
            let literals: Vec<&str> = registry
                .detectors()
                .iter()
                .filter_map(|registered| registered.required_literals())
                .flat_map(|required| required.literals())
                .map(|literal| std::str::from_utf8(literal).unwrap())
                .collect();
            check_exact(&registry, "");
            check_exact(&registry, SHORT_BASE);
            check_exact(&registry, &long);
            for literal in &literals {
                for text in variants(SHORT_BASE, literal) {
                    check_exact(&registry, &text);
                }
            }
            // Long inputs cost more per check in a debug build; every
            // seventh literal still covers every detector family's shape.
            for literal in literals.iter().step_by(7) {
                for text in variants(&long, literal) {
                    check_exact(&registry, &text);
                }
            }
        }
    }

    /// A ruleset detector returns the same candidates inside a pipeline
    /// scan, where it may rule its prefix out from shared byte pairs, as
    /// outside one, where it always searches.
    #[test]
    fn ruleset_detectors_find_the_same_with_and_without_the_prefilter() {
        let ruleset = "ruleset-revision: 1\n\
                       detector: acme-internal-token\n\
                       specificity: contextual\n\
                       prefix: \"ACME_\"\n\
                       alphabet: alnum-dash\n\
                       run: at-least 12\n\
                       validator: none\n\
                       detector: acme-checksum-token\n\
                       specificity: entropy\n\
                       prefix: \"re_q\"\n\
                       alphabet: alnum\n\
                       run: at-least 8\n\
                       validator: trailing-lower-hex\n\
                       detector: acme-unicode-token\n\
                       specificity: contextual\n\
                       prefix: \"é_k\"\n\
                       alphabet: alnum\n\
                       run: exact 10\n\
                       validator: none\n";
        let detectors = crate::load_ruleset(ruleset.as_bytes()).unwrap();
        let long = long_base();
        for base in [SHORT_BASE, long.as_str()] {
            let _scope = ScanScope::enter(base);
            // The prefilter does rule a prefix out, so the comparison
            // below is not vacuous.
            assert!(!ruleset_literal_may_occur(base, b"ACME_"));
        }
        let mut inputs = vec![String::new(), SHORT_BASE.to_owned(), long.clone()];
        for base in [SHORT_BASE, long.as_str()] {
            for literal in ["ACME_", "re_q", "é_k"] {
                inputs.extend(variants(base, literal));
            }
            // Every pair of `re_q` present, apart.
            inputs.push(format!("{base} re e_ _q"));
        }
        for input in &inputs {
            let context = DetectorContext::new(input.len());
            for detector in &detectors {
                let unfiltered = detector.detect(input, &context).unwrap();
                let filtered = {
                    let _scope = ScanScope::enter(input);
                    detector.detect(input, &context).unwrap()
                };
                assert_eq!(filtered, unfiltered, "{}", detector.id());
            }
        }
        let registry = DetectorRegistry::with_built_in(detectors).unwrap();
        for input in &inputs {
            let _ = scan(input, &registry, &DefaultPolicy);
        }
    }

    #[test]
    fn full_declares_93_detectors_and_common_4() {
        let declared = |entries: Vec<super::super::BuiltIn>| {
            entries
                .iter()
                .filter(|entry| entry.required.is_some())
                .count()
        };
        assert_eq!(declared(built_in_entries()), 93);
        assert_eq!(declared(common_built_in_entries()), 4);
    }

    /// The set of built-ins that declare nothing is exactly the reviewed
    /// list of detectors that cannot name a required case-sensitive literal
    /// (issue #983 research), so a new detector is a deliberate choice.
    #[test]
    fn only_the_reviewed_built_ins_run_on_every_call() {
        let always: Vec<String> = built_in_entries()
            .into_iter()
            .filter(|entry| entry.required.is_none())
            .map(|entry| entry.detector.id().to_owned())
            .collect();
        assert_eq!(
            always,
            [
                "twilio-auth-token",
                "twilio-api-key-secret",
                "discord-bot-token",
                "datadog-api-key",
                "datadog-application-key-legacy",
                "new-relic-license-key",
                "pinecone-api-key",
                "confluent-cloud-api-secret-legacy",
                "heroku-api-key-legacy",
                "travisci-api-token",
                "mistral-api-key",
                "cohere-api-key",
                "ai21-api-key",
                "deepgram-api-key",
                "convex-deployment-key",
                "bearer-token",
                "generic-token",
            ]
        );
    }

    /// Issue #1075: a bare-shape detector handed the scan copy walks only the
    /// lines holding a long run; handed anything else it walks every line.
    /// Both must find exactly the same candidates.
    #[test]
    fn bare_shape_detectors_agree_inside_and_outside_a_scan() {
        use crate::types::{Detector, DetectorContext};
        let detectors: Vec<Box<dyn Detector>> = vec![
            Box::new(super::super::twilio::TwilioAuthTokenDetector),
            Box::new(super::super::twilio::TwilioApiKeySecretDetector),
            Box::new(super::super::datadog::DatadogApiKeyDetector),
            Box::new(super::super::datadog::DatadogApplicationKeyLegacyDetector),
            Box::new(super::super::new_relic::NewRelicLicenseKeyDetector),
            Box::new(super::super::heroku::HerokuApiKeyLegacyDetector),
            Box::new(super::super::confluent::ConfluentLegacyApiSecretDetector),
            Box::new(super::super::pinecone::PineconeApiKeyDetector),
            Box::new(super::super::mailchimp::MailchimpMarketingApiKeyDetector),
        ];
        let hex32 = "0123456789abcdef0123456789abcdef";
        let hex40 = "0123456789abcdef0123456789abcdef01234567";
        let uuid = "01234567-89ab-cdef-0123-456789abcdef";
        let b64 = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCdEfGhIjKlMnOpQrStUvWxYz01";
        let alnum32 = "AbCdEfGhIjKlMnOpQrStUvWxYz012345";
        let pool: Vec<String> = vec![
            format!("TWILIO_AUTH_TOKEN={hex32}"),
            format!("AC{hex32} {hex32}"),
            format!("SK{alnum32} {alnum32}"),
            format!("twilio api {alnum32}"),
            "twilio profiles:list --properties authToken".to_owned(),
            "ID     Auth Token".to_owned(),
            format!("pf_one  {hex32}"),
            format!("DD_API_KEY={hex32}"),
            format!("datadog {hex40}"),
            format!("DD_APPLICATION_KEY={hex40}"),
            format!("NEW_RELIC_LICENSE_KEY={hex40}"),
            format!("{}FFFFNRAL", &hex32),
            format!("eu01xx{}FFFFNRAL", &hex32[..26]),
            format!("HEROKU_API_KEY={uuid}"),
            "heroku auth:token".to_owned(),
            format!("machine api.heroku.test password {uuid}"),
            format!("confluent.api.secret={b64}"),
            "schema.registry.url=https://confluent.test".to_owned(),
            format!("basic.auth.user.info=key:{b64}"),
            format!("pinecone_api_key = {uuid}"),
            format!("mailchimp {hex32}-us12"),
            format!("{hex32}-us1"),
            format!("{hex32}-us1.example.test"),
            "short line".to_owned(),
            "0123456789abcdef".to_owned(),
            String::new(),
            "caf\u{e9} \u{597D} 0123".to_owned(),
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state >> 33).unwrap()
        };
        let mut found = 0usize;
        for _ in 0..600 {
            let mut input = String::new();
            for _ in 0..=(next() % 9) {
                input.push_str(&pool[next() % pool.len()]);
                input.push_str(["\n", "\r\n", "\r", " ", "\n\n"][next() % 5]);
            }
            let context = DetectorContext::new(input.len());
            for detector in &detectors {
                let outside = detector.detect(&input, &context).unwrap();
                let inside = {
                    let _scope = ScanScope::enter(&input);
                    detector.detect(&input, &context).unwrap()
                };
                assert_eq!(inside, outside, "{} {input:?}", detector.id());
                found += outside.len();
            }
        }
        assert!(found > 500, "the inputs must exercise matches, saw {found}");
    }

    #[test]
    fn the_long_run_index_is_only_handed_out_for_the_active_scan_copy() {
        let input = format!("{}\nshort\n", "a".repeat(40));
        assert!(long_run_lines(&input).is_none());
        let _scope = ScanScope::enter(&input);
        assert_eq!(long_run_lines(&input).as_deref(), Some(&[(0, 40)][..]));
        assert!(long_run_lines(&input[..45]).is_none());
        assert!(long_run_lines(&input.clone()).is_none());
    }
}
