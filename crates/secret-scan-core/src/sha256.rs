//! SHA-256 (FIPS 180-4) over a byte slice, used for one thing: the revision
//! binding of an action policy document
//! (`decision-explain-and-compare-action-policies-over-one-detection-pass`).
//!
//! The digest names a policy document, which is configuration and never a
//! secret. It is never computed over input text, a matched value or a
//! finding. The implementation is the plain one-shot form: no streaming
//! state, no allocation beyond the padded tail, and no dependency, so the
//! core's dependency boundary is unchanged.

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut schedule = [0_u32; 64];
    let (words, _) = block.as_chunks::<4>();
    for (slot, word) in schedule.iter_mut().zip(words) {
        *slot = u32::from_be_bytes(*word);
    }
    for index in 16..64 {
        let w15 = schedule[index - 15];
        let w2 = schedule[index - 2];
        let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
        let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(s1);
    }

    let mut working = *state;
    for index in 0..64 {
        let [aa, bb, cc, dd, ee, ff, gg, hh] = working;
        let big_s1 = ee.rotate_right(6) ^ ee.rotate_right(11) ^ ee.rotate_right(25);
        let choice = (ee & ff) ^ (!ee & gg);
        let temp1 = hh
            .wrapping_add(big_s1)
            .wrapping_add(choice)
            .wrapping_add(ROUND_CONSTANTS[index])
            .wrapping_add(schedule[index]);
        let big_s0 = aa.rotate_right(2) ^ aa.rotate_right(13) ^ aa.rotate_right(22);
        let majority = (aa & bb) ^ (aa & cc) ^ (bb & cc);
        let temp2 = big_s0.wrapping_add(majority);
        working = [
            temp1.wrapping_add(temp2),
            aa,
            bb,
            cc,
            dd.wrapping_add(temp1),
            ee,
            ff,
            gg,
        ];
    }
    for (slot, value) in state.iter_mut().zip(working) {
        *slot = slot.wrapping_add(value);
    }
}

/// The SHA-256 digest of `bytes`.
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut state = INITIAL_STATE;
    let (blocks, tail) = bytes.as_chunks::<64>();
    for block in blocks {
        compress(&mut state, block);
    }

    // The tail, then the 0x80 marker, zero padding and the 64-bit bit length.
    let mut padded = [0_u8; 128];
    padded[..tail.len()].copy_from_slice(tail);
    padded[tail.len()] = 0x80;
    let total = if tail.len() < 56 { 64 } else { 128 };
    let bit_length = (bytes.len() as u64).wrapping_mul(8);
    padded[total - 8..total].copy_from_slice(&bit_length.to_be_bytes());
    let (padded_blocks, _) = padded[..total].as_chunks::<64>();
    for block in padded_blocks {
        compress(&mut state, block);
    }

    let mut digest = [0_u8; 32];
    let (out_words, _) = digest.as_chunks_mut::<4>();
    for (out, word) in out_words.iter_mut().zip(state) {
        *out = word.to_be_bytes();
    }
    digest
}

/// Lowercase hexadecimal, 64 characters.
pub(crate) fn to_hex(digest: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        to_hex(&sha256(bytes))
    }

    #[test]
    fn matches_the_fips_180_4_vectors() {
        assert_eq!(
            hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn every_padding_boundary_length_is_stable_and_distinct() {
        let mut seen = std::collections::BTreeSet::new();
        for length in 0..=130_usize {
            let digest = hex(&vec![b'x'; length]);
            assert_eq!(digest.len(), 64);
            assert!(seen.insert(digest), "length {length} collided");
        }
    }
}
