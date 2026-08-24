//! ChaCha20 stream cipher (RFC 8439). Used for volume payload encryption
//! with per-slot nonces derived from the slot generation.

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

/// The ChaCha20 block function: 64 bytes of keystream.
pub fn block(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    let working = state;
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let v = state[i].wrapping_add(working[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// XOR `data` with the keystream starting at block number `counter`.
pub fn xor_stream(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    let mut ctr = counter;
    for chunk in data.chunks_mut(64) {
        let ks = block(key, ctr, nonce);
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
        ctr = ctr.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; KEY_LEN] {
        let mut k = [0u8; 32];
        for i in 0..32 {
            k[i] = i as u8;
        }
        k
    }

    #[test]
    fn rfc8439_block_function() {
        // §2.3.2 block function test vector
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let ks = block(&key(), 1, &nonce);
        let expect_head: [u8; 16] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4,
        ];
        assert_eq!(&ks[..16], &expect_head);
    }

    #[test]
    fn rfc8439_encryption() {
        // §2.4.2/§2.4.4: encrypt the Sonnet 130 excerpt
        let key = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut data = *plaintext;
        xor_stream(&key, 1, &nonce, &mut data);
        let expect_head: [u8; 32] = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b,
        ];
        assert_eq!(&data[..32], &expect_head);
        // decrypting again restores plaintext
        xor_stream(&key, 1, &nonce, &mut data);
        assert_eq!(&data[..], plaintext);
    }
}
