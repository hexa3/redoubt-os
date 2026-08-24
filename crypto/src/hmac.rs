//! HMAC-SHA-256 (RFC 2104). Used for volume superblock/slot integrity and
//! audit-record MACs.

use crate::sha256::{sha256, Sha256, DIGEST_LEN};

pub const TAG_LEN: usize = DIGEST_LEN;

const BLOCK: usize = 64;

pub struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; BLOCK];
        if key.len() > BLOCK {
            let d = sha256(key);
            k[..DIGEST_LEN].copy_from_slice(&d);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK];
        let mut opad = [0x5cu8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        let mut outer = Sha256::new();
        outer.update(&opad);
        HmacSha256 { inner, outer }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(mut self) -> [u8; TAG_LEN] {
        let inner_tag = self.inner.finalize();
        self.outer.update(&inner_tag);
        self.outer.finalize()
    }

    pub fn oneshot(key: &[u8], data: &[u8]) -> [u8; TAG_LEN] {
        let mut m = Self::new(key);
        m.update(data);
        m.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> [u8; TAG_LEN] {
        let mut out = [0u8; TAG_LEN];
        for i in 0..TAG_LEN {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn rfc4231_case1_and_2() {
        // TC1: key = 0x0b * 20, data = "Hi There"
        let key = [0x0bu8; 20];
        assert_eq!(
            HmacSha256::oneshot(&key, b"Hi There"),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        // TC2: key = "Jefe", data = "what do ya want for nothing?"
        assert_eq!(
            HmacSha256::oneshot(b"Jefe", b"what do ya want for nothing?"),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn long_key_is_hashed() {
        // key longer than the block size (64) must be hashed first
        let key = [0xaau8; 131];
        let t = HmacSha256::oneshot(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            t,
            hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }
}
