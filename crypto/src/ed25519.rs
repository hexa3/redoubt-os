//! Ed25519 signatures (RFC 8032), verification used on-device for image
//! manifests and update packages, signing used by host tooling.
//!
//! Implementation notes:
//! - Field arithmetic in five 51-bit limbs; curve arithmetic in extended
//!   homogeneous coordinates (X:Y:Z:T) with the unified add-2008-hwcd-3
//!   formulas for a = -1, used for both addition and doubling.
//! - Domain parameters (d, sqrt(-1), the base point) are DERIVED at runtime
//!   from p rather than transcribed, removing an entire class of typos; the
//!   RFC test vectors below are the authority.
//! - Scalar reduction mod L uses straightforward binary long division; the
//!   arithmetic is not constant-time (see lib.rs contract notes).

use crate::sha512::{sha512, Sha512};

// ------------------------------------------------------------------ field

#[derive(Clone, Copy)]
struct Fe([u64; 5]);

const MASK51: u64 = (1u64 << 51) - 1;

/// 2p limb-wise (limb coefficients may exceed 2^51; they are plain
/// radix-coefficients). Guarantees `a + 2P - b >= 0` for any weakly-reduced
/// operands, so subtraction never wraps.
const TWO_P_LIMBS: [u64; 5] = [
    2 * (MASK51 - 18),
    2 * MASK51,
    2 * MASK51,
    2 * MASK51,
    2 * MASK51,
];

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn from_u64(v: u64) -> Fe {
        Fe([v & MASK51, v >> 51, 0, 0, 0])
    }

    fn from_bytes(b: &[u8; 32]) -> Fe {
        fn le64(s: &[u8]) -> u64 {
            let mut w = [0u8; 8];
            w.copy_from_slice(&s[..8]);
            u64::from_le_bytes(w)
        }
        Fe([
            le64(&b[0..8]) & MASK51,
            (le64(&b[6..14]) >> 3) & MASK51,
            (le64(&b[12..20]) >> 6) & MASK51,
            (le64(&b[19..27]) >> 1) & MASK51,
            (le64(&b[24..32]) >> 12) & MASK51,
        ])
    }

    /// Canonical little-endian encoding (fully reduced).
    fn to_bytes(self) -> [u8; 32] {
        const M: u64 = MASK51;
        let mut l = self.0;
        // Fold carries to a fixed point: a single pass can leave a pending
        // wrap out of the top limb (observed as p+k encodings).
        while l.iter().any(|&x| x > M) {
            let c = l[4] >> 51;
            l[4] &= M;
            l[0] += c * 19;
            for i in 0..4 {
                let ci = l[i] >> 51;
                l[i] &= M;
                l[i + 1] += ci;
            }
        }
        // Pack into four 64-bit words (little-endian order).
        let s0 = l[0] | (l[1] << 51);
        let s1 = (l[1] >> 13) | (l[2] << 38);
        let s2 = (l[2] >> 26) | (l[3] << 25);
        let s3 = (l[3] >> 39) | (l[4] << 12);
        // After folding the value lies below 2^255; reduce it modulo
        // p = 2^255 - 19 with at most one conditional subtraction.
        let ws = [s0, s1, s2, s3];
        const PW: [u64; 4] = [
            0xffff_ffff_ffff_ffed,
            u64::MAX,
            u64::MAX,
            0x7fff_ffff_ffff_ffff,
        ];
        // compare ws >= PW, most significant lane first
        let mut geq_p = core::cmp::Ordering::Equal;
        for i in (0..4).rev() {
            match ws[i].cmp(&PW[i]) {
                core::cmp::Ordering::Equal => continue,
                other => {
                    geq_p = other;
                    break;
                }
            }
        }
        let mut rw = ws;
        if geq_p != core::cmp::Ordering::Less {
            let mut br: i128 = 0;
            for i in 0..4 {
                let cur = ws[i] as i128 - PW[i] as i128 - br;
                if cur < 0 {
                    rw[i] = (cur + (1i128 << 64)) as u64;
                    br = 1;
                } else {
                    rw[i] = cur as u64;
                    br = 0;
                }
            }
            debug_assert_eq!(br, 0);
        }

        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&rw[0].to_le_bytes());
        out[8..16].copy_from_slice(&rw[1].to_le_bytes());
        out[16..24].copy_from_slice(&rw[2].to_le_bytes());
        out[24..32].copy_from_slice(&rw[3].to_le_bytes());
        out
    }

    fn weak_reduce(mut self) -> Fe {
        for i in 0..4 {
            let c = self.0[i] >> 51;
            self.0[i] &= MASK51;
            self.0[i + 1] += c;
        }
        let c = self.0[4] >> 51;
        self.0[4] &= MASK51;
        self.0[0] += c * 19;
        self
    }

    fn add(self, rhs: Fe) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + rhs.0[i];
        }
        Fe(r).weak_reduce()
    }

    fn sub(self, rhs: Fe) -> Fe {
        let a = self.weak_reduce();
        let b = rhs.weak_reduce();
        let mut r = [0u64; 5];
        for i in 0..5 {
            // a_i + 2p_i >= b_i because b is reduced limb-wise (< 2^51)
            r[i] = a.0[i] + TWO_P_LIMBS[i] - b.0[i];
        }
        Fe(r).weak_reduce()
    }

    fn neg(self) -> Fe {
        Fe::ZERO.sub(self)
    }

    fn mul(self, rhs: Fe) -> Fe {
        let a = self.weak_reduce().0;
        let b = rhs.weak_reduce().0;
        let b1_19 = (b[1] as u128) * 19;
        let b2_19 = (b[2] as u128) * 19;
        let b3_19 = (b[3] as u128) * 19;
        let b4_19 = (b[4] as u128) * 19;

        let a0 = a[0] as u128;
        let a1 = a[1] as u128;
        let a2 = a[2] as u128;
        let a3 = a[3] as u128;
        let a4 = a[4] as u128;
        let b0 = b[0] as u128;
        let b1 = b[1] as u128;
        let b2 = b[2] as u128;
        let b3 = b[3] as u128;
        let b4 = b[4] as u128;

        let r0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
        let r1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
        let r2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
        let r3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
        let r4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

        let mut t = [r0, r1, r2, r3, r4];
        // fold the u128 accumulators down into 51-bit limbs
        let c = (t[0] >> 51) as u64;
        t[0] &= MASK51 as u128;
        t[1] += c as u128;
        for i in 1..5 {
            let ci = (t[i] >> 51) as u64;
            t[i] &= MASK51 as u128;
            if i < 4 {
                t[i + 1] += ci as u128;
            } else {
                t[0] += (ci as u128) * 19;
                let c0 = (t[0] >> 51) as u64;
                t[0] &= MASK51 as u128;
                t[1] += c0 as u128;
            }
        }
        Fe([
            t[0] as u64,
            t[1] as u64,
            t[2] as u64,
            t[3] as u64,
            t[4] as u64,
        ])
    }

    fn square(self) -> Fe {
        self.mul(self)
    }

    fn pow_bytes_exp(self, exp_le: &[u8; 32]) -> Fe {
        let mut result = Fe::ONE;
        for byte_idx in (0..32).rev() {
            let byte = exp_le[byte_idx];
            for bit in (0..8).rev() {
                result = result.square();
                if (byte >> bit) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }

    fn invert(self) -> Fe {
        self.pow_bytes_exp(&exp_p_minus(2))
    }

    fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    fn is_zero(self) -> bool {
        let b = self.to_bytes();
        let mut acc = 0u8;
        for &x in &b {
            acc |= x;
        }
        acc == 0
    }

    fn eq(self, other: Fe) -> bool {
        self.sub(other).is_zero()
    }

    fn conditional_negate(self, choice: bool) -> Fe {
        if choice {
            self.neg()
        } else {
            self
        }
    }
}

/// p - k as little-endian bytes (k small).
fn exp_p_minus(k: u64) -> [u8; 32] {
    let mut e = [0xffu8; 32];
    e[0] = 0xed;
    e[31] = 0x7f;
    // subtract k from the little-endian number
    let mut borrow = k;
    for i in 0..32 {
        let cur = e[i] as u32;
        let sub = (borrow & 0xff) as u32;
        if cur >= sub {
            e[i] = (cur - sub) as u8;
            borrow >>= 8;
        } else {
            e[i] = (cur + 256 - sub) as u8;
            borrow = (borrow >> 8) + 1;
        }
        if borrow == 0 {
            break;
        }
    }
    e
}

fn exp_shr(mut e: [u8; 32], bits: u32) -> [u8; 32] {
    let mut carry = 0u8;
    for i in (0..32).rev() {
        let next = e[i] & ((1u16 << bits) - 1) as u8;
        e[i] = (e[i] >> bits) | (carry << (8 - bits));
        carry = next;
    }
    e
}

/// The curve constant d = -121665/121666 mod p.
fn d_constant() -> Fe {
    static D: spin::Once<Fe> = spin::Once::new();
    *D.call_once(|| {
        Fe::from_u64(121666)
            .invert()
            .mul(Fe::from_u64(121665).neg())
    })
}

/// sqrt(-1) mod p = 2^((p-1)/4).
fn sqrt_m1() -> Fe {
    static SQRT_M1: spin::Once<Fe> = spin::Once::new();
    *SQRT_M1.call_once(|| Fe::from_u64(2).pow_bytes_exp(&exp_shr(exp_p_minus(1), 2)))
}

// ------------------------------------------------------------------ group

#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    fn identity() -> Point {
        Point {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
            t: Fe::ZERO,
        }
    }

    fn eq(self, other: Point) -> bool {
        self.x.mul(other.z).eq(other.x.mul(self.z)) && self.y.mul(other.z).eq(other.y.mul(self.z))
    }

    /// Unified addition (valid for doubling as well), twisted Edwards
    /// a = -1 extended coordinates. Cross-checked against an independent
    /// affine implementation and the RFC 8032 vectors.
    fn add(self, q: Point) -> Point {
        let d = d_constant();
        let a = self.y.sub(self.x).mul(q.y.sub(q.x));
        let b = self.y.add(self.x).mul(q.y.add(q.x));
        let c = self.t.add(self.t).mul(q.t).mul(d);
        let dd = self.z.add(self.z).mul(q.z);
        let e = b.sub(a);
        let f = dd.sub(c);
        let g = dd.add(c);
        let h = b.add(a);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    fn compress(self) -> [u8; 32] {
        let zinv = self.z.invert();
        let x = self.x.mul(zinv);
        let y = self.y.mul(zinv);
        let mut out = y.to_bytes();
        if x.is_negative() {
            out[31] |= 0x80;
        }
        out
    }
}

/// Recover a point from its compressed encoding; None if not on-curve.
fn decompress(bytes: &[u8; 32]) -> Option<Point> {
    let mut yb = *bytes;
    let sign = yb[31] >> 7 == 1;
    yb[31] &= 0x7f;
    let y = Fe::from_bytes(&yb);

    let yy = y.square();
    let u = yy.sub(Fe::ONE);
    let v = d_constant().mul(yy).add(Fe::ONE);
    // RFC 8032: x = u*v^3 * (u*v^7)^((p-5)/8); multiply by sqrt(-1)
    // when the square check lands on -u instead of +u.
    let v3 = v.square().mul(v);
    let v7 = v3.square().mul(v);
    let exp = exp_shr(exp_p_minus(5), 3);
    let mut x = u.mul(v3).mul(u.mul(v7).pow_bytes_exp(&exp));

    let check = x.square().mul(v);
    if !check.eq(u) {
        if check.eq(u.neg()) {
            x = x.mul(sqrt_m1());
        } else {
            return None;
        }
    }
    if x.is_zero() && sign {
        return None; // negative zero is not a valid encoding
    }
    if x.is_negative() != sign {
        x = x.conditional_negate(true);
    }
    Some(Point {
        x,
        y,
        z: Fe::ONE,
        t: x.mul(y),
    })
}

/// The Ed25519 base point: y = 4/5, x the even root.
fn basepoint() -> Point {
    static BASE: spin::Once<Point> = spin::Once::new();
    *BASE.call_once(|| {
        let five_inv = Fe::from_u64(5).invert();
        let y = Fe::from_u64(4).mul(five_inv);
        let mut b = [0u8; 32];
        b.copy_from_slice(&y.to_bytes());
        decompress(&b).expect("base point is on the curve")
    })
}

/// Cache the base point locally during scalar multiplication (spin::Once
/// lookup per double-and-add step would otherwise dominate the runtime).
fn scalar_mul_base(scalar_le: &[u8; 32]) -> Point {
    let base = basepoint();
    let mut acc = Point::identity();
    let mut started = false;
    for byte_idx in (0..32).rev() {
        let byte = scalar_le[byte_idx];
        for bit in (0..8).rev() {
            if !started {
                if (byte >> bit) & 1 == 0 {
                    continue; // skip leading zeros (identity stays identity)
                }
                started = true;
                acc = base; // first set bit: acc must equal B, not B+identity
                continue;
            }
            acc = acc.add(acc);
            if (byte >> bit) & 1 == 1 {
                acc = acc.add(base);
            }
        }
    }
    acc
}

fn scalar_mul_point(scalar_le: &[u8; 32], p: Point) -> Point {
    let mut acc = Point::identity();
    let mut started = false;
    for byte_idx in (0..32).rev() {
        let byte = scalar_le[byte_idx];
        for bit in (0..8).rev() {
            if !started {
                if (byte >> bit) & 1 == 0 {
                    continue;
                }
                started = true;
                acc = p;
                continue;
            }
            acc = acc.add(acc);
            if (byte >> bit) & 1 == 1 {
                acc = acc.add(p);
            }
        }
    }
    acc
}
// ------------------------------------------------------- scalars mod L

/// Group order L, little-endian u32 limbs (radix 2^32).
const L_LIMBS: [u32; 8] = [
    0x5cf5_d3ed,
    0x5812_631a,
    0xa2f7_9cd6,
    0x14de_f9de,
    0,
    0,
    0,
    0x1000_0000,
];

fn limbs_geq(a: &[u32; 9], b: &[u32; 8]) -> bool {
    for i in (0..8).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true // equal counts as >=
}

fn limbs_sub(a: &mut [u32; 9], b: &[u32; 8]) {
    let mut borrow = 0u64;
    for i in 0..8 {
        let cur = a[i] as u64;
        let sub = b[i] as u64 + borrow;
        a[i] = (cur.wrapping_sub(sub)) as u32;
        borrow = if cur < sub { 1 } else { 0 };
    }
}

/// Reduce an arbitrary-length little-endian integer modulo L.
fn mod_l(input_le: &[u8]) -> [u8; 32] {
    let nbits = input_le.len() * 8;
    let mut rem = [0u32; 9];
    for bit in (0..nbits).rev() {
        let byte = input_le[bit / 8];
        let b = (byte >> (bit % 8)) & 1;
        // rem = rem << 1 | b
        let mut carry = b as u32;
        for limb in rem.iter_mut() {
            let nc = *limb >> 31;
            *limb = (*limb << 1) | carry;
            carry = nc;
        }
        if limbs_geq(&rem, &L_LIMBS) {
            limbs_sub(&mut rem, &L_LIMBS);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&rem[i].to_le_bytes());
    }
    out
}

fn bytes_geq_l(bytes: &[u8; 32]) -> bool {
    let mut lb = [0u8; 32];
    for i in 0..8 {
        lb[i * 4..i * 4 + 4].copy_from_slice(&L_LIMBS[i].to_le_bytes());
    }
    for i in (0..32).rev() {
        match bytes[i].cmp(&lb[i]) {
            core::cmp::Ordering::Greater => return true,
            core::cmp::Ordering::Less => return false,
            core::cmp::Ordering::Equal => {}
        }
    }
    true
}

/// (a*b + c) mod L for 32-byte scalars.
fn mul_add_mod_l(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    // 512-bit schoolbook product
    let mut prod = [0u32; 34]; // up to 17 limbs
    let mut aa = [0u32; 8];
    let mut bb = [0u32; 8];
    for i in 0..8 {
        aa[i] = u32::from_le_bytes(a[i * 4..i * 4 + 4].try_into().unwrap());
        bb[i] = u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 0..8 {
        let mut carry: u64 = 0;
        for j in 0..8 {
            let cur = prod[i + j] as u64 + (aa[i] as u64) * (bb[j] as u64) + carry;
            prod[i + j] = cur as u32;
            carry = cur >> 32;
        }
        prod[i + 8] = prod[i + 8].wrapping_add(carry as u32);
    }
    // serialize product + c into a wide little-endian buffer
    let mut wide = [0u8; 144];
    for (i, limb) in prod.iter().enumerate() {
        wide[i * 4..i * 4 + 4].copy_from_slice(&limb.to_le_bytes());
    }
    // add c (mod 2^136 would suffice; c < 2^253 so track carry properly)
    let mut carry = 0u64;
    for i in 0..32 {
        let sum = wide[i] as u64 + c[i] as u64 + carry;
        wide[i] = sum as u8;
        carry = sum >> 8;
    }
    let mut idx = 32;
    while carry > 0 && idx < wide.len() {
        let sum = wide[idx] as u64 + carry;
        wide[idx] = sum as u8;
        carry = sum >> 8;
        idx += 1;
    }
    mod_l(&wide)
}

// ------------------------------------------------------------ public API

pub const SEED_LEN: usize = 32;
pub const PUBLIC_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// Expand a seed into the clamped secret scalar and nonce prefix.
fn expand_seed(seed: &[u8; SEED_LEN]) -> ([u8; 32], [u8; 32]) {
    let h = sha512(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[0..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&h[32..64]);
    (a, prefix)
}

/// Public key for a seed.
pub fn public_from_seed(seed: &[u8; SEED_LEN]) -> [u8; PUBLIC_LEN] {
    let (a, _) = expand_seed(seed);
    scalar_mul_base(&a).compress()
}

pub fn keypair(seed: &[u8; SEED_LEN]) -> ([u8; PUBLIC_LEN], [u8; SEED_LEN]) {
    (public_from_seed(seed), *seed)
}

/// Sign `msg` with `seed`. Returns R||S.
pub fn sign(seed: &[u8; SEED_LEN], msg: &[u8]) -> [u8; SIGNATURE_LEN] {
    let (a_scalar, prefix) = expand_seed(seed);
    let a_point = scalar_mul_base(&a_scalar);
    let a_bytes = a_point.compress();

    let mut rh = Sha512::new();
    rh.update(&prefix);
    rh.update(msg);
    let r = mod_l(&rh.finalize());

    let big_r = scalar_mul_base(&r);
    let r_bytes = big_r.compress();

    let mut kh = Sha512::new();
    kh.update(&r_bytes);
    kh.update(&a_bytes);
    kh.update(msg);
    let k = mod_l(&kh.finalize());

    let s = mul_add_mod_l(&k, &a_scalar, &r);
    let mut sig = [0u8; SIGNATURE_LEN];
    sig[0..32].copy_from_slice(&r_bytes);
    sig[32..64].copy_from_slice(&s);
    sig
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Signature bytes malformed (bad S range or undecodable points).
    Malformed,
    /// Well-formed but fails verification.
    Invalid,
}

/// Verify `(msg, sig)` against `public`. Strict: rejects S >= L.
pub fn verify(
    public: &[u8; PUBLIC_LEN],
    msg: &[u8],
    sig: &[u8; SIGNATURE_LEN],
) -> Result<(), VerifyError> {
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[0..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..64]);

    if bytes_geq_l(&s_bytes) {
        return Err(VerifyError::Malformed);
    }
    let big_r = decompress(&r_bytes).ok_or(VerifyError::Malformed)?;
    let a_point = decompress(public).ok_or(VerifyError::Malformed)?;

    let mut kh = Sha512::new();
    kh.update(&r_bytes);
    kh.update(public);
    kh.update(msg);
    let k = mod_l(&kh.finalize());

    // [S]B == R + [k]A
    let lhs = scalar_mul_base(&s_bytes);
    let rhs = big_r.add(scalar_mul_point(&k, a_point));
    if lhs.eq(rhs) {
        Ok(())
    } else {
        Err(VerifyError::Invalid)
    }
}

// -------------------------------------------------------------- entropy

/// Mix arbitrary jitter bytes into a 32-byte value (dev key generation and
/// on-device volume-key provisioning only; NOT a CSPRNG replacement — see
/// DESIGN_DECISIONS.md for why Release-1 keys never come from this path).
pub fn mix_entropy(inputs: &[&[u8]]) -> [u8; 32] {
    let mut h = crate::sha256::Sha256::new();
    for i in inputs {
        h.update(&(i.len() as u64).to_le_bytes());
        h.update(i);
    }
    h.finalize()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn hex(s: &str) -> std::vec::Vec<u8> {
        let bytes = s.as_bytes();
        (0..bytes.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    struct Tv {
        seed: &'static str,
        public: &'static str,
        msg: &'static str,
        sig: &'static str,
    }

    // RFC 8032 §7.1 test vectors 1-3.
    const VECTORS: [Tv; 3] = [
        Tv {
            seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            msg: "",
            sig: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        },
        Tv {
            seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            public: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            msg: "72",
            sig: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        },
        Tv {
            seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            public: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            msg: "af82",
            sig: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        },
    ];

    #[test]
    fn rfc8032_sign_and_verify() {
        for v in &VECTORS {
            let seed = hex(v.seed);
            let public = hex(v.public);
            let msg = hex(v.msg);
            let sig = hex(v.sig);

            let mut seed_arr = [0u8; 32];
            seed_arr.copy_from_slice(&seed);
            let mut pub_arr = [0u8; 32];
            pub_arr.copy_from_slice(&public);
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(&sig);

            assert_eq!(public_from_seed(&seed_arr), pub_arr, "public derivation");
            assert_eq!(sign(&seed_arr, &msg), sig_arr, "sign");
            assert_eq!(verify(&pub_arr, &msg, &sig_arr), Ok(()), "verify");
        }
    }

    #[test]
    fn tampered_messages_fail() {
        let v = &VECTORS[2];
        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(&hex(v.public));
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&hex(v.sig));
        assert_eq!(
            verify(&pub_arr, b"af83", &sig_arr),
            Err(VerifyError::Invalid)
        );
        // flipped bit inside R half and inside S half
        let mut bad = sig_arr;
        bad[0] ^= 1;
        assert!(verify(&pub_arr, b"af82", &bad).is_err());
        let mut bad = sig_arr;
        bad[40] ^= 1;
        assert!(verify(&pub_arr, b"af82", &bad).is_err());
    }

    #[test]
    fn s_equal_to_l_rejected() {
        let v = &VECTORS[0];
        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(&hex(v.public));
        let mut sig = [0u8; 64];
        // S := L itself must be rejected outright. Little-endian bytes of
        // L = 2^252 + 277423177773723535435791939928032277430...:
        let l_hex = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";
        assert_eq!(l_hex.len(), 64);
        let lb = hex(l_hex);
        sig[32..64].copy_from_slice(&lb);
        assert_eq!(
            verify(&pub_arr, b"", &sig),
            Err(VerifyError::Malformed),
            "S >= L must be malformed"
        );
    }

    #[test]
    fn field_roundtrip_and_ops() {
        // p - 1 must encode to ff..7e
        let e = exp_p_minus(1);
        assert_eq!(e[0], 0xec);
        assert_eq!(e[31], 0x7f);
        // sqrt(-1)^2 == -1
        let s = sqrt_m1().square().neg();
        assert_eq!(s.to_bytes()[0], 1);
        assert_eq!(&s.to_bytes()[1..], &[0u8; 31]);
        // d is a square: d^((p-1)/2) == 1... d is non-square actually; check
        // curve identity instead: -x^2 + y^2 == 1 + d x^2 y^2 at base point.
        let b = basepoint();
        let x2 = b.x.square();
        let y2 = b.y.square();
        let lhs = x2.neg().add(y2);
        let rhs = Fe::ONE.add(d_constant().mul(x2).mul(y2));
        assert!(lhs.eq(rhs));
        // compress/decompress roundtrip of B
        let rt = decompress(&basepoint().compress()).unwrap();
        assert!(rt.eq(b));
    }

    #[test]
    fn scalar_reduction_matches_known_l_boundary() {
        // L reduced mod L is zero: feed exactly L (little-endian) in.
        let l_hex = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";
        let lb = hex(l_hex);
        let mut l_arr = [0u8; 32];
        l_arr.copy_from_slice(&lb);
        let z = mod_l(&l_arr);
        assert!(z.iter().all(|&b| b == 0), "L mod L must be 0, got {z:?}");
        // L - 1 reduces to itself
        let mut lm1: [u8; 32] = l_arr;
        lm1[0] -= 1;
        assert_eq!(mod_l(&lm1), lm1);
        // L + 1 reduces to 1
        let mut lp1: [u8; 32] = l_arr;
        let (sum, carry) = lp1[0].overflowing_add(1);
        lp1[0] = sum;
        assert!(!carry);
        assert_eq!(mod_l(&lp1)[0], 1);
    }
}
