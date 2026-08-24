//! redoubt cryptographic primitives.
//!
//! Everything here is self-contained, allocation-free, `no_std` Rust so the
//! same code runs in host-side tooling and inside redoubt servers. It is
//! deliberately small: SHA-256/HMAC-SHA-256 for digests and record MACs,
//! SHA-512 + Ed25519 for image signing (RFC 8032), and ChaCha20 for volume
//! stream encryption (RFC 8439).
//!
//! Correctness contract: every primitive is validated against published
//! RFC test vectors by the unit tests below; `cargo test -p redoubt-crypto`
//! is a release gate. The arithmetic is NOT constant-time; acceptable for
//! verifying public material and for development signing keys, and called
//! out in DESIGN_DECISIONS.md.

#![no_std]

pub mod chacha20;
pub mod ed25519;
pub mod hmac;
pub mod layout;
pub mod sha256;
pub mod sha512;
