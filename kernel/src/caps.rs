//! Capability objects and per-task capability tables.
//!
//! A capability is an unforgeable (kernel-private) reference to a kernel
//! object plus a rights mask. User code only ever sees slot indices; all
//! validation happens here in the kernel.

pub const CAP_TABLE_SIZE: usize = 32;

pub const R_READ: u64 = 1 << 0;
pub const R_WRITE: u64 = 1 << 1;
/// May delegate this capability (fully or attenuated) to others.
pub const R_GRANT: u64 = 1 << 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cap {
    /// Permission to use an IPC endpoint.
    Endpoint { endpoint: u64, rights: u64 },
    /// Permission over a contiguous range of physical frames. Reserved for
    /// the memory-grant syscall; part of the capability ABI surface now so
    /// rights handling is uniform from day one.
    #[allow(dead_code)]
    Memory {
        base_paddr: u64,
        pages: u64,
        rights: u64,
    },
    /// Permission over a disk's LBA range `[lba_start, lba_start + lbas)`.
    /// Range attenuation is structural: a derived block cap can only ever
    /// cover the intersection of its parent range with the requested one.
    Block {
        disk: u64,
        lba_start: u64,
        lbas: u64,
        rights: u64,
    },
}

impl Cap {
    pub fn rights(&self) -> u64 {
        match *self {
            Cap::Endpoint { rights, .. }
            | Cap::Memory { rights, .. }
            | Cap::Block { rights, .. } => rights,
        }
    }
}
