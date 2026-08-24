//! Polled PIO ATA driver for the QEMU IDE controller.
//!
//! The appliance contract puts storage behind capability-limited services;
//! this module is deliberately dumb: identify drives, read/write sectors.
//! All policy (volumes, slots, crypto) lives in userspace behind
//! `Cap::Block` capabilities naming a disk index and an LBA range.
//!
//! Runs with IF=0 in the classic single-core model; IRQ14/15 stay masked at
//! the PIC and completion is detected by polling STATUS with bounded spins,
//! so no interrupt plumbing is needed here.

use x86_64::instructions::interrupts;
use x86_64::instructions::port::Port;

const SR_BSY: u8 = 0x80;
const SR_DRQ: u8 = 0x08;
const SR_ERR: u8 = 0x01;

/// Bounded spin counts; QEMU completes long before these expire.
const SPIN_IDENTIFY: usize = 5_000_000;
const SPIN_DATA: usize = 20_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtaError {
    NoDrive,
    BusyTimeout,
    DeviceError,
    BadArgs,
}

/// One probed drive position.
#[derive(Clone, Copy)]
pub struct Drive {
    io: u16,
    ctrl: u16,
    slave: bool,
    /// Total addressable sectors via LBA48 (LBA28 fallback applied).
    pub sectors: u64,
}

impl Drive {
    fn p_in(&self, off: u16) -> u8 {
        unsafe { Port::<u8>::new(self.io + off).read() }
    }
    fn p_out(&self, off: u16, v: u8) {
        unsafe { Port::<u8>::new(self.io + off).write(v) }
    }
    fn p_in16(&self) -> u16 {
        unsafe { Port::<u16>::new(self.io).read() }
    }
    fn p_out16(&self, v: u16) {
        unsafe { Port::<u16>::new(self.io).write(v) }
    }
    /// ~400ns delay via four control-register reads.
    fn io_delay(&self) {
        let _ = self.p_in_at_ctrl();
        let _ = self.p_in_at_ctrl();
        let _ = self.p_in_at_ctrl();
        let _ = self.p_in_at_ctrl();
    }
    fn p_in_at_ctrl(&self) -> u8 {
        unsafe { Port::<u8>::new(self.ctrl).read() }
    }

    fn select(&self) {
        // 0xE0 = bit7 must-be-one | bit6 LBA mode | bit5 must-be-one;
        // bit4 selects the slave. Required for LBA48 commands.
        self.p_out(6, if self.slave { 0xF0 } else { 0xE0 });
        self.io_delay();
    }

    fn wait_not_busy(&self) -> Result<(), AtaError> {
        let mut spins = SPIN_DATA;
        while self.p_in(7) & SR_BSY != 0 {
            spins -= 1;
            if spins == 0 {
                return Err(AtaError::BusyTimeout);
            }
        }
        Ok(())
    }

    fn setup_lba48(&self, lba: u64, count: u16) -> Result<(), AtaError> {
        if count == 0
            || count > 256
            || lba.checked_add(count as u64).ok_or(AtaError::BadArgs)? > self.sectors
        {
            return Err(AtaError::BadArgs);
        }
        self.select();
        self.p_out(2, (count >> 8) as u8); // sector count high
        self.p_out(3, (lba >> 24) as u8);
        self.p_out(4, (lba >> 32) as u8);
        self.p_out(5, (lba >> 40) as u8);
        self.p_out(2, (count & 0xff) as u8); // sector count low
        self.p_out(3, lba as u8);
        self.p_out(4, (lba >> 8) as u8);
        self.p_out(5, (lba >> 16) as u8);
        Ok(())
    }

    fn identify(bus_io: u16, bus_ctrl: u16, slave: bool) -> Option<Drive> {
        let d = Drive {
            io: bus_io,
            ctrl: bus_ctrl,
            slave,
            sectors: 0,
        };
        d.select();
        d.p_out(2, 0);
        d.p_out(3, 0);
        d.p_out(4, 0);
        d.p_out(5, 0);
        d.p_out(7, 0xEC);

        // A floating bus reads back 0xFF; a missing slave often reads 0.
        let st = d.p_in(7);
        if st == 0 || st == 0xFF {
            return None;
        }

        // ATAPI drives report their signature in LBA mid/high.
        let mid = d.p_in(4);
        let high = d.p_in(5);
        if (mid, high) == (0x14, 0xEB) || (mid, high) == (0x69, 0x96) {
            return None; // CD-ROM class: outside the appliance profile
        }

        let mut spins = SPIN_IDENTIFY;
        while d.p_in(7) & SR_BSY != 0 {
            spins -= 1;
            if spins == 0 {
                return None;
            }
        }
        if d.p_in(7) & SR_ERR != 0 || d.p_in(7) & SR_DRQ == 0 {
            return None;
        }

        let mut id = [0u16; 256];
        for w in id.iter_mut() {
            *w = d.p_in16();
        }
        // LBA48 total sector count in words 100..104; fall back to the
        // LBA28 count in words 60/61.
        let lba48 = id[100] as u64
            | ((id[101] as u64) << 16)
            | ((id[102] as u64) << 32)
            | ((id[103] as u64) << 48);
        let sectors = if lba48 == 0 {
            id[60] as u64 | ((id[61] as u64) << 16)
        } else {
            lba48
        };
        Some(Drive { sectors, ..d })
    }

    fn flush(&self) -> Result<(), AtaError> {
        self.p_out(7, 0xE7); // CACHE FLUSH EXT
        self.wait_not_busy()?;
        if self.p_in(7) & SR_ERR != 0 {
            return Err(AtaError::DeviceError);
        }
        Ok(())
    }

    fn read_sectors(&self, lba: u64, count: u16, buf: &mut [u8]) -> Result<(), AtaError> {
        if buf.len() < count as usize * 512 {
            return Err(AtaError::BadArgs);
        }
        self.setup_lba48(lba, count)?;
        self.p_out(7, 0x24); // READ SECTORS EXT

        for s in 0..count as usize {
            self.wait_not_busy()?;
            let st = self.p_in(7);
            if st & SR_ERR != 0 || st & SR_DRQ == 0 {
                return Err(AtaError::DeviceError);
            }
            for w in 0..256usize {
                let v = self.p_in16();
                let off = s * 512 + w * 2;
                buf[off] = v as u8;
                buf[off + 1] = (v >> 8) as u8;
            }
            self.io_delay();
        }
        Ok(())
    }

    fn write_sectors(&self, lba: u64, count: u16, buf: &[u8]) -> Result<(), AtaError> {
        if buf.len() < count as usize * 512 {
            return Err(AtaError::BadArgs);
        }
        self.setup_lba48(lba, count)?;
        self.p_out(7, 0x34); // WRITE SECTORS EXT

        for s in 0..count as usize {
            self.wait_not_busy()?;
            let st = self.p_in(7);
            if st & SR_ERR != 0 || st & SR_DRQ == 0 {
                return Err(AtaError::DeviceError);
            }
            for w in 0..256usize {
                let off = s * 512 + w * 2;
                let v = buf[off] as u16 | ((buf[off + 1] as u16) << 8);
                self.p_out16(v);
            }
            self.io_delay();
        }
        self.flush()
    }
}

use spin::Mutex;

static PRIMARY_DRIVE: Mutex<Option<Drive>> = Mutex::new(None);
static SECONDARY_DRIVE: Mutex<Option<Drive>> = Mutex::new(None);

fn probe_bus(bus_io: u16, bus_ctrl: u16, slot: &Mutex<Option<Drive>>) -> usize {
    let mut found = 0;
    for slave in [false, true] {
        if let Some(d) = Drive::identify(bus_io, bus_ctrl, slave) {
            crate::kprintln!(
                "[redoubt] ata {} {}: {} MiB",
                if bus_io == 0x1F0 {
                    "primary"
                } else {
                    "secondary"
                },
                if slave { "slave" } else { "master" },
                d.sectors.saturating_mul(512) / 1024 / 1024
            );
            *slot.lock() = Some(d);
            found += 1;
            break; // one usable disk per bus keeps indexing deterministic
        }
    }
    found
}

/// Probe primary-master then secondary-master. With `-drive file=a -drive
/// file=b`, QEMU puts `a` at primary-master and `b` at secondary-master
/// (when only masters are used), so disk 0 is the boot image and disk 1 is
/// the persistent volume.
pub fn init() -> usize {
    let pm = probe_bus(0x1F0, 0x3F6, &PRIMARY_DRIVE);
    let sm = probe_bus(0x170, 0x376, &SECONDARY_DRIVE);
    pm + sm
}

/// Disk index space: 0 = boot image (primary), 1 = volume (secondary).
fn with_drive<R>(idx: u64, f: impl FnOnce(&Drive) -> R, none: R) -> R {
    let guard = if idx == 0 {
        PRIMARY_DRIVE.lock()
    } else if idx == 1 {
        SECONDARY_DRIVE.lock()
    } else {
        return none;
    };
    match &*guard {
        Some(d) => f(d),
        None => none,
    }
}

pub fn drive_present(idx: u64) -> bool {
    with_drive(idx, |_| true, false)
}

pub fn drive_sectors(idx: u64) -> u64 {
    with_drive(idx, |d| d.sectors, 0)
}

pub fn read_sectors(idx: u64, lba: u64, count: u16, buf: &mut [u8]) -> Result<(), AtaError> {
    with_drive(
        idx,
        |d| d.read_sectors(lba, count, buf),
        Err(AtaError::NoDrive),
    )
}

pub fn write_sectors(idx: u64, lba: u64, count: u16, buf: &[u8]) -> Result<(), AtaError> {
    with_drive(
        idx,
        |d| d.write_sectors(lba, count, buf),
        Err(AtaError::NoDrive),
    )
}

/// Reboot via the 8042 keyboard-controller reset line. QEMU honors it.
pub fn machine_reboot() -> ! {
    loop {
        interrupts::disable();
        // wait for input buffer empty, then pulse the reset line
        let mut spins = 100_000;
        while spins > 0 && unsafe { Port::<u8>::new(0x64).read() } & 0x02 != 0 {
            spins -= 1;
        }
        unsafe { Port::<u8>::new(0x64).write(0xFE) };
        core::hint::spin_loop();
    }
}
