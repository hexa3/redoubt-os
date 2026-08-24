#![no_std]
#![no_main]

// Links the shared user runtime, including its panic handler and `_start`.
use redoubt_userlib as _;

// Development diagnostic only. #UD is a recoverable ring-3 exception in
// redoubt; the kernel must terminate this task and return 0x106 to its parent.
#[no_mangle]
fn main() -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}
