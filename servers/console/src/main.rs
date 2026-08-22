#![no_std]
#![no_main]

// aegis-console: console/terminal driver server (stub until userspace bring-up)

#[no_mangle]
pub extern "sysv64" fn _start() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
