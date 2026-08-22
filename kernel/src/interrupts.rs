use core::sync::atomic::{AtomicU64, Ordering};

use pic8259::ChainedPics;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use crate::{gdt, kprintln};

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

pub static PICS: spin::Mutex<ChainedPics> =
    spin::Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

pub const TIMER_IRQ: u8 = PIC_1_OFFSET; // vector 32

pub static TICKS: AtomicU64 = AtomicU64::new(0);

pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

static IDT: spin::Once<InterruptDescriptorTable> = spin::Once::new();

extern "x86-interrupt" fn divide_error_handler(frame: InterruptStackFrame) {
    kprintln!("[aegis] EXC #DE divide error at {:#x}", frame.instruction_pointer.as_u64());
    halt_on_fault();
}

extern "x86-interrupt" fn invalid_opcode_handler(frame: InterruptStackFrame) {
    kprintln!("[aegis] EXC #UD invalid opcode at {:#x}", frame.instruction_pointer.as_u64());
    halt_on_fault();
}

extern "x86-interrupt" fn breakpoint_handler(frame: InterruptStackFrame) {
    kprintln!("[aegis] EXC #BP breakpoint at {:#x} (continuing)", frame.instruction_pointer.as_u64());
}

extern "x86-interrupt" fn overflow_handler(frame: InterruptStackFrame) {
    kprintln!("[aegis] EXC #OF overflow at {:#x}", frame.instruction_pointer.as_u64());
    halt_on_fault();
}

extern "x86-interrupt" fn bound_range_handler(frame: InterruptStackFrame) {
    kprintln!("[aegis] EXC #BR bound range at {:#x}", frame.instruction_pointer.as_u64());
    halt_on_fault();
}

extern "x86-interrupt" fn device_not_available_handler(frame: InterruptStackFrame) {
    kprintln!("[aegis] EXC #NM device not available at {:#x}", frame.instruction_pointer.as_u64());
    halt_on_fault();
}

extern "x86-interrupt" fn double_fault_handler(
    frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    kprintln!("[aegis] FATAL double fault at {:#x}", frame.instruction_pointer.as_u64());
    halt_on_fault()
}

extern "x86-interrupt" fn invalid_tss_handler(frame: InterruptStackFrame, code: u64) {
    kprintln!("[aegis] EXC #TS invalid TSS ({code:#x}) at {:#x}", frame.instruction_pointer.as_u64());
    halt_on_fault();
}

extern "x86-interrupt" fn segment_not_present_handler(frame: InterruptStackFrame, code: u64) {
    kprintln!("[aegis] EXC #NP segment not present ({code:#x}) at {:#x}", frame.instruction_pointer.as_u64());
    halt_on_fault();
}

extern "x86-interrupt" fn stack_segment_handler(frame: InterruptStackFrame, code: u64) {
    kprintln!("[aegis] EXC #SS stack segment ({code:#x}) at {:#x}", frame.instruction_pointer.as_u64());
    halt_on_fault();
}

extern "x86-interrupt" fn general_protection_handler(frame: InterruptStackFrame, code: u64) {
    kprintln!(
        "[aegis] EXC #GP general protection fault (code={code:#x}) at {:#x}",
        frame.instruction_pointer.as_u64()
    );
    halt_on_fault();
}

extern "x86-interrupt" fn page_fault_handler(
    frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    let cr2 = x86_64::registers::control::Cr2::read().map(|a| a.as_u64()).unwrap_or(0);
    kprintln!(
        "[aegis] EXC #PF page fault addr={cr2:#x} err={error_code:?} ip={:#x}",
        frame.instruction_pointer.as_u64()
    );
    halt_on_fault();
}

extern "x86-interrupt" fn x87_handler(frame: InterruptStackFrame) {
    kprintln!("[aegis] EXC #MF x87 fault at {:#x}", frame.instruction_pointer.as_u64());
    halt_on_fault();
}

extern "x86-interrupt" fn alignment_handler(frame: InterruptStackFrame, code: u64) {
    kprintln!("[aegis] EXC #AC alignment ({code:#x}) at {:#x}", frame.instruction_pointer.as_u64());
    halt_on_fault();
}

extern "x86-interrupt" fn machine_check_handler(frame: InterruptStackFrame) -> ! {
    panic!("machine check at {:#x}", frame.instruction_pointer.as_u64());
}

extern "x86-interrupt" fn simd_fp_handler(frame: InterruptStackFrame) {
    kprintln!("[aegis] EXC #XM SIMD FP at {:#x}", frame.instruction_pointer.as_u64());
    halt_on_fault();
}

extern "x86-interrupt" fn security_handler(frame: InterruptStackFrame, code: u64) {
    kprintln!("[aegis] EXC #CP security ({code:#x}) at {:#x}", frame.instruction_pointer.as_u64());
    halt_on_fault();
}

extern "x86-interrupt" fn timer_handler(_frame: InterruptStackFrame) {
    TICKS.fetch_add(1, Ordering::Relaxed);
    unsafe { PICS.lock().notify_end_of_interrupt(TIMER_IRQ) };
}

extern "x86-interrupt" fn spurious_irq7(_frame: InterruptStackFrame) {
    unsafe { PICS.lock().notify_end_of_interrupt(PIC_1_OFFSET + 7) };
}

extern "x86-interrupt" fn spurious_irq15(_frame: InterruptStackFrame) {
    unsafe { PICS.lock().notify_end_of_interrupt(PIC_2_OFFSET + 7) };
}

fn halt_on_fault() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

fn pit_init(hz: u32) {
    use crate::serial::port_out;
    let divisor: u16 = (1_193_182 / hz as u32) as u16;
    port_out(0x43, 0x36); // ch0, lo/hi, mode 3
    port_out(0x40, (divisor & 0xff) as u8);
    port_out(0x40, (divisor >> 8) as u8);
}

pub fn init() {
    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();
        idt.divide_error.set_handler_fn(divide_error_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.overflow.set_handler_fn(overflow_handler);
        idt.bound_range_exceeded.set_handler_fn(bound_range_handler);
        idt.device_not_available.set_handler_fn(device_not_available_handler);
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(gdt::DOUBLE_FAULT_IST as u16);
        }
        idt.invalid_tss.set_handler_fn(invalid_tss_handler);
        idt.segment_not_present.set_handler_fn(segment_not_present_handler);
        idt.stack_segment_fault.set_handler_fn(stack_segment_handler);
        idt.general_protection_fault.set_handler_fn(general_protection_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.x87_floating_point.set_handler_fn(x87_handler);
        idt.alignment_check.set_handler_fn(alignment_handler);
        idt.machine_check.set_handler_fn(machine_check_handler);
        idt.simd_floating_point.set_handler_fn(simd_fp_handler);
        idt.security_exception.set_handler_fn(security_handler);
        idt[TIMER_IRQ].set_handler_fn(timer_handler);
        idt[PIC_1_OFFSET + 7].set_handler_fn(spurious_irq7);
        idt[PIC_2_OFFSET + 7].set_handler_fn(spurious_irq15);
        idt
    });
    idt.load();
    // remap PICs to vectors 32..48 *before* anything enables IF
    unsafe { PICS.lock().initialize() };
    pit_init(100);
}
