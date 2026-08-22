use x86_64::instructions::tables::load_tss;
use x86_64::registers::segmentation::{Segment, CS, DS, ES, FS, GS, SS};
use x86_64::structures::gdt::{Descriptor, DescriptorFlags, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use crate::kprintln;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_IST: usize = 0;

/// Per-CPU (single core here) system state.
pub struct Gdt {
    table: GlobalDescriptorTable,
    pub selectors: Selectors,
}

#[derive(Debug, Clone, Copy)]
pub struct Selectors {
    pub kernel_code: SegmentSelector,
    pub kernel_data: SegmentSelector,
    pub user_code: SegmentSelector,
    pub user_data: SegmentSelector,
    pub tss: SegmentSelector,
}

static mut TSS: TaskStateSegment = TaskStateSegment::new();
pub static mut TSS_ADDR: u64 = 0;

static GDT: spin::Once<GlobalDescriptorTable> = spin::Once::new();
static SELECTORS: spin::Once<Selectors> = spin::Once::new();

pub fn selectors() -> &'static Selectors {
    SELECTORS.get().expect("GDT not initialized")
}

pub fn init() {
    // double-fault IST stack
    let df_stack = crate::frame::alloc_frames(8).expect("frames for IST stack");
    let df_top = VirtAddr::new(df_stack.as_u64() + 8 * 4096);

    let tss = unsafe { &mut *(&raw mut TSS) };
    tss.interrupt_stack_table[DOUBLE_FAULT_IST] = df_top;

    let gdt = GDT.call_once(|| {
        let mut table = GlobalDescriptorTable::new();
        let kcode = table.append(Descriptor::kernel_code_segment());
        let kdata = table.append({
            let mut f = DescriptorFlags::USER_SEGMENT
                | DescriptorFlags::PRESENT
                | DescriptorFlags::WRITABLE;
            f.remove(DescriptorFlags::LONG_MODE);
            Descriptor::UserSegment(f.bits())
        });
        let udata = table.append({
            let mut f = DescriptorFlags::USER_SEGMENT
                | DescriptorFlags::PRESENT
                | DescriptorFlags::WRITABLE;
            f.remove(DescriptorFlags::LONG_MODE);
            f.insert(DescriptorFlags::DPL_RING_3);
            Descriptor::UserSegment(f.bits())
        });
        let ucode = table.append({
            let mut f = DescriptorFlags::USER_SEGMENT
                | DescriptorFlags::PRESENT
                | DescriptorFlags::LONG_MODE;
            f.insert(DescriptorFlags::DPL_RING_3);
            Descriptor::UserSegment(f.bits())
        });
        unsafe { TSS_ADDR = &raw const TSS as u64 };
        let tss_sel = table.append(Descriptor::tss_segment(tss));

        let selectors = Selectors {
            kernel_code: kcode,
            kernel_data: kdata,
            user_code: ucode,
            user_data: udata,
            tss: tss_sel,
        };
        SELECTORS.call_once(|| selectors);
        table
    });

    // order matters: GDTR first, then far-jump-free selector reloads, then TR
    gdt.load();
    let sel = selectors();
    unsafe {
        CS::set_reg(sel.kernel_code);
        DS::set_reg(sel.kernel_data);
        ES::set_reg(sel.kernel_data);
        FS::set_reg(sel.kernel_data);
        GS::set_reg(sel.kernel_data);
        SS::set_reg(sel.kernel_data);
    }
    unsafe { load_tss(sel.tss) };
}
