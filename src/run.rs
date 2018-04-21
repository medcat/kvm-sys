#[repr(C)]
#[derive(Copy, Clone)]
pub struct Run {
    /* in */
    pub request_interrupt_window: u8,
    pub immediate_exit: u8,
    pub _pad1: [u8; 6],

    /* out */
    pub exit_reason: u32,
    pub ready_for_interrupt_injection: u8,
    pub if_flag: u8,
    pub flags: u16,

    /* in (pre_kvm_run), out (post_kvm_run) */
    pub cr8: u64,
    pub apic_base: u64,

    /* the processor status word for s390 */
    pub psw_mask: u64, /* psw upper half */
    pub psw_addr: u64, /* psw lower half */

    pub exit: Exit,

    /*
     * shared registers between kvm and userspace.
     * kvm_valid_regs specifies the register classes set by the host
     * kvm_dirty_regs specified the register classes dirtied by userspace
     * struct kvm_sync_regs is architecture specific, as well as the
     * bits for kvm_valid_regs and kvm_dirty_regs
     */
    pub kvm_valid_regs: u64,
    pub kvm_dirty_regs: u64,
    // union {
    //     struct kvm_sync_regs regs;
    // } s;
    //
    // x86 doesn't have anything in struct kvm_sync_regs, so ignore.
    pub _pad2: [u8; 2048]
}

/* KVM_EXIT_UNKNOWN */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitUnknown {
    pub hardware_exit_reason: u64
}

/* KVM_EXIT_FAIL_ENTRY */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitFailEntry {
    pub hardware_entry_failure_reason: u64,
}

/* KVM_EXIT_EXCEPTION */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitException {
    pub exception: u32,
    pub error_code: u32,
}

/* KVM_EXIT_IO */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitIo {
    pub direction: u8,
    pub size: u8,
    pub port: u16,
    pub count: u32,
    pub data_offset: u64,
}

/* KVM_EXIT_MMIO */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitMmio {
    pub phys_addr: u64,
    pub data: [u8; 8],
    pub len: u32
}

/* KVM_EXIT_HYPERCALL */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitHypercall {
    pub nr: u64,
    pub args: [u64; 6],
    pub ret: u64,
    pub longmode: u32,
    pub _pad: u32
}

/* KVM_EXIT_TPR_ACCESS */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitTprAccess {
    pub rip: u64,
    pub is_write: u32,
    pub _pad: u32
}

/* KVM_EXIT_S390_SIEIC */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitS390Sieic {
    pub icptcode: u8,
    pub ipa: u16,
    pub ipb: u32
}

/* KVM_EXIT_S390_UCONTROL */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitS390Ucontrol {
    pub trans_exc_code: u64,
}

/* KVM_EXIT_DCR (deprecated) */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitDcr {
    pub dcrn: u32,
    pub data: u32,
    pub is_write: u8
}

/* KVM_EXIT_INTERNAL_ERROR */
/* Available with KVM_CAP_INTERNAL_ERROR_DATA: ndata, data */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitInternal {
    pub suberror: u32,
    pub ndata: u32,
    pub data: [u64; 16]
}

/* KVM_EXIT_OSI */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitOsi {
    pub gprs: [u64; 32]
}

/* KVM_EXIT_PAPR_HCALL */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitPaprHcall {
    pub nr: u64,
    pub ret: u64,
    pub args: [u64; 9]
}

/* KVM_EXIT_S390_TSCH */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitS390Tsch {
    pub subchannel_id: u16,
    pub subchannel_nr: u16,
    pub io_int_parm: u32,
    pub io_int_word: u32,
    pub ipb: u32,
    pub dequeued: u8
}

/* KVM_EXIT_EPR */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitEpr {
    pub epr: u32
}

/* KVM_EXIT_SYSTEM_EVENT */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitSystemEvent {
    // This is actually `type` in the kernel code.
    pub kind: u32,
    pub flags: u64
}

/* KVM_EXIT_S390_STSI */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitS390Stsi {
    pub addr: u64,
    pub ar: u8,
    pub reserved: u8,
    pub fc: u8,
    pub sel1: u8,
    pub sel2: u16
}

/* KVM_EXIT_IOAPIC_EOI */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExitEoi {
    pub vector: u8
}
    /* KVM_EXIT_HYPERV */
    // struct kvm_hyperv_exit hyperv;

#[repr(C)]
#[derive(Copy, Clone)]
pub union Exit {
    pub hw: ExitUnknown,
    pub fail_entry: ExitFailEntry,
    pub ex: ExitException,
    pub io: ExitIo,
    // debug: ExitDebug
    pub mmio: ExitMmio,
    pub hypercall: ExitHypercall,
    pub tpr_access: ExitTprAccess,
    pub s390_sieic: ExitS390Sieic,
    pub s390_reset_flags: u64,
    pub s390_ucontrol: ExitS390Ucontrol,
    pub dcr: ExitDcr,
    pub internal: ExitInternal,
    pub osi: ExitOsi,
    pub papr_hcall: ExitPaprHcall,
    pub s390_tsch: ExitS390Tsch,
    pub epr: ExitEpr,
    pub system_event: ExitSystemEvent,
    pub s390_stsi: ExitS390Stsi,
    pub eoi: ExitEoi,
    // hyperv:  ExitHyperv
    pub _pad: [u8; 256]
}
