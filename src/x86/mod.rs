use super::ctl::{ehandle, KVMIO};
use libc::ioctl;
use nix;
use std::mem::size_of;
use std::os::unix::io::RawFd;

/// The registers.  Note that this definition only works for x64 hosts and
/// guests; we'll assume that this is the case.  If this a problem, we'll
/// extract this behavior out to be more platform independent.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// From the struct `kvm_regs`.
pub struct Regs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// From the struct `kvm_segment`.
pub struct Segment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    /// Note: in the linux kernel, this is named `type`
    pub kind: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

impl Default for Segment {
    fn default() -> Segment {
        unsafe { ::std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// From the struct `kvm_dtable`.
pub struct Dtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// From the struct `sregs`.
pub struct Sregs {
    pub cs: Segment,
    pub ds: Segment,
    pub es: Segment,
    pub fs: Segment,
    pub gs: Segment,
    pub ss: Segment,
    pub tr: Segment,
    pub ldt: Segment,
    pub gdt: Dtable,
    pub idt: Dtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    /// The size of this field is actually `(KVM_NR_INTERRUPTS + 63) / 64`,
    /// where `KVM_NR_INTERRUPTS = 256`; this was defined in the linux
    /// kernel; see `/arch/x86/include/uapi/asm/kvm.h`.
    ///
    /// This is a bitmap of pending external interrupts.  At most, one bit
    /// may be set.  The interrupt has been acknowledged by the APIC, but
    /// not yet injected.
    pub interrupt_bitmap: [u64; (256 + 63) / 64],
}

/// Reads the general-purpose registers from the given vCPU.  The
/// result of this call is dependent on the architecture.
///
/// # Safety
/// Right now, this assumes that the host/guest architecture will be
/// x86.  Therefore, this assumes that the host/guest architecture
/// will have the registers listed in `Regs`.
///
/// # Support
/// This ioctl is supported by all architectures (except for ARM and
/// arm64), and is a basic capability.  This is available only on
/// the vCPU file descriptor.
pub unsafe fn kvm_get_regs(fd: RawFd, regs: *mut Regs) -> nix::Result<i32> {
    ehandle(ioctl(fd, ior!(KVMIO, 0x81, size_of::<Regs>()), regs))
}

/// Writes to the general-purpose registers into the given vCPU.  The
/// parameter passed into this call is dependent on the architecture.
///
/// # Safety
/// Right now, this assumes that the host/guest architecture will be
/// x86.  Therefore, this assumes that the host/guest architecture
/// will have the registers listed in `Regs`.
///
/// # Support
/// This ioctl is supported by all architectures (except for ARM and
/// arm64), and is a basic capability.  This is available only on
/// the vCPU file descriptor.
pub unsafe fn kvm_set_regs(fd: RawFd, regs: *const Regs) -> nix::Result<i32> {
    ehandle(ioctl(fd, iow!(KVMIO, 0x82, size_of::<Regs>()), regs))
}

/// Reads special registers from the vCPU.  This assumes that the
/// vCPU is x86-based.
///
/// # Support
/// This ioctl is supported only by x86 and ppc, and is a basic
/// capability.  This is available only on the vCPU file descriptor.
pub unsafe fn kvm_get_sregs(fd: RawFd, regs: *mut Sregs) -> nix::Result<i32> {
    ehandle(ioctl(fd, ior!(KVMIO, 0x83, size_of::<Sregs>()), regs))
}

/// Writes special registers to the vCPU.  This assumes that the
/// vCPU is x86-based.
///
/// # Support
/// This ioctl is supported only by x86 and ppc, and is a basic
/// capability.  This is available only on the vCPU file descriptor.
pub unsafe fn kvm_set_sregs(fd: RawFd, regs: *const Sregs) -> nix::Result<i32> {
    ehandle(ioctl(fd, iow!(KVMIO, 0x84, size_of::<Sregs>()), regs))
}
