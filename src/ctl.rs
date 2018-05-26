//! `KVM_GET_IRQCHIP`, `KVM_SET_IRQCHIP`, `KVM_GET_VCPU_EVENTS`, `KVM_SET_VCPU_EVENTS`
//! `KVM_GET_DEBUGREGS`, and `KVM_SET_DEBUGREGS` are unsupported.

pub const KVMIO: u8 = 0xAE;
pub const KVM_CLOCK_TSC_STABLE: u32 = 2;

use libc::ioctl;
use nix;
use std::mem::size_of;
use std::os::unix::io::RawFd;

#[repr(C)]
/// From the struct `kvm_msr_list`.
pub struct MsrList {
    pub nmsrs: u32,
    pub indicies: [u32; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// From the struct `kvm_dirty_log`.
pub struct DirtyLog {
    pub slot: u32,
    pub _pad: u32,
    /// This is meant to be a union of a pointer and a u64; the pointer has
    /// type `struct __user *dirty_bitmap`, with the u64 having the type
    /// `__u64 padding2`.  Make of that what you will.
    pub value: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// From the struct `kvm_interrupt`.
pub struct Interrupt {
    pub irq: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
/// From the struct `kvm_fpu`.
pub struct Fpu {
    pub fpr: [[u8; 16]; 8],
    pub fcw: u16,
    pub fsw: u16,
    pub ftwx: u8,
    pub pad1: u8,
    pub last_opcode: u16,
    pub last_ip: u64,
    pub last_dp: u64,
    pub xmm: [[u8; 16]; 16],
    pub mxcsr: u32,
    pub pad2: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// From the struct `kvm_cpuid_entry`.
pub struct CpuIdEntry {
    pub function: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub _pad: u32,
}

#[repr(C)]
/// From the struct `kvm_cpuid`.
pub struct CpuId {
    pub nent: u32,
    pub padding: u32,
    pub entries: [CpuIdEntry; 0],
}

#[repr(C)]
/// From the struct `kvm_signal_mask`.
pub struct SignalMask {
    pub len: u32,
    pub sigset: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// From the struct `kvm_irq_level`.
pub struct IrqLevel {
    /// This field also acts as the `status` field.
    pub irq: u32,
    pub level: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// From the struct `kvm_xen_hvm_config`.
pub struct XenHvmConfig {
    pub flags: u32,
    pub msr: u32,
    pub blob_addr_32: u64,
    pub blob_addr_64: u64,
    pub blob_size_32: u8,
    pub blob_size_64: u8,
    pub _pad: [u8; 30],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// From the struct `kvm_clock_data`.
pub struct ClockData {
    pub clock: u64,
    pub flags: u32,
    pub _pad: [u32; 9],
}

pub const KVM_MEM_LOG_DIRTY_PAGES: u32 = 1u32 << 0;
pub const KVM_MEM_READONLY: u32 = 1u32 << 1;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// From the struct `kvm_userspace_memory_region`.
pub struct UserspaceMemoryRegion {
    pub slot: u32,
    pub flags: u32,
    pub guest_phys_addr: u64,
    /// in bytes.
    pub memory_size: u64,
    /// the start of th userspace allocated memory.
    pub userspace_addr: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
/// From the struct `kvm_enable_cap`.
pub struct EnableCap {
    /// The capability that is to be enabled.
    pub cap: i32,
    /// Should always be 0.
    pub flags: u32,
    pub args: [u64; 4],
    pub _pad: [u8; 64],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// From the struct `kvm_mp_state`
pub struct MpState {
    pub mp_state: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// From the struct `kvm_translation`.
pub struct Translation {
    /// The input parameter.
    pub linear_address: u64,
    /// The output parameter.
    pub physical_address: u64,
    pub valid: u8,
    pub writable: u8,
    pub usermode: u8,
    pub _pad: [u8; 5],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// From the struct `kvm_msr_entry`.
pub struct MsrEntry {
    pub index: u32,
    pub reserved: u32,
    pub data: u64,
}

#[repr(C)]
/// From the struct `kvm_msrs`.
pub struct Msrs {
    pub nmsrs: u32,
    pub pad: u32,

    pub entries: [MsrEntry; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
/// From the struct `kvm_ioeventfd`.
pub struct IoEventFd {
    pub datamatch: u64,
    pub addr: u64,
    pub len: u32,
    pub fd: i32,
    pub flags: u32,
    pub _pad: [u8; 36],
}

#[repr(C)]
#[derive(Copy, Clone)]
/// From the struct `kvm_irqfd`.
pub struct IrqFd {
    pub fd: u32,
    pub gsi: u32,
    pub flags: u32,
    pub resampled: u32,
    pub _pad: [u8; 16],
}

pub(crate) fn ehandle(out: i32) -> nix::Result<i32> {
    nix::errno::Errno::result(out)
}

/// This identifies the API version as the stable kvm API. It is not
/// expected that this number will change.  However, Linux 2.6.20 and
/// 2.6.21 report earlier versions; these are not documented and not
/// supported.  Applications should refuse to run if this returns a
/// value other than 12.
///
/// # Support
/// This ioctl is supported by all architectures, and is a basic
/// capability. This should only be run on the system file descriptor.
pub unsafe fn kvm_get_api_version(fd: RawFd) -> nix::Result<i32> {
    ehandle(ioctl(fd, io!(KVMIO, 0x00), 0))
}

/// Creates a VM.  The new VM has no virtual CPUs and no memory.  This
/// returns a new file descriptor on success that can then be used with
/// other ioctls.
///
/// # Arguments
/// - `data` - The machine type.  You probably want this to be 0.
///
/// # Support
/// This ioctl is supported by all architectures, and is a basic
/// capability. This should only be run on the system file descriptor.
pub unsafe fn kvm_create_vm(fd: RawFd, kind: i32) -> nix::Result<i32> {
    ehandle(ioctl(fd, io!(KVMIO, 0x01), kind))
}

/// The passed `kvm_msr_list` should have the size of the number of indicies
/// it can hold, and in return, KVM will fill both the incidies and the
/// `nmsrs` with the right data.
///
/// This returns the guest MSRs that are supported.  The list varies by
/// KVM version and host processor, but does not change otherwise.
///
/// **Note:** if KVM indicates support for MCE (via the `KVM_CAP_MCE`
/// capability check), then the MCE bank MSRs are not returned in the MSR list,
/// as different vCPUs can have a different number of banks (as set via
/// `x86_setup_mce`).
///
/// # Support
/// This ioctl is supported only by the x86 architecture, and is a basic
/// capability. This should only be run on the system file descriptor.
pub unsafe fn kvm_get_msr_index_list(fd: RawFd, data: *mut MsrList) -> nix::Result<i32> {
    ehandle(ioctl(fd, iorw!(KVMIO, 0x02, size_of::<MsrList>()), data))
}

/// The passed [`MsrList`] should have the size of the number of indicies
/// it can hold, and in return, KVM will fill both the incidies and the
/// `nmsrs` with the right data.
///
/// This returns the list of MSRs that can be passed to `get_msrs`.  This lets
/// userspace probe host capabilities and processor features that are exposed via
/// MSRs (e.g., VMX capabilities).  This list also varies by kvm version and host
/// processor, but does not change otherwise.
///
/// # Support
/// This ioctl is supported only by the x86 architecture, and requires the
/// [`KVM_CAP_GET_MSR_FEATURES`] capability. This should only be run on the
/// system file descriptor.
pub unsafe fn kvm_get_msr_feature_index_list(fd: RawFd, data: *mut MsrList) -> nix::Result<i32> {
    ehandle(ioctl(fd, iorw!(KVMIO, 0x03, size_of::<MsrList>()), data))
}

/// The API allows the application to query about extensions to the core
/// kvm API.  Userspace passes an extension identifier (an integer) and
/// receives an integer that describes the extension availability.
/// Generally 0 means no and 1 means yes, but some extensions may report
/// additional information in the integer return value.
///
/// Based on their initialization different VMs may have different
/// capabilities. It is thus encouraged to use the VM ioctl to query for
/// capabilities (available with [`KVM_CAP_CHECK_EXTENSION_VM`] on the VM file
/// descriptor).
///
/// Capabilities can be found in the [`capabilities`] module.
///
/// # Support
/// This ioctl is supported by all architectures, and is a basic
/// capability.  This is available on both the system and VM file
/// descriptors.
pub unsafe fn kvm_check_extension(fd: RawFd, ext: i32) -> nix::Result<i32> {
    ehandle(ioctl(fd, io!(KVMIO, 0x03), ext))
}

/// The size of the memory region that the [`kvm_run`] ioctl uses to communicate
/// with userspace, in bytes.
///
/// # Support
/// This ioctl is supported by all architectures, and is a basic
/// capability.  This is available only on the system file descriptor.
pub unsafe fn kvm_get_vcpu_mmap_size(fd: RawFd) -> nix::Result<i32> {
    ehandle(ioctl(fd, io!(KVMIO, 0x04), 0))
}

/// This adds a vCPU to a virtual machine.  No more than `max_cpu`s may be
/// added.  The vCPU id is an integer that is `0 <= id < max_vcpu_id`.  This
/// returns a new file descriptor on success that can then be used with
/// other ioctls.
///
/// The recommended `max_vcpu` can be retrieved using the [`KVM_CAP_NR_VCPUS`]
/// capability check (see [`check_extension`]) at run time.  The absolute
/// maximum possible value for `max_vcpu` can be retrieved using the
/// [`KVM_CAP_MAX_VCPUS`] capability check.  If [`KVM_CAP_NR_VCPUS`] doesn't
/// exist, assume that `max_vcpu = 4`; if [`KVM_CAP_MAX_VCPUS`] doesn't exist,
/// assume that it is the same as the result of [`KVM_CAP_NR_VCPUS`].
///
/// The value for `max_vcpu_id`  can be retrieved using the
/// [`KVM_CAP_MAX_VCPU_ID`] capability check.  If it does not exist, assume
/// that it is the same as the result of [`KVM_CAP_MAX_VCPUS`].
///
/// # Support
/// This ioctl is supported by all architectures, and is a basic
/// capability.  This is available only on the VM file descriptor.
pub unsafe fn kvm_create_vcpu(fd: RawFd, id: i32) -> nix::Result<i32> {
    ehandle(ioctl(fd, io!(KVMIO, 0x41), id))
}

/// Given a memory slot, return a bitmap containing any pages dirtied
/// since the last call to this ioctl.  Bit 0 is the first page in the
/// memory slot.  Ensure the entire structure is cleared to avoid padding
/// issues.
///
/// If [`KVM_CAP_MULTI_ADDRESS_SPACE`] is available, bits 16-31 specifies
/// the address space for which you want to return the dirty bitmap.
/// They must be less than the value that [`kvm_check_extension`] returns for
/// the [`KVM_CAP_MULTI_ADDRESS_SPACE`] capability.
///
/// # Support
/// This ioctl is supported only by the x86 architecture, and is a basic
/// capability.  This is available only on the VM file descriptor.
pub unsafe fn kvm_get_dirty_log(fd: RawFd, log: *const DirtyLog) -> nix::Result<i32> {
    ehandle(ioctl(fd, iow!(KVMIO, 0x42, size_of::<DirtyLog>()), log))
}

/// This ioctl is used to run a guest virtual cpu.  While there are no
/// explicit parameters, there is an implicit parameter block that can be
/// obtained by `mmap`ing the vCPU file descriptor at offset 0, with the size
/// given by [`kvm_get_vcpu_mmap_size`].
///
/// # Support
/// This ioctl is supported by all architectures, and is a basic
/// capability.  This is available only on the vCPU file descriptor.
pub unsafe fn kvm_run(fd: RawFd) -> nix::Result<i32> {
    let r = ioctl(fd, io!(KVMIO, 0x80), 0);
    ehandle(r)
}

/// Translates a virtual address according to the vCPU's current
/// address translation mode.
///
/// # Support
/// This ioctl is supported only by x86, and is a basic capability.
/// This is available only on the vCPU file descriptor.
pub unsafe fn kvm_translate(fd: RawFd, trans: *mut Translation) -> nix::Result<i32> {
    ehandle(ioctl(
        fd,
        iorw!(KVMIO, 0x85, size_of::<Translation>()),
        trans,
    ))
}

/// Queues a hardware interrupt vector to be injected.  Note that
/// the interrupt is an interrupt _vector_.
///
/// # Support
/// This ioctl is supported only by x86, ppc, and mips, and is a
/// basic compatability.  This is available only on the vCPU
/// file descriptor.
pub unsafe fn kvm_interrupt(fd: RawFd, intr: *const Interrupt) -> nix::Result<i32> {
    ehandle(ioctl(fd, iow!(KVMIO, 0x86, size_of::<Interrupt>()), intr))
}

/// This ioctl has varying behavior based on whether it is used on a
/// system file descriptor or a vCPU file descriptor.
///
/// When used on a system file descriptor, it reads the values of
/// MSR-based features that are available for the VM.  This is similar
/// to `kvm_get_supported_cpuid`, but it returns MSR indices and values.
/// The list of MSR-based features can be optained using
/// `kvm_get_msr_feature_index_list`.
///
/// When used on a vCPU file descriptor, it reads model-specific
/// registers from the vCPU.  Supported MSR indicies can be obtained
/// using `kvm_get_msr_index_list`.
///
/// # Support
/// This ioctl is supported only by the x86 architecture.  This is
/// available only on either the system or vCPU file descriptors.
/// If used on a vCPU file descriptor, it is a basic capability.
/// If used on a system file descriptor, it requires the
/// `KVM_CAP_GET_MSR_FEATURES` capability.
pub unsafe fn kvm_get_msrs(fd: RawFd, msrs: *mut Msrs) -> nix::Result<i32> {
    ehandle(ioctl(fd, iorw!(KVMIO, 0x88, size_of::<Msrs>()), msrs))
}

/// Defines the vCPU responses to the CPUID instruction.
///
/// # Support
/// This ioctl is supported only by x86, and is a basic capability.
/// This is available only on the vCPU file descriptor.
pub unsafe fn kvm_set_cpuid(fd: RawFd, cpuid: *const CpuId) -> nix::Result<i32> {
    ehandle(ioctl(fd, iow!(KVMIO, 0x8a, size_of::<CpuId>()), cpuid))
}

/// Defines which signals are blocked during execution of KVM_RUN.  This
/// signal mask temporarily overrides the threads signal mask.  Any
/// unblocked signal received (except SIGKILL and SIGSTOP, which retain
/// their traditional behaviour) will cause KVM_RUN to return with -EINTR.
///
/// Note the signal will only be delivered if not blocked by the original
/// signal mask.
///
/// # Support
/// This ioctl is supported by all architectures, and is a basic
/// capability.  This is available only on the vCPU file descriptor.
pub unsafe fn kvm_set_signal_mask(fd: RawFd, mask: *const SignalMask) -> nix::Result<i32> {
    ehandle(ioctl(fd, iow!(KVMIO, 0x8b, size_of::<SignalMask>()), mask))
}

/// Reads the floating-point state from the vCPU.
///
/// # Support
/// This ioctl is supported only by x86, and is a basic capability.
/// This is available only on the vCPU file descriptor.
pub unsafe fn kvm_get_fpu(fd: RawFd, fpu: *mut Fpu) -> nix::Result<i32> {
    ehandle(ioctl(fd, ior!(KVMIO, 0x8c, size_of::<Fpu>()), fpu))
}

/// Writes the floating-point state to the vCPU.
///
/// # Support
/// This ioctl is supported only by x86, and is a basic capability.
/// This is available only on the vCPU file descriptor.
pub unsafe fn kvm_set_fpu(fd: RawFd, fpu: *const Fpu) -> nix::Result<i32> {
    ehandle(ioctl(fd, iow!(KVMIO, 0x8d, size_of::<Fpu>()), fpu))
}

/// Creates an interrupt control model in the kernel.  For x86,
/// it creates a virtual ioapic, a virtual PIC (two PICs, nested), and
/// sets up future vCPUs to have a local APIC.  IRQ routing for GSIs 0-15
/// is set to both PIC and IOAPIC; GSI 16-23 only go to the IOAPIC.
/// On ARM/arm64, a GICv2 is created. Any other GIC versions require the usage
/// of [`kvm_create_device`], which also supports creating a GICv2.  Using
/// [`kvm_create_device`] is preferred over KVM_CREATE_IRQCHIP for GICv2. On
/// s390, a dummy irq routing table is created.
///
/// # Support
/// This ioctl is only supported by x86, ARM, arm64, and s390 architectures.
/// This requires the [`KVM_CAP_IRQCHIP`] for x86, ARM, and arm64, and
/// [`KVM_CAP_S390_IRQCHIP`] for s390 capabilities.  This is available only on
/// the VM file descriptor.
pub unsafe fn kvm_create_irqchip(fd: RawFd) -> nix::Result<i32> {
    ehandle(ioctl(fd, io!(KVMIO, 0x60), 0))
}

/// Sets the level of a GSI input to the interrupt controller model in the kernel.
/// On some architectures it is required that an interrupt controller model has
/// been previously created with [`kvm_create_irqchip`].  Note that edge-triggered
/// interrupts require the level to be set to 1 and then back to 0.
///
/// On real hardware, interrupt pins can be active-low or active-high.  This
/// does not matter for the level field of struct kvm_irq_level: 1 always
/// means active (asserted), 0 means inactive (deasserted).
///
/// # Support
/// This ioctl is only supported by x86, ARM, and arm64 architectures.
/// This requires the [`KVM_CAP_IRQCHIP`] capability.  This is available only on
/// the VM file descriptor.
pub unsafe fn kvm_irq_line(fd: RawFd, irq: *const IrqLevel) -> nix::Result<i32> {
    ehandle(ioctl(fd, iow!(KVMIO, 0x61, size_of::<IrqLevel>()), irq))
}

/// Sets the MSR that the Xen HVM guest uses to initialize its hypercall
/// page, and provides the starting address and size of the hypercall
/// blobs in userspace.  When the guest writes the MSR, kvm copies one
/// page of a blob (32- or 64-bit, depending on the vcpu mode) to guest
/// memory.
///
/// # Support
/// This ioctl is only supported by x86 architecture. This requires the
/// `KVM_CAP_XEN_HVM` capability.  This is available only on
/// the VM file descriptor.
pub unsafe fn kvm_xen_hvm_config(fd: RawFd, cfg: *const XenHvmConfig) -> nix::Result<i32> {
    ehandle(ioctl(fd, iow!(KVMIO, 0x7a, size_of::<XenHvmConfig>()), cfg))
}

/// Gets the current timestamp of kvmclock as seen by the current guest. In
/// conjunction with [`kvm_set_clock`], it is used to ensure monotonicity on scenarios
/// such as migration.
///
/// When [`KVM_CAP_ADJUST_CLOCK`] is passed to [`KVM_CHECK_EXTENSION`], it returns the
/// set of bits that KVM can return in struct kvm_clock_data's flag member.
///
/// The only flag defined now is [`KVM_CLOCK_TSC_STABLE`].  If set, the returned
/// value is the exact kvmclock value seen by all VCPUs at the instant
/// when [`KVM_GET_CLOCK`] was called.  If clear, the returned value is simply
/// [`CLOCK_MONOTONIC`] plus a constant offset; the offset can be modified
/// with [`KVM_SET_CLOCK`].  KVM will try to make all VCPUs follow this clock,
/// but the exact value read by each VCPU could differ, because the host
/// TSC is not stable.
///
/// # Support
/// This ioctl is only supported by x86 architecture. This requires the
/// [`KVM_CAP_ADJUST_CLOCK`] capability.  This is available only on
/// the VM file descriptor.
pub unsafe fn kvm_get_clock(fd: RawFd, clock: *mut ClockData) -> nix::Result<i32> {
    ehandle(ioctl(fd, ior!(KVMIO, 0x7c, size_of::<ClockData>()), clock))
}

/// Sets the current timestamp of kvmclock as seen by the current guest.  In
/// conjunction with [`kvm_get_clock`], it is used to ensure monotonicity on
/// scenarios such as migration.
///
/// # Support
/// This ioctl is only supported by x86 architecture. This requires the
/// [`KVM_CAP_ADJUST_CLOCK`] capability.  This is available only on
/// the VM file descriptor.
pub unsafe fn kvm_set_clock(fd: RawFd, clock: *const ClockData) -> nix::Result<i32> {
    ehandle(ioctl(fd, iow!(KVMIO, 0x7b, size_of::<ClockData>()), clock))
}

/// This ioctl allows the user to create or modify a guest physical memory
/// slot.  When changing an existing slot, it may be moved in the guest
/// physical memory space, or its flags may be modified.  It may not be
/// resized.  Slots may not overlap in guest physical address space.
/// Bits 0-15 of `slot` specifies the slot id and this value should be
/// less than the maximum number of user memory slots supported per VM.
/// The maximum allowed slots can be queried using the [`KVM_CAP_NR_MEMSLOTS`]
/// capability check, if this capability is supported by the architecture.
///
/// If [`KVM_CAP_MULTI_ADDRESS_SPACE`] is available, bits 16-31 of "slot"
/// specifies the address space which is being modified.  They must be
/// less than the value that `kvm_check_extension` returns for the
/// [`KVM_CAP_MULTI_ADDRESS_SPACE`] capability.  Slots in separate address spaces
/// are unrelated; the restriction on overlapping slots only applies within
/// each address space.
///
/// Memory for the region is taken starting at the address denoted by the
/// field `userspace_addr`, which must point at user addressable memory for
/// the entire memory slot size.  Any object may back this memory, including
/// anonymous memory, ordinary files, and hugetlbfs.
///
/// It is recommended that the lower 21 bits of guest_phys_addr and userspace_addr
/// be identical.  This allows large pages in the guest to be backed by large
/// pages in the host.
///
/// The flags field supports two flags: [`KVM_MEM_LOG_DIRTY_PAGES`] and
/// [`KVM_MEM_READONLY`].  The former can be set to instruct KVM to keep track of
/// writes to memory within the slot.  See [`kvm_get_dirty_log`] to know how to
/// use it.  The latter can be set, if [`KVM_CAP_READONLY_MEM`] capability allows it,
/// to make a new slot read-only.  In this case, writes to this memory will be
/// posted to userspace as [`KVM_EXIT_MMIO`] exits.
///
/// When the [`KVM_CAP_SYNC_MMU`] capability is available, changes in the backing of
/// the memory region are automatically reflected into the guest.  For example, an
/// `mmap` that affects the region will be made visible immediately.  Another
/// example is madvise(MADV_DROP).
///
/// # Support
/// This ioctl is supported by all architectures, and requires the
/// [`KVM_CAP_USER_MEM`] basic capability.  This is available only on the VM file
/// descriptor.
pub unsafe fn kvm_set_user_memory_region(
    fd: RawFd,
    umr: *const UserspaceMemoryRegion,
) -> nix::Result<i32> {
    ehandle(ioctl(
        fd,
        iow!(KVMIO, 0x46, size_of::<UserspaceMemoryRegion>()),
        umr,
    ))
}

/// This ioctl defines the physical address of a three-page region in the guest
/// physical address space.  The region must be within the first 4GB of the
/// guest physical address space and must not conflict with any memory slot
/// or any mmio address.  The guest may malfunction if it accesses this memory
/// region.
///
/// **This ioctl is required on Intel-based hosts.**  This is needed on Intel
/// hardware because of a quirk in the virtualization implementation (see the
/// internals documentation when it pops into existence).
///
/// A good choice for this may be `0xfffbd000`.
///
/// # Support
/// This ioctl is supported only by the x86 architecture, and requires the
/// [`KVM_CAP_SET_TSS_ADDR`] basic capability.  This is available only on the VM
/// file descriptor.
pub unsafe fn kvm_set_tss_addr(fd: RawFd, addr: i32) -> nix::Result<i32> {
    ehandle(ioctl(fd, io!(KVMIO, 0x47), addr))
}

/// Not all extensions are enabled by default. Using this ioctl the application
/// can enable an extension, making it available to the guest.
///
/// On systems that do not support this ioctl, it always fails. On systems that
/// do support it, it only works for extensions that are supported for enablement.
///
/// To check if a capability can be enabled, the [`kvm_check_extension`] ioctl should
/// be used.
///
/// # Support
/// This is only available on either the vCPU file descriptor, or on the VM file
/// descriptor.  It is available:
///
/// - on x86, requiring the [`KVM_CAP_ENABLE_CAP_VM`] capability, and without vCPU
///   file descriptor support;
/// - on mips, requiring the [`KVM_CAP_ENABLE_CAP`] capability, and without VM
///   file descriptor support;
/// - on ppc, requiring the [`KVM_CAP_ENABLE_CAP`] for vCPU file descriptor support,
///   and [`KVM_CAP_ENABLE_CAP_VM`] for VM file descriptor support;
/// - on s390, requiring the [`KVM_CAP_ENABLE_CAP`] for vCPU file descriptor support,
///   and [`KVM_CAP_ENABLE_CAP_VM`] for VM file descriptor support.
pub unsafe fn kvm_enable_cap(fd: RawFd, cap: *const EnableCap) -> nix::Result<i32> {
    ehandle(ioctl(fd, iow!(KVMIO, 0xa3, size_of::<EnableCap>()), cap))
}

/// Returns the vCPU's current "multiprocessing state" (though also valid on
/// uniprocessor guests).  Possible values are [`KVM_MP_STATE_RUNNABLE`],
/// [`KVM_MP_STATE_UNINITIALIZED`], [`KVM_MP_STATE_INIT_RECEIVED`],
/// [`KVM_MP_STATE_HALTED`], [`KVM_MP_STATE_SIPI_RECEIVED`], [`KVM_MP_STATE_STOPPED`],
/// [`KVM_MP_STATE_CHECK_STOP`], [`KVM_MP_STATE_OPERATING`], and [`KVM_MP_STATE_LOAD`].
///
/// On x86, this ioctl is only useful after [`kvm_create_irqchip`]. Without an
/// in-kernel irqchip, the multiprocessing state must be maintained by userspace on
/// these architectures.
///
/// On ARM/arm64, the only states that are valid are [`KVM_MP_STATE_STOPPED`] and
/// [`KVM_MP_STATE_RUNNABLE`] which reflect if the vcpu is paused or not.
///
/// # Support
/// This ioctl is supported only by the x86, s390, ARM, and arm64 architectures,
/// and requires the [`KVM_CAP_MP_STATE`] capability.  This is only available on the
/// vCPU file descriptor.
pub unsafe fn kvm_get_mp_state(fd: RawFd, state: *mut MpState) -> nix::Result<i32> {
    ehandle(ioctl(fd, ior!(KVMIO, 0x98, size_of::<MpState>()), state))
}

/// Sets the vCPU's current "multiprocessing state." Possible values are
/// [`KVM_MP_STATE_RUNNABLE`], [`KVM_MP_STATE_UNINITIALIZED`],
/// [`KVM_MP_STATE_INIT_RECEIVED`], [`KVM_MP_STATE_HALTED`],
/// [`KVM_MP_STATE_SIPI_RECEIVED`], [`KVM_MP_STATE_STOPPED`],
/// [`KVM_MP_STATE_CHECK_STOP`], [`KVM_MP_STATE_OPERATING`], and
/// [`KVM_MP_STATE_LOAD`].
///
/// On x86, this ioctl is only useful after [`kvm_create_irqchip`]. Without an
/// in-kernel irqchip, the multiprocessing state must be maintained by userspace on
/// these architectures.
///
/// On ARM/arm64, The only states that are valid are [`KVM_MP_STATE_STOPPED`] and
/// [`KVM_MP_STATE_RUNNABLE`] which reflect if the vCPU should be paused or not.
///
/// # Support
/// This ioctl is supported only by the x86, s390, ARM, and arm64 architectures,
/// and requires the [`KVM_CAP_MP_STATE`] capability.  This is only available on the
/// vCPU file descriptor.
pub unsafe fn kvm_set_mp_state(fd: RawFd, state: *const MpState) -> nix::Result<i32> {
    ehandle(ioctl(fd, iow!(KVMIO, 0x99, size_of::<MpState>()), state))
}

/// This ioctl defines the physical address of a one-page region in the guest
/// physical address space.  The region must be within the first 4GB of the
/// guest physical address space and must not conflict with any memory slot
/// or any mmio address.  The guest may malfunction if it accesses this memory
/// region.
///
/// Setting the address to 0 will result in resetting the address to its default
/// (`0xfffbc000`).
///
/// **This ioctl is required on Intel-based hosts.**  This is needed on Intel
/// hardware because of a quirk in the virtualization implementation (see the
/// internals documentation when it pops into existence).
///
/// Fails if any vCPU has already been created.
///
/// # Support
/// This ioctl is supported only by the x86 architecture, and requires the
/// [`KVM_CAP_SET_IDENTITY_MAP_ADDR`] capability.  This is only available on the
/// VM file descriptor.
pub unsafe fn kvm_set_identity_map_addr(fd: RawFd, addr: *const u64) -> nix::Result<i32> {
    ehandle(ioctl(fd, iow!(KVMIO, 0x48, size_of::<u64>()), addr))
}

/// This ioctl attaches or detaches an ioeventfd to a legal pio/mmio address
/// within the guest.  A guest write in the registered address will signal
/// the provided event instead of triggering an exit.
///
/// The ioctl takes four possible flags, with this library concerning itself
/// with only two of those: `KVM_IOEVENTFD_FLAG_PIO` and
/// `KVM_IOEVENTFD_FLAG_DEASSIGN`.
///
/// With KVM_CAP_IOEVENTFD_ANY_LENGTH, a zero length ioeventfd is allowed,
/// and the kernel will ignore the length of guest write and may get a
/// faster vmexit.  The speedup may only apply to specific architectures,
/// but the ioeventfd will work anyway.
///
/// # Support
/// This ioctl is supported by all architectures, and requires the
/// `KVM_CAP_IOEVENTFD` capability.  This is only available on the VM file
/// descriptor.
pub unsafe fn kvm_ioeventfd(fd: RawFd, io: *const IoEventFd) -> nix::Result<i32> {
    ehandle(ioctl(fd, iow!(KVMIO, 0x79, size_of::<IoEventFd>()), io))
}

/// Allows setting an eventfd to directly trigger a guest interrupt.
/// `kvm_irqfd.fd` specifies the file descriptor to use as the eventfd and
/// `kvm_irqfd.gsi` specifies the irqchip pin toggled by this event.  When
/// an event is triggered on the eventfd, an interrupt is injected into
/// the guest using the specified gsi pin.  The irqfd is removed using
/// the `KVM_IRQFD_FLAG_DEASSIGN` flag, specifying both `kvm_irqfd.fd`
/// and `kvm_irqfd.gsi.`
///
/// With [`KVM_CAP_IRQFD_RESAMPLE`], [`kvm_irqfd`] supports a de-assert and notify
/// mechanism allowing emulation of level-triggered, irqfd-based
/// interrupts.  When [`KVM_IRQFD_FLAG_RESAMPLE`] is set the user must pass an
/// additional eventfd in the `kvm_irqfd.resamplefd` field.  When operating
/// in resample mode, posting of an interrupt through `kvm_irq.fd` asserts
/// the specified gsi in the irqchip.  When the irqchip is resampled, such
/// as from an EOI, the gsi is de-asserted and the user is notified via
/// `kvm_irqfd.resamplefd`.  It is the user's responsibility to re-queue
/// the interrupt if the device making use of it still requires service.
/// Note that closing the resamplefd is not sufficient to disable the
/// irqfd.  The [`KVM_IRQFD_FLAG_RESAMPLE`] is only necessary on assignment
/// and need not be specified with [`KVM_IRQFD_FLAG_DEASSIGN`].
///
/// On arm/arm64, gsi routing being supported, the following can happen:
/// - in case no routing entry is associated to this gsi, injection fails
/// - in case the gsi is associated to an irqchip routing entry,
///   irqchip.pin + 32 corresponds to the injected SPI ID.
/// - in case the gsi is associated to an MSI routing entry, the MSI
///   message and device ID are translated into an LPI (support restricted
///   to GICv3 ITS in-kernel emulation).
///
/// # Support
/// This ioctl is supported only by the x86, s390, arm, and arm64 architectures,
/// and requires the `KVM_CAP_IRQFD` capability.  This is only available
/// on the VM file descriptor.
pub unsafe fn kvm_irqfd(fd: RawFd, io: *const IrqFd) -> nix::Result<i32> {
    ehandle(ioctl(fd, iow!(KVMIO, 0x76, size_of::<IrqFd>()), io))
}
