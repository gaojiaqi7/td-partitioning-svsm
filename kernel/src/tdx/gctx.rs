// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

use super::error::TdxError;
use super::percpu::this_vcpu;
use super::utils::TdpVmId;
use super::vcr::GuestCpuCrRegs;
use super::vmcs::Vmcs;
use super::vmcs_lib::{VmcsField16Guest, VmcsField32Guest, VmcsField64Guest};
use super::vmsr::GuestCpuMsrs;
use crate::address::VirtAddr;
use crate::cpu::control_regs::CR0Flags;
use crate::locking::SpinLock;
use crate::mm::address_space::virt_to_phys;
use core::default::Default;
use core::fmt::Debug;

#[derive(Debug)]
struct Cache<T>
where
    T: Copy + Clone + Debug + Default,
{
    val: T,
    dirty: bool,
}

pub struct RegCache<T>
where
    T: Copy + Clone + Debug + Default,
{
    vm_id: TdpVmId,
    cache: SpinLock<Option<Cache<T>>>,
    readhw: Option<fn(&Vmcs) -> T>,
    writehw: Option<fn(&Vmcs, T)>,
}

impl<T: Copy + Clone + Debug + Default> RegCache<T> {
    pub fn new(
        vm_id: TdpVmId,
        readhw: Option<fn(&Vmcs) -> T>,
        writehw: Option<fn(&Vmcs, T)>,
    ) -> Self {
        RegCache {
            vm_id,
            cache: SpinLock::new(None),
            readhw,
            writehw,
        }
    }

    pub fn vm_id(&self) -> TdpVmId {
        self.vm_id
    }

    // read from hardware if cache doesn't exists, and
    // cache the value to accelorate reading for the next time.
    pub fn read_cache(&self) -> T {
        let mut cache = self.cache.lock();
        if let Some(v) = cache.as_ref() {
            return v.val;
        }

        let v = if let Some(readhw) = self.readhw {
            let vmcs = this_vcpu(self.vm_id).get_vmcs();
            readhw(vmcs)
        } else {
            T::default()
        };
        *cache = Some(Cache {
            val: v,
            dirty: false,
        });
        v
    }

    // write the value to cache
    pub fn write_cache(&mut self, val: T) {
        *self.cache.lock() = Some(Cache { val, dirty: true });
    }

    fn take_cache(&mut self) -> Option<Cache<T>> {
        let mut cache = self.cache.lock();
        cache.take()
    }

    // write_hw should be called if the write is done
    // by write_cache as write_cache won't write the value
    // to hardware but just cache it.
    pub fn sync_cache(&mut self) {
        if let Some(writehw) = self.writehw {
            let vmcs = this_vcpu(self.vm_id).get_vmcs();
            if self.readhw.is_none() {
                // If there is no readhw operation, which means this
                // is used for a preserved register. Keep the cache.
                if let Some(c) = self.cache.lock().as_ref() {
                    if c.dirty {
                        writehw(vmcs, c.val);
                    }
                }
            } else if let Some(c) = self.take_cache() {
                if c.dirty {
                    writehw(vmcs, c.val);
                }
            }
        }
    }
}

#[derive(Copy, Clone, Default)]
struct GuestCpuGPRegs {
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

#[repr(C)]
#[repr(align(256))]
#[derive(Clone, Copy, Default)]
struct GuestCpuTdpContext {
    gpregs: GuestCpuGPRegs,
    rflags: u64,
    rip: u64,
    ssp: u64,
    intr_status: u16,
}

#[derive(Copy, Clone)]
pub struct Segment {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub attr: u32,
}

impl Segment {
    fn new(selector: u16, base: u64, limit: u32, attr: u32) -> Self {
        Segment {
            selector,
            base,
            limit,
            attr,
        }
    }
}

struct SegCache {
    selector: RegCache<u16>,
    base: RegCache<u64>,
    limit: RegCache<u32>,
    attr: RegCache<u32>,
}

impl SegCache {
    fn get(&self) -> Segment {
        Segment::new(
            self.selector.read_cache(),
            self.base.read_cache(),
            self.limit.read_cache(),
            self.attr.read_cache(),
        )
    }

    fn set(&mut self, seg: Segment) {
        self.selector.write_cache(seg.selector);
        self.base.write_cache(seg.base);
        self.limit.write_cache(seg.limit);
        self.attr.write_cache(seg.attr);
    }

    fn load(&mut self) {
        self.selector.sync_cache();
        self.base.sync_cache();
        self.limit.sync_cache();
        self.attr.sync_cache();
    }
}

macro_rules! seg_cache {
    ($vm_id: ident, $selector: ident, $base: ident, $limit: ident, $attr: ident) => {
        SegCache {
            selector: RegCache::new(
                $vm_id,
                Some(|vmcs| vmcs.read16(VmcsField16Guest::$selector)),
                Some(|vmcs, v| vmcs.write16(VmcsField16Guest::$selector, v)),
            ),
            base: RegCache::new(
                $vm_id,
                Some(|vmcs| vmcs.read64(VmcsField64Guest::$base)),
                Some(|vmcs, v| vmcs.write64(VmcsField64Guest::$base, v)),
            ),
            limit: RegCache::new(
                $vm_id,
                Some(|vmcs| vmcs.read32(VmcsField32Guest::$limit)),
                Some(|vmcs, v| vmcs.write32(VmcsField32Guest::$limit, v)),
            ),
            attr: RegCache::new(
                $vm_id,
                Some(|vmcs| vmcs.read32(VmcsField32Guest::$attr)),
                Some(|vmcs, v| vmcs.write32(VmcsField32Guest::$attr, v)),
            ),
        }
    };
    ($vm_id: ident, $base: ident, $limit: ident) => {
        SegCache {
            selector: RegCache::new($vm_id, None, None),
            base: RegCache::new(
                $vm_id,
                Some(|vmcs| vmcs.read64(VmcsField64Guest::$base)),
                Some(|vmcs, v| vmcs.write64(VmcsField64Guest::$base, v)),
            ),
            limit: RegCache::new(
                $vm_id,
                Some(|vmcs| vmcs.read32(VmcsField32Guest::$limit)),
                Some(|vmcs, v| vmcs.write32(VmcsField32Guest::$limit, v)),
            ),
            attr: RegCache::new($vm_id, None, None),
        }
    };
}

#[allow(dead_code)]
#[derive(Copy, Clone, PartialEq)]
pub enum GuestCpuSegCode {
    Idtr,
    Gdtr,
    Ldtr,
    CS,
    DS,
    ES,
    FS,
    GS,
    SS,
    TR,
}

struct GuestCpuSegs {
    idtr: SegCache,
    gdtr: SegCache,
    ldtr: SegCache,
    cs: SegCache,
    ds: SegCache,
    es: SegCache,
    fs: SegCache,
    gs: SegCache,
    ss: SegCache,
    tr: SegCache,
}

impl GuestCpuSegs {
    fn init(&mut self, vm_id: TdpVmId) {
        self.idtr = seg_cache!(vm_id, IDTR_BASE, IDTR_LIMIT);
        self.gdtr = seg_cache!(vm_id, GDTR_BASE, GDTR_LIMIT);
        self.ldtr = seg_cache!(vm_id, LDTR_SELECTOR, LDTR_BASE, LDTR_LIMIT, LDTR_AR_BYTES);
        self.cs = seg_cache!(vm_id, CS_SELECTOR, CS_BASE, CS_LIMIT, CS_AR_BYTES);
        self.ds = seg_cache!(vm_id, DS_SELECTOR, DS_BASE, DS_LIMIT, DS_AR_BYTES);
        self.es = seg_cache!(vm_id, ES_SELECTOR, ES_BASE, ES_LIMIT, ES_AR_BYTES);
        self.fs = seg_cache!(vm_id, FS_SELECTOR, FS_BASE, FS_LIMIT, FS_AR_BYTES);
        self.gs = seg_cache!(vm_id, GS_SELECTOR, GS_BASE, GS_LIMIT, GS_AR_BYTES);
        self.ss = seg_cache!(vm_id, SS_SELECTOR, SS_BASE, SS_LIMIT, SS_AR_BYTES);
        self.tr = seg_cache!(vm_id, TR_SELECTOR, TR_BASE, TR_LIMIT, TR_AR_BYTES);
    }

    fn load(&mut self) {
        self.idtr.load();
        self.gdtr.load();
        self.ldtr.load();
        self.cs.load();
        self.ds.load();
        self.es.load();
        self.fs.load();
        self.gs.load();
        self.ss.load();
        self.tr.load();
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum GuestCpuGPRegCode {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl TryFrom<u8> for GuestCpuGPRegCode {
    type Error = TdxError;

    fn try_from(val: u8) -> Result<GuestCpuGPRegCode, Self::Error> {
        match val {
            0 => Ok(GuestCpuGPRegCode::Rax),
            1 => Ok(GuestCpuGPRegCode::Rcx),
            2 => Ok(GuestCpuGPRegCode::Rdx),
            3 => Ok(GuestCpuGPRegCode::Rbx),
            4 => Ok(GuestCpuGPRegCode::Rsp),
            5 => Ok(GuestCpuGPRegCode::Rbp),
            6 => Ok(GuestCpuGPRegCode::Rsi),
            7 => Ok(GuestCpuGPRegCode::Rdi),
            8 => Ok(GuestCpuGPRegCode::R8),
            9 => Ok(GuestCpuGPRegCode::R9),
            10 => Ok(GuestCpuGPRegCode::R10),
            11 => Ok(GuestCpuGPRegCode::R11),
            12 => Ok(GuestCpuGPRegCode::R12),
            13 => Ok(GuestCpuGPRegCode::R13),
            14 => Ok(GuestCpuGPRegCode::R14),
            15 => Ok(GuestCpuGPRegCode::R15),
            _ => Err(TdxError::InvalidGPRegCode),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum GuestCpuRegCode {
    GP(GuestCpuGPRegCode),
    Rip,
}

#[derive(Clone, Copy, PartialEq)]
pub enum GuestCpuMode {
    Real,
    Protected,
    Compatibility,
    Bit64,
}

impl GuestCpuMode {
    pub fn is_bit64(&self) -> bool {
        matches!(self, GuestCpuMode::Bit64)
    }
}

const REAL_MODE_RIP: u64 = 0xfff0;
const REAL_MODE_RFLAGS: u64 = 0x02;
const REAL_MODE_BSP_INIT_CODE_SEL: u16 = 0xf000;
const REAL_MODE_DATA_SEG_AR: u32 = 0x0093;
const REAL_MODE_CODE_SEG_AR: u32 = 0x009f;
const REAL_MODE_LDTR_SEG_AR: u32 = 0x0082;
const REAL_MODE_TR_SEG_AR: u32 = 0x008b;
const REAL_MODE_SEG_LIMIT: u32 = 0xffff;
const REAL_MODE_DATA_SEG_BASE: u64 = 0;
const REAL_MODE_CODE_SEG_BASE: u64 = 0xffff_0000;
const REAL_MODE_CR0: u64 = 0x30; /*CR0.ET + CR0.NE*/

pub struct GuestCpuContext {
    vm_id: TdpVmId,
    tdp_ctx: GuestCpuTdpContext,
    tdp_ctx_pa: u64,
    ia32_efer: RegCache<u64>,
    segs: GuestCpuSegs,
    cr: GuestCpuCrRegs,
    msrs: GuestCpuMsrs,
}

impl GuestCpuContext {
    pub fn init(&mut self, vm_id: TdpVmId) {
        self.vm_id = vm_id;
        self.tdp_ctx_pa = u64::from(virt_to_phys(VirtAddr::from(core::ptr::addr_of!(
            self.tdp_ctx
        ))));
        // IA32_EFER is preserved across L2 VM exit & entry, so the
        // cache in RegCache is always up to date. So no need to provide
        // a readhw operation.
        self.ia32_efer = RegCache::new(
            vm_id,
            None,
            Some(|vmcs, v| vmcs.write64(VmcsField64Guest::IA32_EFER, v)),
        );
        self.segs.init(vm_id);
        self.cr.init(vm_id);
        self.msrs.init(vm_id);
    }

    pub fn reset(&mut self) {
        self.tdp_ctx = GuestCpuTdpContext::default();
        self.tdp_ctx.rip = REAL_MODE_RIP;
        self.tdp_ctx.rflags = REAL_MODE_RFLAGS;
        self.ia32_efer.write_cache(0);
        self.segs.idtr.set(Segment::new(
            0,
            REAL_MODE_DATA_SEG_BASE,
            REAL_MODE_SEG_LIMIT,
            0,
        ));
        self.segs.gdtr.set(Segment::new(
            0,
            REAL_MODE_DATA_SEG_BASE,
            REAL_MODE_SEG_LIMIT,
            0,
        ));
        self.segs.cs.set(Segment::new(
            REAL_MODE_BSP_INIT_CODE_SEL,
            REAL_MODE_CODE_SEG_BASE,
            REAL_MODE_SEG_LIMIT,
            REAL_MODE_CODE_SEG_AR,
        ));
        self.segs.ds.set(Segment::new(
            REAL_MODE_BSP_INIT_CODE_SEL,
            REAL_MODE_DATA_SEG_BASE,
            REAL_MODE_SEG_LIMIT,
            REAL_MODE_DATA_SEG_AR,
        ));
        self.segs.es.set(Segment::new(
            REAL_MODE_BSP_INIT_CODE_SEL,
            REAL_MODE_DATA_SEG_BASE,
            REAL_MODE_SEG_LIMIT,
            REAL_MODE_DATA_SEG_AR,
        ));
        self.segs.fs.set(Segment::new(
            REAL_MODE_BSP_INIT_CODE_SEL,
            REAL_MODE_DATA_SEG_BASE,
            REAL_MODE_SEG_LIMIT,
            REAL_MODE_DATA_SEG_AR,
        ));
        self.segs.gs.set(Segment::new(
            REAL_MODE_BSP_INIT_CODE_SEL,
            REAL_MODE_DATA_SEG_BASE,
            REAL_MODE_SEG_LIMIT,
            REAL_MODE_DATA_SEG_AR,
        ));
        self.segs.ss.set(Segment::new(
            REAL_MODE_BSP_INIT_CODE_SEL,
            REAL_MODE_DATA_SEG_BASE,
            REAL_MODE_SEG_LIMIT,
            REAL_MODE_DATA_SEG_AR,
        ));
        self.segs.tr.set(Segment::new(
            0,
            REAL_MODE_DATA_SEG_BASE,
            REAL_MODE_SEG_LIMIT,
            REAL_MODE_TR_SEG_AR,
        ));
        self.segs.ldtr.set(Segment::new(
            0,
            REAL_MODE_DATA_SEG_BASE,
            REAL_MODE_SEG_LIMIT,
            REAL_MODE_LDTR_SEG_AR,
        ));

        self.cr
            .set_cr0(REAL_MODE_CR0)
            .expect("Failed to reset CR0 to real mode");
        self.cr
            .set_cr2(0)
            .expect("Failed to reset CR2 to real mode");
        self.cr
            .set_cr3(0)
            .expect("Failed to reset CR3 to real mode");
        self.cr
            .set_cr4(0)
            .expect("Failed to reset CR4 to real mode");

        self.msrs.reset();
    }

    pub fn get_efer(&self) -> u64 {
        self.ia32_efer.read_cache()
    }

    pub fn set_efer(&mut self, val: u64) {
        self.ia32_efer.write_cache(val);
    }

    pub fn get_cr0(&self) -> u64 {
        self.cr.get_cr0()
    }

    pub fn set_cr2(&mut self, val: u64) -> Result<(), TdxError> {
        self.cr.set_cr2(val)
    }

    pub fn get_cr3(&self) -> u64 {
        self.cr.get_cr3()
    }

    pub fn get_cr4(&self) -> u64 {
        self.cr.get_cr4()
    }

    pub fn get_msrs_mut(&mut self) -> &mut GuestCpuMsrs {
        &mut self.msrs
    }

    pub fn get_msrs(&self) -> &GuestCpuMsrs {
        &self.msrs
    }

    pub fn set_intr_status(&mut self, vec: u8) {
        self.tdp_ctx.intr_status &= !0xff;
        self.tdp_ctx.intr_status |= vec as u16;
    }

    pub fn get_rflags(&self) -> u64 {
        self.tdp_ctx.rflags
    }

    pub fn set_rflags(&mut self, val: u64) {
        self.tdp_ctx.rflags = val;
    }

    pub fn get_rip(&self) -> u64 {
        self.tdp_ctx.rip
    }

    pub fn set_rip(&mut self, val: u64) {
        self.tdp_ctx.rip = val;
    }

    pub fn get_gpreg(&self, reg: GuestCpuGPRegCode) -> u64 {
        match reg {
            GuestCpuGPRegCode::Rax => self.tdp_ctx.gpregs.rax,
            GuestCpuGPRegCode::Rcx => self.tdp_ctx.gpregs.rcx,
            GuestCpuGPRegCode::Rdx => self.tdp_ctx.gpregs.rdx,
            GuestCpuGPRegCode::Rbx => self.tdp_ctx.gpregs.rbx,
            GuestCpuGPRegCode::Rsp => self.tdp_ctx.gpregs.rsp,
            GuestCpuGPRegCode::Rbp => self.tdp_ctx.gpregs.rbp,
            GuestCpuGPRegCode::Rsi => self.tdp_ctx.gpregs.rsi,
            GuestCpuGPRegCode::Rdi => self.tdp_ctx.gpregs.rdi,
            GuestCpuGPRegCode::R8 => self.tdp_ctx.gpregs.r8,
            GuestCpuGPRegCode::R9 => self.tdp_ctx.gpregs.r9,
            GuestCpuGPRegCode::R10 => self.tdp_ctx.gpregs.r10,
            GuestCpuGPRegCode::R11 => self.tdp_ctx.gpregs.r11,
            GuestCpuGPRegCode::R12 => self.tdp_ctx.gpregs.r12,
            GuestCpuGPRegCode::R13 => self.tdp_ctx.gpregs.r13,
            GuestCpuGPRegCode::R14 => self.tdp_ctx.gpregs.r14,
            GuestCpuGPRegCode::R15 => self.tdp_ctx.gpregs.r15,
        }
    }

    pub fn set_gpreg(&mut self, reg: GuestCpuGPRegCode, val: u64) {
        match reg {
            GuestCpuGPRegCode::Rax => self.tdp_ctx.gpregs.rax = val,
            GuestCpuGPRegCode::Rcx => self.tdp_ctx.gpregs.rcx = val,
            GuestCpuGPRegCode::Rdx => self.tdp_ctx.gpregs.rdx = val,
            GuestCpuGPRegCode::Rbx => self.tdp_ctx.gpregs.rbx = val,
            GuestCpuGPRegCode::Rsp => self.tdp_ctx.gpregs.rsp = val,
            GuestCpuGPRegCode::Rbp => self.tdp_ctx.gpregs.rbp = val,
            GuestCpuGPRegCode::Rsi => self.tdp_ctx.gpregs.rsi = val,
            GuestCpuGPRegCode::Rdi => self.tdp_ctx.gpregs.rdi = val,
            GuestCpuGPRegCode::R8 => self.tdp_ctx.gpregs.r8 = val,
            GuestCpuGPRegCode::R9 => self.tdp_ctx.gpregs.r9 = val,
            GuestCpuGPRegCode::R10 => self.tdp_ctx.gpregs.r10 = val,
            GuestCpuGPRegCode::R11 => self.tdp_ctx.gpregs.r11 = val,
            GuestCpuGPRegCode::R12 => self.tdp_ctx.gpregs.r12 = val,
            GuestCpuGPRegCode::R13 => self.tdp_ctx.gpregs.r13 = val,
            GuestCpuGPRegCode::R14 => self.tdp_ctx.gpregs.r14 = val,
            GuestCpuGPRegCode::R15 => self.tdp_ctx.gpregs.r15 = val,
        }
    }

    pub fn get_seg(&self, seg: GuestCpuSegCode) -> Segment {
        match seg {
            GuestCpuSegCode::Idtr => self.segs.idtr.get(),
            GuestCpuSegCode::Gdtr => self.segs.gdtr.get(),
            GuestCpuSegCode::Ldtr => self.segs.ldtr.get(),
            GuestCpuSegCode::CS => self.segs.cs.get(),
            GuestCpuSegCode::DS => self.segs.ds.get(),
            GuestCpuSegCode::ES => self.segs.es.get(),
            GuestCpuSegCode::FS => self.segs.fs.get(),
            GuestCpuSegCode::GS => self.segs.gs.get(),
            GuestCpuSegCode::SS => self.segs.ss.get(),
            GuestCpuSegCode::TR => self.segs.tr.get(),
        }
    }

    pub fn get_cpu_mode(&self) -> GuestCpuMode {
        if (self.get_efer() & 0x400) != 0 {
            /* EFER.LMA = 1 */
            if (self.segs.cs.attr.read_cache() & 0x2000) != 0 {
                // CS.L = 1 represents 64bit mode.
                GuestCpuMode::Bit64
            } else {
                GuestCpuMode::Compatibility
            }
        } else if (self.get_cr0() & CR0Flags::PE.bits()) != 0 {
            /* CR0.PE = 1 */
            GuestCpuMode::Protected
        } else {
            GuestCpuMode::Real
        }
    }

    pub fn get_cpl(&self) -> u8 {
        ((self.segs.ss.attr.read_cache() >> 5) & 3) as u8
    }

    pub fn pre_vmentry(&mut self) -> u64 {
        // load ia32_efer if updated
        self.ia32_efer.sync_cache();

        // load Segment registers if updated
        self.segs.load();

        // Load CR registers if updated
        self.cr.load();

        // The TDP context physical address
        // is used as the input parameter to do
        // vmentry.
        self.tdp_ctx_pa
    }

    pub fn post_vmexit(&mut self) {
        // CR2 is got from native CR2 which should be happened
        // it is changed by native software
        let _ = self.cr.get_cr2();
    }
}
