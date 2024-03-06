// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com>

use crate::cpu::interrupts::IrqError;
use crate::cpu::vc::VcError;
use crate::fs::FsError;
use crate::fw_cfg::FwCfgError;
use crate::mm::alloc::AllocError;
use crate::sev::ghcb::GhcbError;
use crate::sev::msr_protocol::GhcbMsrError;
use crate::sev::SevSnpError;
use crate::task::TaskError;
use crate::tdx::error::TdxError;

// As a general rule, functions private to a given module may use the
// leaf error types. Public functions should return an SvsmError
// containing a leaf error type, usually the one corresponding to
// that module. We always provide a way to convert a leaf error into
// a SvsmError via the From trait at the module level.
#[derive(Clone, Copy, Debug)]
pub enum SvsmError {
    // Errors related to GHCB
    Ghcb(GhcbError),
    // Errors related to MSR protocol
    GhcbMsr(GhcbMsrError),
    // Guest memory map related failure
    GuestMemMap,
    // Guest memory map read related failure
    GuestMemMapRead,
    // Guest memory map size too small
    GuestMemMapSize,
    // Guest memory map write related failure
    GuestMemMapWrite,
    // Errors related to SEV-SNP operations, like PVALIDATE or RMPUPDATE
    SevSnp(SevSnpError),
    // Generic errors related to memory management
    Mem,
    // Errors related to the memory allocator
    Alloc(AllocError),
    // There is no VMSA
    MissingVMSA,
    // There is no CAA
    MissingCAA,
    // Invalid address, usually provided by the guest
    InvalidAddress,
    // Errors related to accessing Model-Specific Registers
    Msr,
    // Errors related to firmware parsing
    Firmware,
    // Errors related to firmware configuration contents
    FwCfg(FwCfgError),
    // Errors related to ACPI parsing.
    Acpi,
    // Errors from file systems
    FileSystem(FsError),
    // Task management errors,
    Task(TaskError),
    // Errors from #VC handler
    Vc(VcError),
    // Errors related to TDX
    Tdx(TdxError),
    // Interrupt handler register related error
    Irq(IrqError),
}
