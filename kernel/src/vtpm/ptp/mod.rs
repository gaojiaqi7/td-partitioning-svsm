// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//

use self::crb::{Result, Tpm};

pub mod crb;

static mut TPM: Tpm = Tpm::new();

/// TPM Address Range
/// This Address range is specific to CRB Interface
pub const TPM_START: u64 = 0xfed4_0000;
pub const TPM_SIZE: u64 = 0x1000;
pub const TPM_CRB_BUFFER_MAX: usize = 3968; // 0x1_000 - 0x80

pub fn vtpm_range() -> (u64, u64) {
    (TPM_START, TPM_START + TPM_SIZE)
}

pub fn vtpm_init() -> Result<()> {
    unsafe { TPM.init() }
}

pub fn tpm_mmio_read(addr: u64, size: usize) -> u64 {
    let mut data = 0;
    unsafe {
        let out = core::slice::from_raw_parts_mut(&mut data as *mut _ as *mut u8, size);
        TPM.mmio_read(addr - TPM_START, out);
    }
    data
}

pub fn tpm_mmio_write(addr: u64, data: u64, size: usize) {
    unsafe {
        let input = core::slice::from_raw_parts(&data as *const _ as *const u8, size);
        TPM.mmio_write(addr - TPM_START, input)
    }
}
