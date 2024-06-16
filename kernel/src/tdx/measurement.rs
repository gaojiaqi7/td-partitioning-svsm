// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use core::str::FromStr;

use super::tdvf::get_tdvf_bfv;
use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::fw_meta::Uuid;
use crate::mm::{PerCPUPageMappingGuard, PAGE_SIZE};
use crate::tdx::error::TdxError;
use crate::vtpm::tpm_cmd::tpm2_command::Tpm2ResponseHeader;
use crate::vtpm::tpm_cmd::tpm2_digests::{
    Tpm2Digest, Tpm2Digests, TPM2_HASH_ALG_ID_SHA384, TPM2_SHA384_SIZE,
};
use crate::vtpm::tpm_cmd::tpm2_extend::{tpm2_pcr_extend_cmd, MAX_TPM_PCR_EXTEND_CMD_SIZE};
use crate::vtpm::tpm_cmd::{
    TPM2_COMMAND_HEADER_SIZE, TPM2_RESPONSE_HEADER_SIZE, TPM_RC_SUCCESS, TPM_STARTUP_CMD,
};
use crate::vtpm::{vtpm_get_locked, MsTpmSimulatorInterface, TpmError};

#[cfg(feature = "sha2")]
use sha2::{Digest, Sha384};

pub const RTM_MEASUREMENT_STATE_SIZE: usize = 1024;
pub const VRTM_BFV_EVENT_GUID: [u8; 16] = [
    0x9D, 0x34, 0x5B, 0x8D, 0x38, 0xC8, 0x9A, 0x41, 0xBE, 0x58, 0x99, 0xDA, 0xBA, 0xB1, 0x52, 0x64,
];
pub const VRTM_SVSM_VERSION_GUID: [u8; 16] = [
    0xBC, 0xE0, 0x8A, 0x6B, 0x8D, 0x87, 0x8D, 0x44, 0xB4, 0x30, 0x40, 0xF6, 0x00, 0x77, 0x3A, 0x96,
];

static mut VRTM_MEASUREMENT_STATE: RtmMeasurementState = RtmMeasurementState::new();

struct RtmMeasurementState {
    size: usize,
    state: [u8; RTM_MEASUREMENT_STATE_SIZE],
}

impl RtmMeasurementState {
    const fn new() -> Self {
        RtmMeasurementState {
            size: 0,
            state: [0; RTM_MEASUREMENT_STATE_SIZE],
        }
    }

    fn write(&mut self, data: &[u8]) -> Result<(), SvsmError> {
        let unused = self.get_unused_mut();
        if unused.len() < data.len() {
            return Err(SvsmError::Tdx(TdxError::Measurement));
        }
        unused[..data.len()].copy_from_slice(data);
        self.size += data.len();

        Ok(())
    }

    fn get_unused_mut(&mut self) -> &mut [u8] {
        &mut self.state[self.size..]
    }
}

fn hash_sha384(
    hash_data: &[u8],
    digest_sha384: &mut [u8; TPM2_SHA384_SIZE],
) -> Result<(), SvsmError> {
    let mut digest = Sha384::new();
    digest.update(hash_data);
    let digest = digest.finalize();

    if digest.len() != TPM2_SHA384_SIZE {
        Err(SvsmError::Tdx(TdxError::Measurement))
    } else {
        digest_sha384.clone_from_slice(digest.as_slice());
        Ok(())
    }
}

fn tpm_startup() -> Result<(), SvsmError> {
    let backend = vtpm_get_locked();

    // Send TPM_STARTUP CMD
    let mut tpm_startup_cmd = TPM_STARTUP_CMD;
    if backend
        .send_tpm_command(&mut tpm_startup_cmd, &mut TPM_STARTUP_CMD.len(), 0)
        .is_ok()
    {
        let mut response: [u8; TPM2_COMMAND_HEADER_SIZE] = [0; TPM2_COMMAND_HEADER_SIZE];
        response.copy_from_slice(&tpm_startup_cmd[..TPM2_RESPONSE_HEADER_SIZE]);

        let res = Tpm2ResponseHeader::try_from(response);
        let rsp = if let Ok(r) = res {
            r
        } else {
            log::error!("Tpm2 Startup failed!\n");
            return Err(SvsmError::Tdx(TdxError::Measurement));
        };

        // Check TPM response code
        if rsp.response_code != TPM_RC_SUCCESS {
            log::error!("Tpm2 Startup failed!\n");
            return Err(SvsmError::Tdx(TdxError::Measurement));
        } else {
            Ok(())
        }
    } else {
        log::error!("send Stratup request fail!\n");
        return Err(SvsmError::Tdx(TdxError::Measurement));
    }
}

fn tpm_extend(digests: &Tpm2Digests) -> Result<(), SvsmError> {
    // Get Tpm2Digests
    let mut cmd_buff = [0u8; MAX_TPM_PCR_EXTEND_CMD_SIZE];
    let mut tpm_cmd_size = tpm2_pcr_extend_cmd(digests, 0, &mut cmd_buff)?;

    let backend = vtpm_get_locked();
    // Send PCR_EXTEND CMD
    backend
        .send_tpm_command(&mut cmd_buff, &mut tpm_cmd_size, 0)
        .map_err(|_| SvsmError::Tdx(TdxError::Measurement))?;

    let mut response = [0; TPM2_COMMAND_HEADER_SIZE];
    response.copy_from_slice(&cmd_buff[..TPM2_RESPONSE_HEADER_SIZE]);

    let rsp_header = Tpm2ResponseHeader::try_from(response)?;
    log::info!("send pcr extend request success:{:02x?}\n", &response);
    // Check TPM response code
    if rsp_header.response_code != TPM_RC_SUCCESS {
        log::error!("Tpm2PcrExtend failed.\n");
        Err(SvsmError::Tdx(TdxError::Measurement))
    } else {
        Ok(())
    }
}

pub fn extend_svsm_version() -> Result<(), SvsmError> {
    let version = env!("CARGO_PKG_VERSION");
    let mut svsm_version_digests = Tpm2Digests::new();
    let mut digest_sha384 = [0u8; TPM2_SHA384_SIZE];

    hash_sha384(version.as_bytes(), &mut digest_sha384)?;

    svsm_version_digests.push_digest(
        &Tpm2Digest::new(TPM2_HASH_ALG_ID_SHA384, &digest_sha384[..])
            .ok_or(SvsmError::Tdx(TdxError::Measurement))?,
    )?;

    tpm_extend(&svsm_version_digests)?;

    unsafe {
        VRTM_MEASUREMENT_STATE.write(&VRTM_SVSM_VERSION_GUID)?;
        VRTM_MEASUREMENT_STATE.write(&(version.as_bytes().len() as u32).to_le_bytes())?;
        VRTM_MEASUREMENT_STATE.write(version.as_bytes())
    }
}

fn extend_tdvf_image() -> Result<(), SvsmError> {
    // Get the BFV of TDVF
    let fw_blob = get_tdvf_bfv()?;

    // Check if the base address of BFV is valid
    let base = fw_blob.base;
    let len = fw_blob.length;
    if base & 0xfff != 0 {
        return Err(SvsmError::Firmware);
    }

    // Map the code region of TDVF
    let guard =
        PerCPUPageMappingGuard::create(PhysAddr::from(base), PhysAddr::from(base + len), 0)?;

    let vstart = guard.virt_addr().as_ptr::<u8>();

    // Safety: we just mapped a page, so the size must hold. The type
    // of the slice elements is `u8` so there are no alignment requirements.
    let mem: &[u8] = unsafe { core::slice::from_raw_parts(vstart, PAGE_SIZE) };

    let mut digest = [0u8; TPM2_SHA384_SIZE];
    hash_sha384(mem, &mut digest)?;
    let tpm2_digest = Tpm2Digest::new(TPM2_HASH_ALG_ID_SHA384, &digest[..])
        .ok_or(SvsmError::Tpm(TpmError::Unexpected))?;
    let mut digests = Tpm2Digests::new();
    digests.push_digest(&tpm2_digest)?;

    tpm_extend(&digests)?;

    // Record the firmware blob event
    unsafe {
        VRTM_MEASUREMENT_STATE.write(&VRTM_BFV_EVENT_GUID)?;
        VRTM_MEASUREMENT_STATE.write(&(fw_blob.size() as u32).to_le_bytes())?;
        fw_blob.write_in_bytes(&mut VRTM_MEASUREMENT_STATE.get_unused_mut());
    }

    Ok(())
}

pub fn tdx_tpm_measurement_init() -> Result<(), SvsmError> {
    // Send the start up command and initialize the TPM
    tpm_startup()?;

    // Then extend the SVSM version into PCR[0]
    extend_svsm_version()?;

    // Finally extend the TDVF code FV into PCR[0]
    extend_tdvf_image()
}
