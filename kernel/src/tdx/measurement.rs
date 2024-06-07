// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
use crate::error::SvsmError;
use crate::tdx::error::TdxError;
use crate::vtpm::tpm_cmd::tpm2_command::Tpm2ResponseHeader;
use crate::vtpm::tpm_cmd::tpm2_digests::{
    Tpm2Digest, Tpm2Digests, TPM2_HASH_ALG_ID_SHA384, TPM2_SHA384_SIZE,
};
use crate::vtpm::tpm_cmd::tpm2_extend::{tpm2_pcr_extend_cmd, MAX_TPM_PCR_EXTEND_CMD_SIZE};
use crate::vtpm::tpm_cmd::{
    TPM2_COMMAND_HEADER_SIZE, TPM2_RESPONSE_HEADER_SIZE, TPM_RC_SUCCESS, TPM_STARTUP_CMD,
};
use crate::vtpm::{vtpm_get_locked, MsTpmSimulatorInterface};

#[cfg(feature = "sha2")]
use sha2::{Digest, Sha384};

fn hash_sha384(
    hash_data: &str,
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

    hash_sha384(version, &mut digest_sha384)?;

    svsm_version_digests.push_digest(
        &Tpm2Digest::new(TPM2_HASH_ALG_ID_SHA384, &digest_sha384[..])
            .ok_or(SvsmError::Tdx(TdxError::Measurement))?,
    )?;

    tpm_extend(&svsm_version_digests)
}

pub fn tdx_tpm_measurement_init() -> Result<(), SvsmError> {
    // Send the start up command and initialize the TPM
    tpm_startup()?;

    // Then extend the SVSM version into PCR[0]
    extend_svsm_version()
}
