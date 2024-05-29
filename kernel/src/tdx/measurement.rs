// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
use crate::vtpm::tpm_cmd::tpm2_command::Tpm2ResponseHeader;
use crate::vtpm::tpm_cmd::tpm2_digests::{
    Tpm2Digest, Tpm2Digests, TPM2_HASH_ALG_ID_SHA384, TPM2_SHA384_SIZE,
};
use crate::vtpm::tpm_cmd::tpm2_extend::{tpm2_pcr_extend_cmd, MAX_TPM_PCR_EXTEND_CMD_SIZE};
use crate::vtpm::tpm_cmd::{
    TPM2_COMMAND_HEADER_SIZE, TPM2_RESPONSE_HEADER_SIZE, TPM_RC_SUCCESS, TPM_STARTUP_CMD,
};
use crate::vtpm::{vtpm_get_locked, MsTpmSimulatorInterface};

pub(crate) type Result<T> = core::result::Result<T, Error>;

#[cfg(feature = "sha2")]
use sha2::{Digest, Sha384};

#[derive(Debug, Clone, Copy)]
pub enum Error {
    StartupTpm,
    ExtendSvsm,
    Hash,
}

fn hash_sha384(hash_data: &str, digest_sha384: &mut [u8; TPM2_SHA384_SIZE]) -> Result<()> {
    let mut digest = Sha384::new();
    digest.update(hash_data);
    let digest = digest.finalize();
    if digest.len() != TPM2_SHA384_SIZE {
        log::error!("Hash SVSM version fail!");
        Err(Error::Hash)
    } else {
        digest_sha384.clone_from_slice(digest.as_slice());
        Ok(())
    }
}

fn tpm_startup() -> Result<()> {
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
            return Err(Error::StartupTpm);
        };

        // Check TPM response code
        if rsp.response_code != TPM_RC_SUCCESS {
            log::error!("Tpm2 Startup failed!\n");
            return Err(Error::StartupTpm);
        } else {
            Ok(())
        }
    } else {
        log::error!("send Stratup request fail!\n");
        return Err(Error::StartupTpm);
    }
}

fn tpm_extend(digests: &Tpm2Digests) -> Result<()> {
    // Get Tpm2Digests
    let mut cmd_buff = [0u8; MAX_TPM_PCR_EXTEND_CMD_SIZE];
    let mut tpm_cmd_size = if let Ok(cmd_size) = tpm2_pcr_extend_cmd(digests, 0, &mut cmd_buff) {
        cmd_size
    } else {
        return Err(Error::ExtendSvsm);
    };

    let backend = vtpm_get_locked();
    // Send PCR_EXTEND CMD
    if backend
        .send_tpm_command(&mut cmd_buff, &mut tpm_cmd_size, 0)
        .is_ok()
    {
        let mut response: [u8; TPM2_COMMAND_HEADER_SIZE] = [0; TPM2_COMMAND_HEADER_SIZE];
        response.copy_from_slice(&cmd_buff[..TPM2_RESPONSE_HEADER_SIZE]);

        let res = Tpm2ResponseHeader::try_from(response);
        log::info!("send pcr extend request success:{:02x?}\n", &response);

        let rsp = if let Ok(r) = res {
            r
        } else {
            return Err(Error::ExtendSvsm);
        };

        // Check TPM response code
        if rsp.response_code != TPM_RC_SUCCESS {
            log::error!("Tpm2PcrExtend failed.\n");
            return Err(Error::ExtendSvsm);
        } else {
            Ok(())
        }
    } else {
        log::error!("send pcr extend request fail!\n");
        return Err(Error::ExtendSvsm);
    }
}

pub fn extend_svsm_version() -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    log::info!("SVSM Version: {:?}", &version);

    let mut svsm_version_digests = Tpm2Digests::new();
    let mut digest_sha384 = [0u8; TPM2_SHA384_SIZE];

    if hash_sha384(version, &mut digest_sha384).is_ok() {
        let hashed_version_digest_sha384 =
            if let Some(digest) = Tpm2Digest::new(TPM2_HASH_ALG_ID_SHA384, &digest_sha384[..]) {
                digest
            } else {
                return Err(Error::Hash);
            };
        if svsm_version_digests
            .push_digest(&hashed_version_digest_sha384)
            .is_ok()
        {
            log::debug!("SVSM extension digests: {:02x?}", &svsm_version_digests);
        } else {
            return Err(Error::Hash);
        }
    } else {
        return Err(Error::Hash);
    }

    if tpm_startup().is_err() {
        return Err(Error::ExtendSvsm);
    }

    if tpm_extend(&svsm_version_digests).is_err() {
        return Err(Error::ExtendSvsm);
    }
    Ok(())
}
