// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use crate::error::SvsmError;
use crate::vtpm::tpm_cmd::tpm2_command::Tpm2CommandHeader;
use crate::vtpm::tpm_cmd::tpm2_digests::Tpm2Digests;
use crate::vtpm::tpm_cmd::tpm2_digests::MAX_TPM2_DIGESTS_SIZE;
use crate::vtpm::tpm_cmd::{TPM2_COMMAND_HEADER_SIZE, TPM_ST_SESSIONS};
use crate::vtpm::TpmError;

/// TPM PcrExtend
/// vTPM platform commands (SVSM spec, section 8.1 - SVSM_VTPM_QUERY)
///
/// The platform commmand values follow the values used by the
/// Official TPM 2.0 Reference Implementation by Microsoft.
///
/// `ms-tpm-20-ref/TPMCmd/Simulator/include/TpmTcpProtocol.h`
pub const TPM_CC_PCR_EXTEND: u32 = 0x182;

pub const MAX_TPM_PCR_EXTEND_CMD_SIZE: usize = 1024;
const TPM_PCR_HANDLE_SIZE: usize = 4;
const TPM_PCR_EXTEND_AUTHORIZATION_INFO_SIZE: usize = 13;
const TPM_PCR_DIGESTS_COUNT_SIZE: usize = 4;

const TPM_PCR_EXTEND_PCR_HANDLE_OFFSET: usize = TPM2_COMMAND_HEADER_SIZE;
const TPM_PCR_EXTEND_AUTHORIZATION_INFO_OFFSET: usize =
    TPM_PCR_EXTEND_PCR_HANDLE_OFFSET + TPM_PCR_HANDLE_SIZE;
const TPM_PCR_EXTEND_DIGESTS_COUNT_OFFSET: usize =
    TPM_PCR_EXTEND_AUTHORIZATION_INFO_OFFSET + TPM_PCR_EXTEND_AUTHORIZATION_INFO_SIZE;
const TPM_PCR_EXTEND_DIGESTS_VALUE_OFFSET: usize =
    TPM_PCR_EXTEND_DIGESTS_COUNT_OFFSET + TPM_PCR_DIGESTS_COUNT_SIZE;

const TPM_PCR_EXTEND_COMMAND_AUTHORIZATION_INFO: [u8; TPM_PCR_EXTEND_AUTHORIZATION_INFO_SIZE] = [
    0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
];

pub fn tpm2_pcr_extend_cmd(
    digests: &Tpm2Digests,
    pcr_index: u32,
    tpm_command: &mut [u8; MAX_TPM_PCR_EXTEND_CMD_SIZE],
) -> Result<usize, SvsmError> {
    let mut tpm_cmd: [u8; MAX_TPM_PCR_EXTEND_CMD_SIZE] = [0u8; MAX_TPM_PCR_EXTEND_CMD_SIZE];
    let digests_count = digests.digests_count as u32;

    let tpm_cmd_size = (TPM2_COMMAND_HEADER_SIZE
        + TPM_PCR_HANDLE_SIZE
        + TPM_PCR_EXTEND_AUTHORIZATION_INFO_SIZE
        + TPM_PCR_DIGESTS_COUNT_SIZE
        + digests.total_size) as u32;

    if tpm_cmd_size > MAX_TPM_PCR_EXTEND_CMD_SIZE as u32 {
        return Err(SvsmError::Tpm(TpmError::Unexpected));
    }

    let mut digests_value_buffer: [u8; MAX_TPM2_DIGESTS_SIZE] = [0; MAX_TPM2_DIGESTS_SIZE];
    let digests_value = digests.to_be_bytes(&mut digests_value_buffer);
    if digests_value.is_none() {
        return Err(SvsmError::Tpm(TpmError::Unexpected));
    }

    let cmd_header = Tpm2CommandHeader::new(TPM_ST_SESSIONS, tpm_cmd_size, TPM_CC_PCR_EXTEND);
    let cmd_header_bytes: [u8; TPM2_COMMAND_HEADER_SIZE] = cmd_header.into();

    // TPM2_PCR_EXTEND Command layout
    // CommandHeader      <-- 10
    // PcrHandle          <-- 4
    // AuthorizationInfo  <-- 13
    // DigestsCount       <-- 4
    // DigestsValue       <-- n
    tpm_cmd[..TPM2_COMMAND_HEADER_SIZE].copy_from_slice(&cmd_header_bytes);
    tpm_cmd[TPM_PCR_EXTEND_PCR_HANDLE_OFFSET..TPM_PCR_EXTEND_AUTHORIZATION_INFO_OFFSET]
        .copy_from_slice(&pcr_index.to_be_bytes());
    tpm_cmd[TPM_PCR_EXTEND_AUTHORIZATION_INFO_OFFSET..TPM_PCR_EXTEND_DIGESTS_COUNT_OFFSET]
        .copy_from_slice(&TPM_PCR_EXTEND_COMMAND_AUTHORIZATION_INFO);
    tpm_cmd[TPM_PCR_EXTEND_DIGESTS_COUNT_OFFSET..TPM_PCR_EXTEND_DIGESTS_VALUE_OFFSET]
        .copy_from_slice(&digests_count.to_be_bytes());
    tpm_cmd[TPM_PCR_EXTEND_DIGESTS_VALUE_OFFSET..tpm_cmd_size as usize]
        .copy_from_slice(&digests_value_buffer[..digests.total_size]);

    // patch the size of tpm_cmd_pcr_extend
    tpm_cmd[2..6].copy_from_slice(&tpm_cmd_size.to_be_bytes());

    log::debug!("tpm_pcr_extend cmd:\n");
    log::debug!("{:02x?}\n", &tpm_cmd[..tpm_cmd_size as usize]);

    tpm_command.clone_from_slice(&tpm_cmd[..MAX_TPM_PCR_EXTEND_CMD_SIZE]);
    Ok(tpm_cmd_size as usize)
}
