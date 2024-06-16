// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Jiaqi Gao <jiaqi.gao@intel.com>

extern crate alloc;

use super::*;
use crate::{
    error::SvsmError,
    vtpm::{vtpm_get_locked, MsTpmSimulatorInterface, TpmError},
};
use alloc::{vec, vec::Vec};

const TPM2_CC_NV_WRITE: u32 = 0x00000137;

pub fn nv_write(nv_index: u32, data: &[u8]) -> Result<(), SvsmError> {
    let mut offset = 0;

    while offset < data.len() {
        let len = if data.len() - offset > MAX_NV_BUFFER_SIZE as usize {
            MAX_NV_BUFFER_SIZE as usize
        } else {
            data.len() - offset
        };
        nv_write_chunck(nv_index, &data[offset..offset + len], offset as u16)?;
        offset += len;
    }

    Ok(())
}

fn nv_write_chunck(nv_index: u32, data: &[u8], offset: u16) -> Result<(), SvsmError> {
    // Setup the NV write command
    let command = tpm2_command_nv_write(nv_index, data, offset)?;
    let mut length = command.len();

    // Copy the command into the request/response buffer
    let mut buffer = vec![0u8; TPM_COMMAND_MAX_BUFFER_SIZE];
    buffer[..length].copy_from_slice(&command);

    // Execute the TPM command
    vtpm_get_locked()
        .send_tpm_command(&mut buffer, &mut length, 0)
        .map_err(|_| SvsmError::Tpm(TpmError::TpmEmulator))?;

    // Validate and parse the TPM response
    tpm2_response_nv_write(&buffer[..length])
}

fn tpm2_command_nv_write(nv_index: u32, data: &[u8], offset: u16) -> Result<Vec<u8>, SvsmError> {
    if data.len() > MAX_NV_BUFFER_SIZE as usize {
        return Err(SvsmError::Tpm(TpmError::Unexpected));
    }

    let mut command: Vec<u8> = Vec::new();

    // TPM header
    command.extend(&TPM2_ST_SESSIONS.to_be_bytes());
    command.extend(&[0u8, 0u8, 0u8, 0u8]); // Placeholder for command size
    command.extend(&TPM2_CC_NV_WRITE.to_be_bytes());

    // authHandle
    command.extend(&TPM2_RH_PLATFORM.to_be_bytes());

    // NV Index
    command.extend(&nv_index.to_be_bytes());

    // Authorization session
    command.extend(&[0u8, 0u8, 0u8, 9u8]); // Authorization size
    command.extend(&TPM2_RS_PW.to_be_bytes()); // Session handle
    command.extend(&[0u8, 0u8]); // Nonce
    command.extend(&[0u8]); // Session attributes
    command.extend(&[0u8, 0u8]); // hmac

    // Data
    command.extend(&(data.len() as u16).to_be_bytes());
    command.extend(data);

    // Offset
    command.extend(&offset.to_be_bytes());

    // Update command size
    let length = command.len() as u32;
    command[2..6].copy_from_slice(&length.to_be_bytes());

    Ok(command)
}

fn tpm2_response_nv_write(response: &[u8]) -> Result<(), SvsmError> {
    if response.len() < TPM2_RESPONSE_HEADER_SIZE {
        return Err(SvsmError::Tpm(TpmError::Unexpected));
    }

    // Safety: we have checked the length of the response
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    if rc != TPM_RC_SUCCESS {
        return Err(SvsmError::Tpm(TpmError::TpmCommands(rc)));
    }

    Ok(())
}
