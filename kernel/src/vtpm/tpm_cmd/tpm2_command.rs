// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use core::convert::{Into, TryFrom};

use crate::vtpm::tpm_cmd::VtpmError;

use crate::vtpm::tpm_cmd::{TPM2_COMMAND_HEADER_SIZE, TPM2_RESPONSE_HEADER_SIZE};

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Tpm2CommandHeader {
    pub tag: u16,
    pub param_size: u32,
    pub command_code: u32,
}

impl Tpm2CommandHeader {
    pub fn new(tag: u16, param_size: u32, command_code: u32) -> Tpm2CommandHeader {
        Self {
            tag,
            param_size,
            command_code,
        }
    }
}

impl TryFrom<[u8; TPM2_COMMAND_HEADER_SIZE]> for Tpm2CommandHeader {
    type Error = VtpmError;

    fn try_from(bytes: [u8; TPM2_COMMAND_HEADER_SIZE]) -> Result<Self, VtpmError> {
        let tag = u16::from_be_bytes([bytes[0], bytes[1]]);
        let param_size = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let command_code = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);

        // log::info!(">> {0:X?}, {1:X?}, {2:X?}\n", tag, param_size, command_code);

        Ok(Tpm2CommandHeader {
            tag,
            param_size,
            command_code,
        })
    }
}

impl Into<[u8; TPM2_COMMAND_HEADER_SIZE]> for Tpm2CommandHeader {
    fn into(self) -> [u8; TPM2_COMMAND_HEADER_SIZE] {
        let tag = self.tag.to_be_bytes();
        let param_size = self.param_size.to_be_bytes();
        let command_code = self.command_code.to_be_bytes();

        let mut bytes = [0u8; TPM2_COMMAND_HEADER_SIZE];
        bytes[..2].copy_from_slice(&tag);
        bytes[2..6].copy_from_slice(&param_size);
        bytes[6..TPM2_COMMAND_HEADER_SIZE].copy_from_slice(&command_code);

        bytes
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Tpm2ResponseHeader {
    pub tag: u16,
    pub param_size: u32,
    pub response_code: u32,
}

impl TryFrom<[u8; TPM2_RESPONSE_HEADER_SIZE]> for Tpm2ResponseHeader {
    type Error = VtpmError;

    fn try_from(bytes: [u8; TPM2_RESPONSE_HEADER_SIZE]) -> Result<Self, VtpmError> {
        let tag = u16::from_be_bytes([bytes[0], bytes[1]]);
        let param_size = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let response_code = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);

        Ok(Tpm2ResponseHeader {
            tag,
            param_size,
            response_code,
        })
    }
}

impl Into<[u8; TPM2_RESPONSE_HEADER_SIZE]> for Tpm2ResponseHeader {
    fn into(self) -> [u8; TPM2_RESPONSE_HEADER_SIZE] {
        let tag = self.tag.to_le_bytes();
        let param_size = self.param_size.to_be_bytes();
        let response_code = self.response_code.to_be_bytes();

        let mut bytes = [0u8; TPM2_RESPONSE_HEADER_SIZE];
        bytes[..2].copy_from_slice(&tag);
        bytes[2..6].copy_from_slice(&param_size);
        bytes[6..TPM2_RESPONSE_HEADER_SIZE].copy_from_slice(&response_code);

        bytes
    }
}
