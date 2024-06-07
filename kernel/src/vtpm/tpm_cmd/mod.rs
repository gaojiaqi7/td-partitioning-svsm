// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

pub mod tpm2_command;
pub mod tpm2_digests;
pub mod tpm2_extend;

pub const TPM2_COMMAND_HEADER_SIZE: usize = 10;
pub const TPM2_RESPONSE_HEADER_SIZE: usize = 10;
pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;

pub const TPM_CC_STARTUP: u32 = 0x144;
pub const TPM_SU_CLEAR: u16 = 0u16;
pub const TPM_SU_STATE: u16 = 1u16;
pub const TPM_RC_SUCCESS: u32 = 0;

/// TPM Startup
pub const TPM_STARTUP_CMD: [u8; 12] = [
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
];

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum VtpmError {
    /// Buffer too small
    Truncated,

    /// Out of Resource
    OutOfResource,

    /// Vmm error
    VmmError,

    /// Spdm error
    SpdmError,

    /// PipeError
    PipeError,

    /// Invalid param
    InvalidParameter,

    ///
    ExceedMaxConnection,

    ///
    ExceedMaxTpmInstanceCount,

    ///
    TpmLibError,

    Unknown,
}
pub type VtpmResult<T = ()> = Result<T, VtpmError>;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum TdVtpmOperation {
    None = 0,
    Communicate = 1,
    Create = 2,
    Destroy = 3,
    Migration = 4,
    Invalid = 0xff,
}

impl TryFrom<u8> for TdVtpmOperation {
    type Error = VtpmError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TdVtpmOperation::None),
            1 => Ok(TdVtpmOperation::Communicate),
            2 => Ok(TdVtpmOperation::Create),
            3 => Ok(TdVtpmOperation::Destroy),
            4 => Ok(TdVtpmOperation::Migration),
            _ => Err(VtpmError::InvalidParameter),
        }
    }
}
