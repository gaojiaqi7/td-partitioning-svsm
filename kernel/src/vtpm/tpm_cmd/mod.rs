// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

extern crate alloc;

use alloc::vec::Vec;

pub mod tpm2_command;
pub mod tpm2_create_loaded;
pub mod tpm2_create_primary;
pub mod tpm2_digests;
pub mod tpm2_extend;
pub mod tpm2_get_capability;
pub mod tpm2_nvdefine;
pub mod tpm2_nvwrite;
pub mod tpm2_sign;

pub const TPM2_COMMAND_HEADER_SIZE: usize = 10;
pub const TPM2_RESPONSE_HEADER_SIZE: usize = 10;
pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;

pub const TPM_CC_STARTUP: u32 = 0x144;
pub const TPM_SU_CLEAR: u16 = 0u16;
pub const TPM_SU_STATE: u16 = 1u16;
pub const TPM_RC_SUCCESS: u32 = 0;

pub const TPM2_ST_SESSIONS: u16 = 0x8002;
pub const TPM2_RH_OWNER: u32 = 0x40000001;
pub const TPM2_RH_ENDORSEMENT: u32 = 0x4000000B;
pub const TPM2_RH_PLATFORM: u32 = 0x4000000C;
pub const TPM2_RS_PW: u32 = 0x40000009;

pub const MAX_NV_BUFFER_SIZE: u32 = 1024;
pub const MAX_NV_INDEX_SIZE: u32 = 2048;

pub const TPM_COMMAND_MAX_BUFFER_SIZE: usize = 0x1000;

// Object attributes
pub const TPMA_OBJ_FIXED_TPM: u32 = 0x00000002; // Fixed attribute indicating that the object is a fixed TPM-reserved object
pub const TPMA_OBJ_RESTRICTED: u32 = 0x00010000; // Restricted attribute indicating that the object requires authorization for use
pub const TPMA_OBJ_FIXED_PERSISTENT: u32 = 0x00020000; // Fixed attribute indicating that the object is persistent
pub const TPMA_OBJ_SENSITIVE_DATA_ORIGIN: u32 = 0x00080000; // Attribute indicating that the object's sensitive data was created in the TPM
pub const TPMA_OBJ_USER_WITH_AUTH: u32 = 0x40000; // Attribute indicating that the object requires user authorization
pub const TPMA_OBJECT_FIXEDPARENT: u32 = 0x00000010; // Fixed attributes indicating that the object's parent cannot be changed once the object has been created.
pub const TPMA_OBJECT_SENSITIVEDATAORIGIN: u32 = 0x00000020;
pub const TPMA_OBJECT_USERWITHAUTH: u32 = 0x00000040;
pub const TPMA_OBJECT_ADMINWITHPOLICY: u32 = 0x00000080;
pub const TPMA_OBJECT_RESTRICTED: u32 = 0x00010000;
pub const TPMA_OBJECT_DECRYPT: u32 = 0x00020000;
pub const TPMA_OBJECT_NO_DA: u32 = 0x00000400;
pub const TPMA_OBJECT_SIGN: u32 = 0x00040000;

// For ECC follow "TCG EK Credential Profile For TPM Family 2.0; Level 0"
// Specification Version 2.3; Revision 2; 23 July 2020
// Section 2.2.1.5.1
pub const TPM2_NV_INDEX_ECC_SECP384R1_HI_EKCERT: u32 = 0x01c00016;
// Section 2.2.1.5.2
pub const TPM2_NV_INDEX_VTPM_CA_CERT_CHAIN: u32 = 0x01c00100;

pub const TPM2_ALG_AES: u16 = 0x0006;
pub const TPM2_ALG_CFB: u16 = 0x0043;
pub const TPM2_ALG_NULL: u16 = 0x0010;
pub const TPMU_SYM_KEY_BITS: u16 = 256;
pub const TPM_ALG_ECDSA: u16 = 0x0018;

// Algorithm identifiers
pub const TPM_ALG_ECC: u16 = 0x0023; // Algorithm identifier for ECC
pub const TPM_ECC_NIST_P384: u16 = 0x0004; // Algorithm identifier for NIST P-384 curve
pub const TPM_ALG_SHA384: u16 = 0x000C;

pub const TPMA_NV_PLATFORMCREATE: u32 = 0x40000000;
pub const TPMA_NV_AUTHREAD: u32 = 0x40000;
pub const TPMA_NV_NO_DA: u32 = 0x2000000;
pub const TPMA_NV_PPWRITE: u32 = 0x1;
pub const TPMA_NV_PPREAD: u32 = 0x10000;
pub const TPMA_NV_OWNERREAD: u32 = 0x20000;
pub const TPMA_NV_WRITEDEFINE: u32 = 0x2000;

/// TPM Startup
pub const TPM_STARTUP_CMD: [u8; 12] = [
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
];
