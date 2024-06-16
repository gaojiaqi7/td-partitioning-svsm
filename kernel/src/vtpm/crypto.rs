// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Jiaqi Gao <jiaqi.gao@intel.com>

extern crate alloc;

use super::{
    ek::{parse_public_area, TPM_EK},
    tpm_cmd::{tpm2_create_loaded::create_loaded, *},
    TpmError,
};
use crate::error::SvsmError;
use alloc::vec::Vec;
use tpm2_sign::sign;

const ECDSA_SHA384_SIGNATURE_SIZE: usize = 96;

#[derive(Debug, Clone)]
pub struct EcdsaSigningKey {
    pub handle: u32,
    pub public_key: Vec<u8>,
}

pub fn create_ecdsa_signing_key() -> Result<EcdsaSigningKey, SvsmError> {
    let parent_handle = TPM_EK
        .lock()
        .get()
        .ok_or(SvsmError::Tpm(TpmError::EndorsementKey))?
        .handle;

    let mut public_area = Vec::new();
    public_area.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    public_area.extend_from_slice(&TPM_ALG_SHA384.to_be_bytes());

    // Object attributes
    let object_attributes = TPMA_OBJECT_SIGN
        | TPMA_OBJ_FIXED_TPM
        | TPMA_OBJECT_FIXEDPARENT
        | TPMA_OBJECT_SENSITIVEDATAORIGIN
        | TPMA_OBJECT_USERWITHAUTH
        | TPMA_OBJECT_ADMINWITHPOLICY;
    public_area.extend_from_slice(&object_attributes.to_be_bytes());

    // Policy digest for authentication
    let policy_digest: [u8; 48] = [
        0xb2, 0x6e, 0x7d, 0x28, 0xd1, 0x1a, 0x50, 0xbc, 0x53, 0xd8, 0x82, 0xbc, 0xf5, 0xfd, 0x3a,
        0x1a, 0x07, 0x41, 0x48, 0xbb, 0x35, 0xd3, 0xb4, 0xe4, 0xcb, 0x1c, 0x0a, 0xd9, 0xbd, 0xe4,
        0x19, 0xca, 0xcb, 0x47, 0xba, 0x09, 0x69, 0x96, 0x46, 0x15, 0x0f, 0x9f, 0xc0, 0x00, 0xf3,
        0xf8, 0x0e, 0x12,
    ];
    public_area.extend_from_slice(&(policy_digest.len() as u16).to_be_bytes());
    public_area.extend_from_slice(&policy_digest);

    // EC parameters for TPM_ECC_NIST_P384
    // symmetric: TPM_ALG_NULL, 256bit
    public_area.extend_from_slice(&TPM2_ALG_NULL.to_be_bytes());
    public_area.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
    public_area.extend_from_slice(&TPM_ALG_SHA384.to_be_bytes());

    public_area.extend_from_slice(&TPM_ECC_NIST_P384.to_be_bytes());
    public_area.extend_from_slice(&TPM2_ALG_NULL.to_be_bytes());
    public_area.extend_from_slice(&0u32.to_be_bytes());

    // public_area.extend_from_slice(&curve_id);
    let result = create_loaded(parent_handle, &public_area);

    // Handle the retry result
    let response = match result {
        Ok(response) => response,
        Err(rc) => {
            if matches!(rc, SvsmError::Tpm(TpmError::TpmCommands(0x922))) {
                create_loaded(parent_handle, &public_area)?
            } else {
                return Err(rc);
            }
        }
    };

    let public_key = parse_public_area(&response.public_area)?;
    Ok(EcdsaSigningKey {
        handle: response.handle,
        public_key,
    })
}

pub fn ecdsa_sign(key: &EcdsaSigningKey, digest: &[u8]) -> Result<Vec<u8>, SvsmError> {
    let sig_struct = sign(key.handle, digest, TPM_ALG_ECDSA, TPM_ALG_SHA384)?;

    // The first 4 bytes are: SIGNATURE ALG and HASH ALG
    // Both `signatureR` and `signatureS` have a two bytes size field
    if sig_struct.len() < 4 + ECDSA_SHA384_SIGNATURE_SIZE {
        return Err(SvsmError::Tpm(TpmError::Unexpected));
    }

    let sig_alg = u16::from_be_bytes([sig_struct[0], sig_struct[1]]);
    if sig_alg != TPM_ALG_ECDSA {
        return Err(SvsmError::Tpm(TpmError::Unexpected));
    }

    let hash_alg = u16::from_be_bytes([sig_struct[2], sig_struct[3]]);
    if hash_alg != TPM_ALG_SHA384 {
        return Err(SvsmError::Tpm(TpmError::Unexpected));
    }

    let r_offset = 4;
    let r_size = u16::from_be_bytes([sig_struct[r_offset], sig_struct[r_offset + 1]]) as usize;
    let mut signature = sig_struct[r_offset + 2..r_offset + 2 + r_size].to_vec();

    let s_offset = r_offset + 2 + r_size;
    let s_size = u16::from_be_bytes([sig_struct[s_offset], sig_struct[s_offset + 1]]) as usize;
    signature.extend(&sig_struct[s_offset + 2..s_offset + 2 + s_size]);

    if signature.len() != ECDSA_SHA384_SIGNATURE_SIZE {
        return Err(SvsmError::Tpm(TpmError::Unexpected));
    }
    Ok(signature)
}
