// Copyright (c) 2022 - 2024 Intel Corporation
//
// SPDX-License-Identifier: MIT OR Apache-2.0

extern crate alloc;
use alloc::vec;

use der::asn1::{BitString, ObjectIdentifier, OctetString, SetOfVec, Utf8String};
use der::{Any, Encodable, Tag};

use crate::crypto_ek::resolve::{ResolveError, ID_EC_PUBKEY_OID, SECP384R1_OID};
use crate::crypto_ek::resolve::{
    AUTHORITY_KEY_IDENTIFIER, BASIC_CONSTRAINTS, EXTENDED_KEY_USAGE, EXTNID_VTPMTD_EVENT_LOG,
    EXTNID_VTPMTD_QUOTE, ID_EC_SIG_OID, KEY_USAGE, TCG_EK_CERTIFICATE,
    VTPMTD_CA_EXTENDED_KEY_USAGE,
};
use crate::crypto_ek::x509::{
    self, AuthorityKeyIdentifier, DistinguishedName, Extension, SubjectAltName,
};
use crate::crypto_ek::x509::{AlgorithmIdentifier, X509Error};

use crate::vtpm::capability::{tpm_property, Tpm2Property};
use crate::vtpm::crypto::{ecdsa_sign, EcdsaSigningKey};
use crate::vtpm::tpm_cmd::tpm2_digests::{TPM2_SHA1_SIZE, TPM2_SHA384_SIZE};

const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.29.17");
const TCG_TPM_MANUFACTURER: ObjectIdentifier = ObjectIdentifier::new("2.23.133.2.1");
const TCG_TPM_MODEL: ObjectIdentifier = ObjectIdentifier::new("2.23.133.2.2");
const TCG_TPM_VERSION: ObjectIdentifier = ObjectIdentifier::new("2.23.133.2.3");

#[cfg(feature = "sha1")]
use sha1::Sha1;

#[cfg(feature = "sha2")]
use sha2::{Digest, Sha384};

fn hash_sha1(hash_data: &[u8], digest_sha1: &mut [u8; TPM2_SHA1_SIZE]) -> Result<(), ResolveError> {
    let mut digest = Sha1::new();
    digest.update(hash_data);
    let digest = digest.finalize();

    if digest.as_slice().len() != TPM2_SHA1_SIZE {
        log::error!("Hash fail!");
        Err(ResolveError::SignCertificate)
    } else {
        digest_sha1.clone_from_slice(digest.as_slice());
        Ok(())
    }
}

fn hash_sha384(
    hash_data: &[u8],
    digest_sha384: &mut [u8; TPM2_SHA384_SIZE],
) -> Result<(), ResolveError> {
    let mut digest = Sha384::new();
    digest.update(hash_data);
    let digest = digest.finalize();

    if digest.as_slice().len() != TPM2_SHA384_SIZE {
        log::error!("Hash fail!");
        Err(ResolveError::SignCertificate)
    } else {
        digest_sha384.clone_from_slice(digest.as_slice());
        Ok(())
    }
}

pub fn generate_ca_cert(
    td_quote: &[u8],
    event_log: &[u8],
    ecdsa_keypair: &EcdsaSigningKey,
) -> Result<alloc::vec::Vec<u8>, ResolveError> {
    let mut sig_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let signer = |data: &[u8], sig_buf: &mut alloc::vec::Vec<u8>| {
        let mut digest = [0u8; TPM2_SHA384_SIZE];
        hash_sha384(data, &mut digest).expect("Failed to hash");
        let signature = ecdsa_sign(ecdsa_keypair, &digest[..]).expect("Failed to sign");
        sig_buf.extend_from_slice(&signature[..]);
    };

    // Generate x.509 certificate
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(Any::new(Tag::ObjectIdentifier, SECP384R1_OID.as_bytes()).unwrap()),
    };

    let sig_alg = AlgorithmIdentifier {
        algorithm: ID_EC_SIG_OID,
        parameters: None,
    };

    // extended key usage
    let eku: alloc::vec::Vec<ObjectIdentifier> = vec![VTPMTD_CA_EXTENDED_KEY_USAGE];
    let eku = eku
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;

    // basic constrains
    let basic_constrains: alloc::vec::Vec<bool> = vec![true];
    let basic_constrains = basic_constrains
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;

    let mut x509_certificate = x509::CertificateBuilder::new(
        sig_alg,
        algorithm,
        ecdsa_keypair.public_key.as_slice(),
        true,
    )?;
    // 1970-01-01T00:00:00Z
    x509_certificate.set_not_before(core::time::Duration::new(0, 0))?;
    // 9999-12-31T23:59:59Z
    x509_certificate.set_not_after(core::time::Duration::new(253402300799, 0))?;

    x509_certificate.add_extension(Extension::new(
        BASIC_CONSTRAINTS,
        Some(true),
        Some(basic_constrains.as_slice()),
    )?)?;
    x509_certificate.add_extension(Extension::new(
        EXTENDED_KEY_USAGE,
        Some(false),
        Some(eku.as_slice()),
    )?)?;
    x509_certificate.add_extension(Extension::new(
        EXTNID_VTPMTD_QUOTE,
        Some(false),
        Some(td_quote),
    )?)?;
    x509_certificate.add_extension(Extension::new(
        EXTNID_VTPMTD_EVENT_LOG,
        Some(false),
        Some(event_log),
    )?)?;
    x509_certificate.sign(&mut sig_buf, signer)?;

    let res = x509_certificate.build();

    res.to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))
}

fn gen_auth_key_identifier(ek_pub: &[u8]) -> Result<alloc::vec::Vec<u8>, ResolveError> {
    // authority key identifier
    let mut ek_pub_sha1 = [0u8; TPM2_SHA1_SIZE];
    let _ = hash_sha1(ek_pub, &mut ek_pub_sha1)?;

    let pub_sha1 = OctetString::new(ek_pub_sha1.as_ref())
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;
    let auth_key_identifier: AuthorityKeyIdentifier<'_> = AuthorityKeyIdentifier(pub_sha1);
    let auth_key_identifier = vec![auth_key_identifier];
    auth_key_identifier
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))
}

fn gen_subject_alt_name() -> Result<alloc::vec::Vec<u8>, ResolveError> {
    let tpm2_caps = tpm_property().expect("Failed to get TPM properties");

    let mut tcg_tpm_manufaturer = SetOfVec::new();
    let mut manufacturer = alloc::vec::Vec::new();
    manufacturer.extend_from_slice(&tpm2_caps.manufacturer.to_be_bytes());
    let _ = tcg_tpm_manufaturer.add(DistinguishedName {
        attribute_type: TCG_TPM_MANUFACTURER,
        value: Utf8String::new(manufacturer.as_slice()).unwrap().into(),
    });

    let mut tcg_tpm_model = SetOfVec::new();
    let mut model = alloc::vec::Vec::new();
    model.extend_from_slice(&tpm2_caps.vendor_1.to_be_bytes());
    model.extend_from_slice(&tpm2_caps.vendor_2.to_be_bytes());
    model.extend_from_slice(&tpm2_caps.vendor_3.to_be_bytes());
    model.extend_from_slice(&tpm2_caps.vendor_4.to_be_bytes());
    let _ = tcg_tpm_model.add(DistinguishedName {
        attribute_type: TCG_TPM_MODEL,
        value: Utf8String::new(model.as_slice()).unwrap().into(),
    });

    let mut tcg_tpm_version = SetOfVec::new();
    let mut version = alloc::vec::Vec::new();
    version.extend_from_slice(&tpm2_caps.version_1.to_be_bytes());
    version.extend_from_slice(&tpm2_caps.version_2.to_be_bytes());
    let _ = tcg_tpm_version.add(DistinguishedName {
        attribute_type: TCG_TPM_VERSION,
        value: Utf8String::new(version.as_slice()).unwrap().into(),
    });

    let sub_alt_name = vec![tcg_tpm_manufaturer, tcg_tpm_model, tcg_tpm_version];
    let sub_alt_name: SubjectAltName<'_> = SubjectAltName(sub_alt_name);
    let sub_alt_name = vec![sub_alt_name];
    sub_alt_name
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))
}

pub fn generate_ek_cert(
    ek_pub: &[u8],
    ecdsa_keypair: &EcdsaSigningKey,
) -> Result<alloc::vec::Vec<u8>, ResolveError> {
    let mut sig_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let signer = |data: &[u8], sig_buf: &mut alloc::vec::Vec<u8>| {
        let mut digest = [0u8; TPM2_SHA384_SIZE];
        hash_sha384(data, &mut digest).expect("Failed to hash");
        let signature = ecdsa_sign(ecdsa_keypair, &digest[..]).expect("Failed to sign");
        sig_buf.extend_from_slice(&signature[..]);
    };

    // Generate x.509 certificate
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(Any::new(Tag::ObjectIdentifier, SECP384R1_OID.as_bytes()).unwrap()),
    };

    let sig_alg = AlgorithmIdentifier {
        algorithm: ID_EC_SIG_OID,
        parameters: None,
    };

    // basic constrains
    let basic_constrains: alloc::vec::Vec<bool> = vec![false];
    let basic_constrains = basic_constrains
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;

    // extended key usage
    let eku: alloc::vec::Vec<ObjectIdentifier> = vec![TCG_EK_CERTIFICATE];
    let eku = eku
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;

    // authority key identifier
    let auth_key_identifier = gen_auth_key_identifier(ek_pub)?;

    // follow ek-credential spec Section 3.2.
    // keyAgreement (4) refers to https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
    let ku = BitString::new(0, &[0x08])
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;
    let ku = ku
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;

    // subject alt name
    let subject_alt_name = gen_subject_alt_name()?;

    let mut x509_certificate = x509::CertificateBuilder::new(sig_alg, algorithm, ek_pub, false)?;
    // 1970-01-01T00:00:00Z
    x509_certificate.set_not_before(core::time::Duration::new(0, 0))?;
    // 9999-12-31T23:59:59Z
    x509_certificate.set_not_after(core::time::Duration::new(253402300799, 0))?;
    x509_certificate.add_extension(Extension::new(
        BASIC_CONSTRAINTS,
        Some(true),
        Some(basic_constrains.as_slice()),
    )?)?;
    x509_certificate.add_extension(Extension::new(
        AUTHORITY_KEY_IDENTIFIER,
        Some(false),
        Some(auth_key_identifier.as_slice()),
    )?)?;
    x509_certificate.add_extension(Extension::new(KEY_USAGE, Some(true), Some(ku.as_slice()))?)?;
    x509_certificate.add_extension(Extension::new(
        EXTENDED_KEY_USAGE,
        Some(false),
        Some(eku.as_slice()),
    )?)?;
    x509_certificate.add_extension(Extension::new(
        SUBJECT_ALT_NAME,
        Some(true),
        Some(subject_alt_name.as_slice()),
    )?)?;
    x509_certificate.sign(&mut sig_buf, signer)?;
    let res = x509_certificate.build();

    res.to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))
}
