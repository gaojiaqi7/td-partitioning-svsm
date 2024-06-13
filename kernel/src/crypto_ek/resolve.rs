// Copyright (c) 2022 - 2024 Intel Corporation
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::crypto_ek::x509::Certificate;
use crate::crypto_ek::x509::{self, Extension, X509Error};
use crate::crypto_ek::x509::{AlgorithmIdentifier, ExtendedKeyUsage, Extensions};
extern crate alloc;
use alloc::vec;
use der::asn1::ObjectIdentifier;
use der::{Any, Decodable, Encodable, Tag};

#[derive(Debug, Clone, Copy)]
pub enum Error {
    InvalidCert,
}

pub const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.19");
pub const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.14");
pub const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.15");
pub const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.35");
pub const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.37");

pub const VTPMTD_EXTENDED_KEY_USAGE: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.2.1");
pub const VTPMTD_CA_EXTENDED_KEY_USAGE: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.2.5");
pub const EXTNID_VTPMTD_REPORT: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.2.4");
pub const EXTNID_VTPMTD_QUOTE: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.2.2");
pub const EXTNID_VTPMTD_EVENT_LOG: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.2.3");

pub const TDVF_EXTENDED_KEY_USAGE: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.3.1");
pub const EXTNID_TDVF_REPORT: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.3.4");
pub const EXTNID_TDVF_QUOTE: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.113741.1.5.5.3.2");

pub const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.1");
pub const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.2");

pub const TCG_EK_CERTIFICATE: ObjectIdentifier = ObjectIdentifier::new("2.23.133.8.1");

// As specified in https://datatracker.ietf.org/doc/html/rfc5480#appendix-A
// id-ecPublicKey OBJECT IDENTIFIER ::= {
//     iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1
// }
pub const ID_EC_PUBKEY_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");
// secp384r1 OBJECT IDENTIFIER ::= {
//     iso(1) identified-organization(3) certicom(132) curve(0) 34
// }
pub const SECP384R1_OID: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.34");

pub const ID_EC_SIG_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.3");

#[derive(Debug, Copy, Clone)]
pub enum ResolveError {
    GenerateKey,
    GenerateCertificate(X509Error),
    SignCertificate,
    GetTdReport,
    GetTdQuote,
}

impl From<X509Error> for ResolveError {
    fn from(e: X509Error) -> Self {
        ResolveError::GenerateCertificate(e)
    }
}
