// Copyright (c) 2022 - 2024 Intel Corporation
//
// SPDX-License-Identifier: MIT OR Apache-2.0

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use core::convert::{TryFrom, TryInto};
use der::asn1::{
    Any, BitString, GeneralizedTime, ObjectIdentifier, OctetString, SetOfVec, UIntBytes, UtcTime,
    Utf8String,
};
use der::{
    Choice, Decodable, Decoder, DerOrd, Encodable, Header, Sequence, Tag, TagNumber, Tagged,
};

#[derive(Debug, Copy, Clone)]
pub enum X509Error {
    DerEncoding(der::Error),
    SignCertificate,
    CalculateHash,
}

impl From<der::Error> for X509Error {
    fn from(e: der::Error) -> Self {
        X509Error::DerEncoding(e)
    }
}

#[derive(Debug)]
pub struct CertificateBuilder<'a>(Certificate<'a>);

impl<'a> CertificateBuilder<'a> {
    pub fn new(
        signature: AlgorithmIdentifier<'a>,
        algorithm: AlgorithmIdentifier<'a>,
        public_key: &'a [u8],
        self_signed: bool,
    ) -> Result<Box<Self>, X509Error> {
        Ok(Box::new(Self(Certificate::new(
            signature,
            algorithm,
            public_key,
            self_signed,
        )?)))
    }

    pub fn set_not_before(&mut self, time: core::time::Duration) -> Result<(), X509Error> {
        self.0.tbs_certificate.validity.not_before =
            Time::Generalized(GeneralizedTime::from_unix_duration(time)?);
        Ok(())
    }

    pub fn set_not_after(&mut self, time: core::time::Duration) -> Result<(), X509Error> {
        self.0.tbs_certificate.validity.not_after =
            Time::Generalized(GeneralizedTime::from_unix_duration(time)?);
        Ok(())
    }

    pub fn set_public_key(
        &mut self,
        algorithm: AlgorithmIdentifier<'a>,
        public_key: &'a [u8],
    ) -> Result<(), X509Error> {
        let subject_public_key_info = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key: BitString::new(0, public_key)?,
        };
        self.0.tbs_certificate.subject_public_key_info = subject_public_key_info;
        Ok(())
    }

    pub fn add_extension(&mut self, extension: Extension<'a>) -> Result<(), X509Error> {
        if let Some(extn) = self.0.tbs_certificate.extensions.as_mut() {
            extn.0.push(extension);
        } else {
            let extensions = vec![extension];
            self.0.tbs_certificate.extensions = Some(Extensions(extensions));
        }
        Ok(())
    }

    pub fn set_signature(&mut self, signature: &'a [u8]) -> Result<(), X509Error> {
        self.0.set_signature(signature)
    }

    pub fn sign(
        &mut self,
        signature: &'a mut alloc::vec::Vec<u8>,
        mut signer: impl FnMut(&[u8], &mut alloc::vec::Vec<u8>),
    ) -> Result<(), X509Error> {
        let tbs = self.0.tbs_certificate.to_vec().unwrap();
        signer(tbs.as_slice(), signature);
        self.0.signature_value = BitString::new(0, signature)?;

        Ok(())
    }

    pub fn build(&self) -> &Certificate<'a> {
        &self.0
    }
}

// https://datatracker.ietf.org/doc/html/rfc5280#section-3.1
// Certificate  ::=  SEQUENCE  {
//    tbsCertificate       TBSCertificate,
//    signatureAlgorithm   AlgorithmIdentifier,
//    signatureValue       BIT STRING  }
#[derive(Clone, Debug)]
pub struct Certificate<'a> {
    pub tbs_certificate: TBSCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: BitString<'a>,
}

impl<'a> Certificate<'a> {
    pub fn new(
        signature: AlgorithmIdentifier<'a>,
        algorithm: AlgorithmIdentifier<'a>,
        public_key: &'a [u8],
        self_signed: bool,
    ) -> Result<Self, X509Error> {
        let version = Version(UIntBytes::new(&[2])?);
        let serial_number = UIntBytes::new(&[1])?;

        let mut issuer_name = SetOfVec::new();
        issuer_name.add(DistinguishedName {
            attribute_type: ObjectIdentifier::new("2.5.4.3"),
            value: Utf8String::new("SVSM")?.into(),
        })?;
        let issuer = vec![issuer_name];

        let subject: alloc::vec::Vec<SetOfVec<DistinguishedName<'_>>> = if self_signed {
            issuer.clone()
        } else {
            alloc::vec::Vec::new()
        };

        let validity = Validity {
            not_before: Time::Generalized(GeneralizedTime::from_unix_duration(
                core::time::Duration::new(0, 0),
            )?),
            not_after: Time::Generalized(GeneralizedTime::from_unix_duration(
                core::time::Duration::new(0, 0),
            )?),
        };

        let subject_public_key_info = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key: BitString::new(0, public_key)?,
        };

        let tbs_certificate = TBSCertificate {
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };

        let signature_value = BitString::new(0, &[])?;

        Ok(Certificate {
            tbs_certificate,
            signature_algorithm: signature,
            signature_value,
        })
    }

    pub fn tbs_certificate(&self) -> &TBSCertificate<'_> {
        &self.tbs_certificate
    }

    pub fn set_signature(&mut self, signature: &'a [u8]) -> Result<(), X509Error> {
        self.signature_value = BitString::new(0, signature)?;
        Ok(())
    }
}

impl<'a> Decodable<'a> for Certificate<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let tbs_certificate = decoder.decode()?;
            let signature_algorithm = decoder.decode()?;
            let signature_value = decoder.decode()?;

            Ok(Self {
                tbs_certificate,
                signature_algorithm,
                signature_value,
            })
        })
    }
}

impl<'a> Sequence<'a> for Certificate<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[
            &self.tbs_certificate,
            &self.signature_algorithm,
            &self.signature_value,
        ])
    }
}

// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
// TBSCertificate  ::=  SEQUENCE  {
//     version         [0]  EXPLICIT Version DEFAULT v1,
//     serialNumber         CertificateSerialNumber,
//     signature            AlgorithmIdentifier,
//     issuer               Name,
//     validity             Validity,
//     subject              Name,
//     subjectPublicKeyInfo SubjectPublicKeyInfo,
//     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//                          -- If present, version MUST be v2 or v3
//     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//                          -- If present, version MUST be v2 or v3
//     extensions      [3]  EXPLICIT Extensions OPTIONAL
//                          -- If present, version MUST be v3
// }
#[derive(Clone, Debug)]
pub struct TBSCertificate<'a> {
    pub version: Version<'a>,
    pub serial_number: UIntBytes<'a>, // ASN.1 INTEGER
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: alloc::vec::Vec<SetOfVec<DistinguishedName<'a>>>,
    pub validity: Validity,
    pub subject: alloc::vec::Vec<SetOfVec<DistinguishedName<'a>>>,
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,
    pub issuer_unique_id: Option<UniqueIdentifier<'a, 1>>,
    pub subject_unique_id: Option<UniqueIdentifier<'a, 2>>,
    pub extensions: Option<Extensions<'a>>,
}

impl<'a> Decodable<'a> for TBSCertificate<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let version = decoder.decode()?;
            let serial_number = decoder.decode()?;
            let signature = decoder.decode()?;
            let issuer = decoder.decode()?;
            let validity = decoder.decode()?;
            let subject = decoder.decode()?;
            let subject_public_key_info = decoder.decode()?;
            let issuer_unique_id = decoder.decode()?;
            let subject_unique_id = decoder.decode()?;
            let extensions = decoder.decode()?;

            Ok(Self {
                version,
                serial_number,
                signature,
                issuer,
                validity,
                subject,
                subject_public_key_info,
                extensions,
                issuer_unique_id,
                subject_unique_id,
            })
        })
    }
}

impl<'a> Sequence<'a> for TBSCertificate<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[
            &self.version,
            &self.serial_number,
            &self.signature,
            &self.issuer,
            &self.validity,
            &self.subject,
            &self.subject_public_key_info,
            &self.extensions,
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityKeyIdentifier<'a>(pub OctetString<'a>);

impl Encodable for AuthorityKeyIdentifier<'_> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(0),
            },
            len,
        )?;
        explicit.encoded_len() + len
    }

    fn encode(&self, encoder: &mut der::Encoder<'_>) -> der::Result<()> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(0),
            },
            len,
        )?;
        explicit.encode(encoder)?;
        self.0.encode(encoder)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectAltName<'a>(pub alloc::vec::Vec<SetOfVec<DistinguishedName<'a>>>);

impl Encodable for SubjectAltName<'_> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(4),
            },
            len,
        )?;
        explicit.encoded_len() + len
    }

    fn encode(&self, encoder: &mut der::Encoder<'_>) -> der::Result<()> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(4),
            },
            len,
        )?;
        explicit.encode(encoder)?;
        self.0.encode(encoder)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Version<'a>(UIntBytes<'a>);

impl<'a> Decodable<'a> for Version<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        let res = decoder.any()?;
        Ok(Self(UIntBytes::from_der(res.value())?))
    }
}

impl Encodable for Version<'_> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(0),
            },
            len,
        )?;
        explicit.encoded_len() + len
    }

    fn encode(&self, encoder: &mut der::Encoder<'_>) -> der::Result<()> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(0),
            },
            len,
        )?;
        explicit.encode(encoder)?;
        self.0.encode(encoder)
    }
}

impl Tagged for Version<'_> {
    fn tag(&self) -> Tag {
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(0),
        }
    }
}

impl<'a> Choice<'a> for Version<'a> {
    fn can_decode(tag: Tag) -> bool {
        tag == Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(0),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Any<'a>>,
}

impl<'a> Decodable<'a> for AlgorithmIdentifier<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let algorithm = decoder.decode()?;
            let parameters = decoder.decode()?;

            Ok(Self {
                algorithm,
                parameters,
            })
        })
    }
}

impl<'a> Sequence<'a> for AlgorithmIdentifier<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[&self.algorithm, &self.parameters])
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct DistinguishedName<'a> {
    pub(crate) attribute_type: ObjectIdentifier,
    pub(crate) value: Any<'a>,
}

impl DerOrd for DistinguishedName<'_> {
    fn der_cmp(&self, other: &Self) -> der::Result<core::cmp::Ordering> {
        Ok(self.attribute_type.cmp(&other.attribute_type))
    }
}

impl<'a> Decodable<'a> for DistinguishedName<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let attribute_type = decoder.decode()?;
            let value = decoder.decode()?;

            Ok(Self {
                attribute_type,
                value,
            })
        })
    }
}

impl<'a> Sequence<'a> for DistinguishedName<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[&self.attribute_type, &self.value])
    }
}

#[derive(Choice, Copy, Clone, Debug, Eq, PartialEq)]
pub enum Time {
    #[asn1(type = "UTCTime")]
    Utc(UtcTime),
    #[asn1(type = "GeneralizedTime")]
    Generalized(GeneralizedTime),
}

impl From<UtcTime> for Time {
    fn from(time: UtcTime) -> Time {
        Time::Utc(time)
    }
}

impl From<GeneralizedTime> for Time {
    fn from(time: GeneralizedTime) -> Time {
        Time::Generalized(time)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Validity {
    not_before: Time,
    not_after: Time,
}

impl Decodable<'_> for Validity {
    fn decode(decoder: &mut Decoder<'_>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let not_before = decoder.decode()?;
            let not_after = decoder.decode()?;

            Ok(Self {
                not_before,
                not_after,
            })
        })
    }
}

impl Sequence<'_> for Validity {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[&self.not_before, &self.not_after])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub subject_public_key: BitString<'a>,
}

#[allow(non_snake_case)]
impl<'a> Decodable<'a> for SubjectPublicKeyInfo<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let algorithm = decoder.decode()?;
            let subject_public_key = decoder.decode()?;

            Ok(Self {
                algorithm,
                subject_public_key,
            })
        })
    }
}

impl<'a> Sequence<'a> for SubjectPublicKeyInfo<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[&self.algorithm, &self.subject_public_key])
    }
}

#[derive(Clone, Debug)]
pub struct UniqueIdentifier<'a, const N: u8>(BitString<'a>);

impl<'a, const N: u8> Decodable<'a> for UniqueIdentifier<'a, N> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        let res = decoder.any()?;
        let uid = BitString::from_der(res.value())?;
        Ok(Self(uid))
    }
}

impl<const N: u8> Encodable for UniqueIdentifier<'_, N> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(N),
            },
            len,
        )?;
        explicit.encoded_len() + len
    }

    fn encode(&self, encoder: &mut der::Encoder<'_>) -> der::Result<()> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(N),
            },
            len,
        )?;
        explicit.encode(encoder)?;
        self.0.encode(encoder)
    }
}

impl<const N: u8> Tagged for UniqueIdentifier<'_, N> {
    fn tag(&self) -> Tag {
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(N),
        }
    }
}

impl<'a, const N: u8> Choice<'a> for UniqueIdentifier<'a, N> {
    fn can_decode(tag: Tag) -> bool {
        tag == Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(N),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Extensions<'a>(alloc::vec::Vec<Extension<'a>>);

impl<'a> Extensions<'a> {
    pub fn get(&self) -> &alloc::vec::Vec<Extension<'a>> {
        &self.0
    }
}

impl<'a> Decodable<'a> for Extensions<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        let res = decoder.any()?;
        Ok(Self(alloc::vec::Vec::from_der(res.value())?))
    }
}

impl Encodable for Extensions<'_> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(3),
            },
            len,
        )?;
        explicit.encoded_len() + len
    }

    fn encode(&self, encoder: &mut der::Encoder<'_>) -> der::Result<()> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(3),
            },
            len,
        )?;
        explicit.encode(encoder)?;
        self.0.encode(encoder)
    }
}

impl Tagged for Extensions<'_> {
    fn tag(&self) -> Tag {
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(3),
        }
    }
}

impl<'a> Choice<'a> for Extensions<'a> {
    fn can_decode(tag: Tag) -> bool {
        tag == Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(3),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extension<'a> {
    pub extn_id: ObjectIdentifier,
    pub critical: Option<bool>, // ASN.1 BOOLEAN.
    pub extn_value: Option<OctetString<'a>>,
}

impl<'a> Extension<'a> {
    pub fn new(
        extn_id: ObjectIdentifier,
        critical: Option<bool>,
        extn_value: Option<&'a [u8]>,
    ) -> Result<Self, X509Error> {
        let extn_value = if let Some(extn_value) = extn_value {
            Some(OctetString::new(extn_value)?)
        } else {
            None
        };

        Ok(Self {
            extn_id,
            critical,
            extn_value,
        })
    }
}

impl<'a> Decodable<'a> for Extension<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let extn_id = decoder.decode()?;
            let critical = decoder.decode()?;
            let extn_value = decoder.decode()?;

            Ok(Self {
                extn_id,
                critical,
                extn_value,
            })
        })
    }
}

impl<'a> Sequence<'a> for Extension<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[&self.extn_id, &self.critical, &self.extn_value])
    }
}

pub type ExtendedKeyUsage = alloc::vec::Vec<ObjectIdentifier>;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EcdsaSignatureDer<'a> {
    pub r: UIntBytes<'a>,
    pub s: UIntBytes<'a>,
}
