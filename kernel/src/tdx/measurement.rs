// Copyright (c) 2022 - 2024 Intel Corporation
//
// SPDX-License-Identifier: MIT OR Apache-2.0

extern crate alloc;
use crate::locking::SpinLock;
use crate::mm::alloc::{allocate_page, free_page};
use crate::utils::align_up;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::{vec, vec::Vec};
use sha1::Sha1;
use sha2::Sha256;

use super::service::{TdVmcallServiceCommandHeader, TdVmcallServiceResponseHeader};
use super::tdvf::get_tdvf_sec_fv;
use crate::address::Address;
use crate::error::SvsmError;
use crate::mm::{PerCPUPageMappingGuard, PAGE_SIZE};
use crate::tdx::error::TdxError;
use crate::vtpm::tpm_cmd::tpm2_command::Tpm2ResponseHeader;
use crate::vtpm::tpm_cmd::tpm2_digests::{
    Tpm2Digest, Tpm2Digests, TPM2_HASH_ALG_ID_SHA1, TPM2_HASH_ALG_ID_SHA256,
    TPM2_HASH_ALG_ID_SHA384, TPM2_SHA1_SIZE, TPM2_SHA256_SIZE, TPM2_SHA384_SIZE,
};
use crate::vtpm::tpm_cmd::tpm2_extend::{tpm2_pcr_extend_cmd, MAX_TPM_PCR_EXTEND_CMD_SIZE};
use crate::vtpm::tpm_cmd::{
    TPM2_COMMAND_HEADER_SIZE, TPM2_RESPONSE_HEADER_SIZE, TPM_RC_SUCCESS, TPM_STARTUP_CMD,
};
use crate::vtpm::{vtpm_get_locked, MsTpmSimulatorInterface, TpmError};

use cc_measurement::log::{CcEventLogError, CcEventLogReader, CcEventLogWriter};
use cc_measurement::{CcEventHeader, TcgPcrEventHeader};
use core::mem::size_of;
use core::ptr::addr_of_mut;

const SHA384_DIGEST_SIZE: usize = 48;
use crate::crypto_ek::ek_cert::{generate_ca_cert, generate_ek_cert};
use crate::tdx::quote_generation;
use crate::tdx::{tdcall_extend_rtmr, TdxDigest};
use crate::vtpm::crypto::create_ecdsa_signing_key;
use crate::vtpm::ek::{create_tpm_ek, provision_ca_cert, provision_ek_cert};

#[cfg(feature = "sha2")]
use sha2::{Digest, Sha384};

const MAX_PLATFORM_BLOB_DESC_SIZE: usize = 255;
const PLATFORM_BLOB_DESC: &[u8] = b"TDVF";
pub const RTM_MEASUREMENT_STATE_SIZE: usize = 1024;
pub const TCG_EVENT2_ENTRY_HOB_GUID: [u8; 16] = [
    0x1e, 0x22, 0x6c, 0xd2, 0x30, 0x24, 0x8a, 0x4c, 0x91, 0x70, 0x3f, 0xcb, 0x45, 0x0, 0x41, 0x3f,
];
const EV_S_CRTM_VERSION: u32 = 0x00000008;
const EV_EFI_PLATFORM_FIRMWARE_BLOB2: u32 = 0x8000_000A;
const HOB_TYPE_GUID_EXTENSION: u16 = 0x0004;
const HOB_TYPE_END_OF_HOB_LIST: u16 = 0xffff;
const L1_VTPM_COMMAND_VERSION: u8 = 0x00;
const L1_VTPM_COMMAND_DETECT: u8 = 0x01;
const L1_VTPM_COMMAND_STATUS_SUCCESS: u8 = 0x00;
const GUIDED_HOB_HEADER_SIZE: usize = 24;

static VRTM_MEASUREMENT: SpinLock<RtmMeasurementState> = SpinLock::new(RtmMeasurementState::new());

struct RtmMeasurementState {
    size: usize,
    state: [u8; RTM_MEASUREMENT_STATE_SIZE],
}

impl RtmMeasurementState {
    const fn new() -> Self {
        RtmMeasurementState {
            size: 0,
            state: [0; RTM_MEASUREMENT_STATE_SIZE],
        }
    }

    fn size(&self) -> usize {
        self.size
    }

    fn state(&self) -> &[u8] {
        &self.state[..self.size]
    }

    fn build_guided_hob_header(&mut self, data_len: usize) -> Result<usize, SvsmError> {
        // Length of HOB shall be 8 bytes aligned
        let aligned = align_up(data_len + GUIDED_HOB_HEADER_SIZE, 8);
        // Type of HOB
        self.write(&HOB_TYPE_GUID_EXTENSION.to_le_bytes())?;
        // Lenght of HOB
        self.write(&(aligned as u16).to_le_bytes())?;
        // Reserved field
        self.write(&0u32.to_le_bytes())?;
        // GUID
        self.write(&TCG_EVENT2_ENTRY_HOB_GUID)?;

        Ok(aligned)
    }

    fn write_event(
        &mut self,
        pcr_index: u32,
        event_type: u32,
        digests: &Tpm2Digests,
        event_data: &[u8],
    ) -> Result<(), SvsmError> {
        let event_len = size_of::<u32>() * 3 // PCR index, event type, digest count
            + digests.total_size
            + size_of::<u32>() // Event data size
            + event_data.len();
        let hob_len = self.build_guided_hob_header(event_len)?;
        self.write(&pcr_index.to_le_bytes())?;
        self.write(&event_type.to_le_bytes())?;
        self.write(&(digests.digests_count as u32).to_le_bytes())?;
        digests
            .to_le_bytes(self.get_unused_mut(digests.total_size)?)
            .ok_or(SvsmError::Tdx(TdxError::Measurement))?;
        self.write(&(event_data.len() as u32).to_le_bytes())?;
        self.write(event_data)?;
        // padding zeros
        let _ = self.get_unused_mut(hob_len - event_len - GUIDED_HOB_HEADER_SIZE)?;
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), SvsmError> {
        // Type of HOB
        self.write(&HOB_TYPE_END_OF_HOB_LIST.to_le_bytes())?;
        // Lenght of HOB
        self.write(&8u32.to_le_bytes())?;
        // Reserved field
        self.write(&0u32.to_le_bytes())
    }

    fn write(&mut self, data: &[u8]) -> Result<(), SvsmError> {
        let unused = self.get_unused_mut(data.len())?;
        unused[..data.len()].copy_from_slice(data);
        Ok(())
    }

    fn get_unused_mut(&mut self, require: usize) -> Result<&mut [u8], SvsmError> {
        if require > RTM_MEASUREMENT_STATE_SIZE - self.size {
            return Err(SvsmError::Tdx(TdxError::Measurement));
        }
        self.size += require;
        Ok(&mut self.state[self.size - require..self.size])
    }
}

/// Used to record the firmware blob information into event log.
///
/// Defined in TCG PC Client Platform Firmware Profile Specification section
/// 'UEFI_PLATFORM_FIRMWARE_BLOB Structure Definition'
#[derive(Debug)]
pub struct UefiPlatformFirmwareBlob2 {
    pub blob_desc_size: u8,
    pub blob_desc: [u8; MAX_PLATFORM_BLOB_DESC_SIZE],
    pub base: u64,
    pub length: u64,
}

impl UefiPlatformFirmwareBlob2 {
    pub fn new(desc: &[u8], base: u64, length: u64) -> Option<Self> {
        if desc.len() > MAX_PLATFORM_BLOB_DESC_SIZE {
            return None;
        }

        let mut fw_blob = UefiPlatformFirmwareBlob2 {
            blob_desc_size: 0,
            blob_desc: [0; MAX_PLATFORM_BLOB_DESC_SIZE],
            base,
            length,
        };
        fw_blob.blob_desc[..desc.len()].copy_from_slice(desc);
        fw_blob.blob_desc_size = desc.len() as u8;

        Some(fw_blob)
    }

    pub fn write_in_bytes(&self, bytes: &mut [u8]) -> Option<usize> {
        let desc_size = self.blob_desc_size as usize;
        let mut idx = 0;

        // Write blob descriptor size
        bytes[idx] = self.blob_desc_size;
        idx = idx.checked_add(1)?;

        // Write blob descriptor
        bytes[idx..idx + desc_size].copy_from_slice(&self.blob_desc[..desc_size]);
        idx = idx.checked_add(desc_size)?;

        // Write blob base address
        bytes[idx..idx + size_of::<u64>()].copy_from_slice(&self.base.to_le_bytes());
        idx = idx.checked_add(size_of::<u64>())?;

        // Write blob length
        bytes[idx..idx + size_of::<u64>()].copy_from_slice(&self.length.to_le_bytes());
        idx = idx.checked_add(size_of::<u64>())?;

        Some(idx)
    }

    pub fn size(&self) -> usize {
        self.blob_desc_size as usize + size_of::<u64>() * 2 + size_of::<u8>()
    }
}

pub const EV_SEPARATOR: u32 = 0x0000_0004;

fn hash_sha1(hash_data: &[u8], digest_sha1: &mut [u8; TPM2_SHA1_SIZE]) -> Result<(), SvsmError> {
    let mut digest = Sha1::new();
    digest.update(hash_data);
    let digest = digest.finalize();

    if digest.len() != TPM2_SHA1_SIZE {
        Err(SvsmError::Tdx(TdxError::Measurement))
    } else {
        digest_sha1.clone_from_slice(digest.as_slice());
        Ok(())
    }
}

fn hash_sha256(
    hash_data: &[u8],
    digest_sha256: &mut [u8; TPM2_SHA256_SIZE],
) -> Result<(), SvsmError> {
    let mut digest = Sha256::new();
    digest.update(hash_data);
    let digest = digest.finalize();

    if digest.len() != TPM2_SHA256_SIZE {
        Err(SvsmError::Tdx(TdxError::Measurement))
    } else {
        digest_sha256.clone_from_slice(digest.as_slice());
        Ok(())
    }
}

fn hash_sha384(
    hash_data: &[u8],
    digest_sha384: &mut [u8; TPM2_SHA384_SIZE],
) -> Result<(), SvsmError> {
    let mut digest = Sha384::new();
    digest.update(hash_data);
    let digest = digest.finalize();

    if digest.len() != TPM2_SHA384_SIZE {
        Err(SvsmError::Tdx(TdxError::Measurement))
    } else {
        digest_sha384.clone_from_slice(digest.as_slice());
        Ok(())
    }
}

fn tpm_startup() -> Result<(), SvsmError> {
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
            return Err(SvsmError::Tdx(TdxError::Measurement));
        };

        // Check TPM response code
        if rsp.response_code != TPM_RC_SUCCESS {
            log::error!("Tpm2 Startup failed!\n");
            return Err(SvsmError::Tdx(TdxError::Measurement));
        } else {
            Ok(())
        }
    } else {
        log::error!("send Stratup request fail!\n");
        return Err(SvsmError::Tdx(TdxError::Measurement));
    }
}

fn tpm_extend(digests: &Tpm2Digests) -> Result<(), SvsmError> {
    // Get Tpm2Digests
    let mut cmd_buff = [0u8; MAX_TPM_PCR_EXTEND_CMD_SIZE];
    let mut tpm_cmd_size = tpm2_pcr_extend_cmd(digests, 0, &mut cmd_buff)?;

    let backend = vtpm_get_locked();
    // Send PCR_EXTEND CMD
    backend
        .send_tpm_command(&mut cmd_buff, &mut tpm_cmd_size, 0)
        .map_err(|_| SvsmError::Tdx(TdxError::Measurement))?;

    let mut response = [0; TPM2_COMMAND_HEADER_SIZE];
    response.copy_from_slice(&cmd_buff[..TPM2_RESPONSE_HEADER_SIZE]);

    let rsp_header = Tpm2ResponseHeader::try_from(response)?;
    log::info!("send pcr extend request success:{:02x?}\n", &response);
    // Check TPM response code
    if rsp_header.response_code != TPM_RC_SUCCESS {
        log::error!("Tpm2PcrExtend failed.\n");
        Err(SvsmError::Tdx(TdxError::Measurement))
    } else {
        Ok(())
    }
}

fn create_digests(data: &[u8]) -> Result<Tpm2Digests, SvsmError> {
    let mut tpm2_digests = Tpm2Digests::new();
    let mut digest_sha1 = [0u8; TPM2_SHA1_SIZE];
    let mut digest_sha256 = [0u8; TPM2_SHA256_SIZE];
    let mut digest_sha384 = [0u8; TPM2_SHA384_SIZE];

    hash_sha1(data, &mut digest_sha1)?;
    hash_sha256(data, &mut digest_sha256)?;
    hash_sha384(data, &mut digest_sha384)?;

    let tpm2_digest_sha1 = Tpm2Digest::new(TPM2_HASH_ALG_ID_SHA1, &digest_sha1[..])
        .ok_or(SvsmError::Tpm(TpmError::Unexpected))?;
    let tpm2_digest_sha256 = Tpm2Digest::new(TPM2_HASH_ALG_ID_SHA256, &digest_sha256[..])
        .ok_or(SvsmError::Tpm(TpmError::Unexpected))?;
    let tpm2_digest_sha384 = Tpm2Digest::new(TPM2_HASH_ALG_ID_SHA384, &digest_sha384[..])
        .ok_or(SvsmError::Tpm(TpmError::Unexpected))?;
    tpm2_digests.push_digest(&tpm2_digest_sha1)?;
    tpm2_digests.push_digest(&tpm2_digest_sha256)?;
    tpm2_digests.push_digest(&tpm2_digest_sha384)?;

    Ok(tpm2_digests)
}

pub fn extend_svsm_version() -> Result<(), SvsmError> {
    let version = String::from(env!("CARGO_PKG_VERSION")) + "\0";
    let digests = create_digests(version.as_bytes())?;

    tpm_extend(&digests)?;

    let mut vrtm = VRTM_MEASUREMENT.lock();
    vrtm.write_event(0, EV_S_CRTM_VERSION, &digests, version.as_bytes())?;

    Ok(())
}

fn extend_tdvf_sec() -> Result<(), SvsmError> {
    // Get the SEC Firmware Volume of TDVF
    let (base, len) = get_tdvf_sec_fv()?;

    // Map the code region of TDVF
    let guard =
        PerCPUPageMappingGuard::create(base, base.checked_add(len).ok_or(SvsmError::Firmware)?, 0)?;

    let vstart = guard.virt_addr().as_ptr::<u8>();

    // Safety: we just mapped a page, so the size must hold. The type
    // of the slice elements is `u8` so there are no alignment requirements.
    let mem: &[u8] = unsafe { core::slice::from_raw_parts(vstart, PAGE_SIZE) };

    let digests = create_digests(mem)?;
    tpm_extend(&digests)?;

    // Put the firmware volume information into the event
    let fw_blob =
        UefiPlatformFirmwareBlob2::new(PLATFORM_BLOB_DESC, base.bits() as u64, len as u64)
            .ok_or(SvsmError::Tdx(TdxError::Measurement))?;
    let fw_blob_size = fw_blob.size();
    let mut fw_blob_bytes = vec![0u8; fw_blob_size];
    fw_blob
        .write_in_bytes(&mut fw_blob_bytes)
        .ok_or(SvsmError::Tdx(TdxError::Measurement))?;

    // Record the firmware blob event
    let mut vrtm = VRTM_MEASUREMENT.lock();
    vrtm.write_event(0, EV_EFI_PLATFORM_FIRMWARE_BLOB2, &digests, &fw_blob_bytes)
}

pub fn tdx_tpm_measurement_init() -> Result<(), SvsmError> {
    // Send the start up command and initialize the TPM
    tpm_startup()?;

    // Then extend the SVSM version into PCR[0]
    extend_svsm_version()?;

    // Then extend the Separator to RTMR[0~3]
    let event_log_buf = extend_separator()?;

    // Then generate ek cert
    generate_cert(event_log_buf.as_slice())?;

    // Finally extend the TDVF code FV into PCR[0]
    extend_tdvf_sec()
}

#[repr(C)]
#[derive(Debug, Default)]
struct L1VtpmCommand {
    version: u8,
    command: u8,
    reserved: u16,
}

impl L1VtpmCommand {
    fn read_from_bytes(bytes: &[u8]) -> Result<Self, TdxError> {
        if bytes.len() < size_of::<Self>() {
            return Err(TdxError::Service);
        }

        let mut header = Self::default();
        unsafe {
            core::slice::from_raw_parts_mut(addr_of_mut!(header) as *mut u8, size_of::<Self>())
                .copy_from_slice(&bytes[..size_of::<Self>()])
        }
        Ok(header)
    }
}

#[repr(C)]
#[derive(Debug, Default)]
struct L1VtpmResponse {
    version: u8,
    command: u8,
    status: u8,
    reserved: u8,
}

impl L1VtpmResponse {
    fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, size_of::<Self>()) }
    }
}

pub fn handle_vtpm_request(command: &[u8], response: &mut [u8]) -> Result<usize, TdxError> {
    let l1_vtpm_cmd =
        L1VtpmCommand::read_from_bytes(&command[size_of::<TdVmcallServiceCommandHeader>()..])?;
    match l1_vtpm_cmd.command {
        L1_VTPM_COMMAND_DETECT => vtpm_detect(response),
        _ => return Err(TdxError::Service),
    }
}

fn vtpm_detect(response: &mut [u8]) -> Result<usize, TdxError> {
    let mut length = size_of::<TdVmcallServiceResponseHeader>();
    let l1_vtpm_resp = &mut response[length..];
    let l1_vtpm_resp_header = L1VtpmResponse {
        version: L1_VTPM_COMMAND_VERSION,
        command: L1_VTPM_COMMAND_DETECT,
        status: L1_VTPM_COMMAND_STATUS_SUCCESS,
        reserved: 0,
    };
    l1_vtpm_resp[..size_of::<L1VtpmResponse>()].copy_from_slice(l1_vtpm_resp_header.as_bytes());
    length += size_of::<L1VtpmResponse>();
    let resp_data = &mut l1_vtpm_resp[size_of::<L1VtpmResponse>()..];

    let mut vrtm = VRTM_MEASUREMENT.lock();
    // Finalize the virtual RTM events, append a end of hob list.
    vrtm.finalize().map_err(|_| TdxError::Service)?;

    //
    let events_size = vrtm.size();
    if resp_data.len() < events_size {
        return Err(TdxError::Measurement);
    }
    resp_data[..events_size].copy_from_slice(vrtm.state());
    length += events_size;

    Ok(length)
}

pub fn extend_rtmr(data: &[u8; SHA384_DIGEST_SIZE], mr_index: u32) -> Result<(), CcEventLogError> {
    let digest = TdxDigest { data: *data };

    let rtmr_index = match mr_index {
        1 | 2 | 3 | 4 => mr_index - 1,
        e => return Err(CcEventLogError::InvalidMrIndex(e)),
    };
    tdcall_extend_rtmr(&digest, rtmr_index).map_err(|_| CcEventLogError::ExtendMr)
}

pub fn create_separator(cc_event_log: &mut CcEventLogWriter<'_>) -> Result<(), CcEventLogError> {
    let separator = u32::to_le_bytes(0);

    // Measure 0x0000_0000 into RTMR[0] RTMR[1] RTMR[2] RTMR[3]
    let _ = cc_event_log.create_event_log(1, EV_SEPARATOR, &[&separator], &separator)?;
    let _ = cc_event_log.create_event_log(2, EV_SEPARATOR, &[&separator], &separator)?;
    let _ = cc_event_log.create_event_log(3, EV_SEPARATOR, &[&separator], &separator)?;
    let _ = cc_event_log.create_event_log(4, EV_SEPARATOR, &[&separator], &separator)?;
    Ok(())
}

fn event_log_size(event_log: &[u8]) -> Option<usize> {
    let reader = CcEventLogReader::new(event_log)?;

    // The first event is TCG_EfiSpecIDEvent with TcgPcrEventHeader
    let mut size = size_of::<TcgPcrEventHeader>() + reader.pcr_event_header.event_size as usize;

    for (header, _) in reader.cc_events {
        size += size_of::<CcEventHeader>() + header.event_size as usize;
    }

    Some(size)
}

pub fn extend_separator() -> Result<Vec<u8>, SvsmError> {
    let page = allocate_page().expect("Failed to allocate Eventlog page");

    let mut event_log_buf =
        unsafe { core::slice::from_raw_parts_mut(page.as_mut_ptr(), PAGE_SIZE) };
    event_log_buf.fill(0xff);

    let mut writer = CcEventLogWriter::new(&mut event_log_buf, Box::new(extend_rtmr))
        .expect("Failed to create and initialize the event log");
    create_separator(&mut writer).map_err(|_| SvsmError::Tdx(TdxError::Measurement))?;

    // Get event log size
    let event_log_size =
        event_log_size(&event_log_buf[..]).ok_or(SvsmError::Tdx(TdxError::Measurement))?;
    let event_log = event_log_buf[..event_log_size].to_vec();

    free_page(page);
    Ok(event_log)
}

pub fn generate_cert(event_log: &[u8]) -> Result<(), SvsmError> {
    let ek_pub = create_tpm_ek()?;
    let ecdsa_keypair = create_ecdsa_signing_key()?;

    let mut quote_buf = alloc::vec![0u8; PAGE_SIZE*2];
    let mut ecdsa_pub_sha384 = [0u8; TPM2_SHA384_SIZE];
    hash_sha384(ecdsa_keypair.public_key.as_slice(), &mut ecdsa_pub_sha384)?;

    let td_quote_len = quote_generation(&ecdsa_pub_sha384, &mut quote_buf)?;
    let td_quote = &quote_buf[..td_quote_len];

    // log::info!("eventlog len {:?} = {:02X?}", event_log.len(), &event_log);
    log::info!("td_quote len {:?} = {:02X?}", td_quote.len(), &td_quote);

    // create ca cert
    let ca_cert = generate_ca_cert(td_quote, event_log, &ecdsa_keypair)
        .map_err(|_| SvsmError::Tdx(TdxError::Measurement))?;
    log::info!(
        "ca_cert len {:?} = {:02X?}",
        ca_cert.as_slice().len(),
        ca_cert.as_slice()
    );

    // create ek cert
    let ek_cert = generate_ek_cert(ek_pub.as_slice(), &ecdsa_keypair)
        .map_err(|_| SvsmError::Tdx(TdxError::Measurement))?;

    provision_ca_cert(&ca_cert)?;
    provision_ek_cert(&ek_cert)?;

    Ok(())
}
