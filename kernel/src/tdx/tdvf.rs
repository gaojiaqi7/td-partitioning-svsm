// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::{
    mem::{align_of, size_of, size_of_val},
    str::FromStr,
};

use crate::{
    address::PhysAddr,
    error::SvsmError,
    fw_meta::{find_table, RawMetaBuffer, Uuid},
    mm::{PerCPUPageMappingGuard, PAGE_SIZE, SIZE_1G, SIZE_1M},
    utils::align_up,
};

const OVMF_TABLE_FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
const OVMF_TABLE_TDX_METADATA_GUID: &str = "e47a6535-984a-4798-865e-4685a7bf8ec2";
const TDX_METADATA_GUID: &str = "e9eaf9f3-168e-44d5-a8eB-7f4d8738f6ae";

/// Section type for EFI Boot Firmware Volume.
pub(crate) const TDX_METADATA_SECTION_TYPE_BFV: u32 = 0;
pub(crate) const FIRMWARE_BLOB2_DESC: &[u8] = b"TDVF";

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TdxMetadataDescriptor {
    pub signature: u32,
    pub length: u32,
    pub version: u32,
    pub number_of_section_entry: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TdxMetadataSection {
    pub data_offset: u32,
    pub raw_data_size: u32,
    pub memory_address: u64,
    pub memory_data_size: u64,
    pub r#type: u32,
    pub attributes: u32,
}

/// Used to record the firmware blob information into event log.
///
/// Defined in TCG PC Client Platform Firmware Profile Specification section
/// 'UEFI_PLATFORM_FIRMWARE_BLOB Structure Definition'
#[derive(Debug)]
pub struct UefiPlatformFirmwareBlob2 {
    pub blob_desc_size: u8,
    pub blob_desc: [u8; 255],
    pub base: u64,
    pub length: u64,
}

impl UefiPlatformFirmwareBlob2 {
    pub fn new(desc: &[u8], base: u64, length: u64) -> Option<Self> {
        if desc.len() > u8::MAX as usize {
            return None;
        }

        let mut fw_blob = UefiPlatformFirmwareBlob2 {
            blob_desc_size: 0,
            blob_desc: [0u8; 255],
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

// Returns the backward offset of metadata in the ROM space
fn get_metadata_offset() -> Result<u32, SvsmError> {
    // Map the metadata location which is defined by the firmware config
    let guard = PerCPUPageMappingGuard::create_4k(PhysAddr::from((4 * SIZE_1G) - PAGE_SIZE))?;
    let vstart = guard.virt_addr().as_ptr::<u8>();
    // Safety: we just mapped a page, so the size must hold. The type
    // of the slice elements is `u8` so there are no alignment requirements.
    let table = unsafe { core::slice::from_raw_parts(vstart, PAGE_SIZE) };

    // Safety: `RawMetaBuffer` has no invalid representations and is
    // `repr(C, packed)`, which means there are no alignment requirements.
    // We have also verified that the size of the slice matches.
    let raw_meta = unsafe { &*table.as_ptr().cast::<RawMetaBuffer>() };

    // Check the UUID
    let raw_uuid = raw_meta.header.uuid;
    let uuid = Uuid::from(&raw_uuid);
    let meta_uuid = Uuid::from_str(OVMF_TABLE_FOOTER_GUID)?;
    if uuid != meta_uuid {
        return Err(SvsmError::Firmware);
    }

    // Get the tables and their length
    let data_len = raw_meta.header.data_len().ok_or(SvsmError::Firmware)?;
    let data_start = size_of_val(&raw_meta.data)
        .checked_sub(data_len)
        .ok_or(SvsmError::Firmware)?;
    let raw_data = raw_meta.data.get(data_start..).ok_or(SvsmError::Firmware)?;

    // First check if this is the SVSM itself instead of OVMF
    let tdx_metadata_uuid = Uuid::from_str(OVMF_TABLE_TDX_METADATA_GUID)?;
    if let Some(data) = find_table(&tdx_metadata_uuid, raw_data) {
        if data.len() == size_of::<u32>() {
            // Safety: we just checked the length of data
            return Ok(u32::from_le_bytes(data.try_into().unwrap()));
        }
    }
    Err(SvsmError::Firmware)
}

// Validate the metadata and get the basic infomation from it if any
pub(crate) fn get_tdvf_bfv() -> Result<UefiPlatformFirmwareBlob2, SvsmError> {
    let offset = get_metadata_offset()?;
    let page = align_up(offset as usize + 16, PAGE_SIZE);
    if page > SIZE_1M * 2 {
        return Err(SvsmError::Firmware);
    }

    // Map the metadata location which is defined by the firmware config
    let guard = PerCPUPageMappingGuard::create_4k(PhysAddr::from((4 * SIZE_1G) - page))?;

    let vstart = guard.virt_addr().as_ptr::<u8>();
    // Safety: we just mapped a page, so the size must hold. The type
    // of the slice elements is `u8` so there are no alignment requirements.
    let mem: &[u8] = unsafe { core::slice::from_raw_parts(vstart, PAGE_SIZE) };
    let metadata = &mem[page - offset as usize - 16..];

    // Then read the guid
    let metadata_guid = Uuid::from_str(TDX_METADATA_GUID)?;
    let actual_guid: [u8; 16] = metadata[..16].try_into().unwrap();
    if metadata_guid != Uuid::from(&actual_guid) {
        return Err(SvsmError::Firmware);
    }

    // Now compute the start and end of the TDX metadata header
    // Bounds check the header and get a pointer to it
    let tdx_meta_desc_ptr = metadata
        .get(16..16 + size_of::<TdxMetadataDescriptor>())
        .ok_or(SvsmError::Firmware)?
        .as_ptr()
        .cast::<TdxMetadataDescriptor>();

    // Check that the header pointer is aligned.
    if tdx_meta_desc_ptr.align_offset(align_of::<TdxMetadataDescriptor>()) != 0 {
        return Err(SvsmError::Firmware);
    }
    // Safety: we have checked the pointer is within bounds and aligned.
    let tdx_meta_desc = unsafe { tdx_meta_desc_ptr.read() };

    // Now find the descriptors
    let sections_start = 16 + size_of::<TdxMetadataDescriptor>();
    let num_section = tdx_meta_desc.number_of_section_entry as usize;
    let _ = num_section
        .checked_mul(size_of::<TdxMetadataSection>())
        .ok_or(SvsmError::Firmware)?;

    // We have a variable number of sections following the descriptor.
    // Unfortunately flexible array members in Rust are not fully supported,
    // so we cannot avoid using raw pointers.
    let tdx_sections_ptr = metadata
        .get(sections_start..sections_start + size_of::<TdxMetadataSection>())
        .ok_or(SvsmError::Firmware)?
        .as_ptr()
        .cast::<TdxMetadataSection>();

    for i in 0..num_section {
        // Safety: We have checked that the descriptors are within bounds of
        // the metadata memory. Since the descriptors follow the header, and
        // the header is properly aligned, the descriptors must be so as
        // well.
        let section = unsafe { tdx_sections_ptr.add(i).read() };
        let t = section.r#type;
        let mem_addr = section.memory_address as usize;
        let mem_size = section.memory_data_size as usize;
        let data_offset = section.data_offset as usize;
        let data_size = section.raw_data_size as usize;

        if (data_size == 0 && data_offset != 0)
            || (data_size != 0 && mem_size < data_size)
            || (mem_addr & 0xfff != 0)
        {
            return Err(SvsmError::Firmware);
        }
        match t {
            TDX_METADATA_SECTION_TYPE_BFV => {
                return UefiPlatformFirmwareBlob2::new(
                    FIRMWARE_BLOB2_DESC,
                    mem_addr as u64,
                    mem_size as u64,
                )
                .ok_or(SvsmError::Firmware)
            }
            _ => continue,
        }
    }

    Err(SvsmError::Firmware)
}
