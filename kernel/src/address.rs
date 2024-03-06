// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com>

use crate::types::{PAGE_SHIFT, PAGE_SIZE};
use core::fmt;
use core::ops;

// The backing type to represent an address;
type InnerAddr = usize;

const SIGN_BIT: usize = 47;

const fn sign_extend(addr: InnerAddr) -> InnerAddr {
    let mask = 1usize << SIGN_BIT;
    if (addr & mask) == mask {
        addr | !((1usize << SIGN_BIT) - 1)
    } else {
        addr & ((1usize << SIGN_BIT) - 1)
    }
}

pub trait Address:
    Copy + From<InnerAddr> + Into<InnerAddr> + PartialEq + Eq + PartialOrd + Ord
{
    // Transform the address into its inner representation for easier
    /// arithmetic manipulation
    fn bits(&self) -> InnerAddr {
        (*self).into()
    }

    fn is_null(&self) -> bool {
        self.bits() == 0
    }

    fn align_up(&self, align: InnerAddr) -> Self {
        Self::from((self.bits() + (align - 1)) & !(align - 1))
    }

    fn page_align_up(&self) -> Self {
        self.align_up(PAGE_SIZE)
    }

    fn page_align(&self) -> Self {
        Self::from(self.bits() & !(PAGE_SIZE - 1))
    }

    fn is_aligned(&self, align: InnerAddr) -> bool {
        (self.bits() & (align - 1)) == 0
    }

    fn is_page_aligned(&self) -> bool {
        self.is_aligned(PAGE_SIZE)
    }

    fn checked_add(&self, off: InnerAddr) -> Option<Self> {
        self.bits().checked_add(off).map(|addr| addr.into())
    }

    fn checked_sub(&self, off: InnerAddr) -> Option<Self> {
        self.bits().checked_sub(off).map(|addr| addr.into())
    }

    fn saturating_add(&self, off: InnerAddr) -> Self {
        Self::from(self.bits().saturating_add(off))
    }

    fn page_offset(&self) -> usize {
        self.bits() & (PAGE_SIZE - 1)
    }

    fn crosses_page(&self, size: usize) -> bool {
        let start = self.bits();
        let x1 = start / PAGE_SIZE;
        let x2 = (start + size - 1) / PAGE_SIZE;
        x1 != x2
    }

    fn pfn(&self) -> InnerAddr {
        self.bits() >> PAGE_SHIFT
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysAddr(InnerAddr);

impl PhysAddr {
    pub const fn new(p: InnerAddr) -> Self {
        Self(p)
    }

    pub const fn null() -> Self {
        Self(0)
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::LowerHex for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl From<InnerAddr> for PhysAddr {
    fn from(addr: InnerAddr) -> PhysAddr {
        Self(addr)
    }
}

impl From<PhysAddr> for InnerAddr {
    fn from(addr: PhysAddr) -> InnerAddr {
        addr.0
    }
}

impl From<u64> for PhysAddr {
    fn from(addr: u64) -> PhysAddr {
        // The unwrap will get optimized away on 64bit platforms,
        // which should be our only target anyway
        let addr: usize = addr.try_into().unwrap();
        PhysAddr::from(addr)
    }
}

impl From<PhysAddr> for u64 {
    fn from(addr: PhysAddr) -> u64 {
        addr.0 as u64
    }
}

// Substracting two addresses produces an usize instead of an address,
// since we normally do this to compute the size of a memory region.
impl ops::Sub<PhysAddr> for PhysAddr {
    type Output = InnerAddr;
    fn sub(self, other: PhysAddr) -> Self::Output {
        self.0 - other.0
    }
}

// Adding and subtracting usize to PhysAddr gives a new PhysAddr
impl ops::Sub<InnerAddr> for PhysAddr {
    type Output = Self;
    fn sub(self, other: InnerAddr) -> Self {
        PhysAddr::from(self.0 - other)
    }
}

impl ops::Add<InnerAddr> for PhysAddr {
    type Output = Self;
    fn add(self, other: InnerAddr) -> Self {
        PhysAddr::from(self.0 + other)
    }
}

impl Address for PhysAddr {}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct VirtAddr(InnerAddr);

impl VirtAddr {
    pub const fn null() -> Self {
        Self(0)
    }

    // const traits experimental, so for now we need this to make up
    // for the lack of VirtAddr::from() in const contexts.
    pub const fn new(addr: InnerAddr) -> Self {
        Self(sign_extend(addr))
    }

    pub fn as_ptr<T>(&self) -> *const T {
        self.0 as *const T
    }

    pub fn as_mut_ptr<T>(&self) -> *mut T {
        self.0 as *mut T
    }

    pub const fn const_add(&self, offset: usize) -> Self {
        VirtAddr::new(self.0 + offset)
    }
}

impl fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::LowerHex for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl From<InnerAddr> for VirtAddr {
    fn from(addr: InnerAddr) -> Self {
        Self(sign_extend(addr))
    }
}

impl From<VirtAddr> for InnerAddr {
    fn from(addr: VirtAddr) -> Self {
        addr.0
    }
}

impl From<u64> for VirtAddr {
    fn from(addr: u64) -> Self {
        let addr: usize = addr.try_into().unwrap();
        VirtAddr::from(addr)
    }
}

impl From<VirtAddr> for u64 {
    fn from(addr: VirtAddr) -> Self {
        addr.0 as u64
    }
}

impl<T> From<*const T> for VirtAddr {
    fn from(ptr: *const T) -> Self {
        Self(ptr as InnerAddr)
    }
}

impl<T> From<*mut T> for VirtAddr {
    fn from(ptr: *mut T) -> Self {
        Self(ptr as InnerAddr)
    }
}

impl ops::Sub<VirtAddr> for VirtAddr {
    type Output = InnerAddr;
    fn sub(self, other: VirtAddr) -> Self::Output {
        sign_extend(self.0 - other.0)
    }
}

impl ops::Sub<usize> for VirtAddr {
    type Output = Self;
    fn sub(self, other: usize) -> Self {
        VirtAddr::from(self.0 - other)
    }
}

impl ops::Add<InnerAddr> for VirtAddr {
    type Output = VirtAddr;

    fn add(self, other: InnerAddr) -> Self {
        VirtAddr::from(self.0 + other)
    }
}

impl Address for VirtAddr {
    fn checked_add(&self, off: InnerAddr) -> Option<Self> {
        self.bits()
            .checked_add(off)
            .map(|addr| sign_extend(addr).into())
    }

    fn checked_sub(&self, off: InnerAddr) -> Option<Self> {
        self.bits()
            .checked_sub(off)
            .map(|addr| sign_extend(addr).into())
    }
}

macro_rules! guest_addr_impl {
    ($structname: ident) => {
        impl $structname {
            pub const fn new(p: InnerAddr) -> Self {
                Self(p)
            }
            pub const fn null() -> Self {
                Self(0)
            }
        }

        impl fmt::Display for $structname {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::LowerHex for $structname {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl From<InnerAddr> for $structname {
            fn from(addr: InnerAddr) -> $structname {
                Self(addr)
            }
        }

        impl From<$structname> for InnerAddr {
            fn from(addr: $structname) -> InnerAddr {
                addr.0
            }
        }

        impl From<u64> for $structname {
            fn from(addr: u64) -> $structname {
                let addr: usize = addr.try_into().unwrap();
                $structname::from(addr)
            }
        }

        impl From<$structname> for u64 {
            fn from(addr: $structname) -> u64 {
                addr.0 as u64
            }
        }

        impl ops::Add<InnerAddr> for $structname {
            type Output = Self;
            fn add(self, other: InnerAddr) -> Self {
                $structname::from(self.0 + other)
            }
        }

        impl Address for $structname {}
    };
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct GuestPhysAddr(InnerAddr);
guest_addr_impl!(GuestPhysAddr);

impl GuestPhysAddr {
    pub fn to_host_phys_addr(&self) -> PhysAddr {
        // GPA == HPA
        PhysAddr::from(self.0)
    }
}

// Substracting two addresses produces an usize instead of an address,
// since we normally do this to compute the size of a memory region.
impl ops::Sub<GuestPhysAddr> for GuestPhysAddr {
    type Output = InnerAddr;
    fn sub(self, other: GuestPhysAddr) -> Self::Output {
        self.0 - other.0
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct GuestVirtAddr(InnerAddr);
guest_addr_impl!(GuestVirtAddr);
