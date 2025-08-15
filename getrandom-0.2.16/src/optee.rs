//! Implementation for OP-TEE TrustZone SDK
use crate::Error;
use core::mem::MaybeUninit;

#[link(name = "utee")]
extern "C" {
    fn TEE_GenerateRandom(randomBuffer: *mut core::ffi::c_void, randomBufferLen: usize);
}

pub fn getrandom_inner(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    unsafe { TEE_GenerateRandom(dest.as_mut_ptr() as *mut core::ffi::c_void, dest.len()) }
    Ok(())
}
