//! Implementation for OP-TEE TrustZone SDK
use crate::Error;
use core::mem::MaybeUninit;

pub fn getrandom_inner(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    // Convert MaybeUninit slice to a regular slice for optee_utee::Random::generate
    // This is safe because we're about to initialize the entire slice
    let dest_slice = unsafe {
        core::slice::from_raw_parts_mut(
            dest.as_mut_ptr() as *mut u8,
            dest.len()
        )
    };
    
    // Use OP-TEE's random number generator
    optee_utee::Random::generate(dest_slice);
    
    Ok(())
}
