// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::plumbing::ec::{EcPrimitives, P256};

use crate::{Extender, ExtenderConfig};

// FIXME: This implementation is based on the one in embedded-cal-rustcrypto and intended for
//  testing purposes for now.
/// An implementation based on `getrandom`.
// FIXME: We should probably have some fast CSPRNG in self that is just seeded from getrandom.
impl<EC: ExtenderConfig, C: EcPrimitives<P256>> rand_core::TryCryptoRng for Extender<EC, C> {}

impl<EC: ExtenderConfig, C: EcPrimitives<P256>> rand_core::TryRng for Extender<EC, C> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(getrandom::u32().expect("platform RNG failure"))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(getrandom::u64().expect("platform RNG failure"))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst).expect("platform RNG failure");
        Ok(())
    }
}
