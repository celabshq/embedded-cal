// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, CryptoEng, and Christian Amsüss
#![no_std]

//! Adapts `embedded-cal`'s hardware [`DhProvider`]/[`EcWeierstrassFullPoint`] backends to
//! `libcrux-p256`'s [`EcdhArrayref`](libcrux_traits::ecdh::arrayref::EcdhArrayref) contract, so
//! that any code generic over that trait (or over
//! [`EcdhSlice`](libcrux_traits::ecdh::slice::EcdhSlice)) can run P-256 scalar multiplication on
//! supported hardware instead of `libcrux-p256`'s own software implementation.
//!
//! Use [`impl_hw_p256`] to instantiate an adapter type for a concrete `embedded-cal` backend, then
//! call that type's `init()` once at startup with a constructed engine before using it as an
//! `EcdhArrayref`/`EcdhSlice` implementation.

use core::cell::RefCell;

use critical_section::Mutex;
use embedded_cal::{DhProvider, EcWeierstrassFullPoint};
use libcrux_secrets::{Classify, DeclassifyRef, U8};
use libcrux_traits::ecdh::arrayref::{DeriveError, SecretToPublicError};

/// Derives the public key `(x||y)` corresponding to `secret` by running the scalar
/// multiplication on the hardware engine held in `cal`.
///
/// Panics if `cal` has not been populated via the adapter's `init()`.
pub fn hw_secret_to_public<C>(
    cal: &Mutex<RefCell<Option<C>>>,
    alg: C::Algorithm,
    public: &mut [u8; 64],
    secret: &[U8; 32],
) -> Result<(), SecretToPublicError>
where
    C: DhProvider + EcWeierstrassFullPoint,
{
    critical_section::with(|cs| {
        let mut engine = cal.borrow(cs).borrow_mut();
        let engine = engine
            .as_mut()
            .expect("hardware P-256 engine not initialized; call init() first");

        let secret_bytes: &[u8; 32] = secret.declassify_ref();
        let visible = engine
            .import_secretkey_bytes(alg, secret_bytes)
            .map_err(|_| SecretToPublicError::InvalidSecret)?;
        let secret_key: C::SecretKey = visible.into();

        let public_key = engine.public_key(&secret_key);
        let (x, y) = engine.public_key_xy(&public_key);
        public[..32].copy_from_slice(&x);
        public[32..].copy_from_slice(&y);
        Ok(())
    })
}

/// Derives the shared secret point `(x||y)` for `public`/`secret` by running the scalar
/// multiplication on the hardware engine held in `cal`.
///
/// The full `public` point's `y` half is not needed: `embedded-cal`'s compact import already
/// reconstructs whichever `y` the hardware needs from `x` alone.
///
/// Panics if `cal` has not been populated via the adapter's `init()`.
pub fn hw_derive_ecdh<C>(
    cal: &Mutex<RefCell<Option<C>>>,
    alg: &C::Algorithm,
    derived: &mut [U8; 64],
    public: &[u8; 64],
    secret: &[U8; 32],
) -> Result<(), DeriveError>
where
    C: DhProvider + EcWeierstrassFullPoint,
{
    critical_section::with(|cs| {
        let mut engine = cal.borrow(cs).borrow_mut();
        let engine = engine
            .as_mut()
            .expect("hardware P-256 engine not initialized; call init() first");

        let secret_bytes: &[u8; 32] = secret.declassify_ref();
        let visible = engine
            .import_secretkey_bytes(alg.clone(), secret_bytes)
            .map_err(|_| DeriveError::InvalidSecret)?;
        let secret_key: C::SecretKey = visible.into();

        let public_key = engine
            .import_publickey_bytes(alg.clone(), &public[..32])
            .map_err(|_| DeriveError::InvalidPublic)?;

        let shared = engine
            .shared_secret(&secret_key, &public_key)
            .map_err(|_| DeriveError::Unknown)?;
        let (x, y) = engine.shared_secret_xy(&shared);
        derived[..32].copy_from_slice(&x.classify());
        derived[32..].copy_from_slice(&y.classify());
        Ok(())
    })
}

/// Instantiates a hardware-backed [`EcdhArrayref<32, 32, 64>`]/`EcdhSlice` adapter for P-256.
///
/// Generates a zero-sized `$name` type holding a global `$engine` singleton (populated once via
/// `$name::init()`), whose `generate_secret`/`validate_secret` delegate to `libcrux-p256`'s own
/// software implementation (they do not involve scalar multiplication), and whose
/// `secret_to_public`/`derive_ecdh` run on the hardware engine via [`hw_secret_to_public`]/
/// [`hw_derive_ecdh`].
#[macro_export]
macro_rules! impl_hw_p256 {
    ($vis:vis $name:ident : $engine:ty = $alg:expr) => {
        $vis struct $name;

        const _: () = {
            static CAL: critical_section::Mutex<core::cell::RefCell<Option<$engine>>> =
                critical_section::Mutex::new(core::cell::RefCell::new(None));

            impl $name {
                /// Populates the global hardware engine backing this adapter. Must be called
                /// once before any `EcdhArrayref`/`EcdhSlice` method is used.
                pub fn init(engine: $engine) {
                    critical_section::with(|cs| {
                        *CAL.borrow(cs).borrow_mut() = Some(engine);
                    });
                }
            }

            impl libcrux_traits::ecdh::arrayref::EcdhArrayref<32, 32, 64> for $name {
                fn generate_secret(
                    secret: &mut [libcrux_secrets::U8; 32],
                    rand: &[libcrux_secrets::U8; 32],
                ) -> Result<(), libcrux_traits::ecdh::arrayref::GenerateSecretError> {
                    <libcrux_p256::P256 as libcrux_traits::ecdh::arrayref::EcdhArrayref<
                        32,
                        32,
                        64,
                    >>::generate_secret(secret, rand)
                }

                fn secret_to_public(
                    public: &mut [u8; 64],
                    secret: &[libcrux_secrets::U8; 32],
                ) -> Result<(), libcrux_traits::ecdh::arrayref::SecretToPublicError> {
                    $crate::hw_secret_to_public(&CAL, $alg, public, secret)
                }

                fn derive_ecdh(
                    derived: &mut [libcrux_secrets::U8; 64],
                    public: &[u8; 64],
                    secret: &[libcrux_secrets::U8; 32],
                ) -> Result<(), libcrux_traits::ecdh::arrayref::DeriveError> {
                    $crate::hw_derive_ecdh(&CAL, &$alg, derived, public, secret)
                }

                fn validate_secret(
                    secret: &[libcrux_secrets::U8; 32],
                ) -> Result<(), libcrux_traits::ecdh::arrayref::ValidateSecretError> {
                    <libcrux_p256::P256 as libcrux_traits::ecdh::arrayref::EcdhArrayref<
                        32,
                        32,
                        64,
                    >>::validate_secret(secret)
                }
            }

            libcrux_traits::ecdh::slice::impl_ecdh_slice_trait!($name => 32, 32, 64);
        };
    };
}

#[cfg(feature = "nrf54l15")]
impl_hw_p256!(pub HwP256Nrf54l15 : embedded_cal_nrf54l15::Nrf54l15Cal = embedded_cal_nrf54l15::DhAlgorithm::EcdhP256);

#[cfg(feature = "stm32wba55")]
impl_hw_p256!(pub HwP256Stm32wba55 : embedded_cal_stm32wba55::Stm32wba55Cal = embedded_cal_stm32wba55::DhAlgorithm::EcdhP256);
