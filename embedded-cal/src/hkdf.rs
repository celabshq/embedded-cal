use crate::{HmacAlgorithm, HmacProvider};

#[derive(Debug, PartialEq, Eq)]
pub enum HkdfError {
    /// Requested OKM length exceeds 255 × 32 bytes (RFC 5869).
    OutputTooLong,
    /// The underlying HMAC produced an output that is not 32 bytes, indicating
    /// the backend does not correctly implement HMAC-SHA-256 for COSE number 5.
    InvalidOutputLength,
}

pub trait HkdfProvider {
    /// HKDF-Extract (RFC 5869): returns a 32-byte pseudorandom key.
    ///
    /// When `salt` is `None`, 32 zero bytes are used as the HMAC key,
    /// HashLen = 32 for SHA-256.
    fn hkdf_extract(&mut self, salt: Option<&[u8]>, ikm: &[u8]) -> Result<[u8; 32], HkdfError>;

    /// HKDF-Expand (RFC 5869): fills `okm` with derived key material.
    fn hkdf_expand(&mut self, prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), HkdfError>;

    /// Extract then expand in one call.
    fn hkdf(
        &mut self,
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), HkdfError> {
        let prk = self.hkdf_extract(salt, ikm)?;
        self.hkdf_expand(&prk, info, okm)
    }
}

/// Blanket impl: any [`HmacProvider`] that supports HMAC-SHA-256 (COSE number 5) gets HKDF.
///
/// Panics at runtime if the provider does not recognise COSE number 5 (HMAC-SHA-256).
impl<H: HmacProvider> HkdfProvider for H {
    fn hkdf_extract(&mut self, salt: Option<&[u8]>, ikm: &[u8]) -> Result<[u8; 32], HkdfError> {
        const ZERO_SALT: [u8; 32] = [0u8; 32];
        let salt = salt.unwrap_or(&ZERO_SALT);
        let alg = H::Algorithm::from_cose_number(5i8)
            .expect("HkdfProvider requires HMAC-SHA-256 (COSE number 5)");
        // PRK = HMAC-Hash(salt, IKM): salt is the HMAC key, IKM is the data.
        let result = self.hmac_with_keydata(alg, salt, ikm);
        result
            .as_ref()
            .try_into()
            .map_err(|_| HkdfError::InvalidOutputLength)
    }

    fn hkdf_expand(&mut self, prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), HkdfError> {
        // FIXME: Only working for SHA256
        const HASH_LEN: usize = 32;
        if okm.len() > 255 * HASH_LEN {
            return Err(HkdfError::OutputTooLong);
        }
        let alg = H::Algorithm::from_cose_number(5i8)
            .expect("HkdfProvider requires HMAC-SHA-256 (COSE number 5)");
        let mut t = [0u8; HASH_LEN];
        let mut t_len = 0usize;
        let mut pos = 0usize;

        while pos < okm.len() {
            // counter is 1-based block index; derived from pos so it never overflows u8
            // (okm.len() <= 255*HASH_LEN is enforced above, so pos/HASH_LEN+1 <= 255)
            let counter = (pos / HASH_LEN + 1) as u8;
            // T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
            let mut state = self.init_with_keydata(alg.clone(), prk);
            if t_len > 0 {
                HmacProvider::update(self, &mut state, &t[..t_len]);
            }
            HmacProvider::update(self, &mut state, info);
            HmacProvider::update(self, &mut state, &[counter]);
            let result = HmacProvider::finalize(self, state);
            let result_bytes = result.as_ref();
            if result_bytes.len() != HASH_LEN {
                return Err(HkdfError::InvalidOutputLength);
            }
            t.copy_from_slice(result_bytes);
            t_len = HASH_LEN;

            let take = (okm.len() - pos).min(HASH_LEN);
            okm[pos..pos + take].copy_from_slice(&t[..take]);
            pos += take;
        }
        Ok(())
    }
}
