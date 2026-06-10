use crate::{HmacAlgorithm, HmacProvider};

#[derive(Debug, PartialEq, Eq)]
pub enum HkdfError {
    /// Requested OKM length exceeds 255 × HashLen bytes (RFC 5869).
    OutputTooLong,
    /// The algorithm's output length exceeds the supported maximum (64 bytes), or the underlying
    /// HMAC returned a length inconsistent with the algorithm's own reported length.
    InvalidOutputLength,
}

/// An interface for using HKDF (defined in
/// [RFC5869](https://datatracker.ietf.org/doc/html/rfc5869)).
///
/// # Current status and roadmap
///
/// This interface is currently provided by a single blanket implementation, as none of the
/// compoenents initially considered (hardware accelerators) do anything special about it.
///
/// This will be revisited when extending work on inextractable secrets to HKDF extraction output.
///
/// Until then, this interface uses no associated types; after that, it will at least have a type
/// for the extract step's output. It will likely *not* grow a dedicated Algorithm type, as HKDF is
/// based on HMAC algorithms.
pub trait HkdfProvider: HmacProvider {
    /// HKDF-Extract (RFC 5869): returns a pseudorandom key.
    ///
    /// When `salt` is `None`, a zero-filled byte string of `HashLen` bytes is used
    /// as the HMAC key (RFC 5869).
    fn hkdf_extract(
        &mut self,
        alg: <Self as HmacProvider>::Algorithm,
        salt: Option<&[u8]>,
        ikm: &[u8],
    ) -> Result<impl AsRef<[u8]> + use<Self>, HkdfError>;

    /// HKDF-Expand (RFC 5869): fills `okm` with derived key material.
    fn hkdf_expand(
        &mut self,
        alg: <Self as HmacProvider>::Algorithm,
        prk: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), HkdfError>;

    /// Extract then expand in one call.
    fn hkdf(
        &mut self,
        alg: <Self as HmacProvider>::Algorithm,
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), HkdfError> {
        let prk = self.hkdf_extract(alg.clone(), salt, ikm)?;
        self.hkdf_expand(alg, prk.as_ref(), info, okm)
    }
}

impl<H: HmacProvider> HkdfProvider for H {
    fn hkdf_extract(
        &mut self,
        alg: <Self as HmacProvider>::Algorithm,
        salt: Option<&[u8]>,
        ikm: &[u8],
    ) -> Result<impl AsRef<[u8]> + use<H>, HkdfError> {
        // When salt is absent, RFC 5869 uses HashLen zero bytes as the HMAC key.
        // Buffer covers standard algorithms up to SHA-512 (64 bytes).
        // Ideally this would be H::Algorithm::MAX_OUTPUT_LEN once const_trait_impl stabilises.
        let zero_salt = [0u8; 64];
        let hash_len = alg.len();
        if hash_len > zero_salt.len() {
            return Err(HkdfError::InvalidOutputLength);
        }
        let salt_bytes = salt.unwrap_or(&zero_salt[..hash_len]);
        // PRK = HMAC-Hash(salt, IKM)
        Ok(self.hmac_with_keydata(alg, salt_bytes, ikm))
    }

    fn hkdf_expand(
        &mut self,
        alg: <Self as HmacProvider>::Algorithm,
        prk: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), HkdfError> {
        let hash_len = alg.len();
        if okm.len() > 255 * hash_len {
            return Err(HkdfError::OutputTooLong);
        }
        // Ideally this would be H::Algorithm::MAX_OUTPUT_LEN once const_trait_impl stabilises.
        let mut t = [0u8; 64];
        if hash_len > t.len() {
            return Err(HkdfError::InvalidOutputLength);
        }
        let mut t_len = 0usize;
        let mut pos = 0usize;

        while pos < okm.len() {
            // counter is 1-based block index; pos/hash_len+1 <= 255 enforced above
            let counter = (pos / hash_len + 1) as u8;
            // T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
            let mut state = self.init_with_keydata(alg.clone(), prk);
            if t_len > 0 {
                HmacProvider::update(self, &mut state, &t[..t_len]);
            }
            HmacProvider::update(self, &mut state, info);
            HmacProvider::update(self, &mut state, &[counter]);
            let result = HmacProvider::finalize(self, state);
            let result_bytes = result.as_ref();
            if result_bytes.len() != hash_len {
                return Err(HkdfError::InvalidOutputLength);
            }
            t[..hash_len].copy_from_slice(result_bytes);
            t_len = hash_len;

            let take = (okm.len() - pos).min(hash_len);
            okm[pos..pos + take].copy_from_slice(&t[..take]);
            pos += take;
        }
        Ok(())
    }
}
