// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

/// Build the CCM B0 block as defined in RFC 3610.
///
/// B0 = flags | nonce | Q, where Q is the message length encoded in L bytes.
pub fn build_b0(nonce: &[u8], msg_len: usize, a_len: usize, tag_len: usize) -> [u8; 16] {
    let mut b0 = [0u8; 16];
    let l = 15 - nonce.len();
    b0[0] = ((l - 1) as u8) | (((tag_len - 2) / 2) as u8) << 3;
    if a_len > 0 {
        b0[0] |= 0x40;
    }
    b0[1..1 + nonce.len()].copy_from_slice(nonce);
    let msg_len_bytes = (msg_len as u64).to_be_bytes();
    b0[16 - l..].copy_from_slice(&msg_len_bytes[8 - l..]);
    b0
}
