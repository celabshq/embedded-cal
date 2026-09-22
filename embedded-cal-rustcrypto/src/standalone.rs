// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::empty;

use super::*;

pub type Standalone = RustcryptoCalExtender<embedded_cal_rand::WithSysRng<empty::EmptyCal>>;

impl Standalone {
    pub fn standalone() -> Self {
        Self::new_extending(embedded_cal_rand::WithSysRng::new_from_sys(empty::EmptyCal))
    }
}

impl Default for Standalone {
    fn default() -> Self {
        Self::standalone()
    }
}
