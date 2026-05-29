//! EA06 LAME stream decryptor.
//!
//! Reproduces the chaotic floating-point keystream the EA06 format uses to obfuscate its embedded
//! data. A 17-word state is seeded, mixed via rotate-and-add, and reinterpreted as IEEE-754 doubles
//! in `[0, 1)` to derive each keystream byte, which is XORed against the ciphertext.

const STATE_LEN: usize = 17;
const INITIAL_C1: usize = 10;
const LAST_INDEX: usize = 16;

/// Decrypts EA06 data with the AutoIt LAME-derived stream.
///
/// Seeds a [`LameStream`] and XORs each input byte against the next keystream byte.
///
/// # Arguments
///
/// * `data` - The encrypted EA06 bytes to decrypt.
/// * `seed` - The 32-bit seed used to initialize the keystream state.
///
/// # Returns
///
/// `Some` with the decrypted bytes, or `None` if keystream generation ever indexes its
/// fixed-size state out of bounds (see [`LameStream::fpusht`]); in practice this cannot occur
/// for valid state and serves as a defensive guard.
#[must_use]
pub fn decrypt(data: &[u8], seed: u32) -> Option<Vec<u8>> {
    let mut lame = LameStream::new(seed)?;
    data.iter()
        .map(|byte| lame.next_byte().map(|key| byte ^ key))
        .collect()
}

#[derive(Debug, Clone)]
struct LameStream {
    c0: usize,
    c1: usize,
    state: [u32; STATE_LEN],
}

impl LameStream {
    /// Creates and warms up a keystream from a seed.
    ///
    /// Fills the 17-word state by iterating `current = 1 - current * 0x53a9_b4fb` (wrapping),
    /// then discards 9 generator steps so the state is fully diffused before the first byte.
    ///
    /// # Arguments
    ///
    /// * `seed` - The 32-bit seed used to initialize the state words.
    ///
    /// # Returns
    ///
    /// `Some` with the warmed-up stream, or `None` if a warm-up step fails (see
    /// [`LameStream::fpusht`]); this cannot occur for valid state.
    fn new(seed: u32) -> Option<Self> {
        let mut stream = Self {
            c0: 0,
            c1: INITIAL_C1,
            state: [0; STATE_LEN],
        };
        let mut current = seed;
        for state_word in &mut stream.state {
            current = 1u32.wrapping_sub(current.wrapping_mul(0x53a9_b4fb));
            *state_word = current;
        }
        for _ in 0..9 {
            let _ = stream.fpusht()?;
        }
        Some(stream)
    }

    /// Produces the next keystream byte.
    ///
    /// Advances the generator twice per byte: the first step is discarded and the second is scaled
    /// by 256. The scaled value is floored into a byte, saturating to `0xff` when it reaches 256.
    ///
    /// # Returns
    ///
    /// `Some` with the next keystream byte, or `None` if a generator step fails (see
    /// [`LameStream::fpusht`]); this cannot occur for valid state.
    fn next_byte(&mut self) -> Option<u8> {
        let _ = self.fpusht()?;
        let value = self.fpusht()? * 256.0;
        if value < 256.0 {
            Some(value as u8)
        } else {
            Some(0xff)
        }
    }

    /// Advances the generator one step and returns a pseudo-random value in `[0, 1)`.
    ///
    /// Mixes the two words at the current cursors `c0` and `c1` via
    /// `rol(first, 9) + rol(second, 13)` (wrapping), stores the result back at `c0`, then walks
    /// both cursors backward through the ring. The 32-bit result is spliced into the mantissa of an
    /// IEEE-754 double with a fixed exponent so the raw bits decode to a value in `[1, 2)`, and 1.0
    /// is subtracted to map it into `[0, 1)`.
    ///
    /// # Returns
    ///
    /// `Some` with the generated value, or `None` if `c0` or `c1` falls outside the state array
    /// (see [`previous_index`]); this cannot occur for valid cursors.
    fn fpusht(&mut self) -> Option<f64> {
        let first = *self.state.get(self.c0)?;
        let second = *self.state.get(self.c1)?;
        let rolled = first.rotate_left(9).wrapping_add(second.rotate_left(13));
        *self.state.get_mut(self.c0)? = rolled;
        self.c0 = previous_index(self.c0)?;
        self.c1 = previous_index(self.c1)?;

        let low = u64::from(rolled << 20);
        let high = u64::from((rolled >> 12) | 0x3ff0_0000);
        let bits = (high << 32) | low;
        Some(f64::from_bits(bits) - 1.0)
    }
}

/// Steps a state cursor backward by one, wrapping around the ring buffer.
///
/// # Arguments
///
/// * `index` - The current cursor position into the 17-word state.
///
/// # Returns
///
/// `Some(LAST_INDEX)` when `index` is 0 (wrap to the end), otherwise `Some(index - 1)`. Returns
/// `None` only if the subtraction underflows, which cannot happen given the zero check.
fn previous_index(index: usize) -> Option<usize> {
    if index == 0 {
        Some(LAST_INDEX)
    } else {
        index.checked_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypts_ea06_file_marker() -> Result<(), String> {
        let decrypted = decrypt(&[0x6b, 0x43, 0xca, 0x52], 0x18ee)
            .ok_or_else(|| "decryption failed".to_string())?;
        if decrypted == b"FILE" {
            Ok(())
        } else {
            Err(format!("got {decrypted:?}, expected FILE"))
        }
    }

    #[test]
    fn emits_stable_ea06_keystream_bytes() -> Result<(), String> {
        let stream = decrypt(&[0; 16], 0x18ee).ok_or_else(|| "decryption failed".to_string())?;
        check_eq(
            stream.as_slice(),
            [
                0x2d, 0x0a, 0x86, 0x17, 0xb6, 0xb3, 0x71, 0xa0, 0x07, 0x10, 0x84, 0xf7, 0xe5, 0xba,
                0xe7, 0x29,
            ]
            .as_slice(),
            "keystream",
        )
    }

    fn check_eq<T>(actual: T, expected: T, context: &str) -> Result<(), String>
    where
        T: core::fmt::Debug + PartialEq,
    {
        if actual == expected {
            Ok(())
        } else {
            Err(format!("{context}: got {actual:?}, expected {expected:?}"))
        }
    }
}
