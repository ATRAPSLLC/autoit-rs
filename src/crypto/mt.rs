//! EA05 Mersenne Twister stream decryptor.
//!
//! Reproduces the MT19937-derived keystream shared by the EA05, EA04, and JB01 formats. A 624-word
//! state is seeded and regenerated in bulk by [`MtStream::twist`], and each tempered word yields one
//! keystream byte that is XORed against the ciphertext. The tempering masks differ from stock
//! MT19937, matching AutoIt's variant.

const STATE_LEN: usize = 624;
const PERIOD_OFFSET: usize = 397;
const FIRST_TWIST_COUNT: usize = 227;
const SECOND_TWIST_COUNT: usize = 396;
const SECOND_TWIST_BASE: usize = 227;
const LAST_INDEX: usize = 623;

/// Decrypts EA05 data with the AutoIt MT-derived stream.
///
/// Seeds an [`MtStream`] and XORs each input byte against the next keystream byte.
///
/// # Arguments
///
/// * `data` - The encrypted EA05 bytes to decrypt.
/// * `seed` - The 32-bit seed used to initialize the Mersenne Twister state.
///
/// # Returns
///
/// `Some` with the decrypted bytes, or `None` if keystream generation ever indexes the fixed-size
/// state out of bounds (see [`MtStream::next_byte`] and [`MtStream::twist`]); this cannot occur for
/// valid state and serves as a defensive guard.
#[must_use]
pub fn decrypt(data: &[u8], seed: u32) -> Option<Vec<u8>> {
    let mut mt = MtStream::new(seed)?;
    data.iter()
        .map(|byte| mt.next_byte().map(|key| byte ^ key))
        .collect()
}

#[derive(Debug, Clone)]
struct MtStream {
    state: [u32; STATE_LEN],
    index: usize,
}

impl MtStream {
    /// Creates a keystream by running the MT19937 seeding recurrence.
    ///
    /// Places `seed` in word 0, then fills the remaining 623 words with
    /// `i + 0x6c07_8965 * (prev ^ (prev >> 30))` (wrapping). The index starts at [`STATE_LEN`] so
    /// the first byte request forces an immediate [`MtStream::twist`].
    ///
    /// # Arguments
    ///
    /// * `seed` - The 32-bit seed placed in the first state word.
    ///
    /// # Returns
    ///
    /// `Some` with the seeded stream, or `None` if the index-to-`u32` conversion or a state index
    /// is out of range; this cannot occur for the fixed 624-word state.
    fn new(seed: u32) -> Option<Self> {
        let mut state = [0; STATE_LEN];
        *state.get_mut(0)? = seed;
        for index in 1..STATE_LEN {
            let previous_index = index.checked_sub(1)?;
            let previous = *state.get(previous_index)?;
            let current = u32::try_from(index)
                .ok()?
                .wrapping_add(0x6c07_8965u32.wrapping_mul(previous ^ (previous >> 30)));
            *state.get_mut(index)? = current;
        }
        Some(Self {
            state,
            index: STATE_LEN,
        })
    }

    /// Produces the next keystream byte.
    ///
    /// Regenerates the state via [`MtStream::twist`] whenever the index reaches [`STATE_LEN`], then
    /// applies AutoIt's tempering transform to the current word and returns its high bits shifted
    /// right by one. The tempering uses the masks `0xff3a_58ad` and `0xffff_df8c`, which differ from
    /// stock MT19937.
    ///
    /// # Returns
    ///
    /// `Some` with the next keystream byte, or `None` if the twist or a state index is out of range
    /// (see [`MtStream::twist`]); this cannot occur for valid state.
    fn next_byte(&mut self) -> Option<u8> {
        if self.index >= STATE_LEN {
            self.twist()?;
            self.index = 0;
        }
        let mut rnd = *self.state.get(self.index)?;
        rnd = ((((rnd >> 11) ^ rnd) & 0xff3a_58ad) << 7) ^ (rnd >> 11) ^ rnd;
        rnd = ((rnd & 0xffff_df8c) << 15) ^ rnd ^ ((((rnd & 0xffff_df8c) << 15) ^ rnd) >> 18);
        self.index = self.index.checked_add(1)?;
        Some((rnd >> 1) as u8)
    }

    /// Regenerates all 624 state words in place (the MT19937 "twist").
    ///
    /// Recombines each word with the one `PERIOD_OFFSET` (397) positions ahead using the standard
    /// MT recurrence: take the high bit of the current word and the low bits of the next, mix into
    /// the offset word, and conditionally XOR the matrix constant `0x9908_b0df` when the next word
    /// is odd. The loop is split into three ranges so the offset arithmetic stays within bounds and
    /// the final word wraps back to word 0.
    ///
    /// # Returns
    ///
    /// `Some(())` on success, or `None` if any computed state index is out of range; this cannot
    /// occur for the fixed 624-word state.
    fn twist(&mut self) -> Option<()> {
        for index in 0..FIRST_TWIST_COUNT {
            let plus_period = index.checked_add(PERIOD_OFFSET)?;
            let plus_one = index.checked_add(1)?;
            let state_index = *self.state.get(index)?;
            let state_next = *self.state.get(plus_one)?;
            let mut value = *self.state.get(plus_period)?;
            value ^= (state_index ^ ((state_next ^ state_index) & 0x7fff_fffe)) >> 1;
            if state_next & 1 != 0 {
                value ^= 0x9908_b0df;
            }
            *self.state.get_mut(index)? = value;
        }

        for index in 0..SECOND_TWIST_COUNT {
            let state_index = SECOND_TWIST_BASE.checked_add(index)?;
            let state_next_index = state_index.checked_add(1)?;
            let state_current = *self.state.get(state_index)?;
            let state_next = *self.state.get(state_next_index)?;
            let mut value = *self.state.get(index)?;
            value ^= (state_current ^ ((state_next ^ state_current) & 0x7fff_fffe)) >> 1;
            if state_next & 1 != 0 {
                value ^= 0x9908_b0df;
            }
            *self.state.get_mut(state_index)? = value;
        }

        let first = *self.state.first()?;
        let last = *self.state.get(LAST_INDEX)?;
        let mut value = *self.state.get(SECOND_TWIST_COUNT)?;
        value ^= (last ^ ((first ^ last) & 0x7fff_fffe)) >> 1;
        if first & 1 != 0 {
            value ^= 0x9908_b0df;
        }
        *self.state.get_mut(LAST_INDEX)? = value;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypts_ea05_file_marker() -> Result<(), String> {
        let decrypted = decrypt(&[0xff, 0x6d, 0xb0, 0xce], 0x16fa)
            .ok_or_else(|| "decryption failed".to_string())?;
        if decrypted == b"FILE" {
            Ok(())
        } else {
            Err(format!("got {decrypted:?}, expected FILE"))
        }
    }

    #[test]
    fn emits_stable_ea05_keystream_bytes() -> Result<(), String> {
        let stream = decrypt(&[0; 16], 0x16fa).ok_or_else(|| "decryption failed".to_string())?;
        check_eq(
            stream.as_slice(),
            [
                0xb9, 0x24, 0xfc, 0x8b, 0xfd, 0xe8, 0xba, 0x7f, 0x87, 0xb0, 0xd1, 0x52, 0x58, 0x30,
                0x66, 0x9c,
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
