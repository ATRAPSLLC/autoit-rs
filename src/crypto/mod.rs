//! AutoIt payload decryptors.
//!
//! Each submodule reconstructs the keystream a particular AutoIt format version XORs over its
//! embedded resources. [`lame`] implements the EA06 LAME-derived chaotic floating-point generator,
//! while [`mt`] implements the Mersenne-Twister-derived generator shared by EA05, EA04, and JB01.

pub mod lame;
pub mod mt;
