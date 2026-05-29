//! JB00/JB01 adaptive-Huffman + LZSS decompressor.
//!
//! This is the compression used by AutoHotkey-classic (and AutoIt v2-era) `JB01`
//! payloads. Unlike the EA05/EA06 LZ scheme it pairs LZSS matches with two
//! adaptive Huffman trees (one for literals/lengths, one for match offsets) that
//! are periodically rebuilt from running symbol frequencies. The algorithm
//! mirrors Jonathan Bennett's `JB01` reference and the `AutoIt-Ripper` port.

use super::bitstream::BitStream;
use crate::Error;

const LITERAL_ALPHABET: usize = 256 + 32;
const LITERAL_LEN_START: usize = 256;
const OFFSET_ALPHABET: usize = 32;
const MIN_MATCH_LEN: usize = 3;
const LITERAL_INITIAL_DELAY: usize = LITERAL_ALPHABET / 4;
const LITERAL_DELAY: usize = LITERAL_ALPHABET * 12;
const OFFSET_INITIAL_DELAY: usize = OFFSET_ALPHABET / 4;
const OFFSET_DELAY: usize = OFFSET_ALPHABET * 12;
const MAX_CODE_BITS: usize = 16;

/// A single node in an adaptive Huffman tree (a leaf symbol or internal node).
#[derive(Clone, Copy)]
struct Node {
    /// Running occurrence count used to order nodes when rebuilding the tree.
    frequency: u32,
    /// Index of the left child; for a leaf this equals the node's own index.
    child_left: usize,
    /// Index of the right child; for a leaf this equals the node's own index.
    child_right: usize,
    /// Index of the parent node, set while the tree is rebuilt.
    parent: usize,
    /// Whether this node is still a merge candidate during a rebuild pass.
    search_me: bool,
}

/// One adaptive Huffman tree plus its rebuild schedule.
struct HuffTree {
    /// All tree nodes: `alphabet` leaves followed by internal nodes, root last.
    nodes: Vec<Node>,
    /// Number of leaf symbols in this tree's alphabet.
    alphabet: usize,
    /// Index of the root node within `nodes`.
    root: usize,
    /// Whether the tree has reached its steady-state (decaying) rebuild cadence.
    fully_active: bool,
    /// Symbols-between-rebuilds during warm-up, grown each warm-up rebuild.
    increment: usize,
    /// Symbols left to read before the next rebuild.
    remaining: usize,
}

/// Returns the shared [`Error::compression_error`] used throughout this module.
///
/// # Returns
///
/// An [`Error`] of kind compression error.
fn err() -> Error {
    Error::compression_error()
}

/// Adds two `usize` values, failing instead of overflowing.
///
/// # Arguments
///
/// * `a` - The left operand.
/// * `b` - The right operand.
///
/// # Returns
///
/// The sum `a + b`.
///
/// # Errors
///
/// Returns [`Error::compression_error`] if the addition overflows.
fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or_else(err)
}

/// Subtracts two `usize` values, failing instead of underflowing.
///
/// # Arguments
///
/// * `a` - The minuend.
/// * `b` - The subtrahend.
///
/// # Returns
///
/// The difference `a - b`.
///
/// # Errors
///
/// Returns [`Error::compression_error`] if the subtraction underflows.
fn sub(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_sub(b).ok_or_else(err)
}

/// Computes `1 << shift`, failing instead of overflowing.
///
/// # Arguments
///
/// * `shift` - The number of bit positions to shift left.
///
/// # Returns
///
/// The value `1 << shift`.
///
/// # Errors
///
/// Returns [`Error::compression_error`] if `shift` does not fit in a `u32` or
/// the shift overflows.
fn shl1(shift: usize) -> Result<usize, Error> {
    1usize
        .checked_shl(u32::try_from(shift).map_err(|_err| err())?)
        .ok_or_else(err)
}

impl HuffTree {
    /// Builds a freshly initialized tree for `alphabet` leaf symbols.
    ///
    /// Allocates `2*alphabet - 1` nodes (leaves plus internal nodes), gives each
    /// leaf a starting frequency of 1, marks leaves as self-referential, and
    /// performs the initial [`HuffTree::generate`] pass.
    ///
    /// # Arguments
    ///
    /// * `alphabet` - Number of leaf symbols the tree must encode.
    /// * `initial_delay` - Initial symbol count between warm-up rebuilds.
    ///
    /// # Returns
    ///
    /// A ready-to-use [`HuffTree`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::compression_error`] if the node count arithmetic
    /// overflows or the initial generate pass fails.
    fn new(alphabet: usize, initial_delay: usize) -> Result<Self, Error> {
        // total nodes = 2*alphabet - 1 (leaves + internal nodes).
        let total = sub(add(alphabet, alphabet)?, 1)?;
        let root = sub(total, 1)?;
        let mut nodes = vec![
            Node {
                frequency: 1,
                child_left: 0,
                child_right: 0,
                parent: 0,
                search_me: false,
            };
            total
        ];
        for (index, node) in nodes.iter_mut().enumerate().take(alphabet) {
            node.child_left = index;
            node.child_right = index;
        }
        let mut tree = Self {
            nodes,
            alphabet,
            root,
            fully_active: false,
            increment: initial_delay,
            remaining: initial_delay,
        };
        tree.generate(0)?;
        Ok(tree)
    }

    /// Returns a shared reference to the node at `index`, bounds-checked.
    ///
    /// # Arguments
    ///
    /// * `index` - Position of the node within `nodes`.
    ///
    /// # Returns
    ///
    /// A reference to the requested [`Node`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::compression_error`] if `index` is out of bounds.
    fn node(&self, index: usize) -> Result<&Node, Error> {
        self.nodes.get(index).ok_or_else(err)
    }

    /// Returns a mutable reference to the node at `index`, bounds-checked.
    ///
    /// # Arguments
    ///
    /// * `index` - Position of the node within `nodes`.
    ///
    /// # Returns
    ///
    /// A mutable reference to the requested [`Node`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::compression_error`] if `index` is out of bounds.
    fn node_mut(&mut self, index: usize) -> Result<&mut Node, Error> {
        self.nodes.get_mut(index).ok_or_else(err)
    }

    /// Rebuilds the internal nodes from current leaf frequencies.
    ///
    /// Repeatedly merges the two lowest-frequency active nodes into each blank
    /// internal node up to the root, reconstructing the tree from scratch. If
    /// the resulting tree has any code longer than `MAX_CODE_BITS` it decays all
    /// leaf frequencies (`>> 2`, then `+ 1`) and retries. After a valid tree is
    /// built, a non-zero `freq_mod` decays leaf frequencies by that shift.
    ///
    /// # Arguments
    ///
    /// * `freq_mod` - Right-shift applied to leaf frequencies after rebuilding;
    ///   `0` leaves them unchanged.
    ///
    /// # Returns
    ///
    /// The unit value once a valid tree is built.
    ///
    /// # Errors
    ///
    /// Returns [`Error::compression_error`] if a node index is out of bounds or
    /// the root-bound arithmetic overflows.
    fn generate(&mut self, freq_mod: u32) -> Result<(), Error> {
        loop {
            for index in 0..self.alphabet {
                self.node_mut(index)?.search_me = true;
            }
            for index in self.alphabet..self.nodes.len() {
                self.node_mut(index)?.search_me = false;
            }

            let end = add(self.root, 1)?;
            let mut next_blank = self.alphabet;
            while next_blank != end {
                let (mut b1, mut b2) = (0usize, 0usize);
                let (mut b1_freq, mut b2_freq) = (u32::MAX, u32::MAX);
                for index in 0..next_blank {
                    let node = self.node(index)?;
                    if node.search_me && node.frequency < b2_freq {
                        if node.frequency < b1_freq {
                            b2 = b1;
                            b2_freq = b1_freq;
                            b1 = index;
                            b1_freq = node.frequency;
                        } else {
                            b2 = index;
                            b2_freq = node.frequency;
                        }
                    }
                }
                let combined = b1_freq.wrapping_add(b2_freq);
                self.node_mut(b1)?.search_me = false;
                self.node_mut(b1)?.parent = next_blank;
                self.node_mut(b2)?.search_me = false;
                self.node_mut(b2)?.parent = next_blank;
                let blank = self.node_mut(next_blank)?;
                blank.frequency = combined;
                blank.search_me = true;
                blank.child_left = b1;
                blank.child_right = b2;
                next_blank = add(next_blank, 1)?;
            }

            if self.max_depth_exceeded()? {
                for index in 0..self.alphabet {
                    let node = self.node_mut(index)?;
                    node.frequency = (node.frequency >> 2).wrapping_add(1);
                }
                continue;
            }
            break;
        }

        if freq_mod != 0 {
            for index in 0..self.alphabet {
                let node = self.node_mut(index)?;
                node.frequency = (node.frequency >> freq_mod).wrapping_add(1);
            }
        }
        Ok(())
    }

    /// Returns whether any leaf's code length exceeds `MAX_CODE_BITS`.
    ///
    /// Walks from each leaf up to the root counting edges, bailing out if the
    /// walk exceeds the node count (a sign of a malformed tree).
    ///
    /// # Returns
    ///
    /// `true` if some leaf is deeper than `MAX_CODE_BITS`, otherwise `false`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::compression_error`] if a parent walk exceeds the node
    /// count, a node index is out of bounds, or the depth counter overflows.
    fn max_depth_exceeded(&self) -> Result<bool, Error> {
        for leaf in 0..self.alphabet {
            let mut parent = leaf;
            let mut depth = 0usize;
            while parent != self.root {
                depth = add(depth, 1)?;
                if depth > self.nodes.len() {
                    return Err(err());
                }
                parent = self.node(parent)?.parent;
            }
            if depth > MAX_CODE_BITS {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Walks the tree from the root, consuming one bit per level, to a leaf.
    ///
    /// At each internal node a `0` bit descends left and a `1` bit descends
    /// right; a leaf is detected when its left child points to itself. The walk
    /// is bounded by the node count to reject malformed trees.
    ///
    /// # Arguments
    ///
    /// * `bits` - The bit stream to read code bits from.
    ///
    /// # Returns
    ///
    /// The index of the reached leaf, which equals the decoded symbol.
    ///
    /// # Errors
    ///
    /// Returns [`Error::compression_error`] if the walk exceeds the node count,
    /// a node index is out of bounds, or the step counter overflows. Propagates
    /// [`Error::truncated`] when the bit stream is exhausted.
    fn read_symbol(&self, bits: &mut BitStream<'_>) -> Result<usize, Error> {
        let mut code = self.root;
        let mut steps = 0usize;
        loop {
            let node = self.node(code)?;
            if node.child_left == code {
                return Ok(code);
            }
            code = if bits.read_bits(1)? == 0 {
                node.child_left
            } else {
                node.child_right
            };
            steps = add(steps, 1)?;
            if steps > self.nodes.len() {
                return Err(err());
            }
        }
    }

    /// Reads one symbol and advances the adaptive rebuild schedule.
    ///
    /// After decoding, the symbol's leaf frequency is incremented and the
    /// `remaining` counter decremented. When it reaches zero the tree rebuilds:
    /// during warm-up `increment` grows by the initial delay (flipping
    /// `fully_active` once it reaches `delay`) and the rebuild keeps frequencies;
    /// once fully active rebuilds happen every `delay` symbols with decay.
    ///
    /// # Arguments
    ///
    /// * `bits` - The bit stream to decode the next symbol from.
    /// * `delay` - The steady-state number of symbols between rebuilds.
    ///
    /// # Returns
    ///
    /// The decoded symbol index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::compression_error`] if the schedule arithmetic over- or
    /// underflows, a node index is out of bounds, or a rebuild fails. Propagates
    /// [`Error::truncated`] when the bit stream is exhausted.
    fn read_adaptive(&mut self, bits: &mut BitStream<'_>, delay: usize) -> Result<usize, Error> {
        let symbol = self.read_symbol(bits)?;
        let node = self.node_mut(symbol)?;
        node.frequency = node.frequency.wrapping_add(1);
        self.remaining = sub(self.remaining, 1)?;
        if self.remaining == 0 {
            if self.fully_active {
                self.remaining = delay;
                self.generate(1)?;
            } else {
                self.increment = add(self.increment, self.initial_delay())?;
                if self.increment >= delay {
                    self.fully_active = true;
                }
                self.remaining = self.initial_delay();
                self.generate(0)?;
            }
        }
        Ok(symbol)
    }

    /// Returns the warm-up rebuild interval for this tree's alphabet.
    ///
    /// # Returns
    ///
    /// `OFFSET_INITIAL_DELAY` for the offset alphabet, otherwise
    /// `LITERAL_INITIAL_DELAY`.
    fn initial_delay(&self) -> usize {
        if self.alphabet == OFFSET_ALPHABET {
            OFFSET_INITIAL_DELAY
        } else {
            LITERAL_INITIAL_DELAY
        }
    }
}

/// Decodes the extra match-length bits for a literal/length symbol `>= 256`.
///
/// Symbols `256..=263` map directly to lengths `0..=7`. Higher symbols carry a
/// base derived from an implied most-significant bit plus a number of extra bits
/// read from the stream, reconstructing the length value.
///
/// # Arguments
///
/// * `bits` - The bit stream positioned at the extra length bits.
/// * `symbol` - The length symbol from the literal/length tree (`>= 256`).
///
/// # Returns
///
/// The decoded length value (before adding `MIN_MATCH_LEN`).
///
/// # Errors
///
/// Returns [`Error::compression_error`] if the bit-width or value arithmetic
/// over- or underflows. Propagates [`Error::truncated`] when the bit stream is
/// exhausted.
fn read_length(bits: &mut BitStream<'_>, symbol: usize) -> Result<usize, Error> {
    if symbol <= 263 {
        return sub(symbol, LITERAL_LEN_START);
    }
    let code = sub(symbol, 264)?;
    let extra_bits = add(code >> 2, 1)?;
    let msb_value = shl1(add(extra_bits, 2)?)?;
    let low = code & 0x0003;
    let value = bits.read_bits(extra_bits)? as usize;
    add(
        add(value, msb_value)?,
        low.checked_shl(u32::try_from(extra_bits).map_err(|_err| err())?)
            .ok_or_else(err)?,
    )
}

/// Reads a match offset from the offset tree.
///
/// Decodes an offset code from the adaptive offset tree: codes `0..=3` are the
/// offset directly, while larger codes carry an implied most-significant bit
/// plus extra bits read from the stream to reconstruct the offset.
///
/// # Arguments
///
/// * `tree` - The adaptive offset Huffman tree.
/// * `bits` - The bit stream to decode the code and any extra bits from.
///
/// # Returns
///
/// The decoded back-reference offset.
///
/// # Errors
///
/// Returns [`Error::compression_error`] if the bit-width or value arithmetic
/// over- or underflows or a rebuild fails. Propagates [`Error::truncated`] when
/// the bit stream is exhausted.
fn read_offset(tree: &mut HuffTree, bits: &mut BitStream<'_>) -> Result<usize, Error> {
    let code = tree.read_adaptive(bits, OFFSET_DELAY)?;
    if code <= 3 {
        return Ok(code);
    }
    let code = sub(code, 4)?;
    let extra_bits = add(code >> 1, 1)?;
    let msb_value = shl1(add(extra_bits, 1)?)?;
    let low = code & 0x0001;
    let value = bits.read_bits(extra_bits)? as usize;
    add(
        add(value, msb_value)?,
        low.checked_shl(u32::try_from(extra_bits).map_err(|_err| err())?)
            .ok_or_else(err)?,
    )
}

/// Decompresses a JB01 payload (the bytes after the 8-byte wrapper header).
///
/// Maintains two adaptive Huffman trees, one for literal/length symbols and one
/// for offsets. Each iteration decodes a literal/length symbol: values below
/// `LITERAL_LEN_START` are emitted as literal bytes, while larger values give a
/// match length (via [`read_length`] plus `MIN_MATCH_LEN`) paired with an offset
/// (via [`read_offset`]), which is copied byte-by-byte from earlier output so
/// overlapping matches repeat correctly. Decoding stops once `output_size`
/// bytes are produced.
///
/// # Arguments
///
/// * `payload` - The compressed bytes after the 8-byte wrapper header.
/// * `output_size` - The exact decompressed length to produce.
///
/// # Returns
///
/// The decompressed bytes of length `output_size`.
///
/// # Errors
///
/// Returns [`Error::compression_error`] if a literal byte cannot be
/// represented, an offset is zero or beyond the current output, or a copy would
/// exceed `output_size` or a source index is unreachable. Propagates
/// [`Error::truncated`] when the bit stream is exhausted and errors from tree
/// construction or symbol decoding.
pub fn decompress_jb01(payload: &[u8], output_size: usize) -> Result<Vec<u8>, Error> {
    let mut bits = BitStream::new(payload);
    let mut literals = HuffTree::new(LITERAL_ALPHABET, LITERAL_INITIAL_DELAY)?;
    let mut offsets = HuffTree::new(OFFSET_ALPHABET, OFFSET_INITIAL_DELAY)?;
    let mut output = Vec::with_capacity(output_size.min(1024 * 1024));

    while output.len() < output_size {
        let symbol = literals.read_adaptive(&mut bits, LITERAL_DELAY)?;
        if symbol < LITERAL_LEN_START {
            let byte = u8::try_from(symbol).map_err(|_err| err())?;
            output.push(byte);
        } else {
            let match_len = add(read_length(&mut bits, symbol)?, MIN_MATCH_LEN)?;
            let offset = read_offset(&mut offsets, &mut bits)?;
            if offset == 0 || offset > output.len() {
                return Err(err());
            }
            let end = add(output.len(), match_len)?;
            if end > output_size {
                return Err(err());
            }
            for _ in 0..match_len {
                let source = sub(output.len(), offset)?;
                let byte = *output.get(source).ok_or_else(err)?;
                output.push(byte);
            }
        }
    }
    Ok(output)
}
