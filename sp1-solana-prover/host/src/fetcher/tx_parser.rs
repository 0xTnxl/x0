//! Shared transaction parsing utilities for Solana vote transaction processing
//!
//! Provides low-level parsing of raw Solana transactions used by multiple
//! fetcher submodules. Centralizes:
//!
//! - **Compact u16** encoding/decoding (Solana's variable-length integer format)
//! - **Raw transaction deserialization** (signatures + message + account keys)
//! - **Message instruction extraction** (program index, data, data offset)
//! - **Transaction binary decoding** (base64/base58 → raw bytes)
//!
//! These primitives are used by `votes.rs` (for bank hash search in vote data),
//! `mod.rs` (for bank hash discovery), and `rpc.rs` (for extracting writable keys).

use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::{EncodedTransaction, TransactionBinaryEncoding};

/// The Solana Vote program ID (base58 string)
pub const VOTE_PROGRAM_ID_STR: &str = "Vote111111111111111111111111111111111111111";

// ============================================================================
// Transaction Binary Decoding
// ============================================================================

/// Decode a Solana `EncodedTransaction` from binary format (base64 or base58)
/// to raw bytes.
///
/// Returns `None` for JSON-encoded or other non-binary transaction formats.
/// The host always requests base64 encoding from RPC, so this should succeed
/// for all well-formed transactions.
pub fn decode_transaction_bytes(tx: &EncodedTransaction) -> Option<Vec<u8>> {
    match tx {
        EncodedTransaction::Binary(data, encoding) => match encoding {
            TransactionBinaryEncoding::Base64 => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.decode(data).ok()
            }
            TransactionBinaryEncoding::Base58 => bs58::decode(data).into_vec().ok(),
        },
        _ => None,
    }
}

// ============================================================================
// Raw Transaction Parsing
// ============================================================================

/// Parse raw serialized transaction bytes into components.
///
/// # Returns
/// `(message_bytes, signatures, account_keys)` where:
/// - `message_bytes`: the serialized message (everything after signatures)
/// - `signatures`: list of Ed25519 signatures (64 bytes each)
/// - `account_keys`: parsed account public keys from the message header
///
/// # Transaction Wire Format
/// ```text
/// [compact_u16: num_signatures]
/// [signatures: 64 bytes × num_signatures]
/// [message:]
///   [header: 3 bytes (num_required_sigs, num_readonly_signed, num_readonly_unsigned)]
///   [compact_u16: num_account_keys]
///   [account_keys: 32 bytes × num_account_keys]
///   [recent_blockhash: 32 bytes]
///   [compact_u16: num_instructions]
///   [instructions...]
/// ```
pub fn parse_raw_transaction(raw: &[u8]) -> Option<(Vec<u8>, Vec<Vec<u8>>, Vec<Pubkey>)> {
    let mut offset = 0;

    // Number of signatures (compact u16)
    let (num_sigs, bytes_read) = read_compact_u16(raw, offset)?;
    offset += bytes_read;

    // Read signatures
    let mut signatures = Vec::with_capacity(num_sigs);
    for _ in 0..num_sigs {
        if offset + 64 > raw.len() {
            return None;
        }
        signatures.push(raw[offset..offset + 64].to_vec());
        offset += 64;
    }

    // Everything after signatures is the message
    let message_bytes = raw[offset..].to_vec();

    // Parse message header to get account keys
    if message_bytes.len() < 3 {
        return None;
    }

    let msg = &message_bytes;
    let mut msg_offset = 3; // Skip header (3 bytes)

    // Number of account keys (compact u16)
    let (num_keys, bytes_read) = read_compact_u16(msg, msg_offset)?;
    msg_offset += bytes_read;

    // Read account keys
    let mut account_keys = Vec::with_capacity(num_keys);
    for _ in 0..num_keys {
        if msg_offset + 32 > msg.len() {
            return None;
        }
        let key = Pubkey::try_from(&msg[msg_offset..msg_offset + 32]).ok()?;
        account_keys.push(key);
        msg_offset += 32;
    }

    Some((message_bytes, signatures, account_keys))
}

// ============================================================================
// Message Instruction Parsing
// ============================================================================

/// Parse instructions from a serialized Solana message.
///
/// # Returns
/// `Vec<(program_id_index, instruction_data, data_offset_in_message)>` where:
/// - `program_id_index`: index into the message's account keys for the program
/// - `instruction_data`: the raw instruction data bytes
/// - `data_offset_in_message`: byte offset of instruction data within the message
///   (needed for computing bank hash position in vote instructions)
///
/// # Message Layout (after header)
/// ```text
/// [header: 3 bytes]
/// [compact_u16: num_account_keys]
/// [account_keys: 32 × N bytes]
/// [recent_blockhash: 32 bytes]
/// [compact_u16: num_instructions]
/// [instructions: ...]
/// ```
pub fn parse_instructions_from_message(
    message: &[u8],
) -> Option<Vec<(u8, Vec<u8>, usize)>> {
    let mut offset = 3; // Skip header

    // Skip account keys
    let (num_keys, bytes_read) = read_compact_u16(message, offset)?;
    offset += bytes_read;
    offset += num_keys * 32;

    // Skip recent blockhash
    offset += 32;

    // Number of instructions
    let (num_instructions, bytes_read) = read_compact_u16(message, offset)?;
    offset += bytes_read;

    let mut instructions = Vec::with_capacity(num_instructions);

    for _ in 0..num_instructions {
        if offset >= message.len() {
            break;
        }

        // Program ID index
        let program_id_index = message[offset];
        offset += 1;

        // Number of account indices
        let (num_accounts, bytes_read) = read_compact_u16(message, offset)?;
        offset += bytes_read;

        // Skip account indices
        offset += num_accounts;

        // Instruction data length
        let (data_len, bytes_read) = read_compact_u16(message, offset)?;
        offset += bytes_read;

        // Instruction data — record the offset for bank hash location
        let data_offset = offset;
        if offset + data_len > message.len() {
            break;
        }
        let data = message[offset..offset + data_len].to_vec();
        offset += data_len;

        instructions.push((program_id_index, data, data_offset));
    }

    Some(instructions)
}

// ============================================================================
// Compact u16 Encoding
// ============================================================================

/// Read a Solana compact u16 value from a byte slice.
///
/// Solana uses a variable-length encoding for small integers (array lengths,
/// instruction counts, etc.). The encoding uses 1–3 bytes:
///
/// - `0x00..0x7F` → 1 byte, value 0–127
/// - High bit set → continue to next byte (7 bits per continuation byte)
///
/// # Returns
/// `(value, bytes_consumed)` or `None` if the slice is too short.
pub fn read_compact_u16(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    if offset >= data.len() {
        return None;
    }

    let first = data[offset] as usize;
    if first < 0x80 {
        return Some((first, 1));
    }

    if offset + 1 >= data.len() {
        return None;
    }
    let second = data[offset + 1] as usize;
    if second < 0x80 {
        return Some(((first & 0x7F) | (second << 7), 2));
    }

    if offset + 2 >= data.len() {
        return None;
    }
    let third = data[offset + 2] as usize;
    Some(((first & 0x7F) | ((second & 0x7F) << 7) | (third << 14), 3))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_u16_single_byte() {
        assert_eq!(read_compact_u16(&[0x00], 0), Some((0, 1)));
        assert_eq!(read_compact_u16(&[0x01], 0), Some((1, 1)));
        assert_eq!(read_compact_u16(&[0x7F], 0), Some((127, 1)));
    }

    #[test]
    fn test_compact_u16_two_bytes() {
        // 128 = (0x80 & 0x7F) | (0x01 << 7) = 0 | 128 = 128
        assert_eq!(read_compact_u16(&[0x80, 0x01], 0), Some((128, 2)));
        // 255 = (0xFF & 0x7F) | (0x01 << 7) = 127 | 128 = 255
        assert_eq!(read_compact_u16(&[0xFF, 0x01], 0), Some((255, 2)));
        // 300 = (0xAC & 0x7F) | (0x02 << 7) = 44 | 256 = 300
        assert_eq!(read_compact_u16(&[0xAC, 0x02], 0), Some((300, 2)));
    }

    #[test]
    fn test_compact_u16_three_bytes() {
        // Large value: 16384 = (0x80 & 0x7F) | ((0x80 & 0x7F) << 7) | (0x01 << 14)
        assert_eq!(
            read_compact_u16(&[0x80, 0x80, 0x01], 0),
            Some((16384, 3))
        );
    }

    #[test]
    fn test_compact_u16_with_offset() {
        let data = [0xAA, 0xBB, 0x05]; // garbage prefix, value 5 at offset 2
        assert_eq!(read_compact_u16(&data, 2), Some((5, 1)));
    }

    #[test]
    fn test_compact_u16_empty_and_bounds() {
        assert_eq!(read_compact_u16(&[], 0), None);
        assert_eq!(read_compact_u16(&[0x00], 1), None); // offset past end
        assert_eq!(read_compact_u16(&[0x80], 0), None); // needs continuation but no data
    }

    #[test]
    fn test_decode_transaction_bytes_returns_none_for_non_binary() {
        // Accounts-only encoding should return None
        let tx = EncodedTransaction::Accounts(
            solana_transaction_status::UiAccountsList {
                signatures: vec![],
                account_keys: vec![],
            },
        );
        assert!(decode_transaction_bytes(&tx).is_none());
    }

    #[test]
    fn test_parse_raw_transaction_too_short() {
        // Empty data
        assert!(parse_raw_transaction(&[]).is_none());

        // Just a compact u16 for 0 sigs, then not enough message data
        assert!(parse_raw_transaction(&[0x00, 0x00, 0x00]).is_none());
    }

    #[test]
    fn test_parse_instructions_empty_message() {
        // Message too short for header
        assert!(parse_instructions_from_message(&[0x00]).is_none());
    }
}
