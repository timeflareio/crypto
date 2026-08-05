//! Shamir Secret Sharing implementation for Timeflare
//!
//! This module provides a pure Rust implementation of Shamir's Secret Sharing scheme
//! operating over GF(256). It supports splitting secrets of arbitrary size into shares
//! where any threshold number of shares can reconstruct the original secret.
//!
//! Based on the mathematical foundation of polynomial interpolation over finite fields.
//!
//! # Constraints and Limitations
//!
//! - **Threshold**: Must be between 2 and 16 (inclusive)
//!   - Minimum 2 for security (threshold=1 would mean any single share reveals the secret)
//!   - Maximum 16 for performance and mobile compatibility
//!
//! - **Number of Shares**: Must be between threshold and 32 (inclusive)
//!   - Maximum 32 for reasonable guardian coordination and economics
//!   - Must be at least equal to threshold for the scheme to work
//!
//! - **Secret Size**: Must be between 0 bytes and 1MB (inclusive)
//!   - Empty secrets are valid
//!   - Each share will be the same size as the secret
//!   - Memory usage is O(secret_size * num_shares)
//!   - 1MB maximum ensures mobile compatibility and prevents DoS attacks. It
//!     is an implementation ceiling, not a protocol one — callers split a
//!     32-byte X25519 scalar, so nothing reaches it
//!   - Total memory usage capped at 50MB
//!
//! - **Share IDs**: Automatically assigned from 1 to num_shares
//!   - ID 0 is reserved and invalid
//!   - Each share must have a unique ID
//!
//! # Security Notes
//!
//! - GF(256) arithmetic is table-driven: `gf256_mul` and `gf256_div` index the
//!   log/exp tables by operand, so they perform input-dependent memory accesses
//!   and are not constant-time. What that exposes, and why it is accepted, is
//!   recorded under "Security posture" in `README.md`
//! - Random coefficients are generated using ChaCha20Rng for cryptographic security
//! - Shares can only be validated during reconstruction phase

use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use std::collections::HashSet;

// Hard constraints for production safety and performance
const MIN_SECRET_SIZE: usize = 0; // Allow empty secrets
const MAX_SECRET_SIZE: usize = 1_048_576; // 1MB maximum
const MIN_THRESHOLD: u8 = 2; // Security minimum
const MAX_THRESHOLD: u8 = 16; // Performance maximum
const MIN_SHARES: u8 = 2; // Must equal threshold minimum
const MAX_SHARES: u8 = 32; // Economic/performance maximum
const MAX_TOTAL_MEMORY: usize = 50 * 1024 * 1024; // 50MB limit (allows max case: 1MB×t16×n32=47MB)

/// Error types for SSS operations
#[derive(Debug, thiserror::Error)]
pub enum SssError {
    #[error("Invalid threshold: {0}")]
    InvalidThreshold(String),
    #[error("Invalid share count: {0}")]
    InvalidShareCount(String),
    #[error("Insufficient shares: need {needed}, got {provided}")]
    InsufficientShares { needed: u8, provided: usize },
    #[error("Duplicate share IDs detected")]
    DuplicateShareIds,
    #[error("Invalid share data: {0}")]
    InvalidShareData(String),
    #[error("Share lengths do not match")]
    MismatchedShareLengths,
    #[error("Division by zero in GF(256)")]
    DivisionByZero,
    #[error("Secret too small: {size} bytes (min: {min})")]
    SecretTooSmall { size: usize, min: usize },
    #[error("Secret too large: {size} bytes (max: {max})")]
    SecretTooLarge { size: usize, max: usize },
    #[error("Threshold too low: {threshold} (min: {min})")]
    ThresholdTooLow { threshold: u8, min: u8 },
    #[error("Threshold too high: {threshold} (max: {max})")]
    ThresholdTooHigh { threshold: u8, max: u8 },
    #[error("Share count too low: {shares} (min: {min})")]
    ShareCountTooLow { shares: u8, min: u8 },
    #[error("Share count too high: {shares} (max: {max})")]
    ShareCountTooHigh { shares: u8, max: u8 },
    #[error("Memory limit exceeded: {required} bytes (max: {limit})")]
    MemoryLimitExceeded { required: usize, limit: usize },
}

/// A share of a secret in Shamir's Secret Sharing scheme
#[derive(Clone, Debug, PartialEq)]
pub struct Share {
    /// The share identifier (x-coordinate), must be between 1 and 255
    pub id: u8,
    /// The share data (y-coordinates for each byte's polynomial)
    pub data: Vec<u8>,
}

/// Split a secret into shares using Shamir's Secret Sharing
///
/// # Arguments
/// * `secret` - The secret data to split (can be any size)
/// * `threshold` - Minimum number of shares needed to reconstruct (must be >= 2)
/// * `shares` - Total number of shares to generate (must be >= threshold)
///
/// # Returns
/// A vector of shares, each containing an ID and share data
///
pub fn split_secret(secret: &[u8], threshold: u8, shares: u8) -> Result<Vec<Share>, SssError> {
    // Comprehensive input validation
    validate_secret_size(secret)?;
    validate_parameters(threshold, shares)?;
    validate_memory_requirements(secret.len(), threshold, shares)?;

    // Use ChaCha20Rng with manual seeding for WASM compatibility
    let seed_bytes = crate::utils::generate_random_bytes(32)
        .map_err(|_| SssError::InvalidThreshold("Failed to generate random seed".to_string()))?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut result_shares = Vec::with_capacity(shares as usize);

    // Initialize shares with IDs
    for i in 1..=shares {
        result_shares.push(Share {
            id: i,
            data: Vec::with_capacity(secret.len()),
        });
    }

    // Pre-allocate buffer for random coefficients to avoid repeated small allocations
    let coefficients_per_byte = (threshold - 1) as usize;
    let total_random_bytes = coefficients_per_byte * secret.len();
    let mut random_coefficients = vec![0u8; total_random_bytes];
    rng.fill_bytes(&mut random_coefficients);

    // For each byte in the secret, create a polynomial and evaluate it at each share ID
    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        // Generate random coefficients for polynomial of degree (threshold - 1)
        // The constant term is the secret byte
        let mut coefficients = Vec::with_capacity(threshold as usize);
        coefficients.push(secret_byte);

        // Add the pre-generated random coefficients
        let coeff_start = byte_idx * coefficients_per_byte;
        let coeff_end = coeff_start + coefficients_per_byte;
        coefficients.extend_from_slice(&random_coefficients[coeff_start..coeff_end]);

        // Evaluate polynomial at each share ID
        for share in &mut result_shares {
            let y = evaluate_polynomial(&coefficients, share.id);
            share.data.push(y);
        }
    }

    Ok(result_shares)
}

/// Combine shares to reconstruct the original secret
///
/// # Arguments
/// * `shares` - A slice of shares to combine (must have at least threshold shares)
/// * `threshold` - The threshold value used when splitting the secret
///
/// # Returns
/// The reconstructed secret as a vector of bytes
///
pub fn combine_shares(shares: &[Share], threshold: u8) -> Result<Vec<u8>, SssError> {
    // Validate threshold bounds
    validate_threshold_bounds(threshold)?;

    // Handle empty shares case first
    if shares.is_empty() {
        return Ok(Vec::new());
    }

    // Validate we have enough shares
    if shares.len() < threshold as usize {
        return Err(SssError::InsufficientShares {
            needed: threshold,
            provided: shares.len(),
        });
    }

    // Check for duplicate share IDs and validate IDs
    let mut seen_ids = HashSet::new();
    let mut valid_shares = Vec::with_capacity(shares.len());

    for share in shares {
        if share.id == 0 {
            return Err(SssError::InvalidShareData("Invalid share ID".to_string()));
        }

        if !seen_ids.insert(share.id) {
            return Err(SssError::DuplicateShareIds);
        }

        valid_shares.push(share);
    }

    // Verify all shares have the same length
    let expected_len = valid_shares[0].data.len();
    for share in &valid_shares {
        if share.data.len() != expected_len {
            return Err(SssError::MismatchedShareLengths);
        }
    }

    // Select exactly threshold shares for reconstruction
    // Uses first available shares for deterministic results
    let shares_to_use: Vec<&Share> = valid_shares
        .iter()
        .take(threshold as usize)
        .copied()
        .collect();

    let mut secret = Vec::with_capacity(expected_len);

    // Reconstruct each byte of the secret
    for byte_idx in 0..expected_len {
        // Collect x and y values for this byte position
        let mut xs = Vec::with_capacity(threshold as usize);
        let mut ys = Vec::with_capacity(threshold as usize);

        for share in &shares_to_use {
            xs.push(share.id);
            ys.push(share.data[byte_idx]);
        }

        // Use Lagrange interpolation to find f(0)
        let secret_byte = lagrange_interpolation(&xs, &ys, 0)?;
        secret.push(secret_byte);
    }

    Ok(secret)
}

/// Evaluate a polynomial at a given x value in GF(256)
fn evaluate_polynomial(coefficients: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    let mut x_power = 1u8; // x^0 = 1

    for &coeff in coefficients {
        result = gf256_add(result, gf256_mul(coeff, x_power));
        x_power = gf256_mul(x_power, x);
    }

    result
}

/// Lagrange interpolation in GF(256) to find f(x)
fn lagrange_interpolation(xs: &[u8], ys: &[u8], x: u8) -> Result<u8, SssError> {
    let mut result = 0u8;

    for i in 0..xs.len() {
        let mut numerator = 1u8;
        let mut denominator = 1u8;

        for j in 0..xs.len() {
            if i != j {
                numerator = gf256_mul(numerator, gf256_sub(x, xs[j]));
                denominator = gf256_mul(denominator, gf256_sub(xs[i], xs[j]));
                // Note: denominator could theoretically become 0 if two shares have the same ID,
                // but we already check for duplicate IDs in combine_shares()
            }
        }

        let fraction = gf256_div(numerator, denominator)?;
        let term = gf256_mul(ys[i], fraction);
        result = gf256_add(result, term);
    }

    Ok(result)
}

/// Validate secret size constraints
fn validate_secret_size(secret: &[u8]) -> Result<(), SssError> {
    let size = secret.len();

    // MIN_SECRET_SIZE is 0, so this comparison is always false: empty secrets
    // are valid. The bound is checked anyway so both ends are enforced in one
    // place, and raising MIN_SECRET_SIZE takes effect here with no other edit.
    #[allow(clippy::absurd_extreme_comparisons)]
    if size < MIN_SECRET_SIZE {
        return Err(SssError::SecretTooSmall {
            size,
            min: MIN_SECRET_SIZE,
        });
    }

    if size > MAX_SECRET_SIZE {
        return Err(SssError::SecretTooLarge {
            size,
            max: MAX_SECRET_SIZE,
        });
    }

    Ok(())
}

/// Validate threshold and share count parameters
fn validate_parameters(threshold: u8, shares: u8) -> Result<(), SssError> {
    // Threshold bounds validation
    if threshold < MIN_THRESHOLD {
        return Err(SssError::ThresholdTooLow {
            threshold,
            min: MIN_THRESHOLD,
        });
    }

    if threshold > MAX_THRESHOLD {
        return Err(SssError::ThresholdTooHigh {
            threshold,
            max: MAX_THRESHOLD,
        });
    }

    // Share count bounds validation
    if shares < MIN_SHARES {
        return Err(SssError::ShareCountTooLow {
            shares,
            min: MIN_SHARES,
        });
    }

    if shares > MAX_SHARES {
        return Err(SssError::ShareCountTooHigh {
            shares,
            max: MAX_SHARES,
        });
    }

    // Relationship validation
    if shares < threshold {
        return Err(SssError::InvalidShareCount(format!(
            "Number of shares ({}) must be at least equal to threshold ({})",
            shares, threshold
        )));
    }

    Ok(())
}

/// Validate threshold bounds (used in combine_shares)
fn validate_threshold_bounds(threshold: u8) -> Result<(), SssError> {
    if threshold < MIN_THRESHOLD {
        return Err(SssError::ThresholdTooLow {
            threshold,
            min: MIN_THRESHOLD,
        });
    }

    if threshold > MAX_THRESHOLD {
        return Err(SssError::ThresholdTooHigh {
            threshold,
            max: MAX_THRESHOLD,
        });
    }

    Ok(())
}

/// Validate memory requirements to prevent DoS attacks
fn validate_memory_requirements(
    secret_size: usize,
    threshold: u8,
    shares: u8,
) -> Result<(), SssError> {
    // Calculate memory requirements with overflow protection
    let coeff_bytes = secret_size.saturating_mul((threshold - 1) as usize);
    let share_bytes = secret_size.saturating_mul(shares as usize);
    let total_memory = coeff_bytes.saturating_add(share_bytes);

    if total_memory > MAX_TOTAL_MEMORY {
        return Err(SssError::MemoryLimitExceeded {
            required: total_memory,
            limit: MAX_TOTAL_MEMORY,
        });
    }

    Ok(())
}

// GF(256) arithmetic operations

/// Addition in GF(256) is XOR
#[inline]
fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Subtraction in GF(256) is the same as addition (XOR)
#[inline]
fn gf256_sub(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplication in GF(256) using logarithm tables
#[inline]
fn gf256_mul(a: u8, b: u8) -> u8 {
    // Handle zero multiplication directly for correctness
    if a == 0 || b == 0 {
        return 0;
    }

    // Perform logarithmic multiplication for non-zero values
    let log_a = GF256_LOG[a as usize] as u16;
    let log_b = GF256_LOG[b as usize] as u16;
    // Note: We use % 255 not % 256 because the multiplicative group of GF(256)
    // has order 255 (excluding 0). This ensures correct wraparound in the log table.
    let log_result = (log_a + log_b) % 255;
    GF256_EXP[log_result as usize]
}

/// Division in GF(256) using logarithm tables
#[inline]
fn gf256_div(a: u8, b: u8) -> Result<u8, SssError> {
    // Division by zero check
    if b == 0 {
        return Err(SssError::DivisionByZero);
    }

    // Handle zero dividend
    if a == 0 {
        return Ok(0);
    }

    // Perform logarithmic division for non-zero values
    let log_a = GF256_LOG[a as usize] as i16;
    let log_b = GF256_LOG[b as usize] as i16;
    let mut log_result = log_a - log_b;

    // Handle negative results by adding the field order
    if log_result < 0 {
        log_result += 255;
    }

    Ok(GF256_EXP[log_result as usize])
}

// Precomputed logarithm table for GF(256) with primitive polynomial 0x11d
// These tables are standard for GF(256) and widely used in cryptographic implementations.
// We use hardcoded tables for performance rather than runtime generation.
// Table integrity is verified in tests to ensure mathematical correctness.
// Note: First element is 0x00 for log(0), which is undefined mathematically.
// This is handled by always checking for zero inputs in multiplication/division.
static GF256_LOG: [u8; 256] = [
    0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6, 0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03,
    0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef, 0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1,
    0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a, 0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78,
    0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24, 0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e,
    0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94, 0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38,
    0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62, 0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10,
    0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42, 0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
    0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca, 0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57,
    0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74, 0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8,
    0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5, 0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0,
    0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec, 0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
    0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86, 0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d,
    0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc, 0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1,
    0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47, 0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
    0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89, 0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5,
    0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18, 0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07,
];

// Precomputed exponential table for GF(256)
static GF256_EXP: [u8; 256] = [
    0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
    0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
    0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
    0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
    0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
    0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
    0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
    0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
    0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
    0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
    0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
    0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
    0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
    0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
    0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
    0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incremental_share_combinations() {
        let secret = b"Hello, Timeflare!";
        let threshold = 3;
        let total_shares = 5;

        // Split the secret
        let shares = split_secret(secret, threshold, total_shares).unwrap();
        assert_eq!(shares.len(), total_shares as usize);

        // Each share should have the same length as the secret
        for share in &shares {
            assert_eq!(share.data.len(), secret.len());
            assert!(share.id >= 1 && share.id <= total_shares);
        }

        // Test 1: Incrementally add shares from 1 to total_shares
        println!("Testing incremental share combinations:");
        for num_shares in 1..=total_shares {
            let selected_shares = &shares[..num_shares as usize];

            if num_shares < threshold {
                // Should fail with insufficient shares
                println!(
                    "  Testing with {} shares (< threshold of {}): expecting failure",
                    num_shares, threshold
                );
                let result = combine_shares(selected_shares, threshold);
                match result {
                    Err(SssError::InsufficientShares { needed, provided }) => {
                        assert_eq!(needed, threshold);
                        assert_eq!(provided, num_shares as usize);
                        println!(
                            "    ✓ Failed as expected: need {}, got {}",
                            needed, provided
                        );
                    }
                    _ => panic!("Expected InsufficientShares error, got: {:?}", result),
                }
            } else {
                // Should successfully reconstruct
                println!(
                    "  Testing with {} shares (>= threshold of {}): expecting success",
                    num_shares, threshold
                );
                let recovered = combine_shares(selected_shares, threshold).unwrap();
                assert_eq!(recovered, secret);
                println!("    ✓ Successfully reconstructed secret");
            }
        }

        // Test 2: Try different non-sequential combinations
        println!("\nTesting non-sequential share combinations:");

        // Test with 2 shares from non-adjacent positions (should fail)
        println!("  Testing with shares [1, 4] (2 shares < threshold of 3):");
        let two_shares = vec![shares[0].clone(), shares[3].clone()];
        let result = combine_shares(&two_shares, threshold);
        match result {
            Err(SssError::InsufficientShares { needed, provided }) => {
                assert_eq!(needed, threshold);
                assert_eq!(provided, 2);
                println!(
                    "    ✓ Failed as expected: need {}, got {}",
                    needed, provided
                );
            }
            _ => panic!("Expected InsufficientShares error, got: {:?}", result),
        }

        // Test with 3 shares from different positions (should succeed)
        println!("  Testing with shares [2, 4, 5] (3 shares = threshold):");
        let three_shares = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];
        let recovered = combine_shares(&three_shares, threshold).unwrap();
        assert_eq!(recovered, secret);
        println!("    ✓ Successfully reconstructed secret");

        // Test with 4 shares from scattered positions (should succeed)
        println!("  Testing with shares [1, 3, 4, 5] (4 shares > threshold):");
        let four_shares = vec![
            shares[0].clone(),
            shares[2].clone(),
            shares[3].clone(),
            shares[4].clone(),
        ];
        let recovered = combine_shares(&four_shares, threshold).unwrap();
        assert_eq!(recovered, secret);
        println!("    ✓ Successfully reconstructed secret");

        // Test edge case: exactly 1 share (should fail)
        println!("  Testing with single share [3] (1 share < threshold):");
        let single_share = vec![shares[2].clone()];
        let result = combine_shares(&single_share, threshold);
        match result {
            Err(SssError::InsufficientShares { needed, provided }) => {
                assert_eq!(needed, threshold);
                assert_eq!(provided, 1);
                println!(
                    "    ✓ Failed as expected: need {}, got {}",
                    needed, provided
                );
            }
            _ => panic!("Expected InsufficientShares error, got: {:?}", result),
        }
    }

    #[test]
    fn test_simple_split_and_combine() {
        let secret = b"Test Secret";
        let threshold = 2;
        let total_shares = 3;

        // Basic split and combine test
        let shares = split_secret(secret, threshold, total_shares).unwrap();

        // Combine using exactly threshold shares
        let recovered = combine_shares(&shares[..threshold as usize], threshold).unwrap();
        assert_eq!(recovered, secret);

        // Combine using all shares
        let recovered2 = combine_shares(&shares, threshold).unwrap();
        assert_eq!(recovered2, secret);
    }

    #[test]
    fn test_different_share_combinations() {
        let secret = b"Test secret";
        let threshold = 3;
        let total_shares = 5;

        let shares = split_secret(secret, threshold, total_shares).unwrap();

        // Try different combinations of 3 shares
        let combinations = vec![vec![0, 1, 2], vec![0, 2, 4], vec![1, 3, 4], vec![2, 3, 4]];

        for combo in combinations {
            let selected_shares: Vec<Share> = combo.iter().map(|&i| shares[i].clone()).collect();

            let recovered = combine_shares(&selected_shares, threshold).unwrap();
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = b"Secret data";
        let threshold = 3;
        let total_shares = 5;

        let shares = split_secret(secret, threshold, total_shares).unwrap();

        // Try with too few shares
        let result = combine_shares(&shares[..2], threshold);
        assert!(matches!(result, Err(SssError::InsufficientShares { .. })));
    }

    #[test]
    fn test_invalid_parameters() {
        let secret = b"test";

        // Test threshold < 2
        assert!(split_secret(secret, 1, 5).is_err());

        // Test shares < threshold
        assert!(split_secret(secret, 5, 3).is_err());

        // Test shares = 0
        assert!(split_secret(secret, 3, 0).is_err());
    }

    #[test]
    fn test_constraint_validation() {
        let valid_secret = vec![0x42; 1024]; // 1KB secret

        // Test secret size constraints - empty secrets are now allowed
        let empty_secret = vec![];
        assert!(split_secret(&empty_secret, 3, 5).is_ok());

        let huge_secret = vec![0x42; MAX_SECRET_SIZE + 1];
        assert!(matches!(
            split_secret(&huge_secret, 3, 5),
            Err(SssError::SecretTooLarge { .. })
        ));

        // Test threshold constraints
        assert!(matches!(
            split_secret(&valid_secret, MIN_THRESHOLD - 1, 5),
            Err(SssError::ThresholdTooLow { .. })
        ));

        assert!(matches!(
            split_secret(&valid_secret, MAX_THRESHOLD + 1, 64),
            Err(SssError::ThresholdTooHigh { .. })
        ));

        // Test share count constraints
        assert!(matches!(
            split_secret(&valid_secret, 3, MIN_SHARES - 1),
            Err(SssError::ShareCountTooLow { .. })
        ));

        assert!(matches!(
            split_secret(&valid_secret, 3, MAX_SHARES + 1),
            Err(SssError::ShareCountTooHigh { .. })
        ));

        // Test memory constraints
        let max_secret = vec![0x42; MAX_SECRET_SIZE];
        assert!(split_secret(&max_secret, MAX_THRESHOLD, MAX_SHARES).is_ok());
    }

    #[test]
    fn test_boundary_conditions() {
        // Test minimum valid parameters
        let min_secret = vec![0x42; MIN_SECRET_SIZE];
        assert!(split_secret(&min_secret, MIN_THRESHOLD, MIN_SHARES).is_ok());

        // Test maximum valid parameters
        let max_secret = vec![0x42; MAX_SECRET_SIZE];
        assert!(split_secret(&max_secret, MAX_THRESHOLD, MAX_SHARES).is_ok());

        // Test combine_shares threshold validation
        let secret = b"test";
        let shares = split_secret(secret, 3, 5).unwrap();

        assert!(matches!(
            combine_shares(&shares, MIN_THRESHOLD - 1),
            Err(SssError::ThresholdTooLow { .. })
        ));

        assert!(matches!(
            combine_shares(&shares, MAX_THRESHOLD + 1),
            Err(SssError::ThresholdTooHigh { .. })
        ));
    }

    #[test]
    fn test_empty_secret() {
        let secret = b"";
        let threshold = 3;
        let total_shares = 5;

        let shares = split_secret(secret, threshold, total_shares).unwrap();

        // Empty secret should produce shares with empty data
        for share in &shares {
            assert_eq!(share.data.len(), 0);
        }

        let recovered = combine_shares(&shares[..threshold as usize], threshold).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_single_byte_secret() {
        let secret = b"X";
        let threshold = 2;
        let total_shares = 3;

        let shares = split_secret(secret, threshold, total_shares).unwrap();
        let recovered = combine_shares(&shares[..threshold as usize], threshold).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_large_secret_1kb() {
        let secret = vec![0x42; 1024]; // 1KB of 0x42
        let threshold = 3;
        let total_shares = 5;

        let shares = split_secret(&secret, threshold, total_shares).unwrap();

        // Each share should be approximately the same size as the secret
        for share in &shares {
            assert_eq!(share.data.len(), 1024);
        }

        let recovered = combine_shares(&shares[..threshold as usize], threshold).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_large_secret_1mb() {
        let secret = vec![0x55; 1024 * 1024]; // 1MB
        let threshold = 3;
        let total_shares = 5;

        let shares = split_secret(&secret, threshold, total_shares).unwrap();

        // Verify share size
        for share in &shares {
            assert_eq!(share.data.len(), 1024 * 1024);
        }

        // Test reconstruction with minimum shares
        let recovered = combine_shares(&shares[..threshold as usize], threshold).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_binary_data() {
        // Test with all possible byte values
        let mut secret = Vec::with_capacity(256);
        for i in 0..=255u8 {
            secret.push(i);
        }

        let threshold = 4;
        let total_shares = 7;

        let shares = split_secret(&secret, threshold, total_shares).unwrap();
        let recovered = combine_shares(&shares[..threshold as usize], threshold).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_duplicate_shares_rejected() {
        let secret = b"test";
        let threshold = 3;
        let total_shares = 5;

        let shares = split_secret(secret, threshold, total_shares).unwrap();

        // Create duplicate shares
        let duplicate_shares = vec![
            shares[0].clone(),
            shares[0].clone(), // Duplicate
            shares[2].clone(),
        ];

        let result = combine_shares(&duplicate_shares, threshold);
        assert!(matches!(result, Err(SssError::DuplicateShareIds)));
    }

    #[test]
    fn test_mismatched_share_lengths() {
        let share1 = Share {
            id: 1,
            data: vec![1, 2, 3],
        };
        let share2 = Share {
            id: 2,
            data: vec![4, 5],
        }; // Different length
        let share3 = Share {
            id: 3,
            data: vec![6, 7, 8],
        };

        let shares = vec![share1, share2, share3];
        let result = combine_shares(&shares, 3);
        assert!(matches!(result, Err(SssError::MismatchedShareLengths)));
    }

    #[test]
    fn test_gf256_arithmetic() {
        // Test addition (XOR)
        assert_eq!(gf256_add(0x53, 0xCA), 0x99);
        assert_eq!(gf256_add(0xFF, 0xFF), 0x00);

        // Test multiplication
        assert_eq!(gf256_mul(0x00, 0x42), 0x00);
        assert_eq!(gf256_mul(0x01, 0x42), 0x42);
        assert_eq!(gf256_mul(0x02, 0x02), 0x04);

        // Test division
        assert_eq!(gf256_div(0x00, 0x42).unwrap(), 0x00);
        assert_eq!(gf256_div(0x42, 0x01).unwrap(), 0x42);
        assert!(gf256_div(0x42, 0x00).is_err());
    }

    #[test]
    fn test_share_uniqueness() {
        let secret = b"test secret";
        let threshold = 3;
        let total_shares = 5;

        // Generate shares multiple times
        let shares1 = split_secret(secret, threshold, total_shares).unwrap();
        let shares2 = split_secret(secret, threshold, total_shares).unwrap();

        // Shares should be different due to random coefficients
        for i in 0..total_shares as usize {
            assert_ne!(shares1[i].data, shares2[i].data);
        }

        // But both should reconstruct to the same secret
        let recovered1 = combine_shares(&shares1[..threshold as usize], threshold).unwrap();
        let recovered2 = combine_shares(&shares2[..threshold as usize], threshold).unwrap();
        assert_eq!(recovered1, secret);
        assert_eq!(recovered2, secret);
    }

    #[test]
    fn test_maximum_shares() {
        let secret = b"max shares test";
        let threshold = 3;
        let total_shares = 32; // Maximum allowed in our constraints

        let shares = split_secret(secret, threshold, total_shares).unwrap();
        assert_eq!(shares.len(), 32);

        // Test reconstruction with various share combinations
        let recovered = combine_shares(&shares[..threshold as usize], threshold).unwrap();
        assert_eq!(recovered, secret);

        // Test with shares from the end
        let end_shares = &shares[29..32];
        let recovered2 = combine_shares(end_shares, threshold).unwrap();
        assert_eq!(recovered2, secret);
    }

    #[test]
    fn test_gf256_table_integrity() {
        // Verify that our GF(256) tables are mathematically consistent
        // This ensures the hardcoded tables haven't been corrupted

        // Test fundamental GF(256) properties
        // 1. Multiplicative identity: a * 1 = a for all non-zero a
        for a in 1..=255u8 {
            assert_eq!(
                gf256_mul(a, 1),
                a,
                "Multiplicative identity failed for {}",
                a
            );
        }

        // 2. Multiplicative inverse: a * a^(-1) = 1 for all non-zero a
        for a in 1..=255u8 {
            if let Ok(inv) = gf256_div(1, a) {
                assert_eq!(
                    gf256_mul(a, inv),
                    1,
                    "Multiplicative inverse failed for {}",
                    a
                );
            }
        }

        // 3. Zero multiplication: a * 0 = 0 for all a
        for a in 0..=255u8 {
            assert_eq!(gf256_mul(a, 0), 0, "Zero multiplication failed for {}", a);
            assert_eq!(gf256_mul(0, a), 0, "Zero multiplication failed for {}", a);
        }

        // 4. Generator property: powers of 3 should cycle through all non-zero elements
        let mut seen = vec![false; 256];
        let mut current = 1u8;
        for _ in 0..255 {
            assert!(
                !seen[current as usize],
                "Generator cycle repeated at {}",
                current
            );
            seen[current as usize] = true;
            current = gf256_mul(current, 3); // 3 is a generator for this field
        }
        assert_eq!(current, 1, "Generator should return to 1 after 255 steps");

        // Verify all non-zero elements were visited
        for (element, visited) in seen.iter().enumerate().skip(1) {
            assert!(visited, "Generator didn't visit element {}", element);
        }
    }

    #[test]
    fn test_performance_benchmark() {
        use std::time::Instant;

        // Benchmark different secret sizes
        let sizes = vec![100, 1_000, 10_000, 100_000, 1_000_000];
        let threshold = 3;
        let total_shares = 5;

        for size in sizes {
            let secret = vec![0x42; size];

            let start = Instant::now();
            let shares = split_secret(&secret, threshold, total_shares).unwrap();
            let split_time = start.elapsed();

            let start = Instant::now();
            let recovered = combine_shares(&shares[..threshold as usize], threshold).unwrap();
            let combine_time = start.elapsed();

            assert_eq!(recovered, secret);

            println!(
                "Size: {} bytes - Split: {:?}, Combine: {:?}",
                size, split_time, combine_time
            );
        }
    }
}

/// Property tests over the GF(256) field and the split/combine pair.
///
/// The unit tests above check the field laws at chosen points. These check them
/// for every point proptest can reach, which is the only universal check
/// available here: Shamir has exactly one implementation in this project, so
/// there is nothing to differential-test it against.
///
/// Case count is `PROPTEST_CASES` (default 256). `make fuzz` raises it to turn
/// this from a check into a soak.
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::sample::Index;

    /// A valid `(threshold, shares)` pair drawn from the declared bands.
    fn valid_parameters() -> impl Strategy<Value = (u8, u8)> {
        (MIN_THRESHOLD..=MAX_THRESHOLD)
            .prop_flat_map(|threshold| (Just(threshold), threshold..=MAX_SHARES))
    }

    /// Secrets stay small deliberately. These properties explore *shape* —
    /// thresholds, subsets, malformed input — and a large secret only repeats
    /// the same per-byte polynomial arithmetic more times. The `MAX_SECRET_SIZE`
    /// ceiling is a boundary case, asserted by the unit tests above.
    fn small_secret() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..=64)
    }

    /// Take `k` distinct shares, chosen by the generated indices so proptest can
    /// shrink the choice rather than a raw seed.
    fn pick_distinct(shares: &[Share], picks: &[Index], k: usize) -> Vec<Share> {
        let mut pool = shares.to_vec();
        let mut chosen = Vec::with_capacity(k);
        for pick in picks.iter().take(k) {
            chosen.push(pool.remove(pick.index(pool.len())));
        }
        chosen
    }

    proptest! {
        /// Multiplication commutes.
        #[test]
        fn gf256_mul_is_commutative(a: u8, b: u8) {
            prop_assert_eq!(gf256_mul(a, b), gf256_mul(b, a));
        }

        /// Multiplication associates.
        #[test]
        fn gf256_mul_is_associative(a: u8, b: u8, c: u8) {
            prop_assert_eq!(gf256_mul(gf256_mul(a, b), c), gf256_mul(a, gf256_mul(b, c)));
        }

        /// Multiplication distributes over addition, which in GF(256) is XOR.
        #[test]
        fn gf256_mul_distributes_over_addition(a: u8, b: u8, c: u8) {
            prop_assert_eq!(
                gf256_mul(a, gf256_add(b, c)),
                gf256_add(gf256_mul(a, b), gf256_mul(a, c))
            );
        }

        /// 1 is the multiplicative identity and 0 annihilates.
        #[test]
        fn gf256_mul_identity_and_zero(a: u8) {
            prop_assert_eq!(gf256_mul(a, 1), a);
            prop_assert_eq!(gf256_mul(a, 0), 0);
        }

        /// Every non-zero element has a multiplicative inverse.
        #[test]
        fn gf256_nonzero_elements_have_inverses(a in 1u8..=255) {
            let inverse = gf256_div(1, a).expect("division by a non-zero element succeeds");
            prop_assert_eq!(gf256_mul(a, inverse), 1);
        }

        /// Division undoes multiplication.
        #[test]
        fn gf256_div_inverts_mul(a: u8, b in 1u8..=255) {
            prop_assert_eq!(gf256_div(gf256_mul(a, b), b).unwrap(), a);
        }

        /// Division by zero is refused rather than indexing the tables.
        #[test]
        fn gf256_div_by_zero_is_an_error(a: u8) {
            prop_assert!(gf256_div(a, 0).is_err());
        }

        /// The log and exp tables invert each other on the multiplicative group.
        #[test]
        fn gf256_log_and_exp_are_inverse(x in 1u8..=255) {
            prop_assert_eq!(GF256_EXP[GF256_LOG[x as usize] as usize], x);
        }

        /// Subtraction is addition, and both are XOR.
        #[test]
        fn gf256_add_and_sub_agree(a: u8, b: u8) {
            prop_assert_eq!(gf256_add(a, b), gf256_sub(a, b));
            prop_assert_eq!(gf256_add(gf256_add(a, b), b), a);
        }

        /// Any threshold-sized subset of the shares reconstructs the secret
        /// exactly. This is the whole scheme in one assertion.
        #[test]
        fn split_then_combine_is_the_identity(
            secret in small_secret(),
            (threshold, shares) in valid_parameters(),
            picks in prop::collection::vec(any::<Index>(), MAX_THRESHOLD as usize),
        ) {
            let split = split_secret(&secret, threshold, shares)
                .expect("valid parameters split successfully");
            prop_assert_eq!(split.len(), shares as usize);

            let subset = pick_distinct(&split, &picks, threshold as usize);
            let recovered = combine_shares(&subset, threshold)
                .expect("a threshold-sized subset reconstructs");
            prop_assert_eq!(recovered, secret);
        }

        /// Every share is the same length as the secret, and share IDs are the
        /// contiguous range 1..=shares — ID 0 is never issued.
        #[test]
        fn split_produces_well_formed_shares(
            secret in small_secret(),
            (threshold, shares) in valid_parameters(),
        ) {
            let split = split_secret(&secret, threshold, shares).unwrap();
            for (position, share) in split.iter().enumerate() {
                prop_assert_eq!(share.data.len(), secret.len());
                prop_assert_eq!(share.id, position as u8 + 1);
            }
        }

        /// Fewer than `threshold` shares is refused outright. Whether the
        /// remaining shares leak anything about the secret is a proof
        /// obligation, not something a test can settle — what is asserted here
        /// is that the call fails cleanly rather than returning a plausible
        /// wrong answer.
        #[test]
        fn sub_threshold_subsets_are_refused(
            secret in prop::collection::vec(any::<u8>(), 1..=64),
            (threshold, shares) in valid_parameters(),
            picks in prop::collection::vec(any::<Index>(), MAX_THRESHOLD as usize),
        ) {
            let split = split_secret(&secret, threshold, shares).unwrap();
            let subset = pick_distinct(&split, &picks, threshold as usize - 1);

            match combine_shares(&subset, threshold) {
                Err(SssError::InsufficientShares { .. }) => {}
                Err(other) => prop_assert!(false, "unexpected error: {}", other),
                Ok(reconstructed) => prop_assert!(false,
                    "sub-threshold subset reconstructed {} bytes", reconstructed.len()),
            }
        }

        /// A duplicated share ID is caught rather than silently interpolating
        /// through the same point twice.
        #[test]
        fn duplicate_share_ids_are_refused(
            secret in prop::collection::vec(any::<u8>(), 1..=64),
            (threshold, shares) in valid_parameters(),
        ) {
            let split = split_secret(&secret, threshold, shares).unwrap();
            let mut subset: Vec<Share> = split[..threshold as usize].to_vec();
            subset[threshold as usize - 1] = subset[0].clone();

            prop_assert!(matches!(
                combine_shares(&subset, threshold),
                Err(SssError::DuplicateShareIds)
            ));
        }

        /// A share whose length disagrees with its peers is caught.
        #[test]
        fn mismatched_share_lengths_are_refused(
            secret in prop::collection::vec(any::<u8>(), 2..=64),
            (threshold, shares) in valid_parameters(),
        ) {
            let split = split_secret(&secret, threshold, shares).unwrap();
            let mut subset: Vec<Share> = split[..threshold as usize].to_vec();
            subset[0].data.truncate(secret.len() - 1);

            prop_assert!(matches!(
                combine_shares(&subset, threshold),
                Err(SssError::MismatchedShareLengths)
            ));
        }

        /// Arbitrary shares — arbitrary IDs, arbitrary and unequal data lengths,
        /// arbitrary threshold including values outside the declared band —
        /// against `combine_shares`, which the SDK reaches through the
        /// `reconstruct_secret` WASM facade. The result is uninteresting; that
        /// the call returns at all is the assertion.
        #[test]
        fn combine_shares_never_panics_on_arbitrary_input(
            raw in prop::collection::vec(
                (any::<u8>(), prop::collection::vec(any::<u8>(), 0..=48)),
                0..=24,
            ),
            threshold: u8,
        ) {
            let shares: Vec<Share> = raw
                .into_iter()
                .map(|(id, data)| Share { id, data })
                .collect();
            let _ = combine_shares(&shares, threshold);
        }

        /// Split rejects out-of-band parameters rather than panicking, for any
        /// combination of the two.
        #[test]
        fn split_secret_never_panics_on_arbitrary_parameters(
            secret in prop::collection::vec(any::<u8>(), 0..=32),
            threshold: u8,
            shares: u8,
        ) {
            let result = split_secret(&secret, threshold, shares);
            let in_band = (MIN_THRESHOLD..=MAX_THRESHOLD).contains(&threshold)
                && (MIN_SHARES..=MAX_SHARES).contains(&shares)
                && shares >= threshold;
            prop_assert_eq!(result.is_ok(), in_band);
        }
    }
}
