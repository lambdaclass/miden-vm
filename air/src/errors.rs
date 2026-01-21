use alloc::string::String;

// HASH FUNCTION ERROR
// ================================================================================================

/// Error type for invalid hash function strings.
#[derive(Debug, thiserror::Error)]
pub enum HashFunctionError {
    #[error(
        "invalid hash function '{hash_function}'. Valid options are: blake3-256, rpo, rpx, poseidon2, keccak"
    )]
    InvalidHashFunction { hash_function: String },
}
