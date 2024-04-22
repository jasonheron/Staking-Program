use anchor_lang::prelude::*;

#[error_code]
pub enum ErrorCode {
    // validations
    #[msg("Invalid stake pool")]
    InvalidStakePool = 0,
    #[msg("Invalid Admin")]
    InvalidAdmin,

    #[msg("Mismatched user and escrow")]
    InvalidEscrow,

    #[msg("Minimum stake seconds not satisfied")]
    MinStakeSecondsNotSatisfied,

    #[msg("Invalid mint metadata")]
    InvalidMintMetadata = 20,
    #[msg("Mint not allowed in this pool")]
    MintNotAllowedInPool,
    #[msg("Mint metadata is owned by the incorrect program")]
    InvalidMintMetadataOwner,
}
