use thiserror::Error;

/// Represents errors.
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum ElGamalError {
    #[error("Verify EncRightProof failed")]
    VerifyEncRightProofFailed,
    #[error("Verify EncEqualProof failed")]
    VerifyEncEqualProofFailed,
    #[error("Verify BatchEncEqualProof failed")]
    VerifyBatchEncEqualProofFailed,
    #[error("Verify BatchDecEqualProof failed")]
    VerifyBatchDecEqualProofFailed,
}