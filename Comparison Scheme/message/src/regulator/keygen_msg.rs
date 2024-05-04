use bincode::config::BigEndian;
use curv::cryptographic_primitives::secret_sharing::pedersen_vss::VerifiableSS;
use curv::elliptic::curves::Scalar;
use curv::BigInt;
use curv::{elliptic::curves::{Secp256k1, Point}};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use bulletproof::proofs::range_proof::RangeProof;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegulatorKeyGenPhaseStartFlag
{
    pub sender:u16,
    pub role:String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegulatorKeyGenPhaseOneBroadcastMsg{
    pub g:Point<Secp256k1>,
    pub h:Point<Secp256k1>,
}


