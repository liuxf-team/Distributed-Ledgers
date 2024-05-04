use std::collections::HashMap;
use curv::elliptic::curves::{Curve, Point, Scalar, Secp256k1};
use curv::cryptographic_primitives::hashing::Digest;
use serde::{Deserialize, Serialize};
use curv::BigInt;
use curv::cryptographic_primitives::secret_sharing::pedersen_vss::VerifiableSS;
use sha2::Sha256;
use bulletproof::proofs::range_proof::RangeProof;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindFactors{
    pub blind_factor_m:BigInt,
    pub blind_factor_r:BigInt
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HashCommitments{
    pub com_m:BigInt,
    pub com_r:BigInt
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProofPedersenCom{
    pub range_proof:RangeProof,
    pub pedersen_commitment:Point<Secp256k1>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeKeyGenPhaseOneBroadcastMsg
{
    pub sender:u16,
    pub role:String,
    pub blind_factors:BlindFactors,
    pub Mi:Point<Secp256k1>,
    pub Ri:Point<Secp256k1>,
    pub coms:HashCommitments,
    pub range_proof_pedersen_com:RangeProofPedersenCom
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareCom
{
    pub share:Scalar<Secp256k1>,
    pub commit:Point<Secp256k1>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToNodeKeyGenPhaseTwoP2PMsg
{
    pub sender:u16,
    pub receiver:u16,
    pub role:String,
    pub share:BigInt,
    pub random_share:BigInt,
    pub vss_scheme:VerifiableSS<Secp256k1>,
} 


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToRegulatorKeyGenPhaseFiveP2PMsg{
    pub sender:u16,
    pub role:String,
    pub xi:Scalar<Secp256k1>,
    pub mi:Scalar<Secp256k1>
}

