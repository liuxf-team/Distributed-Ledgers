use bulletproof::proofs::range_proof::RangeProof;
use curv::elliptic::curves::{Point, Secp256k1};
use serde::{Deserialize, Serialize};
use elgamal::elgamal::elgamal::{BatchDecRightProof, BatchEncRightProof, ElgamalCipher, EncEqualProof};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeDecPhaseOneBroadcastMsg
{
    pub sender:u16,
    pub role:String,
    pub mul_cipher_vec:Vec<ElgamalCipher>,
    pub cipher_vec_reg:Vec<ElgamalCipher>,
    pub batch_enc_proof:BatchEncRightProof,
    pub range_proof:RangeProof,
    pub equal_proof_vec:Vec<EncEqualProof>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeDecPhaseTwoBroadcastMsg
{
    pub sender:u16,
    pub role:String,
    pub batch_dec_c1:Vec<Point<Secp256k1>>,
    pub dec_proof:BatchDecRightProof
}