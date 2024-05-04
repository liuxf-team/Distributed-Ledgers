use curv::{cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS, elliptic::curves::Secp256k1, BigInt};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeKeyGenPhaseOneBroadcastMsg
{
    pub sender:u16,
    pub role:String
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToNodeFeldmanVssParamMsg
{
    pub sender: u16,
    pub receiver: u16,
    pub vss: FeldmanVss
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeldmanVss {
    pub share: BigInt,
    pub commits: VerifiableSS<Secp256k1>
}
