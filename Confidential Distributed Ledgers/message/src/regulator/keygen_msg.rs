
use curv::elliptic::curves::{Secp256k1, Point};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegKeyGenPhaseStartFlag
{
    pub sender:u16,
    pub role:String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegKeyGenPhaseOneBroadcastMsg{
    pub g:Point<Secp256k1>,
    pub participants:Vec<u16>,
}