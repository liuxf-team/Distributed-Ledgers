use curv::elliptic::curves::{Point,Secp256k1};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo{
    pub id: u16,// assigned id
    pub address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegSetupPhaseBroadcastMsg{
    pub node_info_vec: Vec<NodeInfo>,
    pub regulator_pk: Point<Secp256k1>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegSetupPhaseFinishFlag
{
    pub sender:u16,
    pub role: String
}