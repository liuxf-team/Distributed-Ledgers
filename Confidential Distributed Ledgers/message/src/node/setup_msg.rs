use serde::{Deserialize, Serialize};

// use crate::params::PKHex;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToRegSetupPhaseP2PMsg{
    pub role:String,
    pub address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeSetupPhaseFinishFlag{
    pub sender:u16,
    pub role:String,
}
 