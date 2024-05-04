use serde::{Deserialize, Serialize};
use crate::node::setup_msg::{NodeToRegulatorSetupPhaseP2PMsg, NodeSetupPhaseFinishFlag};
use crate::node::keygen_msg::{NodeKeyGenPhaseOneBroadcastMsg, NodeToNodeKeyGenPhaseTwoP2PMsg,NodeToRegulatorKeyGenPhaseFiveP2PMsg};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GSTBKMsg {
    SetupMsg(SetupMsg),
    KeyGenMsg(KeyGenMsg),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SetupMsg 
{
    NodeToRegulatorSetupPhaseP2PMsg(NodeToRegulatorSetupPhaseP2PMsg),
    NodeSetupPhaseFinishFlag(NodeSetupPhaseFinishFlag)     
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyGenMsg {
    NodeKeyGenPhaseOneBroadcastMsg(NodeKeyGenPhaseOneBroadcastMsg),
    NodeToNodeKeyGenPhaseTwoP2PMsg(NodeToNodeKeyGenPhaseTwoP2PMsg),
    NodeToRegulatorKeyGenPhaseFiveP2PMsg(NodeToRegulatorKeyGenPhaseFiveP2PMsg)
}
