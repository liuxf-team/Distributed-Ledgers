use serde::{Deserialize, Serialize};
use crate::node::setup_msg::{NodeToRegSetupPhaseP2PMsg, NodeSetupPhaseFinishFlag};


use super::dec_msg::{NodeDecPhaseOneBroadcastMsg, NodeDecPhaseTwoBroadcastMsg};
use super::keygen_msg::NodeToNodeFeldmanVssParamMsg;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GSTBKMsg {
    SetupMsg(SetupMsg),
    KeyGenMsg(KeyGenMsg),
    DecMsg(DecMsg)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SetupMsg 
{
    NodeToRegSetupPhaseP2PMsg(NodeToRegSetupPhaseP2PMsg),
    NodeSetupPhaseFinishFlag(NodeSetupPhaseFinishFlag)     
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyGenMsg {
    NodeToNodeFeldmanVssParamMsg(NodeToNodeFeldmanVssParamMsg),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DecMsg {
    NodeDecPhaseOneBroadcastMsg(NodeDecPhaseOneBroadcastMsg),
    NodeDecPhaseTwoBroadcastMsg(NodeDecPhaseTwoBroadcastMsg)
}