use serde::{Deserialize, Serialize};

use crate::regulator::setup_msg::{RegSetupPhaseBroadcastMsg,RegSetupPhaseFinishFlag};
use crate::regulator::keygen_msg::{RegKeyGenPhaseOneBroadcastMsg,RegKeyGenPhaseStartFlag};
use super::dec_msg::{RegDecPhaseOneBroadcastMsg, RegDecPhaseStartFlag};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GSTBKMsg {
    SetupMsg(SetupMsg),
    KeyGenMsg(KeyGenMsg),
    DecMsg(DecMsg)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SetupMsg 
{
    RegSetupPhaseBroadcastMsg(RegSetupPhaseBroadcastMsg), 
    RegSetupPhaseFinishFlag(RegSetupPhaseFinishFlag)     
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyGenMsg {
    RegKeyGenPhaseStartFlag(RegKeyGenPhaseStartFlag),
    RegKeyGenPhaseOneBroadcastMsg(RegKeyGenPhaseOneBroadcastMsg)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DecMsg {
    RegDecPhaseOneBroadcastMsg(RegDecPhaseOneBroadcastMsg),
    RegDecPhaseStartFlag(RegDecPhaseStartFlag)
}