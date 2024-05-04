use serde::{Deserialize, Serialize};

use crate::regulator::setup_msg::{RegulatorSetupPhaseBroadcastMsg,RegulatorSetupPhaseFinishFlag};
use crate::regulator::keygen_msg::{RegulatorKeyGenPhaseOneBroadcastMsg,RegulatorKeyGenPhaseStartFlag};


#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GSTBKMsg {
    SetupMsg(SetupMsg),
    KeyGenMsg(KeyGenMsg),
    // KeyManageMsg(KeyManageMsg)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SetupMsg 
{
    RegulatorSetupPhaseBroadcastMsg(RegulatorSetupPhaseBroadcastMsg), 
    RegulatorSetupPhaseFinishFlag(RegulatorSetupPhaseFinishFlag)     
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyGenMSKFlag {
    GammaA(KeyGenMsg),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyGenMsg {
    RegulatorKeyGenPhaseStartFlag(RegulatorKeyGenPhaseStartFlag),
    RegulatorKeyGenPhaseOneBroadcastMsg(RegulatorKeyGenPhaseOneBroadcastMsg),
}