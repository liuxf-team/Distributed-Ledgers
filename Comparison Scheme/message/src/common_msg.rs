use serde::{Deserialize, Serialize};
use crate::regulator::common_msg::GSTBKMsg as GSTBKMsgP;
use crate::node::common_msg::GSTBKMsg as GSTBKMsgN;

#[derive(Clone, Debug, Serialize, Deserialize)]

pub enum GSTBKMsg {
    GSTBKMsgN(GSTBKMsgN),
    GSTBKMsgP(GSTBKMsgP)
}