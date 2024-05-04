use serde::{Deserialize, Serialize};

use message::{params::ThreasholdParam, regulator::setup_msg::NodeInfo};
use message::params::Gpk;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reg
{
    pub id: u16, 
    pub role:String,
    pub address: String, 
    pub threashold_param: ThreasholdParam,
    pub gpk:Option<Gpk>,
    pub node_info_vec: Option<Vec<NodeInfo>>,
    pub participants: Option<Vec<u16>>
}



  