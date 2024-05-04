use serde::{Deserialize, Serialize};

use message::{params::ThreasholdParam, regulator::setup_msg::NodeInfo};
use message::params::{Generators};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Regulator
{
    pub id: u16, 
    pub role:String,
    pub address: String, 
    pub threashold_param: ThreasholdParam,
    pub generators:Option<Generators>,
    pub node_info_vec: Option<Vec<NodeInfo>>,
    pub participants: Option<Vec<u16>>
}



  