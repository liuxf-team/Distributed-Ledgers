use std::collections::HashMap;


use curv::{elliptic::curves::{Secp256k1, Point, Scalar}};
use serde::{Deserialize, Serialize};


use message::params::{ThreasholdParam,Generators};
use message::regulator::setup_msg::NodeInfo;

  
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node
{
    pub id: Option<u16>,
    pub role:String,
    pub address: String, 
    pub listen_addr:String,
    pub regulator_address: String, 
    pub threashold_param: ThreasholdParam,
    pub dkgparam: DKGParam, 
    pub generators:Option<Generators>,
    pub node_info_vec: Option<Vec<NodeInfo>>,
    pub participants: Option<Vec<u16>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig
{
    pub id: Option<u16>,
    pub role:String,
    pub address: String, 
    pub regulator_address: String,
    pub threashold_param: ThreasholdParam,
    pub dkgparam: DKGParam, 
    pub generators:Option<Generators>,
    pub node_info_vec: Option<Vec<NodeInfo>>,
    pub participants: Option<Vec<u16>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DKGParam
{
    pub mi:Option<Scalar<Secp256k1>>,// mi
    pub Mi:Option<Point<Secp256k1>>,// g^mi
    pub ri:Option<Scalar<Secp256k1>>,// ri,random number
    pub Ri:Option<Point<Secp256k1>>,// g^ri
    pub M:Option<Point<Secp256k1>>,// g^m
    pub R:Option<Point<Secp256k1>>,// g^r
    pub share: Option<Scalar<Secp256k1>>,// xi
    pub random_share: Option<Scalar<Secp256k1>>,// random share
}