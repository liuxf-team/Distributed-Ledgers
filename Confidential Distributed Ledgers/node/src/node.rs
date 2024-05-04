use std::collections::HashMap;


use curv::{elliptic::curves::{Point, Scalar, Secp256k1}, BigInt};
use elgamal::elgamal::elgamal::ElgamalCipher;
use serde::{Deserialize, Serialize};


use message::params::{ThreasholdParam,Gpk};
use message::regulator::setup_msg::NodeInfo;

 
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node
{
    pub id: Option<u16>,
    pub role:String,
    pub address: String, 
    pub listen_addr:String,
    pub reg_address: String,
    pub threashold_param: ThreasholdParam,
    pub regulator_pk: Option<Point<Secp256k1>>,
    pub pk: Option<Point<Secp256k1>>,
    pub sk: Option<Scalar<Secp256k1>>,
    pub pk_share_vec: Option<Vec<Point<Secp256k1>>>,
    pub batch_total_money: Option<Vec<ElgamalCipher>>,
    pub dkgparam: DKGParam, 
    pub gpk:Option<Gpk>,
    pub node_info_vec: Option<Vec<NodeInfo>>,
    pub participants: Option<Vec<u16>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig
{
    pub id: Option<u16>,
    pub role:String,
    pub address: String, 
    pub reg_address: String,
    pub threashold_param: ThreasholdParam,
    pub dkgparam: DKGParam, 
    pub gpk:Option<Gpk>,
    pub node_info_vec: Option<Vec<NodeInfo>>,
    pub participants: Option<Vec<u16>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DKGParam
{
    pub ui:Option<BigInt>,// a
    pub yi:Option<String>, // gp^a
    pub yi_map:Option<HashMap<u16, String>>,
    pub y:Option<String>, // pk
    pub mskshare: Option<Scalar<Secp256k1>>,// x_i
    pub addshare:Option<Scalar<Secp256k1>>,// x_i * li
}