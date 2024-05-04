use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio_util::codec::{Framed, LinesCodec};
use tokio_stream::StreamExt;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use std::net::SocketAddr;
use log::{error, warn};

use message::common_msg::GSTBKMsg;
use message::regulator::setup_msg::NodeInfo;
use message::node::setup_msg::{NodeToRegSetupPhaseP2PMsg,NodeSetupPhaseFinishFlag};


/// 接受并序列化消息
pub async fn get_message(mut framed:Framed<TcpStream,LinesCodec>) -> Result<GSTBKMsg, Box<dyn std::error::Error>>
{
    let message = match framed.next().await 
    {
        Some(Ok(m)) => m,
        //坏了传不进来
        Some(Err(e)) => 
        {
            error!("Failed to get from framed: {:?}",e);
            return Err(Box::new(e));
        }
        None => 
        {
            error!("Failed to get a message.");
            return Err("Failed to get a message.".into());
        }
    };
    let result: Result<GSTBKMsg,_> =  serde_json::from_str(&message);
    let node_message = match result 
    {
        Ok(v) => v,
        Err(e) => 
        {
            error!("Error deserializing JSON: {:?}", e);
            return Err(Box::new(e));
        }
    };
    return  Ok(node_message);
}

/// 拆分处理各种类型的消息
pub async fn handle_setup_msg(msg : NodeToRegSetupPhaseP2PMsg, msg_vec : &Arc<TokioMutex<Vec<NodeToRegSetupPhaseP2PMsg>>>, msg_num : &Arc<TokioMutex<i32>>) 
{
    let mut locked_msg_vec = msg_vec.lock().await; 
    let mut locked_num = msg_num.lock().await;
    locked_msg_vec.push(msg.clone());
    *locked_num += 1;
}

/// 处理setup阶段node的finish消息
pub async fn handle_setup_tag(msg : NodeSetupPhaseFinishFlag, node_setup_finish_vec : &Arc<TokioMutex<Vec<NodeSetupPhaseFinishFlag>>>, finish_num : &Arc<TokioMutex<i32>>) 
{
    let mut locked_vec = node_setup_finish_vec.lock().await;
    let mut locked_num = finish_num.lock().await;
    locked_vec.push(msg);
    *locked_num += 1;
}

/// 序列化setup阶段的消息
pub fn setup_to_gstbk(msg_setup : message::regulator::common_msg::SetupMsg) -> String 
{
    let msg_str = serde_json::to_string(&::message::common_msg::GSTBKMsg::GSTBKMsgP(message::regulator::common_msg::GSTBKMsg::SetupMsg(msg_setup))).unwrap();
    return msg_str;
}

/// 序列化keygen阶段的消息
pub fn keygen_to_gstbk(msg_keygen : message::regulator::common_msg::KeyGenMsg) -> String 
{
    let msg_str = serde_json::to_string(&message::common_msg::GSTBKMsg::GSTBKMsgP(message::regulator::common_msg::GSTBKMsg::KeyGenMsg(msg_keygen))).unwrap();
    return msg_str;
}

///dec阶段序列化消息
pub fn dec_to_gstbk(msg_dec : message::regulator::common_msg::DecMsg)->String
{
    let msg_str = serde_json::to_string(&message::common_msg::GSTBKMsg::GSTBKMsgP(message::regulator::common_msg::GSTBKMsg::DecMsg(msg_dec))).unwrap();
    return msg_str;
}

/// 序列化key manage阶段的消息
// pub fn key_manage_to_gstbk (msg_key_manage : gs_tbk_scheme::messages::reg::common_msg::KeyManageMsg) -> String
// {
//     let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgP(gs_tbk_scheme::messages::reg::common_msg::GSTBKMsg::KeyManageMsg(msg_key_manage))).unwrap();
//     return msg_str;
// }

/// 广播信道
pub async fn broadcast(msg : String, node_list : Vec<NodeInfo>) -> Result<(), anyhow::Error> 
{
    for node in node_list 
    {
        let addr : SocketAddr = node.address.parse()?;
        let mut node_stream = TcpStream::connect(addr).await?;
        node_stream.write_all(msg.as_bytes()).await?; 
        node_stream.shutdown().await?;
    }
    Ok(())
}

/// node p2p信道
pub async fn p2p(msg : String, id : u16, node_list : Vec<NodeInfo>) -> Result<(), anyhow::Error> 
{
    if let Some(node) = node_list.iter().find(|&node_info| node_info.id == id) 
    {
        let add : SocketAddr = node.address.parse()?;
        let mut node_stream = TcpStream::connect(add).await?;
        node_stream.write_all(msg.as_bytes()).await?;
        node_stream.shutdown().await?;
    }
    else 
    {
        warn!("Nodelist with id {} not found.", id);
    }
    Ok(())
}

// /// user p2p 信道
// pub async fn to_user (msg : String, addr : String) -> Result<(), anyhow::Error> 
// {
//     let add : SocketAddr = addr.parse()?;
//     let mut node_stream = TcpStream::connect(addr).await?;
//     node_stream.write_all(msg.as_bytes()).await?;
//     node_stream.shutdown().await?;
//     Ok(())
// }