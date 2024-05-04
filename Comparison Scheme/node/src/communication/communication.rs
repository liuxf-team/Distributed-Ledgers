use message::regulator::setup_msg::NodeInfo;
use tokio::net::{TcpStream};
use tokio::io::AsyncWriteExt;
use tokio_util::codec::{Framed, LinesCodec};
use tokio_stream::StreamExt;
use std::net::SocketAddr;
use log::{error, info, warn};
use crate::node::{Node, NodeConfig};
use message::common_msg::GSTBKMsg;

///接收并序列化消息
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
    let msg = match result 
    {
        Ok(v) => v,
        Err(e) => 
        {
            error!("Error deserializing JSON: {:?}", e);
            return Err(Box::new(e));
        }
    };
    return  Ok(msg);
}

/// 序列化setup阶段的消息
pub fn setup_to_gstbk(msg_setup : message::node::common_msg::SetupMsg) -> String 
{
    let msg_str = serde_json::to_string(&message::common_msg::GSTBKMsg::GSTBKMsgN(message::node::common_msg::GSTBKMsg::SetupMsg(msg_setup))).unwrap();
    return msg_str;
}

///Keygen阶段序列化消息
pub fn keygen_to_gstbk(msg_keygen : message::node::common_msg::KeyGenMsg)->String
{
    let msg_str = serde_json::to_string(&message::common_msg::GSTBKMsg::GSTBKMsgN(message::node::common_msg::GSTBKMsg::KeyGenMsg(msg_keygen))).unwrap();
    return msg_str;
}

// ///KeyManage阶段序列化消息
// pub fn key_manage_to_gstbk (msg_key_manage : gs_tbk_scheme::messages::node::common_msg::KeyManageMsg) -> String
// {
//     let msg_str = serde_json::to_string(&gs_tbk_scheme::messages::common_msg::GSTBKMsg::GSTBKMsgN(gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::KeyManageMsg(msg_key_manage))).unwrap();
//     return msg_str;
// }

///创建转为16进制的node
pub fn get_node_config (node : Node) -> NodeConfig 
{
    NodeConfig 
    { 
        id: node.id, 
        role: node.role, 
        address: node.address, 
        regulator_address: node.regulator_address, 
        threashold_param: node.threashold_param, 
        dkgparam: node.dkgparam, 
        generators: node.generators, 
        node_info_vec: node.node_info_vec, 
        participants: node.participants, 
    }
}

///p2p信道
pub async fn p2p(msg : String,str_add : String) -> Result<(), anyhow::Error> 
{
    let add : SocketAddr = str_add.parse()?;
    // info!("addr {}",add);
    let mut tcp_stream = TcpStream::connect(add).await?;
    // info!("connect sucessfilly");
    tcp_stream.write_all(msg.as_bytes()).await?; 
    tcp_stream.shutdown().await?;
    Ok(())
}



///node之间的p2p信到
pub async fn to_node(msg : String,id : u16,node_list : Vec<NodeInfo>) -> Result<(), anyhow::Error> 
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

///广播信道
pub async fn broadcast(msg : String,node_list : Vec<NodeInfo>,node_id : u16) -> Result<(), anyhow::Error> 
{
    for node in node_list 
    {
            if node_id == node.id  
            {
                continue;
            }
            else 
            {
                let add : SocketAddr = node.address.parse()?;
                let mut tcp_stream = TcpStream::connect(add).await?;
                tcp_stream.write_all(msg.as_bytes()).await?; 
                tcp_stream.shutdown().await?;
            }    
    }
    Ok(())
}
