use message::node::dec_msg::{NodeDecPhaseOneBroadcastMsg, NodeDecPhaseTwoBroadcastMsg};
use message::node::setup_msg::NodeSetupPhaseFinishFlag;
use tokio::net::TcpListener;
use tokio::sync::Mutex as TokioMutex;
use tokio_util::codec::{Framed, LinesCodec};
use std::net::SocketAddr;
use std::sync::Arc;
use std::env;
use log::{error, info};
use node::communication::communication::*;
use node::node::Node;
use node::config::config::Config;
use message::common_msg::GSTBKMsg;
use message::node::keygen_msg::NodeToNodeFeldmanVssParamMsg;
use message::node::common_msg::{SetupMsg, KeyGenMsg, DecMsg};


#[tokio::main]
pub async fn decrypt() -> Result<(), anyhow::Error> 
{
    let log_path = String::from(env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/node/node1/config/config_file/log4rs.yaml";
    log4rs::init_file(log_path, Default::default()).unwrap();
    
    //init node
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/node/node1/config/config_file/node_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();

    let node = Node::init(gs_tbk_config);
    let shared_node = Arc::new(TokioMutex::new(node.clone()));

    let shared_dec_phase_one_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeDecPhaseOneBroadcastMsg>::new()));
    let shared_dec_phase_two_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeDecPhaseTwoBroadcastMsg>::new()));

    let node_addr:SocketAddr = node.listen_addr.parse()?;
    let listener = TcpListener::bind(node_addr).await?;
    info!("node1 is listening on {}",node.address);

    let node_setup_msg_str = serde_json::to_string(&message::common_msg::GSTBKMsg::GSTBKMsgN(message::node::common_msg::GSTBKMsg::SetupMsg(SetupMsg::NodeToRegSetupPhaseP2PMsg(node.setup_phase_one())))).unwrap();
    match p2p(node_setup_msg_str, node.reg_address).await
    {
        Ok(_) => {}
        Err(e) => 
        {
            error!("node setup msg can not sent Err:{}",e);
        }
    };

    while let Result::Ok(( tcp_stream,_)) = listener.accept().await
    {
        let node_clone = shared_node.clone();

        let dec_phase_one_msg_vec_clone = shared_dec_phase_one_msg_vec.clone();
        let dec_phase_two_msg_vec_clone = shared_dec_phase_two_msg_vec.clone();

        tokio::spawn(async move
        {
            let node = node_clone.clone();

            let dec_phase_one_msg_vec = dec_phase_one_msg_vec_clone.clone();
            let dec_phase_two_msg_vec = dec_phase_two_msg_vec_clone.clone();

            let framed = Framed::new( tcp_stream,LinesCodec::new());
            let message = match get_message(framed).await
            {
                Ok(v) => v,
                Err(e) => 
                {
                    error!("Failed to get nodemessage: {:?}",e);
                    return ;
                }
            }; 
            match message 
            {
                GSTBKMsg::GSTBKMsgP(gstbk_reg_msg) => 
                {
                    match gstbk_reg_msg
                    {
                        message::regulator::common_msg::GSTBKMsg::SetupMsg(setup_msg) => 
                        {
                            match setup_msg 
                            {
                                message::regulator::common_msg::SetupMsg::RegSetupPhaseBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Reg  Get RegSetupPhaseBroadcastMsg");
                                    let mut locked_node = node.lock().await;
                                    let setup_phase_two_msg_str = setup_to_gstbk(SetupMsg::NodeSetupPhaseFinishFlag(locked_node.setup_phase_two(msg)));
                                    match p2p(setup_phase_two_msg_str, (*locked_node.reg_address).to_string()).await 
                                    {
                                        Ok(_) => {}
                                        Err(e) => 
                                        {
                                            error!("Error: {}, NodeToRegSetupFinishMsg can not sent ",e);
                                            return ;
                                        }
                                    };
                                }
                                message::regulator::common_msg::SetupMsg::RegSetupPhaseFinishFlag(_msg) => 
                                {
                                    info!("From id : 0 ,Role : Reg  Get RegSetupPhaseFinishFlag");
                                    let locked_node = node.lock().await;
                                    locked_node.setup_phase_three();
                                }
                            }
        
                        }
                        message::regulator::common_msg::GSTBKMsg::DecMsg(dec_msg) => 
                        {
                            match dec_msg
                            {
                                message::regulator::common_msg::DecMsg::RegDecPhaseOneBroadcastMsg(_msg) => 
                                {
                                    info!("From id : 0 ,Role : Reg  Get RegToNodeKeyGenPhaseThreeP2PMsg");
        
                                    let mut locked_node = node.lock().await;
                                    
                                    info!("Decrypt phase is staring!");

                                    let mut locked_vec = dec_phase_one_msg_vec.lock().await;
    
                                    let dec_phase_one_msg = locked_node.dec_phase_one();
                                    locked_vec.push(dec_phase_one_msg.clone());

                                    let dec_phase_one_msg_str = dec_to_gstbk(DecMsg::NodeDecPhaseOneBroadcastMsg(dec_phase_one_msg));

                                    let mut msg_vec:Vec<String> = Vec::new();
                                    msg_vec.push(dec_phase_one_msg_str);
                                    let node_list = locked_node.node_info_vec.clone().unwrap();

                                    let node_id = locked_node.id.clone().unwrap();

                                    //broadcast msg
                                    for msg in msg_vec
                                    {
                                        match broadcast(msg, node_list.clone(),node_id.clone()).await
                                        {
                                            Ok(_) => {}
                                            Err(e) => 
                                            {
                                                error!("Error: {}, NodeKeyGenPhaseOneBroadcastMsg can not sent ",e);
                                                return ;
                                            }
                                        };
                                    }

                                }
                                _ => {} 
                            }
                        } _ => {} 
                    }
                }
                GSTBKMsg::GSTBKMsgN(gstbk_node_msg) => 
                {
                    match gstbk_node_msg
                    {
                        message::node::common_msg::GSTBKMsg::DecMsg(dec_msg) => 
                        {
                            match dec_msg
                            {
                                message::node::common_msg::DecMsg::NodeDecPhaseOneBroadcastMsg(msg) => 
                                {
                                    info!("From id : {} ,Role : {} Get NodeKeyGenPhaseFiveBroadcastMsg ",msg.sender,msg.role);
                                    let mut locked_node = node.lock().await;
                                    let mut locked_vec = dec_phase_one_msg_vec.lock().await;
                                    let mut send_vec = dec_phase_two_msg_vec.lock().await;
                                    locked_vec.push(msg);
                                    if locked_vec.len() == locked_node.threashold_param.share_counts as usize  
                                    {
                                        let vec = (*locked_vec).clone();
                                        let dec_phase_two_msg = locked_node.dec_phase_two(&vec);
                                        send_vec.push(dec_phase_two_msg.clone());
                                        let dec_phase_two_msg_str = dec_to_gstbk(DecMsg::NodeDecPhaseTwoBroadcastMsg(dec_phase_two_msg));

                                        let mut msg_vec:Vec<String> = Vec::new();
                                        msg_vec.push(dec_phase_two_msg_str);
                                        let node_list = locked_node.node_info_vec.clone().unwrap();

                                        let node_id = locked_node.id.clone().unwrap();
                                        for msg in msg_vec
                                        {
                                            match broadcast(msg, node_list.clone(),node_id.clone()).await
                                            {
                                                Ok(_) => {}
                                                Err(e) => 
                                                {
                                                    error!("Error: {}, NodeKeyGenPhaseTwoBroadcastMsg can not sent ",e);
                                                    return ;
                                                }
                                            };
                                        }

                                    }
                                }
                                message::node::common_msg::DecMsg::NodeDecPhaseTwoBroadcastMsg(msg) => 
                                {
                                    info!("From id : {} ,Role : {} Get NodeKeyGenPhaseFiveBroadcastMsg ",msg.sender,msg.role);
                                    let mut locked_node = node.lock().await;
                                    let mut locked_vec = dec_phase_two_msg_vec.lock().await;
                                    locked_vec.push(msg);
                                    if locked_vec.len() == locked_node.threashold_param.share_counts as usize  
                                    {
                                        let vec = (*locked_vec).clone();
                                        locked_node.dec_phase_three(&vec);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        });
    }
    Ok(())
}

#[tokio::main]
pub async fn main() -> Result<(), anyhow::Error> 
{
    let log_path = String::from(env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/node/node1/config/config_file/log4rs.yaml";
    log4rs::init_file(log_path, Default::default()).unwrap();
    
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/node/node1/config/config_file/node_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();

    let node = Node::init(gs_tbk_config);
    let shared_node = Arc::new(TokioMutex::new(node.clone()));

    let shared_setup_finish = Arc::new(TokioMutex::new(Vec::<NodeSetupPhaseFinishFlag>::new()));
    let shared_keygen_feldman_vss_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToNodeFeldmanVssParamMsg>::new()));

    let node_addr:SocketAddr = node.listen_addr.parse()?;
    let listener = TcpListener::bind(node_addr).await?;
    info!("node1 is listening on {}",node.address);

    let node_setup_msg_str = serde_json::to_string(&message::common_msg::GSTBKMsg::GSTBKMsgN(message::node::common_msg::GSTBKMsg::SetupMsg(SetupMsg::NodeToRegSetupPhaseP2PMsg(node.setup_phase_one())))).unwrap();
    match p2p(node_setup_msg_str, node.reg_address).await
    {
        Ok(_) => {}
        Err(e) => 
        {
            error!("node setup msg can not sent Err:{}",e);
        }
    };

    while let Result::Ok(( tcp_stream,_)) = listener.accept().await
    {
        let node_clone = shared_node.clone();
        
        let shared_setup_finish_clone = shared_setup_finish.clone();
        let feldman_vss_msg_vec_clone = shared_keygen_feldman_vss_msg_vec.clone();


        tokio::spawn(async move
            {
            let node = node_clone.clone();

            let setup_finish_vec = shared_setup_finish_clone.clone();
            let feldman_vss_msg_vec = feldman_vss_msg_vec_clone.clone();
            let framed = Framed::new( tcp_stream,LinesCodec::new());
            let message = match get_message(framed).await
            {
                Ok(v) => v,
                Err(e) => 
                {
                    error!("Failed to get nodemessage: {:?}",e);
                    return ;
                }
            }; 
            match message 
            {
                GSTBKMsg::GSTBKMsgP(gstbk_reg_msg) => 
                {
                    match gstbk_reg_msg
                    {
                        message::regulator::common_msg::GSTBKMsg::SetupMsg(setup_msg) => 
                        {
                            match setup_msg 
                            {
                                message::regulator::common_msg::SetupMsg::RegSetupPhaseBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Reg  Get RegSetupPhaseBroadcastMsg");
                                    let mut locked_node = node.lock().await;
                                    let msg_two = locked_node.setup_phase_two(msg);
                                    let ntn_msg = serde_json::to_string(&message::common_msg::GSTBKMsg::GSTBKMsgN(message::node::common_msg::GSTBKMsg::SetupMsg(SetupMsg::NodeSetupPhaseFinishFlag(msg_two)))).unwrap();
                                    let node_list = locked_node.node_info_vec.clone().unwrap(); 
                                    let node_id = locked_node.id.unwrap().clone();
                                    match broadcast(ntn_msg, node_list, node_id).await {
                                        Ok(_) => {}
                                        Err(e) => 
                                        {
                                            error!("Error: {}, NodeToRegSetupFinishMsg can not sent ",e);
                                            return ;
                                        }
                                    }
                                }
                                _ => {} 
                            }   
                        }
                        _ => {} 
                    }
                }
                GSTBKMsg::GSTBKMsgN(gstbk_node_msg) => 
                {
                    match gstbk_node_msg
                    {
                        message::node::common_msg::GSTBKMsg::SetupMsg(setup_msg) => {
                            match setup_msg {
                                message::node::common_msg::SetupMsg::NodeSetupPhaseFinishFlag(msg) => {

                                    let mut locked_node = node.lock().await;
                                    let mut locked_finish_vec = setup_finish_vec.lock().await;
                                    locked_finish_vec.push(msg);
                                    if locked_finish_vec.len() == (locked_node.threashold_param.share_counts - 1) as usize {
                                    //if locked_finish_vec.len() == (locked_node.threashold_param.share_counts - 1) as usize {
                                        let vss_map = locked_node.keygen_phase_one(); 
                                        for (id,param) in vss_map.iter() {
                                            let ntn_msg = serde_json::to_string(&message::common_msg::GSTBKMsg::GSTBKMsgN(message::node::common_msg::GSTBKMsg::KeyGenMsg(KeyGenMsg::NodeToNodeFeldmanVssParamMsg(param.clone())))).unwrap();
                                            let node_list = locked_node.node_info_vec.clone().unwrap(); 
                                            match to_node(ntn_msg, id.clone(), node_list).await {
                                                Ok(_) => {}
                                                Err(e) => 
                                                {
                                                    error!("Error: {}, NodeToNodeFeldmanVssParamMsg can not sent ",e);
                                                    return ;
                                                }
                                            }                                      
                                        }                                                                      
                                    }
                                }
                                _ => {}
                            }
                           
                        }
                        message::node::common_msg::GSTBKMsg::KeyGenMsg(keygen_msg) => 
                        {
                            match keygen_msg 
                            {
                                message::node::common_msg::KeyGenMsg::NodeToNodeFeldmanVssParamMsg(msg) => {
                                    let mut locked_node = node.lock().await;
                                    let mut loced_feldman_vss_vec = feldman_vss_msg_vec.lock().await;
                                    loced_feldman_vss_vec.push(msg.clone());
                                    if loced_feldman_vss_vec.len() == (locked_node.threashold_param.share_counts - 1) as usize
                                    {
                                        let msg_vec = (*loced_feldman_vss_vec).clone();
                                        locked_node.keygen_phase_two(&msg_vec).unwrap();
                                    }
                                    
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        });
    }
    Ok(())
}

#[test]
fn test() 
{
    match main() 
    {
        Ok(_) => 
        {
            println!("Ok");
        }
        Err(_) => 
        {
            println!("No");
        } 
    };
}

#[test]
fn test_decrypt() 
{
    match decrypt() 
    {
        Ok(_) => 
        {
            println!("Ok");
        }
        Err(_) => 
        {
            println!("No");
        } 
    };
}