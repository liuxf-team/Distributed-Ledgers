use tokio::net::{TcpListener};
use tokio::sync::Mutex as TokioMutex;
use tokio_util::codec::{Framed, LinesCodec};
use std::net::SocketAddr;
use std::sync::Arc;
use std::env;
use log::{error, info};


use node::communication::communication::*;
use node::node::{Node}; 
use node::config::config::Config;
use message::common_msg::GSTBKMsg;
use message::node::keygen_msg::{NodeKeyGenPhaseOneBroadcastMsg,NodeToNodeKeyGenPhaseTwoP2PMsg};
use message::node::common_msg::{SetupMsg, KeyGenMsg};

#[tokio::main] 
pub async fn main() -> Result<(), anyhow::Error> 
{
    // 初始化 日志记录器
    let log_path = String::from(env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/node/node4/config/config_file/log4rs.yaml";
    log4rs::init_file(log_path, Default::default()).unwrap();
    
    //初始化node
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/node/node4/config/config_file/node_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();

    //将node设置成共享变量以便在async中能够修改
    //不用Arc<node>的原因是,Arc用于共享不可变数据，多个线程可以同时访问,但如果有一个线程尝试修改它，就可能会导致竞争条件和不确定的行为
    let node = Node::init(gs_tbk_config);
    let shared_node = Arc::new(TokioMutex::new(node.clone()));

    //设置keygen阶段的共享变量
    let shared_keygen_phase_one_msg_vec_A = Arc::new(TokioMutex::new(Vec::<NodeKeyGenPhaseOneBroadcastMsg>::new()));
    let shared_keygen_phase_one_msg_vec_B = Arc::new(TokioMutex::new(Vec::<NodeToNodeKeyGenPhaseTwoP2PMsg>::new()));
    let shared_xj_num = Arc::new(TokioMutex::new(0));
    

    //开启节点监听接口
    let node_addr:SocketAddr = node.listen_addr.parse()?;
    let listener = TcpListener::bind(node_addr).await?;
    info!("node4 is listening on {}",node.address);
    info!("regular is listening on {}",node.regulator_address);
    //向regulator发送消息，代码，启动
    let node_setup_msg_str = serde_json::to_string(&message::common_msg::GSTBKMsg::GSTBKMsgN(message::node::common_msg::GSTBKMsg::SetupMsg(SetupMsg::NodeToRegulatorSetupPhaseP2PMsg(node.setup_phase_one())))).unwrap();
    match p2p(node_setup_msg_str, node.regulator_address).await
    {
        Ok(_) => {}
        Err(e) => 
        {
            error!("node setup msg can not sent Err:{}",e);
        }
    };

    //循环接受消息
    while let Result::Ok(( tcp_stream,_)) = listener.accept().await
    {
        //对共享变量进行克隆
        let node_clone = shared_node.clone();
        
        //keygen阶段
        let keygen_phase_one_msg_vec_A_clone = shared_keygen_phase_one_msg_vec_A.clone();
        let keygen_phase_one_msg_vec_B_clone = shared_keygen_phase_one_msg_vec_B.clone();
        let xj_num_clone = shared_xj_num.clone();

        tokio::spawn(async move
            {
            //闭包里克隆共享变量
            let node = node_clone.clone();

            //keygen阶段
            let keygen_phase_one_msg_vec_A = keygen_phase_one_msg_vec_A_clone.clone();
            let keygen_phase_one_msg_vec_B = keygen_phase_one_msg_vec_B_clone.clone();
            let xj_num = xj_num_clone.clone();
            //接收并拆分出消息
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
                GSTBKMsg::GSTBKMsgP(gstbk_regulator_msg) => 
                {
                    match gstbk_regulator_msg
                    {
                        message::regulator::common_msg::GSTBKMsg::SetupMsg(setup_msg) => 
                        {
                            match setup_msg 
                            {
                                message::regulator::common_msg::SetupMsg::RegulatorSetupPhaseBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Regulator  Get RegulatorSetupPhaseBroadcastMsg");
                                    let mut locked_node = node.lock().await;
                                    let setup_phase_two_msg_str = setup_to_gstbk(SetupMsg::NodeSetupPhaseFinishFlag(locked_node.setup_phase_two(msg)));
                                    match p2p(setup_phase_two_msg_str, (*locked_node.regulator_address).to_string()).await 
                                    {
                                        Ok(_) => {}
                                        Err(e) => 
                                        {
                                            error!("Error: {}, NodeToRegulatorSetupFinishMsg can not sent ",e);
                                            return ;
                                        }
                                    };
                                }
                                message::regulator::common_msg::SetupMsg::RegulatorSetupPhaseFinishFlag(msg) => 
                                {
                                    info!("From id : 0 ,Role : Regulator  Get RegulatorSetupPhaseFinishFlag");
                                    let locked_node = node.lock().await;
                                    locked_node.setup_phase_three(msg);
                                }
                            }
        
                        }
                        message::regulator::common_msg::GSTBKMsg::KeyGenMsg(keygen_msg) => 
                        {
                            match keygen_msg  
                            {
                                message::regulator::common_msg::KeyGenMsg::RegulatorKeyGenPhaseStartFlag(msg) => 
                                {
                                    info!("From id : 0 ,Role : Regulator  Get RegulatorKeyGenPhaseStartFlag");
                                    //info!("StartFlag is {:?}",msg);
                                }
                                message::regulator::common_msg::KeyGenMsg::RegulatorKeyGenPhaseOneBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Regulator  Get RegulatorKeyGenPhaseOneBroadcastMsg");
                                    info!("Keygen phase is staring!");
                                    //生成ABOC
                                    // let tag_A = DKGTag::Gamma_A;
                                    let mut locked_node = node.lock().await;

                                    //压入自己的vec
                                    let mut locked_vec_A = keygen_phase_one_msg_vec_A.lock().await;

                                    //生成并序列化NodeKeyGenPhaseOneBroadcastMsg
                                    let keygen_phase_one_msg_A = locked_node.keygen_phase_one(msg.clone());
                                    locked_vec_A.push(keygen_phase_one_msg_A.clone());

                                    let keygen_phase_one_msg_A_str = keygen_to_gstbk(KeyGenMsg::NodeKeyGenPhaseOneBroadcastMsg(keygen_phase_one_msg_A));

                                    let mut msg_vec:Vec<String> = Vec::new();
                                    msg_vec.push(keygen_phase_one_msg_A_str);
                                    let node_list = locked_node.node_info_vec.clone().unwrap();

                                    let node_id = locked_node.id.clone().unwrap();

                                    //将消息广播发送出去
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
                                
                                
                            }
                        }
                        
                    }
                }
                GSTBKMsg::GSTBKMsgN(gstbk_node_msg) => 
                {
                    match gstbk_node_msg
                    {
                        message::node::common_msg::GSTBKMsg::KeyGenMsg(keygen_msg) => 
                        {
                            match keygen_msg 
                            {
                                message::node::common_msg::KeyGenMsg::NodeKeyGenPhaseOneBroadcastMsg(msg) => 
                                {
                                    info!("From id : {} ,Role : {} Get NodeKeyGenPhaseOneBroadcastMsg ",msg.sender,msg.role);
                                    let mut locked_node = node.lock().await;
                                    let mut locked_vec = keygen_phase_one_msg_vec_A.lock().await;
                                    locked_vec.push(msg);
                                    if locked_vec.len() == locked_node.threashold_param.share_counts as usize  
                                    {
                                        let vec = (*locked_vec).clone();
                                        let keygen_phase_two_msg_vec = match locked_node.keygen_phase_two(&vec) 
                                        {
                                            Ok(v) => v,
                                            Err(e) => 
                                            {
                                                error!("Error:{}, can not get NodeToRegulatorKeyGenPhaseTwoP2PMsg_A ",e);
                                                return ;
                                            } 
                                        };
                                        let node_list = locked_node.node_info_vec.clone().unwrap();
                                        for m in keygen_phase_two_msg_vec{
                                            let node_id = m.receiver;
                                            let keygen_phase_two_msg_str = serde_json::to_string(&message::common_msg::GSTBKMsg::GSTBKMsgN(message::node::common_msg::GSTBKMsg::KeyGenMsg(message::node::common_msg::KeyGenMsg::NodeToNodeKeyGenPhaseTwoP2PMsg(m)))).unwrap();
                                            match to_node(keygen_phase_two_msg_str, node_id, node_list.clone()).await 
                                            {
                                                Ok(_) => {}
                                                Err(e) => 
                                                {
                                                    error!("Error:{}, NodeToRegulatorKeyGenPhaseTwoP2PMsg_A can not sent",e);
                                                    return ;
                                                }
                                            };
                                        }
                                    }
                                }
                                message::node::common_msg::KeyGenMsg::NodeToNodeKeyGenPhaseTwoP2PMsg(msg) =>
                                {
                                    info!("From id : 0 ,Role : Regulator  Get NodeToNodeKeyGenPhaseTwoP2PMsg");
                                    let mut locked_num = xj_num.lock().await;
                                    let mut locked_node = node.lock().await;
                                    //压入自己的vec
                                    let mut locked_vec_B = keygen_phase_one_msg_vec_B.lock().await;
                                    locked_vec_B.push(msg);
                                    *locked_num += 1;
                                    if *locked_num == locked_node.threashold_param.share_counts as i32 - 1
                                    && locked_vec_B.len() == locked_node.threashold_param.share_counts as usize - 1
                                    {

                                        match locked_node.keygen_phase_four(locked_vec_B.clone()) 
                                        {
                                            Ok(_) => 
                                            {
                                                *locked_num += 1;
                                            }
                                            Err(e) => 
                                            {
                                                error!("can not get xj Err is {}",e);
                                            }
                                        };
                                        
                                        info!("Keygen phase is finished!");
                                        println!("Keygen phase is finished!");

                                        let keygen_phase_five_msg = locked_node.keygen_phase_five();
                                        let keygen_phase_five_msg_str = keygen_to_gstbk(KeyGenMsg::NodeToRegulatorKeyGenPhaseFiveP2PMsg(keygen_phase_five_msg));

                                        //将消息p2p
                                        match p2p(keygen_phase_five_msg_str, (*locked_node.regulator_address).to_string()).await
                                        {
                                            Ok(_) => {
                                                info!("NodeToRegulatorKeyGenPhaseFourP2PMsg has sent");
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error: {}, NodeToRegulatorKeyGenPhaseFourP2PMsg can not sent ",e);
                                                return ;
                                            }
                                        };
                                    }

                    
                                }
                                _ => 
                                {}   
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