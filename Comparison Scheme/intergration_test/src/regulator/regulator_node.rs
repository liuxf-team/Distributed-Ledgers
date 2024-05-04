use std::net::SocketAddr;
use tokio::net::{TcpListener};
use tokio_util::codec::{Framed, LinesCodec};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use std::thread::sleep;
use std::time::Duration;
use std::env;
use log::{error, info, warn}; 

use regulator::communication::communication::*;
use message::regulator::common_msg::{SetupMsg, KeyGenMsg};
use regulator::regulator::Regulator;
use regulator::config::config::Config;
use message::node::setup_msg::{NodeToRegulatorSetupPhaseP2PMsg,NodeSetupPhaseFinishFlag};
use message::node::keygen_msg::{NodeToRegulatorKeyGenPhaseFiveP2PMsg};
use message::common_msg::{GSTBKMsg};
// use gs_tbk_scheme::messages::node::key_manage_msg::{NodeToRegulatorKeyRecoverP2PMsg,NodeToRegulatorKeyRefreshOneP2PMsg};



#[tokio::main]
pub async fn main () -> Result<(), anyhow::Error> 
{
    // 初始化 日志记录器
    let log_path = String::from(env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/regulator/config/config_file/log4rs.yaml";
    log4rs::init_file(log_path, Default::default()).unwrap();
    
    // 初始化
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/regulator/config/config_file/regulator_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();
    let regulator = Regulator::init(gs_tbk_config);

    // 创建setup阶段的一些共享变量
    let shared_node_setup_p2p_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToRegulatorSetupPhaseP2PMsg>::new()));
    let setup_msg_num = Arc::new(TokioMutex::new(0));
    let setup_finish_num = Arc::new(TokioMutex::new(0));
    let shared_node_setup_finish_vec = Arc::new(TokioMutex::new(Vec::<NodeSetupPhaseFinishFlag>::new()));
    
    // 创建KeyGen阶段的共享变量
    //let shared_keygen_phase_two_msg_A_vec = Arc::new(TokioMutex::new(Vec::<NodeToRegulatorKeyGenPhaseTwoP2PMsg>::new()));
    let shared_xj_num = Arc::new(TokioMutex::new(0));
    let shared_xj_num2 = Arc::new(TokioMutex::new(0));
    let shared_keygen_phase_five_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToRegulatorKeyGenPhaseFiveP2PMsg>::new()));
    
    // // 创建KeyManage阶段的共享变量
    // let shared_key_recover_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToRegulatorKeyRecoverP2PMsg>::new()));
    // let shared_key_refresh_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToRegulatorKeyRefreshOneP2PMsg>::new()));

    
    // 开启代理的监听端口
    let regulator_addr:SocketAddr = regulator.address.parse()?;
    let listener = TcpListener::bind(regulator_addr).await?;
    info!("Regulator_node is listening on {}",regulator_addr);
    let shared_regulator = Arc::new(TokioMutex::new(regulator));// 定义共享
    
    // 循环接收消息
    while let Result::Ok(( tcp_stream,_)) = listener.accept().await 
    {
        // 拷贝共享代理结构体
        let regulator_clone = shared_regulator.clone();

        // 拷贝共享变量
        let shared_node_setup_p2p_msg_vec_clone = shared_node_setup_p2p_msg_vec.clone();
        let msg_num_clone = setup_msg_num.clone();                            
        let finish_num_clone = setup_finish_num.clone();
        let node_setup_finish_vec_clone = shared_node_setup_finish_vec.clone();
        
        //keygen阶段克隆
        // let shared_keygen_phase_two_msg_A_vec_clone = shared_keygen_phase_two_msg_A_vec.clone();
        let keygen_phase_five_msg_vec_clone = shared_keygen_phase_five_msg_vec.clone();
        let xj_num_clone = shared_xj_num.clone();
        let xj_num_clone2 = shared_xj_num2.clone();

        tokio::spawn(async move
        {
            let regulator = regulator_clone.clone();
            let xj_num = xj_num_clone.clone();
            let xj_num2 = xj_num_clone2.clone();
            //接收并拆分出消息
            let framed = Framed::new( tcp_stream,LinesCodec::new());
            let message = match get_message(framed).await 
            {
                Ok(v) => v,
                Err(e) => 
                {
                    error!("Failed to get node's message: {:?}",e);
                    return ;
                } 
            };
            //对不同的消息类型做处理
            match message 
            {
                GSTBKMsg::GSTBKMsgN(gstbkn_msg) => 
                {
                    match gstbkn_msg 
                    {
                        message::node::common_msg::GSTBKMsg::SetupMsg(setup_msg) =>  
                        { 
                            match setup_msg 
                            {
                                message::node::common_msg::SetupMsg::NodeToRegulatorSetupPhaseP2PMsg(msg) => 
                                {
                                    info!("From Role : {}, Get NodeToRegulatorSetupPhaseP2PMsg", msg.role);
                                    let node_setup_p2p_msg_vec = shared_node_setup_p2p_msg_vec_clone.clone();
                                    let msg_num = msg_num_clone.clone(); 
                                    let mut locked_regulator = regulator.lock().await;                           
                                    handle_setup_msg(msg,&node_setup_p2p_msg_vec,&msg_num).await;
                                    //判断收到的消息是否达到了n
                                    if *msg_num.lock().await == (locked_regulator.threashold_param.share_counts as i32) 
                                    {
                                        //info!("Setup phase is starting!");
                                        //等待一秒，等所有的节点监听接口都能打开
                                        let duration = Duration::from_secs(1);
                                        sleep(duration); 
                                        //生成regulator_setup_msg 
                                        let msg_vec = (*node_setup_p2p_msg_vec.lock().await).clone();
                                        let setup_msg_str = setup_to_gstbk(SetupMsg::RegulatorSetupPhaseBroadcastMsg(locked_regulator.setup_phase_one(msg_vec)));
                                        //广播
                                        let node_list = locked_regulator.node_info_vec.clone().unwrap(); 
                                        match broadcast(setup_msg_str, node_list).await{
                                            Ok(_) => 
                                            {
                                                //println!("RegulatorSetupBroadcastMsg have send");
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error!: {}, RegulatorSetupBroadcastMsg can not send ",e);
                                                return ;
                                            }
                                        };
                                    }
                                    else 
                                    {
                                        warn!("Insufficient number of messages, and current number is {:?}", msg_num);
                                        return;
                                    }
                                }
                                message::node::common_msg::SetupMsg::NodeSetupPhaseFinishFlag(msg) => 
                                {
                                    info!("From id : {}, Role : {}, Get NodeSetupPhaseFinishFlag",msg.sender,msg.role);
                                    let node_setup_finish_vec = node_setup_finish_vec_clone.clone();
                                    let finish_num = finish_num_clone.clone();
                                    let mut locked_regulator = regulator.lock().await;
                                    handle_setup_tag(msg,&node_setup_finish_vec,&finish_num).await;
                                    //判断是否所有节点都发了
                                    if *finish_num.lock().await == (locked_regulator.threashold_param.share_counts as i32) 
                                    {
                                        let setup_finish_flag_str = setup_to_gstbk(SetupMsg::RegulatorSetupPhaseFinishFlag(locked_regulator.setup_phase_two((*node_setup_finish_vec.lock().await).clone())));
                                        //广播
                                        let node_list = locked_regulator.node_info_vec.clone().unwrap(); 
                                        match broadcast(setup_finish_flag_str, node_list).await
                                        {
                                            Ok(_) => {
                                                //println!("RegulatorSetupFinishMsg have send");
                                            }
                                            Err(e) => {
                                                error!("Error: {}, RegulatorSetupFinishMsg can not sent ",e);
                                                return ;
                                            }
                                        };
                                    }
                                    else 
                                    {
                                        warn!("Insufficient number of messages, and current number is {:?}", finish_num);
                                        return;
                                    }

                                    //生成第二轮KeyGen的消息
                                    let (keygen_start_flag,keygen_phase_one_msg) = locked_regulator.keygen_phase_one();
                                    //处理发送regulator的Phaseone KeyGenStartFlag
                                    let keygen_start_flag_str = keygen_to_gstbk(KeyGenMsg::RegulatorKeyGenPhaseStartFlag(keygen_start_flag));
                                    //广播
                                    let node_list = locked_regulator.node_info_vec.clone().unwrap(); 
                                    match broadcast(keygen_start_flag_str, node_list.clone()).await
                                    {
                                        Ok(_) => 
                                        {
                                            //println!("RegulatorSetupFinishMsg have send");
                                        } 
                                        Err(e) => 
                                        {
                                            error!("KeygenStartFlag can not sent Error: {}",e);
                                            return ;
                                        }
                                    };
                                    //处理发送regulator的Phase_one RegulatorKeyGenPhaseOneBroadcastMsg
                                    let keygen_phase_one_msg_str = keygen_to_gstbk(KeyGenMsg::RegulatorKeyGenPhaseOneBroadcastMsg(keygen_phase_one_msg));
                                    //广播
                                    match broadcast(keygen_phase_one_msg_str, node_list.clone()).await
                                    {
                                        Ok(_) => 
                                        {
                                            //println!("RegulatorSetupFinishMsg have send");
                                        }
                                        Err(e) => 
                                        {
                                            error!("KeygenPhaseOneMsg can not sent Error: {}",e);
                                            return ;
                                        }
                                    };
                                }
                                
                            }
                        }
                        message::node::common_msg::GSTBKMsg::KeyGenMsg(keygen_msg) => 
                        {
                            match keygen_msg {
                               
                                message::node::common_msg::KeyGenMsg::NodeToRegulatorKeyGenPhaseFiveP2PMsg(msg)=>
                                {
                                    info!("From id : {}, Role : {}, Get NodeToRegulatorKeyGenPhaseFourP2PMsg",msg.sender,msg.role);
                                    let node_keygen_phase_five_p2p_msg_vec = keygen_phase_five_msg_vec_clone.clone();
                                    let mut locked_num = xj_num2.lock().await;
                                    let locked_regulator = regulator.lock().await;
                                    let mut locked_msg_vec = node_keygen_phase_five_p2p_msg_vec.lock().await; 
                                    locked_msg_vec.push(msg.clone());
                                    *locked_num += 1;
                                    if *locked_num == locked_regulator.threashold_param.share_counts as i32 && locked_msg_vec.len() == locked_regulator.threashold_param.share_counts as usize
                                    {
                                        //println!("6666");
                                        let msg_vec = locked_msg_vec.clone();
                                        locked_regulator.keygen_phase_five((msg_vec).clone());
                                        //println!("6666");
                                    }

                                    
                                }
                                _=>
                                {

                                }
                            }
                        }
                        
                    }
                }
                _ => 
                {

                }
                
            }
        });
    }
    Ok(())
} 

//test
#[test]
fn test() 
{
   match main()  
   { 
    Ok(_) =>
    {
        info!("Ok"); 
    }  
    Err(_) => 
    {
        error!("No");
    } 
   };
}

 