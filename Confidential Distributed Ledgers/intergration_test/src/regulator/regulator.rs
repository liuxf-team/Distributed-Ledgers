use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_util::codec::{Framed, LinesCodec};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use std::thread::sleep;
use std::time::Duration;
use std::env;
use log::{error, info, warn};

use regulator::communication::communication::*;
use message::regulator::common_msg::{SetupMsg, DecMsg};
use regulator::regulator::Reg;
use regulator::config::config::Config;
use message::node::setup_msg::{NodeToRegSetupPhaseP2PMsg,NodeSetupPhaseFinishFlag};
use message::common_msg::GSTBKMsg;
// use gs_tbk_scheme::messages::node::key_manage_msg::{NodeToRegKeyRecoverP2PMsg,NodeToRegKeyRefreshOneP2PMsg};

#[tokio::main]
pub async fn decrypt () -> Result<(), anyhow::Error> 
{
    // 初始化 日志记录器
    let log_path = String::from(env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/regulator/config/config_file/log4rs.yaml";
    log4rs::init_file(log_path, Default::default()).unwrap();
    
    // 初始化
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/regulator/config/config_file/reg_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();
    let reg = Reg::init(gs_tbk_config);

    // 创建setup阶段的一些共享变量
    let shared_node_setup_p2p_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToRegSetupPhaseP2PMsg>::new()));
    let setup_msg_num = Arc::new(TokioMutex::new(0));
    let setup_finish_num = Arc::new(TokioMutex::new(0));
    let shared_node_setup_finish_vec = Arc::new(TokioMutex::new(Vec::<NodeSetupPhaseFinishFlag>::new()));
    
    // 开启代理的监听端口
    let reg_addr:SocketAddr = reg.address.parse()?;
    let listener = TcpListener::bind(reg_addr).await?;
    info!("Reg_node is listening on {}",reg_addr);
    let shared_reg = Arc::new(TokioMutex::new(reg));// 定义共享
    
    // 循环接收消息
    while let Result::Ok(( tcp_stream,_)) = listener.accept().await 
    {
        // 拷贝共享代理结构体
        let reg_clone = shared_reg.clone();

        // 拷贝共享变量
        let shared_node_setup_p2p_msg_vec_clone = shared_node_setup_p2p_msg_vec.clone();
        let msg_num_clone = setup_msg_num.clone();                            
        let finish_num_clone = setup_finish_num.clone();
        let node_setup_finish_vec_clone = shared_node_setup_finish_vec.clone();
    
        
        //let open_two_vec_clone = shared_ntp_open_two_vec.clone();
        tokio::spawn(async move
        {
            let reg = reg_clone.clone();
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
                                message::node::common_msg::SetupMsg::NodeToRegSetupPhaseP2PMsg(msg) => 
                                {
                                    info!("From Role : {}, Get NodeToRegSetupPhaseP2PMsg", msg.role);
                                    let node_setup_p2p_msg_vec = shared_node_setup_p2p_msg_vec_clone.clone();
                                    let msg_num = msg_num_clone.clone(); 
                                    let mut locked_reg = reg.lock().await;                           
                                    handle_setup_msg(msg,&node_setup_p2p_msg_vec,&msg_num).await;
                                    //判断收到的消息是否达到了n
                                    if *msg_num.lock().await == (locked_reg.threashold_param.share_counts as i32) 
                                    {
                                        //info!("Setup phase is starting!");
                                        //等待一秒，等所有的节点监听接口都能打开
                                        let duration = Duration::from_secs(1);
                                        sleep(duration); 
                                        //生成reg_setup_msg 
                                        let msg_vec = (*node_setup_p2p_msg_vec.lock().await).clone();
                                        let setup_msg_str = setup_to_gstbk(SetupMsg::RegSetupPhaseBroadcastMsg(locked_reg.setup_phase_one(msg_vec)));
                                        //广播
                                        let node_list = locked_reg.node_info_vec.clone().unwrap(); 
                                        match broadcast(setup_msg_str, node_list).await{
                                            Ok(_) => 
                                            {
                                                //println!("RegSetupBroadcastMsg have send");
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error!: {}, RegSetupBroadcastMsg can not send ",e);
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
                                    let mut locked_reg = reg.lock().await;
                                    handle_setup_tag(msg,&node_setup_finish_vec,&finish_num).await;
                               
                                    if *finish_num.lock().await == (locked_reg.threashold_param.share_counts as i32) 
                                    {
                                        let setup_finish_flag_str = setup_to_gstbk(SetupMsg::RegSetupPhaseFinishFlag(locked_reg.setup_phase_two((*node_setup_finish_vec.lock().await).clone())));
                                        //broadcast
                                        let node_list = locked_reg.node_info_vec.clone().unwrap(); 
                                        match broadcast(setup_finish_flag_str, node_list).await
                                        {
                                            Ok(_) => {
                                                //println!("RegSetupFinishMsg have send");
                                            }
                                            Err(e) => {
                                                error!("Error: {}, RegSetupFinishMsg can not sent ",e);
                                                return ;
                                            }
                                        };
                                    }
                                    else 
                                    {
                                        warn!("Insufficient number of messages, and current number is {:?}", finish_num);
                                        return;
                                    }

                                    let (dec_start_flag,dec_phase_one_msg) = locked_reg.dec_phase_one();
                                
                                    let dec_start_flag_str = dec_to_gstbk(DecMsg::RegDecPhaseStartFlag(dec_start_flag));

                                    let node_list = locked_reg.node_info_vec.clone().unwrap(); 
                                    match broadcast(dec_start_flag_str, node_list.clone()).await
                                    {
                                        Ok(_) => 
                                        {
                                        }
                                        Err(e) => 
                                        {
                                            error!("KeygenStartFlag can not sent Error: {}",e);
                                            return ;
                                        }
                                    };
                                    let dec_phase_one_msg_str = dec_to_gstbk(DecMsg::RegDecPhaseOneBroadcastMsg(dec_phase_one_msg));

                                    match broadcast(dec_phase_one_msg_str, node_list.clone()).await
                                    {
                                        Ok(_) => 
                                        {
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
                        _ => {}  
                    }
                }
                _ => {}
            }
        });
    }
    Ok(())
}


#[tokio::main]
pub async fn main () -> Result<(), anyhow::Error> 
{
    let log_path = String::from(env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/regulator/config/config_file/log4rs.yaml";
    log4rs::init_file(log_path, Default::default()).unwrap();

    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/regulator/config/config_file/reg_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();
    let reg = Reg::init(gs_tbk_config);

    let shared_node_setup_p2p_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToRegSetupPhaseP2PMsg>::new()));
    let setup_msg_num = Arc::new(TokioMutex::new(0));
    let setup_finish_num = Arc::new(TokioMutex::new(0));
    let shared_node_setup_finish_vec = Arc::new(TokioMutex::new(Vec::<NodeSetupPhaseFinishFlag>::new()));
 
    let reg_addr:SocketAddr = reg.address.parse()?;
    let listener = TcpListener::bind(reg_addr).await?;
    info!("Reg_node is listening on {}",reg_addr);
    let shared_reg = Arc::new(TokioMutex::new(reg));// 定义共享

    while let Result::Ok(( tcp_stream,_)) = listener.accept().await 
    {
        let reg_clone = shared_reg.clone();

        let shared_node_setup_p2p_msg_vec_clone = shared_node_setup_p2p_msg_vec.clone();
        let msg_num_clone = setup_msg_num.clone();                            
        let finish_num_clone = setup_finish_num.clone();
        let node_setup_finish_vec_clone = shared_node_setup_finish_vec.clone();
 
        tokio::spawn(async move
        {
            let reg = reg_clone.clone();

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
                                message::node::common_msg::SetupMsg::NodeToRegSetupPhaseP2PMsg(msg) => 
                                {
                                    info!("From Role : {}, Get NodeToRegSetupPhaseP2PMsg", msg.role);
                                    let node_setup_p2p_msg_vec = shared_node_setup_p2p_msg_vec_clone.clone();
                                    let msg_num = msg_num_clone.clone(); 
                                    let mut locked_reg = reg.lock().await;                           
                                    handle_setup_msg(msg,&node_setup_p2p_msg_vec,&msg_num).await;
                                    if *msg_num.lock().await == (locked_reg.threashold_param.share_counts as i32) 
                                    {
 
                                        let duration = Duration::from_secs(1);
                                        sleep(duration); 
                                        let msg_vec = (*node_setup_p2p_msg_vec.lock().await).clone();
                                        let setup_msg_str = setup_to_gstbk(SetupMsg::RegSetupPhaseBroadcastMsg(locked_reg.setup_phase_one(msg_vec)));
                                        
                                        let node_list = locked_reg.node_info_vec.clone().unwrap(); 
                                        match broadcast(setup_msg_str, node_list).await{
                                            Ok(_) => 
                                            {
                                                //println!("RegSetupBroadcastMsg have send");
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error!: {}, RegSetupBroadcastMsg can not send ",e);
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
                                    let locked_reg = reg.lock().await;
                                    handle_setup_tag(msg,&node_setup_finish_vec,&finish_num).await;
                                    if *finish_num.lock().await == (locked_reg.threashold_param.share_counts as i32) 
                                    {
                                        let setup_finish_flag_str = setup_to_gstbk(SetupMsg::RegSetupPhaseFinishFlag(locked_reg.setup_phase_two((*node_setup_finish_vec.lock().await).clone())));
                                        //广播
                                        let node_list = locked_reg.node_info_vec.clone().unwrap(); 
                                        match broadcast(setup_finish_flag_str, node_list).await
                                        {
                                            Ok(_) => {
                                                //println!("RegSetupFinishMsg have send");
                                            }
                                            Err(e) => {
                                                error!("Error: {}, RegSetupFinishMsg can not sent ",e);
                                                return ;
                                            }
                                        };
                                    }
                                    else 
                                    {
                                        warn!("Insufficient number of messages, and current number is {:?}", finish_num);
                                        return;
                                    }
                                }
                                
                            }
                        }_ => {}
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

//test
#[test]
fn decrypt_test() 
{
   match decrypt() 
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
