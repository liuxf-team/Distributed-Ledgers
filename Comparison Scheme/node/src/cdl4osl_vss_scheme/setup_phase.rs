use log::info;
use curv::elliptic::curves::{Secp256k1, Scalar};
use crate::config::config::Config;
use crate::node::{Node,DKGParam};
use message::regulator::setup_msg::{RegulatorSetupPhaseBroadcastMsg,RegulatorSetupPhaseFinishFlag};
use message::node::setup_msg::{NodeToRegulatorSetupPhaseP2PMsg,NodeSetupPhaseFinishFlag};

pub type FE = Scalar<Secp256k1>;

impl Node{
    /// 初始化自身信息，加载配置等
    pub fn init(gs_tbk_config:Config) -> Self
    {
        Self
        { 
            id:None,
            role:"Group Manager Node".to_string(),
            address:gs_tbk_config.node_addr,
            listen_addr:gs_tbk_config.listen_addr,
            regulator_address:gs_tbk_config.regulator_addr,
            threashold_param:gs_tbk_config.threshold_params,
            dkgparam:DKGParam{mi:None,Mi:None,ri:None,Ri:None,M:None,R:None,share:None,random_share:None},
            generators:None,
            node_info_vec:None,
            participants:None,
        }
        
    }

    /// 发送自己的地址给代理
    pub fn setup_phase_one(&self)->NodeToRegulatorSetupPhaseP2PMsg
    {
        info!("Setup phase is starting!");
        NodeToRegulatorSetupPhaseP2PMsg
        {
            role:self.role.clone(),
            address:self.address.clone(),
           
        }

    }

    /// 存储所有管理员的基本信息，公钥，id，地址等等
    pub fn setup_phase_two(&mut self, msg:RegulatorSetupPhaseBroadcastMsg)-> NodeSetupPhaseFinishFlag
    {
        for node in msg.node_info_vec.iter()
        {
            if node.address == self.address
            {
                self.id = Some(node.id);
            }
        }
        self.node_info_vec = Some(msg.node_info_vec);
        NodeSetupPhaseFinishFlag 
        { 
            sender: self.id.unwrap(), 
            role:self.role.clone(),
        }
    }

    pub fn setup_phase_three(&self,flag:RegulatorSetupPhaseFinishFlag)
    {
        info!("Setup phase is finished!")
    }
 
}


#[test]
fn test()
{
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/config/config_files/gs_tbk_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();
    let node = Node::init(gs_tbk_config);
    //println!("{:?}",node);
}