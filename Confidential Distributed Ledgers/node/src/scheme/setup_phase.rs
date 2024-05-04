use log::info;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use crate::config::config::Config;
use crate::node::{Node,DKGParam};
use message::regulator::setup_msg::RegSetupPhaseBroadcastMsg;
use message::node::setup_msg::{NodeToRegSetupPhaseP2PMsg,NodeSetupPhaseFinishFlag};

pub type FE = Scalar<Secp256k1>;
pub type GE = Point<Secp256k1>;

impl Node{
    /// 初始化自身信息，加载配置，生成cl密钥对等
    pub fn init(gs_tbk_config:Config) -> Self
    {  
        Self
        {
            id:None,
            role:"Group Manager Node".to_string(),
            address:gs_tbk_config.node_addr,
            listen_addr:gs_tbk_config.listen_addr,
            reg_address:gs_tbk_config.reg_addr,
            threashold_param:gs_tbk_config.threshold_params,
            regulator_pk:None,
            pk:Some(GE::zero()),
            sk:Some(FE::zero()),
            pk_share_vec:None,
            batch_total_money: None,
            dkgparam:DKGParam{ui:None,yi:None,yi_map:None,y:None,mskshare:None,addshare:None},
            gpk:None,
            node_info_vec:None,
            participants:None,
        }
        
    }

    /// 发送自己的公钥和地址给代理
    pub fn setup_phase_one(&self)->NodeToRegSetupPhaseP2PMsg
    {
        info!("Setup phase is starting!");
        NodeToRegSetupPhaseP2PMsg
        {
            role:self.role.clone(),
            address:self.address.clone(),
        }

    }

    /// 存储所有管理员的基本信息，公钥，id，地址等等
    pub fn setup_phase_two(&mut self, msg:RegSetupPhaseBroadcastMsg)-> NodeSetupPhaseFinishFlag
    {
        for node in msg.node_info_vec.iter()
        {
            if node.address == self.address
            {
                self.id = Some(node.id);
            }
        }
        self.node_info_vec = Some(msg.node_info_vec);
        self.regulator_pk = Some(msg.regulator_pk);
        NodeSetupPhaseFinishFlag 
        { 
            sender: self.id.unwrap(), 
            role:self.role.clone(),
        }
        
    }

    pub fn setup_phase_three(&self)
    {
        info!("Setup phase is finished!")
    }
 
}


#[test]
fn test()
{
}