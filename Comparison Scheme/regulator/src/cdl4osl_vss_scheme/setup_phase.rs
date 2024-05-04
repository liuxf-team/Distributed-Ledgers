// use serde::{Deserialize, Serialize};
// use std::collections::HashMap;
// use std::io::Write;
// use std::fs::File;

use crate::config::config::Config;
use crate::regulator::Regulator;
use message::regulator::setup_msg::{NodeInfo, RegulatorSetupPhaseBroadcastMsg, RegulatorSetupPhaseFinishFlag};
use message::node::setup_msg::{NodeToRegulatorSetupPhaseP2PMsg, NodeSetupPhaseFinishFlag};
use log::{info};
impl Regulator{
    /// 初始化自身基本信息
    pub fn init(gs_tbk_config:Config)->Self
    {
        Self
        {
            id:0,
            role:"Regulator".to_string(),
            address:gs_tbk_config.listen_addr,
            threashold_param:gs_tbk_config.threshold_params,
            generators:None,
            node_info_vec:None,
            participants:None,
        }
    }
    
    /// 生成树，为管理员们分配id，然后发送树和管理员信息
    pub fn setup_phase_one(&mut self, node_setup_p2pmsg_vec:Vec<NodeToRegulatorSetupPhaseP2PMsg>)->RegulatorSetupPhaseBroadcastMsg
    {
        info!("Setup phase is staring!");
        // Build tree
        let mut node_info_vec = Vec::new();
        let mut i = 1;
        for node_init_msg in node_setup_p2pmsg_vec
        {
            let node_info = NodeInfo
            {
                id:i,
                address:node_init_msg.address,
               
            };
            node_info_vec.push(node_info);
            i = i + 1;
        }
        //info!("{:?}",node_info_vec);
        let setup_bromsg = RegulatorSetupPhaseBroadcastMsg { node_info_vec: node_info_vec};

        self.node_info_vec = Some(setup_bromsg.node_info_vec.clone());
        
        setup_bromsg
    }

    /// 结束flag
    pub fn setup_phase_two(&self, setup_finish_flag_vec:Vec<NodeSetupPhaseFinishFlag>) -> RegulatorSetupPhaseFinishFlag
    {
        assert_eq!(setup_finish_flag_vec.len(),self.node_info_vec.as_ref().unwrap().len());
        {
            info!("Setup phase is finished!");
            RegulatorSetupPhaseFinishFlag
            {
                sender:self.id,
                role:self.role.clone()
            }
        }
    }
    
}

#[test]
fn test_init_phase(){
    //Regulator::setup_phase();
}