use crate::config::config::Config;
use crate::regulator::Reg;
use elgamal::elgamal::eckeypair::EcKeyPair;
use message::regulator::setup_msg::{NodeInfo, RegSetupPhaseBroadcastMsg, RegSetupPhaseFinishFlag};
use message::node::setup_msg::{NodeToRegSetupPhaseP2PMsg, NodeSetupPhaseFinishFlag};
use log::info;
impl Reg{
    pub fn init(gs_tbk_config:Config)->Self
    {
        Self
        {
            id:0,
            role:"Reg".to_string(),
            address:gs_tbk_config.listen_addr,
            threashold_param:gs_tbk_config.threshold_params,
            gpk:None,
            node_info_vec:None,
            participants:None,
        }
    }
    
    pub fn setup_phase_one(&mut self, node_setup_p2pmsg_vec:Vec<NodeToRegSetupPhaseP2PMsg>)->RegSetupPhaseBroadcastMsg
    {
        info!("Setup phase is staring!");
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
        let keypair = EcKeyPair::new();
        let regulator_pk = keypair.get_public_key().clone();
        let setup_bromsg = RegSetupPhaseBroadcastMsg { node_info_vec: node_info_vec, regulator_pk};

        self.node_info_vec = Some(setup_bromsg.node_info_vec.clone());
        
        setup_bromsg
    }

    pub fn setup_phase_two(&self, setup_finish_flag_vec:Vec<NodeSetupPhaseFinishFlag>) -> RegSetupPhaseFinishFlag
    {
        assert_eq!(setup_finish_flag_vec.len(),self.node_info_vec.as_ref().unwrap().len());
        {
            info!("Setup phase is finished!");
            RegSetupPhaseFinishFlag
            {
                sender:self.id,
                role:self.role.clone()
            }
        }
    }
    
}