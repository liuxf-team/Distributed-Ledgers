use log::info;
use message::regulator::dec_msg::{RegDecPhaseStartFlag, RegDecPhaseOneBroadcastMsg};
use crate::regulator::Reg;

impl Reg
{
    /// 生成部分公钥，随机选择参与方，然后广播给管理员
    pub fn dec_phase_one(&mut self)->(RegDecPhaseStartFlag, RegDecPhaseOneBroadcastMsg)
    {
        info!("Keygen phase is staring!");
        println!("Keygen phase is staring!");
        let flag = RegDecPhaseStartFlag
        {
            sender:self.id,
            role:self.role.clone(),
        };


        let new_message = "12345".to_string();
        let msg = RegDecPhaseOneBroadcastMsg{
            new_message:new_message,
        };
        (flag,msg) 
    }
}