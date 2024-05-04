use std::collections::HashMap;
use curv::elliptic::curves::{Secp256k1, Point, Scalar};
use curv::cryptographic_primitives::secret_sharing::pedersen_vss::{VerifiableSS,ShamirSecretSharing};
use log::{info};
use message::regulator::keygen_msg::{RegulatorKeyGenPhaseStartFlag,RegulatorKeyGenPhaseOneBroadcastMsg};
use message::node::keygen_msg::{NodeToRegulatorKeyGenPhaseFiveP2PMsg, ShareCom};
use crate::regulator::{Regulator};
use crate::Error::{self,InvalidSS};
use message::params::{Generators};  

impl Regulator 
{
    /// 随机选择参与方，然后广播给管理员
    pub fn keygen_phase_one(&mut self)->(RegulatorKeyGenPhaseStartFlag, RegulatorKeyGenPhaseOneBroadcastMsg)
    {
        info!("Keygen phase is staring!");
        println!("Keygen phase is staring!");
        let flag = RegulatorKeyGenPhaseStartFlag
        {
            sender:self.id,
            role:self.role.clone(),
        };

        let g = Point::<Secp256k1>::generator() * Scalar::<Secp256k1>::from(1);
        let h = Point::<Secp256k1>::base_point2() * Scalar::<Secp256k1>::from(1);
        self.generators = Some(Generators{
            g:g.clone(),
            h:h.clone()
        });
        let msg = RegulatorKeyGenPhaseOneBroadcastMsg{
            g:g,
            h:h
        };
        (flag,msg) 
    }

    /// 验证密钥正确性
    pub fn keygen_phase_five(&self,msg_vec:Vec<NodeToRegulatorKeyGenPhaseFiveP2PMsg>){
        //println!("我要进来咯");
        let mut indices:Vec<u16> = Vec::new();
        let mut shares:Vec<Scalar<Secp256k1>> = Vec::new();
        let mut m_orin = Scalar::<Secp256k1>::zero();
        for msg in msg_vec{
            indices.push(msg.sender-1);
            shares.push(msg.xi);
            m_orin = m_orin+msg.mi;
        }
        let points = indices
            .iter()
            .map(|i| Scalar::from(*i + 1))
            .collect::<Vec<_>>();

        let m = VerifiableSS::<Secp256k1>::lagrange_interpolation_at_zero(&points, &shares);
        info!("{:?}",m_orin);
        info!("{:?}",m);
        assert_eq!(m_orin,m);
        info!("Key Reconstructs successfully!")
    }

}

