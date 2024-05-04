use std::clone;
use std::collections::HashMap;
use bulletproof::proofs::range_proof;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::secret_sharing::pedersen_vss::{SecretShares,VerifiableSS};
use curv::elliptic::curves::{Secp256k1, Point, Scalar};
use curv::BigInt;
use log::info;
use sha2::{Sha256, Digest};

use crate::Error::{self, InvalidSS};
use message::regulator::keygen_msg::{RegulatorKeyGenPhaseOneBroadcastMsg};
use message::node::keygen_msg::{BlindFactors, HashCommitments,RangeProofPedersenCom, NodeKeyGenPhaseOneBroadcastMsg, NodeToNodeKeyGenPhaseTwoP2PMsg,NodeToRegulatorKeyGenPhaseFiveP2PMsg, ShareCom};
use message::params::{Generators};
use crate::node::{Node};
use crate::cdl4osl_vss_scheme::bulletproofs::*;

impl Node { 

    /// 确定金额和随机数，计算哈希承诺并广播
    pub fn keygen_phase_one(&mut self, msg:RegulatorKeyGenPhaseOneBroadcastMsg) -> NodeKeyGenPhaseOneBroadcastMsg
    {
        info!("Key is generating!");
        let generators = Generators
        {
            g:msg.g, 
            h:msg.h
        };
        let range = BigInt::from(2).pow(32 as u32);
        let mi = Scalar::<Secp256k1>::from(&BigInt::sample_below(&range));
        // let mi = Scalar::<Secp256k1>::random();
        let Mi = &generators.g.clone() * &mi;
        let ri = Scalar::<Secp256k1>::random();
        let Ri = &generators.h.clone() * &ri;
        
        // 生成范围证明
        let ped_coms = &generators.g * &mi + &generators.h * &ri;
        let range_proof = bulletproof_prove(vec![mi.clone()], &[ri.clone()]);

        self.generators = Some(generators);
        self.dkgparam.mi = Some(mi);
        self.dkgparam.Mi = Some(Mi.clone());
        self.dkgparam.ri = Some(ri);
        self.dkgparam.Ri = Some(Ri.clone());

        let blind_factor_m = BigInt::sample(256);
        let blind_factor_r = BigInt::sample(256);
        let com_m = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(Mi.clone().to_bytes(true).as_ref()),
            &blind_factor_m,
        );
        let com_r = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(Ri.clone().to_bytes(true).as_ref()),
            &blind_factor_r,
        );
        
        NodeKeyGenPhaseOneBroadcastMsg
        {
            sender:self.id.unwrap(),
            role:self.role.clone(),
            blind_factors:BlindFactors{
                blind_factor_m,
                blind_factor_r
            },
            Mi:Mi,
            Ri:Ri,
            coms:HashCommitments{
                com_m,
                com_r
            },
            range_proof_pedersen_com:RangeProofPedersenCom{
                range_proof,
                pedersen_commitment:ped_coms
            }
        }
        
    }

    /// 验证哈希承诺，进行范围证明
    /// 然后进行Pedersen vss，shares, 相关系数承诺   
    pub fn keygen_phase_two(&mut self, msg_vec:&Vec<NodeKeyGenPhaseOneBroadcastMsg>)
    -> Result<Vec<NodeToNodeKeyGenPhaseTwoP2PMsg>, Error>
    {
        //verify length
        assert_eq!(msg_vec.len(), self.threashold_param.share_counts as usize);
        //Verify all Hashcommitment
        let all_com_verify_tag = (0..msg_vec.len()).all( |i| {
            bulletproof_aggregated(msg_vec[i].range_proof_pedersen_com.range_proof.clone(), &[msg_vec[i].range_proof_pedersen_com.pedersen_commitment.clone()])
            &&
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(&BigInt::from_bytes(msg_vec[i].Mi.to_bytes(true).as_ref()), &msg_vec[i].blind_factors.blind_factor_m )== msg_vec[i].coms.com_m
            &&
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(&BigInt::from_bytes(msg_vec[i].Ri.to_bytes(true).as_ref()), &msg_vec[i].blind_factors.blind_factor_r )== msg_vec[i].coms.com_r
        });

        if all_com_verify_tag 
        {
            // 合并g^m 和 h^r
            let M= msg_vec.iter().fold(Point::<Secp256k1>::zero(), |acc,m|acc+&m.Mi);
            let R= msg_vec.iter().fold(Point::<Secp256k1>::zero(), |acc,m|acc+&m.Ri);
            
            let dkgparam = self.dkgparam.clone();

            //生成系数承诺和share值
            let share_result =
            VerifiableSS::share(self.threashold_param.threshold, self.threashold_param.share_counts, &dkgparam.mi.as_ref().unwrap(),dkgparam.ri.as_ref().unwrap());
            let vss_scheme:VerifiableSS<Secp256k1> = share_result.0;
            let secret_shares:SecretShares<Secp256k1> = share_result.1;

            // 获取自己的share，然后打包其他的share
            let shares = secret_shares.shares.to_vec();
            let random_shares = secret_shares.random_shares.to_vec();

            // 存入结构体
            self.dkgparam.share = Some(shares[(self.id.unwrap() as usize) -1].clone()); 
            self.dkgparam.random_share = Some(random_shares[(self.id.unwrap() as usize) -1].clone());
            self.dkgparam.M = Some(M);
            self.dkgparam.R = Some(R);
            
            
            let mut msg_vec:Vec<NodeToNodeKeyGenPhaseTwoP2PMsg> = Vec::new();
            // 打包消息
            for node in self.node_info_vec.as_ref().unwrap()
            {
                if node.id!=self.id.unwrap()
                {
                    let msg = NodeToNodeKeyGenPhaseTwoP2PMsg
                    {
                        sender:self.id.unwrap(),
                        receiver:node.id,
                        role:self.role.clone(),
                        share:shares[(node.id as usize)-1].clone().to_bigint(),
                        random_share:random_shares[(node.id as usize)-1].clone().to_bigint(),
                        vss_scheme:vss_scheme.clone(),
                    };
                    msg_vec.push(msg);
                }
            }
            Ok
            (
                msg_vec
            )
        } 
        else
        {
            Err(Error::InvalidCom) 
        }
    }

    /// 进行系数承诺验证，share验证，然后合并share得到最终share
    pub fn keygen_phase_four(&mut self, msg_vec:Vec<NodeToNodeKeyGenPhaseTwoP2PMsg> )->Result<(), Error>
    {
        
        let all_com_flag = msg_vec.iter()
        .all(|m|{m.vss_scheme.validate_share(&Scalar::from_bigint(&m.share),&Scalar::from_bigint(&m.random_share), self.id.unwrap()).is_ok()});
        let share = self.dkgparam.share.clone().unwrap().to_bigint();
        let random_share = self.dkgparam.random_share.clone().unwrap().to_bigint();
        // verify coefficient commitment
        if all_com_flag
        {
            let (mi,ri) = msg_vec.iter().fold((share,random_share), |(acc1,acc2),m|{
                (acc1+m.share.clone(),acc2+m.random_share.clone())
            });
            self.dkgparam.share = Some(Scalar::from_bigint(&mi));
            self.dkgparam.random_share = Some(Scalar::from_bigint(&ri));
            info!("Current mi is {:?}", self.dkgparam.share.clone().unwrap()); 
            Ok(
                ()
            )
        }   
        else
        {
            Err(InvalidSS)
        }
            
    }

    pub fn keygen_phase_five(&self)->NodeToRegulatorKeyGenPhaseFiveP2PMsg
    {
        NodeToRegulatorKeyGenPhaseFiveP2PMsg{
            sender: self.id.unwrap(),
            role:self.role.clone() ,
            xi:self.dkgparam.clone().share.unwrap(),
            mi:self.dkgparam.clone().mi.unwrap()
        }
    }
}

#[test]
fn test(){
    // let (sk,pk) = group.keygen();
    // let a = Scalar::<Bls12_381_1>::random();
    // let g = Point::<Bls12_381_1>::generator() * Scalar::<Bls12_381_1>::from(1);
    // let g_a = &g * &a;
    // //let (c,proof) = CLGroup::verifiably_encrypt(&group, &pk, (&a,&g_a));
    // let (c,_) = encrypt(&group, &pk, &a);
    // println!("{:?}",c);
}

#[test]
pub fn test1()
{
    let g1 = Point::<Secp256k1>::base_point2();
    let g2 = Point::<Secp256k1>::base_point2();
    assert_eq!(g1,g2);
}



