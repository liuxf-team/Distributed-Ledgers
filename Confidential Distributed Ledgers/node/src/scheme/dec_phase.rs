
use std::fs::File;
use std::io::{BufReader, BufRead};
use std::path::PathBuf;

use bulletproof::proofs::range_proof::RangeProof;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
pub type FE = Scalar<Secp256k1>;
pub type GE = Point<Secp256k1>;
use curv::BigInt;
use log::info;
use message::node::dec_msg::{NodeDecPhaseOneBroadcastMsg, NodeDecPhaseTwoBroadcastMsg};
use elgamal::elgamal::elgamal::{map_share_to_new_params, BatchDecRightProof, BatchEncRightProof, ElgamalCipher, EncEqualProof};
use crate::node::Node;

impl Node {
    pub fn dec_phase_one(&mut self) -> NodeDecPhaseOneBroadcastMsg
    {
        info!("money calculate is starting");
        let current_dir = std::env::current_dir().unwrap();
        let mut input_path = PathBuf::from(current_dir.clone());
        let path = "src/node/node".to_string() + &self.id.unwrap().to_string() + "/keypair.txt";
        input_path.push(path.clone());
        
        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);
        let mut lines = reader.lines().map(|l| l.unwrap());
        
        self.regulator_pk = Some(serde_json::from_str(&lines.next().unwrap()).unwrap()).unwrap();
        self.pk = Some(serde_json::from_str(&lines.next().unwrap()).unwrap()).unwrap();
        let sk_str = &lines.next().unwrap();
        let sk_vec = sk_str.trim().as_bytes().chunks(2).map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)).collect::<Result<Vec<u8>, _>>().unwrap();
        self.sk = Some(FE::from_bytes(&sk_vec).unwrap());
        let batch_size = 1;
        let mut money_vec = Vec::new();
        let mut cipher_vec = Vec::new();
        let mut cipher_vec_reg = Vec::new();
        let mut random_vec = Vec::new();
        let mut equal_proof_vec = Vec::new();
        for _i in 0 .. batch_size{
            let money = FE::from(100);
            let (cipher, random) = ElgamalCipher::encrypt(self.pk.as_ref().unwrap(), &money);
            let (cipher_reg, random_reg) = ElgamalCipher::encrypt(self.regulator_pk.as_ref().unwrap(), &money);
            let equal_proof = EncEqualProof::proof(self.pk.as_ref().unwrap(), self.regulator_pk.as_ref().unwrap(), cipher.clone(), cipher_reg.clone(), &money, &random, &random_reg);
            money_vec.push(money);
            cipher_vec.push(cipher);
            cipher_vec_reg.push(cipher_reg);
            random_vec.push(random);
            equal_proof_vec.push(equal_proof);
        }
        let batch_enc_proof = BatchEncRightProof::proof(self.pk.as_ref().unwrap(), cipher_vec.clone(), money_vec.clone(), random_vec.clone());
        let range_proof = RangeProof::batch_prove_warpper(self.pk.as_ref().unwrap().clone(), money_vec.clone(), random_vec.clone());
        
       
        NodeDecPhaseOneBroadcastMsg
        {
            sender:self.id.unwrap(),
            role:self.role.clone(),
            mul_cipher_vec: cipher_vec,
            cipher_vec_reg,
            batch_enc_proof,
            range_proof,
            equal_proof_vec

        }
    }

    pub fn dec_phase_two(&mut self, msg_vec:&Vec<NodeDecPhaseOneBroadcastMsg>) -> NodeDecPhaseTwoBroadcastMsg
    {
        let batch_cipher_vec:Vec<Vec<ElgamalCipher>> = msg_vec.iter().map(|msg|msg.mul_cipher_vec.clone()).collect();
        let batch_proof = msg_vec.iter().map(|msg|msg.batch_enc_proof.clone()).collect();
        BatchEncRightProof::batch_verify(batch_proof, self.pk.as_ref().unwrap(), batch_cipher_vec.clone()).unwrap();
        for i in 0 .. self.threashold_param.share_counts as usize
        {
            let msg = msg_vec.get(i).unwrap();
            let ped_com_vec = msg.mul_cipher_vec.clone().iter().map(|cipher|cipher.c2.clone()).collect();
            msg.range_proof.batch_verify_warpper(self.pk.as_ref().unwrap().clone(), ped_com_vec).unwrap();
        }
        let mut batch_total_money = batch_cipher_vec[0].clone();
        for cipher_vec in batch_cipher_vec.iter().skip(1).clone(){
            for i in 0 .. cipher_vec.len(){
                batch_total_money[i] = batch_total_money.get(i).unwrap().clone() + cipher_vec.get(i).unwrap().clone();
            }
        }

        self.batch_total_money = Some(batch_total_money.clone());
        let batch_c1:Vec<Point<Secp256k1>> = batch_total_money.iter().map(|money|money.c1.clone()).collect();
        let batch_dec_c1:Vec<Point<Secp256k1>> = batch_c1.iter().map(|money_c1| money_c1 * self.sk.as_ref().unwrap()).collect();
        let pk_share = GE::generator() * self.sk.as_ref().unwrap();


        let dec_proof = BatchDecRightProof::proof(&pk_share, batch_c1, batch_dec_c1.clone(), self.sk.as_ref().unwrap().clone());
        info!("dec_phase_two");
        NodeDecPhaseTwoBroadcastMsg
        {
            sender:self.id.unwrap(),
            role:self.role.clone(),
            batch_dec_c1,
            dec_proof
        }
    }

    pub fn dec_phase_three(&mut self, msg_vec:&Vec<NodeDecPhaseTwoBroadcastMsg>)
    {   
        let current_dir = std::env::current_dir().unwrap();
        let mut input_path = PathBuf::from(current_dir.clone());
        let path = "src/node/node".to_string() + &self.id.unwrap().to_string() + "/pk_share.txt";
        input_path.push(path.clone());
        
        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);
        let mut lines = reader.lines().map(|l| l.unwrap());
        let mut pk_share_vec: Vec<Point<Secp256k1>> = Vec::new();
        let mut pk_share_vec_queue: Vec<Point<Secp256k1>> = Vec::new();
        for _i in 0.. self.threashold_param.share_counts {
            pk_share_vec.push(serde_json::from_str(&lines.next().unwrap()).unwrap());
        }
        for msg in msg_vec {
            pk_share_vec_queue.push(pk_share_vec.get(msg.sender as usize - 1 ).unwrap().clone())
        }

        let batch_dec_proof = msg_vec.iter().map(|msg|msg.dec_proof.clone()).collect();
        let batch_dec_c1_vec = msg_vec.iter().map(|msg|msg.batch_dec_c1.clone()).collect();
        let c1_vec: Vec<Point<Secp256k1>> = self.batch_total_money.as_ref().unwrap().iter().map(|money|money.c1.clone()).collect();
 
        BatchDecRightProof::batch_verify(batch_dec_proof, pk_share_vec_queue, c1_vec.clone(), batch_dec_c1_vec).unwrap();


        let mut lagrange_vec = Vec::new();
        for i in 0 ..= self.threashold_param.threshold as usize
        {
            lagrange_vec.push(BigInt::from(msg_vec.get(i).unwrap().sender));
        }

        let mut batch_c1_total = vec![GE::zero();c1_vec.len()];
        for i in 0 ..= self.threashold_param.threshold as usize
        {
            let msg = msg_vec.get(i).unwrap();
            let li = map_share_to_new_params(BigInt::from(msg.sender), &lagrange_vec);
            for j in 0 .. batch_c1_total.len(){
                let power_li = msg.batch_dec_c1.get(j).unwrap() * li.clone();
                batch_c1_total[j] = batch_c1_total.get(j).unwrap() + power_li;
            }
        }

        let mut gm_vec = Vec::new();
        for i in 0 .. batch_c1_total.len(){
            gm_vec.push(self.batch_total_money.as_ref().unwrap().get(i).unwrap().c2.clone() - batch_c1_total.get(i).unwrap());
        }

        let gm_ = GE::base_point2() * FE::from(400);
        info!("gm_vec = {:?}", gm_vec.clone());
        info!("gm_ = {:?}", gm_);
    }
}