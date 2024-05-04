use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
pub type FE = Scalar<Secp256k1>;
pub type GE = Point<Secp256k1>;
use log::info;
use crate::Error::{self, InvalidSS};
use message::node::keygen_msg::{FeldmanVss, NodeToNodeFeldmanVssParamMsg};
use crate::node::Node;
use std::io::prelude::*;
use hex::encode as hex_encode;
impl Node { 
    pub fn keygen_phase_one(&mut self) -> HashMap<u16,NodeToNodeFeldmanVssParamMsg>
    {
        info!("Key is generating!");
        let si = FE::random();
        let (vss_scheme, secret_shares) = VerifiableSS::share(self.threashold_param.threshold, self.threashold_param.share_counts, &si);
        let shares = secret_shares.to_vec();
        let mut share_map:HashMap<u16,NodeToNodeFeldmanVssParamMsg> = HashMap::new();
        for node in self.node_info_vec.as_ref().unwrap()
        { 
            let id = node.id; 
            // share 1~n, vec 0~n-1
            let share = &shares[id as usize-1 ];

            if self.id.unwrap() == id {
                self.sk = Some(share.clone());
                self.pk = Some(vss_scheme.commitments.get(0).unwrap().clone());
                let mut pk_share_vec = Vec::new();
                for i in 1 ..=self.threashold_param.share_counts as usize{
                    pk_share_vec.push(vss_scheme.get_point_commitment(i as u16));
                }
                self.pk_share_vec = Some(pk_share_vec);
                continue;
            }

            let feldman_vss_i = FeldmanVss {
                share: share.to_bigint(),
                commits: vss_scheme.clone()
            };

            let feldman_vss_msg = NodeToNodeFeldmanVssParamMsg {
                sender:self.id.unwrap(),
                receiver: id,
                vss: feldman_vss_i
            };

            share_map.insert(id, feldman_vss_msg);
        }
        share_map

    }

    pub fn keygen_phase_two(&mut self, msg_vec:&Vec<NodeToNodeFeldmanVssParamMsg>)
    -> Result<(), Error>
    {   
        for msg in msg_vec {
            let feldman_i = &msg.vss;
            let fi = FE::from_bigint(&feldman_i.share);
            let vss_scheme = feldman_i.commits.clone();
            
            // verify coefficient commitment
            if vss_scheme.validate_share(&fi, self.id.unwrap()).is_ok()
            {
                self.sk = Some(self.sk.as_ref().unwrap() + fi.clone());
                self.pk = Some(self.pk.as_ref().unwrap() + vss_scheme.commitments.get(0).unwrap());
            }
            else
            {
                return Err(InvalidSS);
            }
        }
        info!("PK = {:?}",self.pk.as_ref().unwrap());
        info!("Xi = {:?}",self.sk.as_ref().unwrap());
        info!("PK_share = {:?}",self.sk.as_ref().unwrap() * GE::generator());
        let mul_pk = serde_json::to_string(&self.pk.as_ref().unwrap()).unwrap();
        let regulator_pk = serde_json::to_string(&self.regulator_pk.as_ref().unwrap()).unwrap();
        let keypair = regulator_pk + "\n" + &mul_pk + "\n" + &hex_encode(&self.sk.as_ref().unwrap().to_bytes().to_vec());

         let current_dir = std::env::current_dir().unwrap();
         let mut output_path = PathBuf::from(current_dir.clone());
         let path = "src/node/node".to_string() + &self.id.unwrap().to_string() + "/keypair.txt";
         output_path.push(path);
         let file = File::create(output_path.clone());

         match file.unwrap().write_all(keypair.as_bytes()){
             Ok(_) => println!("keypair write in keypair.txt"),
             Err(err) => eprintln!("write error: {}", err),
         }

         let mut pk_share_vec: Vec<Point<Secp256k1>> = self.pk_share_vec.as_ref().unwrap().clone();
         let vss_vec: Vec<VerifiableSS<Secp256k1>>= msg_vec.iter().map(|msg|msg.vss.commits.clone()).collect();
         for vss in vss_vec{
            for i in 1 ..=self.threashold_param.share_counts as usize{
                pk_share_vec[i-1] = pk_share_vec.get(i - 1).unwrap() + vss.get_point_commitment(i as u16);
            }
         }

        let mut pk_share_path = PathBuf::from(current_dir);
        let path = "src/node/node".to_string() + &self.id.unwrap().to_string() + "/pk_share.txt";
        pk_share_path.push(path);
        let mut pk_share_file = File::create(pk_share_path.clone());
        for pk_share in pk_share_vec{
            let file = pk_share_file.as_mut().unwrap();
            file.write_all(serde_json::to_string(&pk_share).unwrap().as_bytes()).unwrap();
            file.write_all(b"\n").unwrap();
        }
        Ok(())
    }
}



