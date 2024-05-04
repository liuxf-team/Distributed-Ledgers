use std::ops::Add;

use curv::{cryptographic_primitives::hashing::DigestExt, elliptic::curves::{Point, Scalar, Secp256k1}, BigInt};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use super::error::ElGamalError;
pub type CU = Secp256k1;
pub type FE = Scalar<Secp256k1>;
pub type GE = Point<Secp256k1>;

static HEX_TABLE :[char;16] = ['0','1','2','3','4','5','6','7','8','9',
                                        'A','B','C','D','E','F'];


#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ElgamalCipher {
    pub c1: GE,
    pub c2: GE,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncRightProof {
    pub zm: BigInt,
    pub zr: BigInt,
    pub e: BigInt
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchEncRightProof {
    pub c1_vec: Vec<Point<Secp256k1>>,
    pub c2_vec: Vec<Point<Secp256k1>>,
    pub total_zm: BigInt,
    pub total_zr: BigInt
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncEqualProof {
    pub zm: BigInt,
    pub zr1: BigInt,
    pub zr2: BigInt,
    pub e: BigInt
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecRightProof {
    pub zm: BigInt,
    pub e: BigInt
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchDecRightProof {
    pub t1: Point<Secp256k1>,
    pub t2_vec: Vec<Point<Secp256k1>>,
    pub zm: BigInt
}

impl ElgamalCipher {
    pub fn encrypt(pk: &GE, m: &FE) -> (Self, FE) {
        let base = Point::generator();
        let base2 = Point::base_point2();
        let r: FE = Scalar::random();
        let c1 = base * &r;
        let hr = pk * &r;
        let gm = base2 * m;
        let c2 = hr + gm;
        (ElgamalCipher { c1, c2 }, r)
    }
    pub fn encrypt_with_randomness(pk: &GE, m: &FE, r: &FE) -> Self {
        let base = Point::generator();
        let base2 = Point::base_point2();
        let c1 = base * r;
        let hr = pk * r;
        let gm = base2 * m;
        let c2 = hr + gm;
        ElgamalCipher { c1, c2 }
    }
    pub fn decrypt(&self, sk: &FE) -> GE {
        let c1x = self.c1.clone() * sk;
        let gm = self.c2.clone() - c1x;
        gm
    }
}

impl Add for ElgamalCipher {
    type Output = ElgamalCipher;

    fn add(self, rhs: ElgamalCipher) -> ElgamalCipher {
        ElgamalCipher {
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
        }
    }
}

impl EncRightProof{
    pub fn proof(pk: &GE, cip: ElgamalCipher, m: &FE, r: &FE) -> Self {
        let sm = FE::random();
        let sr = FE::random();
        let t = ElgamalCipher::encrypt_with_randomness(pk, &sm, &sr);
        let e = Sha256::new()
            .chain_points([pk, &cip.c1, &cip.c2, &t.c1, &t.c2])
            .result_scalar();
        let zm = e.clone() * m + sm;
        let zr = e.clone() * r + sr;
        EncRightProof{zm:zm.to_bigint(), zr:zr.to_bigint(), e:e.to_bigint()}
    }

    pub fn verify(&self, pk: &GE, cip: ElgamalCipher) -> Result<(), ElGamalError> {
        let cu = ElgamalCipher::encrypt_with_randomness(pk, &FE::from_bigint(&self.zm), &FE::from_bigint(&self.zr));
        let c1e = cip.c1.clone() * FE::from_bigint(&self.e);
        let c2e = cip.c2.clone() * FE::from_bigint(&self.e);
        let t1 = cu.c1 - c1e;
        let t2 = cu.c2 - c2e;
        let e = Sha256::new()
            .chain_points([pk, &cip.c1, &cip.c2, &t1, &t2])
            .result_scalar();
        if e == FE::from_bigint(&self.e){
            Ok(())
        } else {
            Err(ElGamalError::VerifyEncRightProofFailed)
        }
    }
}

impl BatchEncRightProof {
    pub fn proof(pk: &GE, cip_vec: Vec<ElgamalCipher>, m_vec: Vec<FE>, r_vec:Vec<FE>) -> Self{
        let mut total_zm = FE::from(0);
        let mut total_zr = FE::from(0);
        let mut c1_vec = Vec::new();
        let mut c2_vec = Vec::new();
        for i in 0 .. cip_vec.len(){
            let sm = FE::random();
            let sr = FE::random();
            let t = ElgamalCipher::encrypt_with_randomness(pk, &sm, &sr);
            let e = Sha256::new()
                .chain_points([pk, &cip_vec.get(i).unwrap().c1, &cip_vec.get(i).unwrap().c2, &t.c1, &t.c2])
                .result_scalar();
            c1_vec.push(t.c1);
            c2_vec.push(t.c2);
            let zm = e.clone() * m_vec.get(i).unwrap() + sm;
            let zr = e.clone() * r_vec.get(i).unwrap() + sr;
            total_zm = total_zm + zm;
            total_zr = total_zr + zr;
        }
        BatchEncRightProof{c1_vec, c2_vec, total_zm: total_zm.to_bigint(), total_zr: total_zr.to_bigint()}
    }
    pub fn verify(&self, pk: &GE, cip_vec: Vec<ElgamalCipher>) -> Result<(), ElGamalError>{
        let mut total_c1_left = GE::zero();
        let mut total_c2_left = GE::zero();
        let total_c1_right = GE::generator() * FE::from_bigint(&self.total_zr);
        let total_c2_right = GE::base_point2() * FE::from_bigint(&self.total_zm) + pk * FE::from_bigint(&self.total_zr);
        for i in  0 .. cip_vec.len(){
            let e = Sha256::new()
                .chain_points([pk, &cip_vec.get(i).unwrap().c1, &cip_vec.get(i).unwrap().c2, &self.c1_vec.get(i).unwrap(), &self.c2_vec.get(i).unwrap()])
                .result_scalar();
            total_c1_left = total_c1_left + self.c1_vec.get(i).unwrap() + cip_vec.get(i).unwrap().c1.clone() * e.clone();
            total_c2_left = total_c2_left + self.c2_vec.get(i).unwrap() + cip_vec.get(i).unwrap().c2.clone() * e.clone();
        }
        if total_c1_left == total_c1_right && total_c2_left == total_c2_right {
            Ok(())
        } else {
            Err(ElGamalError::VerifyBatchEncEqualProofFailed)
        }
    }
    pub fn batch_verify(batch_proof: Vec<BatchEncRightProof>, pk: &GE, batch_cip_vec: Vec<Vec<ElgamalCipher>>) -> Result<(), ElGamalError> {
        let mut total_c1_left = GE::zero();
        let mut total_c2_left = GE::zero();
        let mut total_zr = FE::zero();
        let mut total_zm = FE::zero();
        for proof in batch_proof.clone(){
            total_zr = total_zr.clone() + FE::from_bigint(&proof.total_zr);
            total_zm = total_zm.clone() + FE::from_bigint(&proof.total_zm);
            
        }
        let total_c1_right = GE::generator() * total_zr.clone();
        let total_c2_right = GE::base_point2() * total_zm + pk * total_zr;
        for i in 0 .. batch_proof.len(){
            let proof = batch_proof.get(i).unwrap();
            let cip_vec = batch_cip_vec.get(i).unwrap();
            for j in  0 .. cip_vec.len(){
                let e = Sha256::new()
                    .chain_points([pk, &cip_vec.get(j).unwrap().c1, &cip_vec.get(j).unwrap().c2, proof.c1_vec.get(j).unwrap(), proof.c2_vec.get(j).unwrap()])
                    .result_scalar();
                total_c1_left = total_c1_left + proof.c1_vec.get(j).unwrap() + cip_vec.get(j).unwrap().c1.clone() * e.clone();
                total_c2_left = total_c2_left + proof.c2_vec.get(j).unwrap() + cip_vec.get(j).unwrap().c2.clone() * e.clone();
            }
        }
        if total_c1_left == total_c1_right && total_c2_left == total_c2_right {
            Ok(())
        } else {
            Err(ElGamalError::VerifyBatchEncEqualProofFailed)
        }
    }
}

impl EncEqualProof{
    pub fn proof(pk1: &GE, pk2: &GE, cip1: ElgamalCipher,cip2: ElgamalCipher, m: &FE, r1: &FE, r2: &FE) -> Self {
        let sm = FE::random();
        let sr1 = FE::random();
        let sr2 = FE::random();
        let t1 = ElgamalCipher::encrypt_with_randomness(pk1, &sm, &sr1);
        let t2 = ElgamalCipher::encrypt_with_randomness(pk2, &sm, &sr2);
        let e = Sha256::new()
            .chain_points([pk1, pk2, &cip1.c1, &cip1.c2, &cip2.c1, &cip2.c2, &t1.c1, &t1.c2, &t2.c1, &t2.c2])
            .result_scalar();
        let zm = e.clone() * m + sm;
        let zr1 = e.clone() * r1 + sr1;
        let zr2 = e.clone() * r2 + sr2;
        EncEqualProof{zm:zm.to_bigint(), zr1:zr1.to_bigint(), zr2:zr2.to_bigint(), e:e.to_bigint()}
    }

    pub fn verify(&self, pk1: &GE, pk2: &GE, cip1: ElgamalCipher, cip2: ElgamalCipher) -> Result<(), ElGamalError> {
        let cu1 = ElgamalCipher::encrypt_with_randomness(pk1, &FE::from_bigint(&self.zm), &FE::from_bigint(&self.zr1));
        let cu2 = ElgamalCipher::encrypt_with_randomness(pk2, &FE::from_bigint(&self.zm), &FE::from_bigint(&self.zr2));
        let c11e = cip1.c1.clone() * FE::from_bigint(&self.e);
        let c12e = cip1.c2.clone() * FE::from_bigint(&self.e);
        let c21e = cip2.c1.clone() * FE::from_bigint(&self.e);
        let c22e = cip2.c2.clone() * FE::from_bigint(&self.e);
        let t11 = cu1.c1 - c11e;
        let t12 = cu1.c2 - c12e;
        let t21 = cu2.c1 - c21e;
        let t22 = cu2.c2 - c22e;
        let e = Sha256::new()
            .chain_points([pk1, pk2, &cip1.c1, &cip1.c2, &cip2.c1, &cip2.c2, &t11, &t12, &t21, &t22])
            .result_scalar();
        if e == FE::from_bigint(&self.e){
            Ok(())
        } else {
            Err(ElGamalError::VerifyEncEqualProofFailed)
        }
    }
}

impl DecRightProof{
    pub fn proof(pk_share: &GE, c1: &GE, dec_c1: &GE, sk: &FE) -> Self {
        let sm = FE::random();
        let t1 = GE::generator() * sm.clone();
        let t2 = c1 * sm.clone();
        let e = Sha256::new()
            .chain_points([pk_share, c1, dec_c1, &t1, &t2])
            .result_scalar();
        let zm = e.clone() * sk + sm;
        DecRightProof{zm:zm.to_bigint(), e:e.to_bigint()}
    }

    pub fn verify(&self, pk_share: &GE, c1: &GE, dec_c1: &GE) -> Result<(), ElGamalError> {
        let t1 = GE::generator() * FE::from_bigint(&self.zm) - pk_share * FE::from_bigint(&self.e);
        let t2 = c1 * FE::from_bigint(&self.zm)- dec_c1 * FE::from_bigint(&self.e);
        let e = Sha256::new()
            .chain_points([pk_share, c1, dec_c1, &t1, &t2])
            .result_scalar();
        if e == FE::from_bigint(&self.e){
            Ok(())
        } else {
            Err(ElGamalError::VerifyEncRightProofFailed)
        }
    }
}

impl BatchDecRightProof{
    pub fn proof(pk_share: &GE, c1_vec: Vec<GE>, dec_c1_vec: Vec<GE>, sk: FE) -> Self {
        let sm = FE::random();
        let t1 = GE::generator() * sm.clone();
        let mut t2_vec = Vec::new();
        for i in 0 .. c1_vec.len(){
            let t2 = c1_vec.get(i).unwrap().clone() * sm.clone();
            t2_vec.push(t2);
        }
        let e = Sha256::new()
        .chain_points([pk_share, &t1]).chain_points(t2_vec.iter()).chain_points(c1_vec.iter()).chain_points(dec_c1_vec.iter())
        .result_scalar();
        let zm = e.clone() * sk + sm;
        BatchDecRightProof{t1, t2_vec, zm:zm.to_bigint()}
    }

    pub fn verify(&self, pk_share: &GE, c1_vec: Vec<GE>, dec_c1_vec: Vec<GE>)-> Result<(), ElGamalError> {
        let e = Sha256::new()
        .chain_points([pk_share, &self.t1.clone()]).chain_points(self.t2_vec.iter()).chain_points(c1_vec.iter()).chain_points(dec_c1_vec.iter())
        .result_scalar();
        let total_t1_left = self.t1.clone() + pk_share * e.clone();
        let total_t1_right = GE::generator() *  FE::from_bigint(&self.zm);
        let mut total_t2_left = GE::zero();
        let mut total_t2_right = GE::zero();
       
        for i in 0 .. c1_vec.len(){
            total_t2_left = total_t2_left + self.t2_vec.get(i).unwrap() + dec_c1_vec.get(i).unwrap() * e.clone();
            total_t2_right = total_t2_right + c1_vec.get(i).unwrap() *  FE::from_bigint(&self.zm);
        }
        if total_t1_left == total_t1_right && total_t2_left == total_t2_right {
            Ok(())
        } else {
            Err(ElGamalError::VerifyBatchDecEqualProofFailed)
        }
    }

    pub fn batch_verify(batch_proof: Vec<BatchDecRightProof>, batch_pk_share: Vec<GE>, c1_vec: Vec<GE>, batch_dec_c1_vec: Vec<Vec<GE>>) -> Result<(), ElGamalError> {
        let mut total_zm = FE::zero();
        for proof in batch_proof.clone(){
            total_zm = total_zm + FE::from_bigint(&proof.zm);
        }
        
        let mut total_t1_left = GE::zero();
        let mut total_t2_left = GE::zero();
        let total_t1_right = GE::generator() * total_zm.clone();
        let mut total_t2_right = GE::zero();
    
        for c1 in c1_vec.clone(){
            total_t2_right = total_t2_right + c1 *  total_zm.clone();
        }

        for i in 0 .. batch_proof.len(){
            let proof = batch_proof.get(i).unwrap();
            let dec_c1_vec = batch_dec_c1_vec.get(i).unwrap();
            let e = Sha256::new()
            .chain_points([batch_pk_share.get(i).unwrap(), &proof.t1]).chain_points(proof.t2_vec.iter()).chain_points(c1_vec.iter()).chain_points(dec_c1_vec.iter())
            .result_scalar();
            total_t1_left = total_t1_left + proof.t1.clone() + batch_pk_share.get(i).unwrap() * e.clone();
            for j in 0 .. dec_c1_vec.len(){
                total_t2_left = total_t2_left + proof.t2_vec.get(j).unwrap() + dec_c1_vec.get(j).unwrap() * e.clone();
            }
        }
        if total_t1_left == total_t1_right && total_t2_left == total_t2_right {
            Ok(())
        } else {
            Err(ElGamalError::VerifyBatchDecEqualProofFailed)
        }
    }
}

pub fn to_hex(data : impl AsRef<[u8]>) -> String {
    let data = data.as_ref();
    let len = data.len();
    let mut res = String::with_capacity(len * 2);

    for i in 0..len {
        res.push(HEX_TABLE[usize::from(data[i] >> 4)] );
        res.push(HEX_TABLE[usize::from(data[i] & 0x0F)]);
    }
    res
}

pub fn map_share_to_new_params(index: BigInt, s: &[BigInt]) -> FE {
    let s_len = s.len();
    // add one to indices to get points
    let points: Vec<FE> = s.iter().map(|i| Scalar::from(i)).collect();

    let xi: FE = Scalar::from(&index);
    let num: FE = Scalar::from(&BigInt::from(1));
    let denum: FE = Scalar::from(&BigInt::from(1));
    let num = (0..s_len).fold(
        num,
        |acc, i| {
            if s[i] != index {
                acc * &points[i]
            } else {
                acc
            }
        },
    );
    let denum = (0..s_len).fold(denum, |acc, i| {
        if s[i] != index {
            let xj_sub_xi = &points[i] - &xi;
            acc * xj_sub_xi
        } else {
            acc
        }
    });
    let denum = denum.invert().unwrap();
    num * denum
}