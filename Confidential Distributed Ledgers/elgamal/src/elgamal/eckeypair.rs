
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
pub type FE = Scalar<Secp256k1>;
pub type GE = Point<Secp256k1>;

#[derive(Clone, Debug)]
pub struct EcKeyPair {
    pub public_share: GE,
    pub secret_share: FE,
}

impl EcKeyPair {
    pub fn new() -> Self {
        let base = Point::generator();
        let secret_share: FE = Scalar::random();
        // let secret_share1: FE = Scalar::random();
        // let secret_total: FE = secret_share.clone() + secret_share1.clone();
        let public_share = base.clone() * &secret_share;
        Self {
            secret_share,
            public_share,
        }
    }

    pub fn from_sk(sk: FE) -> Self {
        let base = Point::generator();
        let public_share = base * &sk;
        Self {
            secret_share: sk,
            public_share,
        }
    }

    pub fn get_public_key(&self) -> &GE {
        &self.public_share
    }

    pub fn get_secret_key(&self) -> &FE {
        &self.secret_share
    }
}

#[test]
fn test(){
    
}
