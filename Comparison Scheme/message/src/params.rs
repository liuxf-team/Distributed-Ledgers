use serde::{Deserialize, Serialize};
use curv::elliptic::curves::{Secp256k1, Point};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreasholdParam{
    pub threshold: u16,
    pub share_counts: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Generators
{
    pub g:Point<Secp256k1>,
    pub h:Point<Secp256k1>
}
