use bulletproof::proofs::range_proof::{self, *};
use curv::arithmetic::traits::*;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use curv::BigInt;
use sha2::Sha256;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File;
use std::io::{Read, Write};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PointCommitments{
    g_vec:Vec<Point<Secp256k1>>,
    h_vec:Vec<Point<Secp256k1>>
}


pub fn get_point_commitment()
{
    let seed = BigInt::from_bytes(&[75, 90, 101, 110]);
    let g_vec = (0..32)
        .map(|i| {
            let kzen_label_i = BigInt::from(i as u32) + &seed;
            let hash_i = Sha256::new().chain_bigint(&kzen_label_i).result_bigint();
            generate_random_point(&Converter::to_bytes(&hash_i))
        })
        .collect::<Vec<Point<Secp256k1>>>();
    
    // can run in parallel to g_vec:
    let h_vec = (0..32)
        .map(|i| {
            let kzen_label_j = BigInt::from(32 as u32) + BigInt::from(i as u32) + &seed;
            let hash_j = Sha256::new().chain_bigint(&kzen_label_j).result_bigint();
            generate_random_point(&Converter::to_bytes(&hash_j))
        })
        .collect::<Vec<Point<Secp256k1>>>();
    let point_commitments = PointCommitments{g_vec,h_vec};
    let write_json_data = serde_json::to_string(&point_commitments).unwrap();
    let mut file = File::create("src/cdl4osl_vss_scheme/point_commitments.json").unwrap();
    file.write_all(write_json_data.as_bytes()).unwrap();
}

pub fn get_point_commitment_default()->PointCommitments{
    let json_data = r#"{
        "g_vec":
        [
            {"curve":"secp256k1","point":"026c2bef05a3b2bfe333063e468aae8823aef0f2596f30683b162042c496caecec"},
            {"curve":"secp256k1","point":"02e884ddcd0a008faca0e69a049ecc215c33d51869cbc8a2654a7040157b14facc"},
            {"curve":"secp256k1","point":"029195dcedcc11aec553f48070f4b675cf96eb59303c353f55fd6db144ca952bf7"},
            {"curve":"secp256k1","point":"02178656e8118faf16dff179e6aa9abe94aecd1c6a4cdf77e057756c7bcd1fbaf1"},
            {"curve":"secp256k1","point":"029cc28fe40ac27813cf5a75baf15c6aae696ad981d95e794739bfed1d626b44e1"},
            {"curve":"secp256k1","point":"0291d4c356cddd38ce3117dfd2a036846423b3e6e9829ff03307ff0afc4456d702"},
            {"curve":"secp256k1","point":"02a053d4b1db513251b60162cf92d0c94f128598ce155a71e10e5f881707247055"},
            {"curve":"secp256k1","point":"02981dda3e2e64b510ad76e24022afdf3f39a2056786cc136b93981c9b7cec3a5b"},
            {"curve":"secp256k1","point":"02f6437cce19f0c4b83a5fb77e84b7c3b39d934228a5d10eb23c27bafb551f05d6"},
            {"curve":"secp256k1","point":"0251c1a09657537535f6d3cd81270b990b29bf3eb24c358d711ac04468b30e9e3a"},
            {"curve":"secp256k1","point":"02428513e7ece080c62e79f7e32e7559a1e3e2d66b3c6278cb901557f31b2a2bfa"},
            {"curve":"secp256k1","point":"02d756bfbe80fb517c7f1732822a574f73311ca6fca5f6a648ca12da0c3f527210"},
            {"curve":"secp256k1","point":"026f5f2901efeee20c5a50e42e2a1f5b1133e7f24ccf6bd26af63e396a97bfa6cb"},
            {"curve":"secp256k1","point":"0233ebb7bfaadc6f3a938ca2ab856f05f306c139109c31d38bb702ec06dc6b17a9"},
            {"curve":"secp256k1","point":"024974362895d0d3e2481abece29523924c591681f12703b7c27b2ef773da36cfe"},
            {"curve":"secp256k1","point":"021ed20ffd5935f6e54233b8eaab7bc33326bb705bb5d02e325ee4ec361d9b2164"},
            {"curve":"secp256k1","point":"025baf510e6d136b198da099b27206f841d8be164182fd070edef4c3cc9b532e8c"},
            {"curve":"secp256k1","point":"025a4ad72dce6c8761221e10cb8f13f65e5281052bc361f2ee22f7791bce79b800"},
            {"curve":"secp256k1","point":"023b38e8f800ced896124e067be5aff87eb328187f679f780c570d1342f9c2af83"},
            {"curve":"secp256k1","point":"02b867f41c0f5d1a636f36120e81100bc12dcaedc1c35c987ed9504d6b5d062177"},
            {"curve":"secp256k1","point":"026c51f260fb5878c4f31b9cd39bdec322c215ccf64333cb5d7c779700776062b4"},
            {"curve":"secp256k1","point":"0235a1db5601f12012864e52ff18e0d06703884dbda646566857abc115ead503ff"},
            {"curve":"secp256k1","point":"025f3bc2235515a849f2ba88e1e1e733797d447b84d6313ae18cbbe0d43bdb3246"},
            {"curve":"secp256k1","point":"025b170b83e5a4cb23565e9436a3d4150341a8f9177064cca86fd03243b2a2810a"},
            {"curve":"secp256k1","point":"029d676d9a364e79ef9c676d7a2ebca0a67e4d87957b659afdae4d5996012ca215"},
            {"curve":"secp256k1","point":"0206170d3671ad9bb94ba96bf78ac055f76e65fa91912f566f73ec0e3b5364844d"},
            {"curve":"secp256k1","point":"025d064c04779c1853572e17cc21c2414d074631fce0adf7a5115b0ccfe08dd5ff"},
            {"curve":"secp256k1","point":"028ada10c169f143166014628cf0b006929b09136edbcddc26b16b082237c46b2d"},
            {"curve":"secp256k1","point":"022a0aa59d0abb5df7bda535f2f22d9837ec44f03c6f6898c69b31ef474ad4db25"},
            {"curve":"secp256k1","point":"0274375d5df884782a1e155c86d903a39c5e335e059afbc0dd0a751689d232ca56"},
            {"curve":"secp256k1","point":"02ae6331b9511758cc6acbf7323d8b2f48d361ed67146aeabaa4d3bbd9d13a5e8c"},
            {"curve":"secp256k1","point":"02da99be826d29eb91cf48c0e4eb13e93c5332c162c86db3c49d344e010a77f4f2"}
        ],
        "h_vec":
        [
            {"curve":"secp256k1","point":"0269fc2788439557be37c2dd95748bf4946772da315e9dc6491ec0c72f5ece126b"},
            {"curve":"secp256k1","point":"028dc07e977c98cc2a5df661fca8c4e0c71945a99928f143e0219d6815d734ac16"},
            {"curve":"secp256k1","point":"029f13199ba7a2ea844f049413b63596a8f2dcc79d65a1737719e5a12da6ef919d"},
            {"curve":"secp256k1","point":"02278c4dac888f7adf08a154df7318027bbf366c5458585a0f8afc35f2169c144a"},
            {"curve":"secp256k1","point":"02ae7ca078302a6dd2a10ea052a1973810ebc608ec056c8299fc709f717312de17"},
            {"curve":"secp256k1","point":"021e2ad151f69ccaa842e6f36428598f4b49e325dc80a06eee387ed13c11f24840"},
            {"curve":"secp256k1","point":"024d764c4a254f0cbcf2192884c46afe3b6bb5150e5a4d60f95ae5d064cc250481"},
            {"curve":"secp256k1","point":"021a3a17677781abb01ecca35a48b25bb41dc620e79a70a350c647236f8b7a726e"},
            {"curve":"secp256k1","point":"0290dcd19fd77c47861a6078d005620c48394b59f7ed6e4710e7fcbdc6313e8b43"},
            {"curve":"secp256k1","point":"02b0bff1689adef7a604bd7d558dfcd2186e82cfa76b3e900b0cae9076ec72a40d"},
            {"curve":"secp256k1","point":"0233b043b0b56c80fa276c80f090ec5614be223de9430f09a76acc182031bb5766"},
            {"curve":"secp256k1","point":"023023e35bb837f19225812990215d0a9966b86a7e68ea97304d9a49ab2616200b"},
            {"curve":"secp256k1","point":"02ae92ea496dcc440062e6141fcb616f289ac0134a2fae1b910cd88f47d5c25f2a"},
            {"curve":"secp256k1","point":"0285b2486064b373cfeb281ee874f532c1767ecdb11fd0a556c47224adea1285c0"},
            {"curve":"secp256k1","point":"02226c3ea697a9f2b3def859d8009ddd62ce0fc7ba17518bf2f35dba2808cb5790"},
            {"curve":"secp256k1","point":"02e5fe2a23e77ff97e9f13988667f67aef23f3658c5c63aa58eae647ef70d8e12b"},
            {"curve":"secp256k1","point":"02a5ef6ed473d6337dcec2abd479914ed5ff1b5b14d008a86e06d3b86bde1efbed"},
            {"curve":"secp256k1","point":"02c4a42a5acfee7fb4d909583ba0838e83bd067196d02a343756b00d7a1a4f39ee"},
            {"curve":"secp256k1","point":"02cfe4a4f80bc4a44ac4221bfd22b8a4e9a30ae21fde85956f4a33bf5bf3ddb5e1"},
            {"curve":"secp256k1","point":"0291b673e189b11f4d17533549e8aae696035ba383143ea0ff1065259f85fb4734"},
            {"curve":"secp256k1","point":"021dfd7bfdd39b8f323de943e39237b4c4e33ebc762055938c0d156491343f577a"},
            {"curve":"secp256k1","point":"02b0e9e640deda2f804c81c9ee74932fcddb0893c00bb81e8b75c4d1b0b9289d60"},
            {"curve":"secp256k1","point":"02b5620ab508a07934ace3acaada0c474c3916325e74ebdc4e1278946747548058"},
            {"curve":"secp256k1","point":"02be223894810cdc2298432c0f442b5a5e052f86eed22a3cb0a5c6fa7eb7077864"},
            {"curve":"secp256k1","point":"02dda3b94c73bea5cea5f837172cb50c46bab60abae3e5770ca1f32e7c98e35ee0"},
            {"curve":"secp256k1","point":"02027a002c44a2d5212e07e228f60ca528266d5b24693f67df7fe2cf7e692b9b94"},
            {"curve":"secp256k1","point":"022510dfec467e2dd6c72e4835e85bdc3d502a042960ae178521ff228a2ca41892"},
            {"curve":"secp256k1","point":"025075202602631aebafe2a9513f5591d574bdc6a927497154df093e253c91118c"},
            {"curve":"secp256k1","point":"022f60d6c12538c2a7f32d21938e00d3195ecd649351770aa7032ba5a4f64aa789"},
            {"curve":"secp256k1","point":"02554e3a87d6f8649494056badc9dbebae745157a2873ce48f4b5ef321069af10f"},
            {"curve":"secp256k1","point":"0219eee7bb1e3665b293e7069978f079040cc1fe9716ef3d44ec145016ae26f13b"},
            {"curve":"secp256k1","point":"027f97f71f058da970cd4f6876d1e9463ec33e8d5f580a9b8fd48a201f88c226df"}
        ]
    }"#;
    let point_commitments: PointCommitments = serde_json::from_str(&json_data).unwrap();
    point_commitments

}

pub fn bulletproof_prove(
    secret: Vec<Scalar<Secp256k1>>,
    blinding: &[Scalar<Secp256k1>])
-> RangeProof{//n (bit length),m (number of secret)
    let point_commitments: PointCommitments = get_point_commitment_default();
    let g = Point::<Secp256k1>::generator();
    let h = Point::<Secp256k1>::base_point2();
    RangeProof::prove(&point_commitments.g_vec, &point_commitments.h_vec, &g, &h, secret, &blinding, 32)   
}

pub fn bulletproof_aggregated(
    range_proof:RangeProof,
    ped_coms: &[Point<Secp256k1>]
)-> bool{
    let point_commitments: PointCommitments = get_point_commitment_default();
    let g = Point::<Secp256k1>::generator();
    let h = Point::<Secp256k1>::base_point2();
    
    if RangeProof::aggregated_verify(&range_proof, &point_commitments.g_vec, &point_commitments.h_vec, &g, &h, &ped_coms, 32).is_ok(){
        true
    }
    else {
        false
    }
}

#[test]
pub fn test(){
    get_point_commitment();
}

#[test] pub fn proof_verify_test(){
    let range = BigInt::from(2).pow(32 as u32);
    let secret = vec![Scalar::<Secp256k1>::from(&BigInt::sample_below(&range))];
    let blinding = &[Scalar::<Secp256k1>::random()];

    let seed = BigInt::from_bytes(&[75, 90, 101, 110]);
    let g_vec = (0..32)
        .map(|i| {
            let kzen_label_i = BigInt::from(i as u32) + &seed;
            let hash_i = Sha256::new().chain_bigint(&kzen_label_i).result_bigint();
            generate_random_point(&Converter::to_bytes(&hash_i))
        })
        .collect::<Vec<Point<Secp256k1>>>();
    
    // can run in parallel to g_vec:
    let h_vec = (0..32)
        .map(|i| {
            let kzen_label_j = BigInt::from(32 as u32) + BigInt::from(i as u32) + &seed;
            let hash_j = Sha256::new().chain_bigint(&kzen_label_j).result_bigint();
            generate_random_point(&Converter::to_bytes(&hash_j))
        })
        .collect::<Vec<Point<Secp256k1>>>();

    let point_commitments = PointCommitments{g_vec,h_vec};
    let g = Point::<Secp256k1>::generator();
    let h = Point::<Secp256k1>::base_point2();
    let range_proof = RangeProof::prove(&point_commitments.g_vec, &point_commitments.h_vec, &g, &h, secret.clone(), &blinding.clone(), 32)  ; 
    
    let ped_coms = (0..1)
    .map(|i| *&g * &secret[i] + *&h * &blinding[i])
    .collect::<Vec<Point<Secp256k1>>>();
    
    if RangeProof::aggregated_verify(&range_proof, &point_commitments.g_vec, &point_commitments.h_vec, &g, &h, &ped_coms, 32).is_ok(){
        println!("Success!");
    }
}
#[test]
pub fn proof_test(){
    let range = BigInt::from(2).pow(32 as u32);
    let secret = vec![Scalar::<Secp256k1>::from(&BigInt::sample_below(&range))];
    let blinding = &[Scalar::<Secp256k1>::random()];
    let range_proof = bulletproof_prove(secret.clone(), blinding);
    let g = Point::<Secp256k1>::generator();
    let h = Point::<Secp256k1>::base_point2();

    let ped_com_vec = (0..1)
    .map(|i| *&g * &secret[i] + *&h * &blinding[i])
    .collect::<Vec<Point<Secp256k1>>>();

    if bulletproof_aggregated(range_proof, &ped_com_vec){
        println!("Success!");
    }
        
}
