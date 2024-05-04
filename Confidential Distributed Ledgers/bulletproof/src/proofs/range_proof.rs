#![allow(non_snake_case)]

/*

Copyright 2018 by Kzen Networks

This file is part of bulletproof library
(https://github.com/KZen-networks/bulletproof)

bulletproof is free software: you can redistribute
it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either
version 3 of the License, or (at your option) any later version.

@license GPL-3.0+ <https://github.com/KZen-networks/bulletproof/blob/master/LICENSE>
*/

// based on the paper: https://eprint.iacr.org/2017/1066.pdf

use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, ECPoint, Point, Scalar};
use curv::BigInt;
use sha2::Sha256;

use generic_array::{typenum::Unsigned, GenericArray};
use itertools::iterate;
use proofs::inner_product::InnerProductArg;
use std::ops::{Shl, Shr};
use Errors::{self, RangeProofError};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProof {
    A: Point<Secp256k1>,
    S: Point<Secp256k1>,
    T1: Point<Secp256k1>,
    T2: Point<Secp256k1>,
    tau_x: BigInt,
    miu: BigInt,
    tx: BigInt,
    inner_product_proof: InnerProductArg,
}

impl RangeProof {
    pub fn prove(
        g_vec: &[Point<Secp256k1>],
        h_vec: &[Point<Secp256k1>],
        G: &Point<Secp256k1>,
        H: &Point<Secp256k1>,
        mut secret: Vec<Scalar<Secp256k1>>,
        blinding: &[Scalar<Secp256k1>],
        bit_length: usize,
    ) -> RangeProof {
        let num_of_proofs = secret.len();
        //num of proofs times bit length
        let nm = num_of_proofs * bit_length;
        let alpha = Scalar::<Secp256k1>::random();
        let rho = Scalar::<Secp256k1>::random();

        let g_vec = g_vec.to_vec();
        let h_vec = h_vec.to_vec();

        let mut A = H * &alpha;
        let mut S = H * &rho;
        let two = BigInt::from(2);
        let one = BigInt::from(1);
        let order = Scalar::<Secp256k1>::group_order();

        //concat all secrets:
        secret.reverse();
        let secret_agg = secret
            .iter()
            .fold(BigInt::zero(), |acc, x| acc.shl(bit_length) + x.to_bigint());

        let aL = (0..nm)
            .map(|i| {
                let shr_secret = secret_agg.clone().shr(i);
                shr_secret.modulus(&two)
            })
            .collect::<Vec<BigInt>>();
        let aR = (0..nm)
            .map(|i| BigInt::mod_sub(&aL[i], &one, order))
            .collect::<Vec<BigInt>>();

        let secret_bits = (0..nm)
            .map(|i| {
                let bignum_bit: BigInt = aL[i].clone() & BigInt::one();
                let byte = BigInt::to_bytes(&bignum_bit);
                byte[0] == 1
            })
            .collect::<Vec<bool>>();
        let mut index: usize = 0;
        A = g_vec.iter().zip(secret_bits.clone()).fold(
            A,
            |acc, x| {
                if x.1 {
                    acc + x.0
                } else {
                    acc
                }
            },
        );

        A = h_vec
            .iter()
            .zip(secret_bits)
            .fold(A, |acc, x| if !x.1 { acc - x.0 } else { acc });

        let SR = (0..nm)
            .map(|_| Scalar::<Secp256k1>::random())
            .collect::<Vec<Scalar<Secp256k1>>>();
        let SL = (0..nm)
            .map(|_| Scalar::<Secp256k1>::random())
            .collect::<Vec<Scalar<Secp256k1>>>();

        S = SL.iter().zip(&SR).fold(S, |acc, x| {
            let g_vec_i_SLi = &g_vec[index] * x.0;
            let h_vec_i_SRi = &h_vec[index] * x.1;
            index += 1;
            let SRhi_plus_SLgi = h_vec_i_SRi + g_vec_i_SLi;
            acc + SRhi_plus_SLgi
        });

        let y = Sha256::new().chain_points([&A, &S]).result_scalar();
        let base_point = Point::<Secp256k1>::generator();
        let yG: Point<Secp256k1> = base_point * &y;
        let z: Scalar<Secp256k1> = Sha256::new().chain_points([&yG]).result_scalar();
        let z_bn = z.to_bigint();

        let one_fe = Scalar::<Secp256k1>::from(&one);
        let yi = iterate(one_fe.clone(), |i| i.clone() * &y)
            .take(nm)
            .collect::<Vec<Scalar<Secp256k1>>>();

        let t2 = (0..nm)
            .map(|i| SR[i].clone() * &yi[i] * &SL[i])
            .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + x);
        let t2 = t2.to_bigint();

        let two_fe = Scalar::<Secp256k1>::from(&two);
        let vec_2n = iterate(one_fe, |i| i.clone() * &two_fe)
            .take(bit_length)
            .collect::<Vec<Scalar<Secp256k1>>>();

        let t1 = (0..nm)
            .map(|i| {
                let t1_1 = BigInt::mod_add(&aR[i], &z_bn, order);
                let t1_2 = BigInt::mod_mul(&t1_1, &yi[i].to_bigint(), order);
                let t1_3 = BigInt::mod_mul(&SL[i].to_bigint(), &t1_2, order);
                let t1_4 = BigInt::mod_sub(&aL[i], &z_bn, order);
                let t1_5 = BigInt::mod_mul(&SR[i].to_bigint(), &yi[i].to_bigint(), order);
                let t1_6 = BigInt::mod_mul(&t1_4, &t1_5, order);
                let j = i / bit_length + 2;
                let k = i % bit_length;
                let z_index = BigInt::mod_pow(&z_bn, &BigInt::from(j as u32), order);
                let two_to_the_i = vec_2n[k].clone().to_bigint();
                let t1_7 = BigInt::mod_mul(&z_index, &two_to_the_i, order);
                let t1_8 = BigInt::mod_mul(&t1_7, &SL[i].to_bigint(), order);
                let t1_68 = BigInt::mod_add(&t1_6, &t1_8, order);
                BigInt::mod_add(&t1_3, &t1_68, order)
            })
            .fold(BigInt::zero(), |acc, x| BigInt::mod_add(&acc, &x, order));

        let tau1 = Scalar::<Secp256k1>::random();
        let tau2 = Scalar::<Secp256k1>::random();
        let t1_fe = Scalar::<Secp256k1>::from(&t1);
        let t2_fe = Scalar::<Secp256k1>::from(&t2);
        let T1 = G * &t1_fe + H * &tau1;
        let T2 = G * &t2_fe + H * &tau2;

        let fs_challenge = Sha256::new().chain_points([&T1, &T2, G, H]).result_scalar();
        let fs_challenge_square = &fs_challenge * &fs_challenge;
        let taux_1 = &fs_challenge * &tau1;
        let taux_2 = fs_challenge_square * &tau2;
        let taux_3 = (0..num_of_proofs)
            .map(|i| {
                let j = BigInt::mod_add(&two, &BigInt::from(i as u32), order);
                let z_j = BigInt::mod_pow(&z_bn, &j, order);
                let z_j_fe = Scalar::<Secp256k1>::from(&z_j);
                z_j_fe * &blinding[i]
            })
            .fold(taux_2, |acc, x| acc + &x);
        let tau_x = taux_1 + &taux_3;
        let miu = (rho * &fs_challenge) + &alpha;

        let Lp = (0..nm)
            .map(|i| {
                let Lp_1 = (&SL[i] * &fs_challenge).to_bigint();
                let Lp_2 = BigInt::mod_sub(&aL[i], &z_bn, order);
                BigInt::mod_add(&Lp_1, &Lp_2, order)
            })
            .collect::<Vec<BigInt>>();

        let Rp = (0..nm)
            .map(|i| {
                let Rp_1 = (&SR[i] * &fs_challenge).to_bigint();

                let j = i / bit_length + 2;
                let k = i % bit_length;
                let z_index = BigInt::mod_pow(&z_bn, &BigInt::from(j as u32), order);
                let two_to_the_i = vec_2n[k].clone().to_bigint();
                let Rp_2 = BigInt::mod_mul(&z_index, &two_to_the_i, order);
                let Rp_3 = BigInt::mod_add(&BigInt::mod_add(&z_bn, &aR[i], order), &Rp_1, order);
                let Rp_4 = BigInt::mod_mul(&yi[i].to_bigint(), &Rp_3, order);
                BigInt::mod_add(&Rp_4, &Rp_2, order)
            })
            .collect::<Vec<BigInt>>();
        let tx = Lp.iter().zip(&Rp).fold(BigInt::zero(), |acc, x| {
            let Lp_iRp_i = BigInt::mod_mul(x.0, x.1, order);
            BigInt::mod_add(&acc, &Lp_iRp_i, order)
        });
        let tx_fe = Scalar::<Secp256k1>::from(&tx);

        let challenge_x: Scalar<Secp256k1> = Sha256::new()
            .chain_bigint(&tau_x.to_bigint())
            .chain_bigint(&miu.to_bigint())
            .chain_bigint(&tx)
            .result_scalar();
        let Gx = G * &challenge_x;
        // P' = u^{xc}
        let P = &Gx * &tx_fe;

        let yi_inv = (0..nm)
            .map(|i| {
                //     let yi_fe = Scalar::<Secp256k1>::from(&yi[i]);
                //     yi_fe.invert()
                yi[i].invert().unwrap()
            })
            .collect::<Vec<Scalar<Secp256k1>>>();

        let hi_tag = (0..nm)
            .map(|i| &h_vec[i] * &yi_inv[i])
            .collect::<Vec<Point<Secp256k1>>>();

        // P' = P' g^l
        let P = g_vec.iter().zip(&Lp).fold(P, |acc, x| {
            let g_vec_i_lp_i = x.0 * &Scalar::<Secp256k1>::from(x.1);
            acc + g_vec_i_lp_i
        });
        // P' = P' h'^r
        let P = hi_tag.iter().zip(&Rp).fold(P, |acc, x| {
            let h_vec_i_rp_i = x.0 * &Scalar::<Secp256k1>::from(x.1);
            acc + h_vec_i_rp_i
        });
        // line 9
        // public input : g,h,u^x,P' = g_vec, hi_tag, Gx,P
        // private input: a,b  = Lp,Rp
        let L_vec = Vec::with_capacity(nm);
        let R_vec = Vec::with_capacity(nm);
        let inner_product_proof =
            InnerProductArg::prove(&g_vec, &hi_tag, &Gx, &P, &Lp, &Rp, L_vec, R_vec);

        RangeProof {
            A,
            S,
            T1,
            T2,
            tau_x:tau_x.to_bigint(),
            miu:miu.to_bigint(),
            tx: tx_fe.to_bigint(),
            inner_product_proof,
        }
    }

    pub fn prove_warpper(pk: Point<Secp256k1>, secret:Scalar<Secp256k1>, blinding:Scalar<Secp256k1>) -> RangeProof {
        let G = Point::base_point2();
        let H = pk;
        let g_vec: Vec<Point<Secp256k1>> = vec![
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"020d01d3c9e27471eb9cc5a47b1ecccb918b04d82c34074daa7d7e6c522747df0a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"029c2d729055e611d80efbd5d0480c06f972967b815e7e6bba103febee258e9ad3\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02e9f8bd09d2077eb938db28cf36573a55e2099dbb5ee8f53bc6c3d1a0029a70e1\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"022fff73f059ebc4406b85529a75029b8ee5b8b3bb5e8c1ffc2dd4a8634abe6559\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024837b26c996e1ad3a879f8fc3ad770cf08c64d31703cd1f78bb585fcbf752764\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02bbd167a864979d8ee813f538c27a3968d58b4eb441691c4ecd78531ae1544421\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"021dc248aeecc395ff4d22bed40a48c580d36b0acc69c33ef06da2b349764301ab\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02f797cb99597d7f46ad13aad9f815961018795cb68dce7bcf711e6fcd7d872599\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d227a14d72e517419b533354934ee99ecd24afc650dfd935ec8103f2993e851f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0229f75b227588a7e45f7245ad06d1a04969a51d3703470f12c9a6e8ffdf8bdb85\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"025806386aaea71ebdfbc4ad93c5ed02160fc0aa2069db8bad20dc0aff6c18e1e2\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0281179d4ca54a7545dba26d1c81dd581a4b16c86ccc5baf0bf10f1c63d04a2b5f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d266d366124d85cb4fe10a54291bb69428809dd1e7a475a536c74b1da7173019\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024bf8f9cb91bcfdd94a639917b4504ea0cc491b41d4d982e8d52a991e8f239e3b\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"022364c1834b1e912b73f767e1650f45cce6076e8a5915b718340e601ed9163ce4\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0226ea1e207f59e04c9271da55ca5f6f3cbe1c83a055b58542089c9e2aa3a0cee3\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024e735df955547c735e4aca2fea4b38508850ece86f7e4a5ee9c1875227a246a9\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0210514f544b3253d50e5d3864f9ada8fc9a60823e943721374e028ba49315a0e9\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02a458a5589f4d7852811e480490947de439857ee1b6bb297ecedba0f9f6185367\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0216708a40d47c0167075884ee6111d3c170c04ad91e37c0c517b4adb57b3be692\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024200a09e230d45ad38fa5be8c04d166e6ccc1d602596fd831298d3477d230070\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0299554a5399e76a15cd3504c25448e3e88bb4cfdb26ef56fed0d89bd50fd12e74\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02fc22357ff06f737b9431c244b63d2971b689daa4c62d92153f139dfd7df7c827\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02b4623459a4a545274de635234d09146ebb0b7ef5567247667f4429dc9d6d9c6a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0229eb853d8672ae0bc00930ec8158f1af547c57ff16bdab5ed08d28795576eee6\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d9c756eb91131d28387b1f7d756d4306978df4fa48253f10b95d7d4f1749a5f8\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"025b6bdd212e65977298b65043dacfb97826ec912401427e92ccd0ff80f2f33a4f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0225adbe28940d98140a9a452cbd6525a90564c47a2d0cdd619c01cfdba2c50614\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024b3a31fa09b0a1c89b44d252a6ebc05cce2549fb7306959491bd159c3b0073c5\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02088103e6dac035ab180244aafea0ca55890bac05518daa8b0968ed118ecaebb7\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02ecb3939af4c089ea0042356dbbd2fea9cf9febec0ef283a74bcc9f75a99a539c\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"029c7fb23a00af9358b3151163c9744b2a0eed934660da3f4925054126454ee66a\"}").unwrap(),
        ];
       
        let h_vec: Vec<Point<Secp256k1>> = vec![
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0258714ff3bde3fa308184a97e2be10b8602d7d4b63991db50c842546a5ede10ab\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02695db2b479cfe4fbad003dc4b3716185a89b8bb088c9a683f9c830f3e16ff3dd\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0240e6118507302626c18cedf7f557b7908ec13bdaf0f9a24d1e98cd9ddd27402e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02adb07d81cc84337e4c9c84675f6d3f08087234e12dbef21f1af90afde8f2032d\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0231812b2b9891c432c618a30653a81a8f02b14717cd84dc840cbd50f08e15fcbd\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02765053c718ccbdfa4716c32d9fe1f3e75d7414ae8d2f519ffa9735a46125d0c6\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"025f3e2eb992b3bb710b33031f17c338d17c7b7eead5e9857dde679c8c0563d414\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0234a1c7d43b38fb0044dc08810827b84229ac633c68572b89192122bb88f8ac6a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d7114f8266e0dded972a606ca1da660c2b23e0d7762ae7543020689bfb1a8668\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d080f064db0bf8be8a27df1359ad2cf400430bff5e1ccb2136ea6a34f522624e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02e07984db34a99c19c7bf6a5359086764b6234ea04761d33d13c5ba947180e96f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0215ae4fa0d39da97c9c78188a01f582aad1387afbed38849e77909b57f6fcd5b0\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0207c1871b5d714ba74124f50cf01ea6f71cf25e82a89216b7c8c962850886b23a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"023fb3a853a1e743ddcb020373a82a8009b660aa2c8491a723f153de564925f62c\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0202fc199149e967d48c09e904feb8ad9dd55e9ad3bbe3ff60a32a41c9cb68a5ab\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0260ff719e4186d3f66e0c1addfdcbd36017cdca290f994d8c10ef1d50fdcdbc1e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02bc0e7d9392f42e5b6c044812dc2a43db124de4d7862a7a4924fd06a3cc291262\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024b45a688dcf30487e9cdcbb5da4d67082e060046e6d1fe350988c82bd231d3a8\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02a54ea11201af6adb46116ff2b480edb3a038335f0094ef71ea515ec591b0e529\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02c50500d1be94881d183209db5c87830956d9b8ecd513b651e70db4b5c859a1d9\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0212e911e107b40265041aa77f275930610f4ab50a0cf3d02323d033749aab5b60\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02b909628ce1d7081b27279954889e2229806dcd34b18bf3f4ca8014b5ff1c92f7\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0251d62d8aa82fb65b2fd52ea23e95b3fb6a7abf27cb5b5a81c20f54ca0d9f882b\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02df02e25fb530982bb30330c7230c44cb81374bd14d969ace702b62d82cf73255\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02dc4fb76e8381152b206ee272146025b6a1bb74fdf3a2921652cccb81dd4394e5\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"023a50330a7f7616ee713cde46a0e1668709b26716fd5a06094080adfe293bcc36\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"028efec4f432abc2b196ac931726f9a8244604f65503372916d1916d07ff729826\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02c56cd07d5a5030532330d422bd146859ff2a22e3cb2b60fddb5476d2c474702a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0253e1f76f930412acb9a13b7a62416cefe0c1eb332167c5ae25d20622e16a1908\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0279ca51708212d42bfa325eef1d86834c2e2a80ffa6c4949b9719cee49344dc1e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"023d3a216c77e4a9c76839bbbfd117f7acf6fc30e54dab32bf1a2bc73319373572\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02c36d2905537ce46d02fd780ba57de5bee7546388ac2d965364a4279c8f609688\"}").unwrap(),
        ];

        let mut v_vec = Vec::new();
        v_vec.push(secret);
    
        let r_vec = [blinding];

        Self::prove(&g_vec, &h_vec, &G, &H, v_vec, &r_vec, 32)
    }

    pub fn batch_prove_warpper(pk: Point<Secp256k1>, v_vec:Vec<Scalar<Secp256k1>>, r_vec:Vec<Scalar<Secp256k1>>) -> RangeProof {
        let G = Point::base_point2();
        let H = pk;
        let g_vec: Vec<Point<Secp256k1>> = vec![
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"020d01d3c9e27471eb9cc5a47b1ecccb918b04d82c34074daa7d7e6c522747df0a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"029c2d729055e611d80efbd5d0480c06f972967b815e7e6bba103febee258e9ad3\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02e9f8bd09d2077eb938db28cf36573a55e2099dbb5ee8f53bc6c3d1a0029a70e1\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"022fff73f059ebc4406b85529a75029b8ee5b8b3bb5e8c1ffc2dd4a8634abe6559\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024837b26c996e1ad3a879f8fc3ad770cf08c64d31703cd1f78bb585fcbf752764\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02bbd167a864979d8ee813f538c27a3968d58b4eb441691c4ecd78531ae1544421\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"021dc248aeecc395ff4d22bed40a48c580d36b0acc69c33ef06da2b349764301ab\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02f797cb99597d7f46ad13aad9f815961018795cb68dce7bcf711e6fcd7d872599\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d227a14d72e517419b533354934ee99ecd24afc650dfd935ec8103f2993e851f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0229f75b227588a7e45f7245ad06d1a04969a51d3703470f12c9a6e8ffdf8bdb85\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"025806386aaea71ebdfbc4ad93c5ed02160fc0aa2069db8bad20dc0aff6c18e1e2\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0281179d4ca54a7545dba26d1c81dd581a4b16c86ccc5baf0bf10f1c63d04a2b5f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d266d366124d85cb4fe10a54291bb69428809dd1e7a475a536c74b1da7173019\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024bf8f9cb91bcfdd94a639917b4504ea0cc491b41d4d982e8d52a991e8f239e3b\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"022364c1834b1e912b73f767e1650f45cce6076e8a5915b718340e601ed9163ce4\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0226ea1e207f59e04c9271da55ca5f6f3cbe1c83a055b58542089c9e2aa3a0cee3\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024e735df955547c735e4aca2fea4b38508850ece86f7e4a5ee9c1875227a246a9\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0210514f544b3253d50e5d3864f9ada8fc9a60823e943721374e028ba49315a0e9\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02a458a5589f4d7852811e480490947de439857ee1b6bb297ecedba0f9f6185367\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0216708a40d47c0167075884ee6111d3c170c04ad91e37c0c517b4adb57b3be692\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024200a09e230d45ad38fa5be8c04d166e6ccc1d602596fd831298d3477d230070\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0299554a5399e76a15cd3504c25448e3e88bb4cfdb26ef56fed0d89bd50fd12e74\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02fc22357ff06f737b9431c244b63d2971b689daa4c62d92153f139dfd7df7c827\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02b4623459a4a545274de635234d09146ebb0b7ef5567247667f4429dc9d6d9c6a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0229eb853d8672ae0bc00930ec8158f1af547c57ff16bdab5ed08d28795576eee6\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d9c756eb91131d28387b1f7d756d4306978df4fa48253f10b95d7d4f1749a5f8\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"025b6bdd212e65977298b65043dacfb97826ec912401427e92ccd0ff80f2f33a4f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0225adbe28940d98140a9a452cbd6525a90564c47a2d0cdd619c01cfdba2c50614\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024b3a31fa09b0a1c89b44d252a6ebc05cce2549fb7306959491bd159c3b0073c5\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02088103e6dac035ab180244aafea0ca55890bac05518daa8b0968ed118ecaebb7\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02ecb3939af4c089ea0042356dbbd2fea9cf9febec0ef283a74bcc9f75a99a539c\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"029c7fb23a00af9358b3151163c9744b2a0eed934660da3f4925054126454ee66a\"}").unwrap(),
        ];
       
        let h_vec: Vec<Point<Secp256k1>> = vec![
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0258714ff3bde3fa308184a97e2be10b8602d7d4b63991db50c842546a5ede10ab\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02695db2b479cfe4fbad003dc4b3716185a89b8bb088c9a683f9c830f3e16ff3dd\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0240e6118507302626c18cedf7f557b7908ec13bdaf0f9a24d1e98cd9ddd27402e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02adb07d81cc84337e4c9c84675f6d3f08087234e12dbef21f1af90afde8f2032d\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0231812b2b9891c432c618a30653a81a8f02b14717cd84dc840cbd50f08e15fcbd\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02765053c718ccbdfa4716c32d9fe1f3e75d7414ae8d2f519ffa9735a46125d0c6\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"025f3e2eb992b3bb710b33031f17c338d17c7b7eead5e9857dde679c8c0563d414\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0234a1c7d43b38fb0044dc08810827b84229ac633c68572b89192122bb88f8ac6a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d7114f8266e0dded972a606ca1da660c2b23e0d7762ae7543020689bfb1a8668\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d080f064db0bf8be8a27df1359ad2cf400430bff5e1ccb2136ea6a34f522624e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02e07984db34a99c19c7bf6a5359086764b6234ea04761d33d13c5ba947180e96f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0215ae4fa0d39da97c9c78188a01f582aad1387afbed38849e77909b57f6fcd5b0\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0207c1871b5d714ba74124f50cf01ea6f71cf25e82a89216b7c8c962850886b23a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"023fb3a853a1e743ddcb020373a82a8009b660aa2c8491a723f153de564925f62c\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0202fc199149e967d48c09e904feb8ad9dd55e9ad3bbe3ff60a32a41c9cb68a5ab\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0260ff719e4186d3f66e0c1addfdcbd36017cdca290f994d8c10ef1d50fdcdbc1e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02bc0e7d9392f42e5b6c044812dc2a43db124de4d7862a7a4924fd06a3cc291262\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024b45a688dcf30487e9cdcbb5da4d67082e060046e6d1fe350988c82bd231d3a8\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02a54ea11201af6adb46116ff2b480edb3a038335f0094ef71ea515ec591b0e529\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02c50500d1be94881d183209db5c87830956d9b8ecd513b651e70db4b5c859a1d9\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0212e911e107b40265041aa77f275930610f4ab50a0cf3d02323d033749aab5b60\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02b909628ce1d7081b27279954889e2229806dcd34b18bf3f4ca8014b5ff1c92f7\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0251d62d8aa82fb65b2fd52ea23e95b3fb6a7abf27cb5b5a81c20f54ca0d9f882b\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02df02e25fb530982bb30330c7230c44cb81374bd14d969ace702b62d82cf73255\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02dc4fb76e8381152b206ee272146025b6a1bb74fdf3a2921652cccb81dd4394e5\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"023a50330a7f7616ee713cde46a0e1668709b26716fd5a06094080adfe293bcc36\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"028efec4f432abc2b196ac931726f9a8244604f65503372916d1916d07ff729826\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02c56cd07d5a5030532330d422bd146859ff2a22e3cb2b60fddb5476d2c474702a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0253e1f76f930412acb9a13b7a62416cefe0c1eb332167c5ae25d20622e16a1908\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0279ca51708212d42bfa325eef1d86834c2e2a80ffa6c4949b9719cee49344dc1e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"023d3a216c77e4a9c76839bbbfd117f7acf6fc30e54dab32bf1a2bc73319373572\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02c36d2905537ce46d02fd780ba57de5bee7546388ac2d965364a4279c8f609688\"}").unwrap(),
        ];

        let batch_g_vec:Vec<Point<Secp256k1>>  = g_vec.iter().cloned().cycle().take(g_vec.len() * v_vec.len()).collect();
        let batch_h_vec:Vec<Point<Secp256k1>>  = h_vec.iter().cloned().cycle().take(h_vec.len() * v_vec.len()).collect();
        Self::prove(&batch_g_vec, &batch_h_vec, &G, &H, v_vec, &r_vec, 32)
    }

    pub fn verify(
        &self,
        g_vec: &[Point<Secp256k1>],
        h_vec: &[Point<Secp256k1>],
        G: &Point<Secp256k1>,
        H: &Point<Secp256k1>,
        ped_com: &[Point<Secp256k1>],
        bit_length: usize,
    ) -> Result<(), Errors> {
        let num_of_proofs = ped_com.len();
        let nm = num_of_proofs * bit_length;

        let y = Sha256::new()
            .chain_points([&self.A, &self.S])
            .result_scalar();
        let base_point = Point::<Secp256k1>::generator();
        let yG: Point<Secp256k1> = base_point * &y;
        let z: Scalar<Secp256k1> = Sha256::new().chain_points([&yG]).result_scalar();
        let z_bn = z.to_bigint();
        let order = Scalar::<Secp256k1>::group_order();
        let z_minus = BigInt::mod_sub(order, &z.to_bigint(), order);
        let z_minus_fe = Scalar::<Secp256k1>::from(&z_minus);
        let z_squared = BigInt::mod_pow(&z.to_bigint(), &BigInt::from(2), order);
        // delta(x,y):
        let one_bn = BigInt::one();
        let one_fe = Scalar::<Secp256k1>::from(&one_bn);
        let yi = iterate(one_fe.clone(), |i| i.clone() * &y)
            .take(nm)
            .collect::<Vec<Scalar<Secp256k1>>>();

        let scalar_mul_yn = yi
            .iter()
            .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + x);
        let scalar_mul_yn = scalar_mul_yn.to_bigint();
        let two = BigInt::from(2);

        let two_fe = Scalar::<Secp256k1>::from(&two);
        let vec_2n = iterate(one_fe, |i| i.clone() * &two_fe)
            .take(bit_length)
            .collect::<Vec<Scalar<Secp256k1>>>();

        let scalar_mul_2n = vec_2n
            .iter()
            .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + x);
        let scalar_mul_2n = scalar_mul_2n.to_bigint();

        let z_cubed_scalar_mul_2n = (0..num_of_proofs)
            .map(|i| {
                let j = BigInt::mod_add(&BigInt::from(3), &BigInt::from(i as u32), order);
                let z_j = BigInt::mod_pow(&z_bn, &j, order);
                BigInt::mod_mul(&z_j, &scalar_mul_2n, order)
            })
            .fold(BigInt::zero(), |acc, x| BigInt::mod_add(&acc, &x, order));

        let z_minus_zsq = BigInt::mod_sub(&z_bn, &z_squared, order);
        let z_minus_zsq_scalar_mul_yn = BigInt::mod_mul(&z_minus_zsq, &scalar_mul_yn, order);
        let delta = BigInt::mod_sub(&z_minus_zsq_scalar_mul_yn, &z_cubed_scalar_mul_2n, order);

        let yi_inv = (0..nm)
            .map(|i| yi[i].invert().unwrap())
            .collect::<Vec<Scalar<Secp256k1>>>();

        let hi_tag = (0..nm)
            .map(|i| &h_vec[i] * &yi_inv[i])
            .collect::<Vec<Point<Secp256k1>>>();

        let fs_challenge = Sha256::new()
            .chain_points([&self.T1, &self.T2, G, H])
            .result_scalar();
        let fs_challenge_square = &fs_challenge * &fs_challenge;

        // eq 65:
        let Gtx = G * Scalar::<Secp256k1>::from(&self.tx);
        let Htaux = H * Scalar::<Secp256k1>::from(&self.tau_x);
        let left_side = Gtx + Htaux;
        let delta_fe = Scalar::<Secp256k1>::from(&delta);
        let Gdelta = G * &delta_fe;
        let Tx = &self.T1 * &fs_challenge;
        let Tx_sq = &self.T2 * &fs_challenge_square;

        let mut vec_ped_zm = (0..num_of_proofs)
            .map(|i| {
                let z_2_m = BigInt::mod_pow(&z_bn, &BigInt::from((2 + i) as u32), order);
                let z_2_m_fe = Scalar::<Secp256k1>::from(&z_2_m);
                &ped_com[i] * &z_2_m_fe
            })
            .collect::<Vec<Point<Secp256k1>>>();
        let vec_ped_zm_1 = vec_ped_zm.remove(0);
        let ped_com_sum = vec_ped_zm.iter().fold(vec_ped_zm_1, |acc, x| acc + x);
        let right_side = ped_com_sum + Gdelta + Tx + Tx_sq;

        let challenge_x = Sha256::new()
            .chain_bigint(&self.tau_x)
            .chain_bigint(&self.miu)
            .chain_bigint(&self.tx)
            .result_scalar();
        let Gx = G * &challenge_x;
        // P' = u^{xc}

        let P = &Gx * Scalar::<Secp256k1>::from(&self.tx);
        let minus_miu = BigInt::mod_sub(
            Scalar::<Secp256k1>::group_order(),
            &self.miu,
            Scalar::<Secp256k1>::group_order(),
        );
        let minus_miu_fe = Scalar::<Secp256k1>::from(&minus_miu);
        let Hmiu = H * &minus_miu_fe;
        let Sx = &self.S * &fs_challenge;
        let P = Hmiu + P + self.A.clone() + Sx;

        let P1 = (0..nm)
            .map(|i| {
                let z_yn = BigInt::mod_mul(&z_bn, &yi[i].to_bigint(), order);
                let j = i / bit_length;
                let k = i % bit_length;
                let z_j = BigInt::mod_pow(&z_bn, &BigInt::from((2 + j) as u32), order);
                let z_j_2_n = BigInt::mod_mul(&z_j, &vec_2n[k].to_bigint(), order);
                // let z_sq_2n = BigInt::mod_mul(&z_squared, &vec_2n[i], &order);
                let zyn_zsq2n = BigInt::mod_add(&z_yn, &z_j_2_n, order);
                let zyn_zsq2n_fe = Scalar::<Secp256k1>::from(&zyn_zsq2n);
                &hi_tag[i] * &zyn_zsq2n_fe
            })
            .fold(P, |acc, x| acc + x);

        let P = (0..nm)
            .map(|i| &g_vec[i] * &z_minus_fe)
            .fold(P1, |acc, x| acc + x);
        let verify = self.inner_product_proof.verify(g_vec, &hi_tag, &Gx, &P);
        if verify.is_ok() && left_side == right_side {
            Ok(())
        } else {
            Err(RangeProofError)
        }
    }

    pub fn fast_verify(
        &self,
        g_vec: &[Point<Secp256k1>],
        h_vec: &[Point<Secp256k1>],
        G: &Point<Secp256k1>,
        H: &Point<Secp256k1>,
        ped_com: &[Point<Secp256k1>],
        bit_length: usize,
    ) -> Result<(), Errors> {
        let num_of_proofs = ped_com.len();
        let nm = num_of_proofs * bit_length;

        let y = Sha256::new()
            .chain_points([&self.A, &self.S])
            .result_scalar();
        let base_point = Point::<Secp256k1>::generator();
        let yG: Point<Secp256k1> = base_point * &y;
        let z: Scalar<Secp256k1> = Sha256::new().chain_points([&yG]).result_scalar();
        let z_bn = z.to_bigint();
        let order = Scalar::<Secp256k1>::group_order();
        let z_minus = BigInt::mod_sub(order, &z.to_bigint(), order);
        let z_minus_fe = Scalar::<Secp256k1>::from(&z_minus);
        let z_squared = BigInt::mod_pow(&z.to_bigint(), &BigInt::from(2), order);
        // delta(x,y):
        let one_bn = BigInt::one();
        let one_fe = Scalar::<Secp256k1>::from(&one_bn);
        let yi = iterate(one_fe.clone(), |i| i.clone() * &y)
            .take(nm)
            .collect::<Vec<Scalar<Secp256k1>>>();

        let scalar_mul_yn = yi
            .iter()
            .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + x);
        let scalar_mul_yn = scalar_mul_yn.to_bigint();
        let two = BigInt::from(2);

        let two_fe = Scalar::<Secp256k1>::from(&two);
        let vec_2n = iterate(one_fe, |i| i.clone() * &two_fe)
            .take(bit_length)
            .collect::<Vec<Scalar<Secp256k1>>>();

        let scalar_mul_2n = vec_2n
            .iter()
            .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + x);
        let scalar_mul_2n = scalar_mul_2n.to_bigint();

        let z_cubed_scalar_mul_2n = (0..num_of_proofs)
            .map(|i| {
                let j = BigInt::mod_add(&BigInt::from(3), &BigInt::from(i as u32), order);
                let z_j = BigInt::mod_pow(&z_bn, &j, order);
                BigInt::mod_mul(&z_j, &scalar_mul_2n, order)
            })
            .fold(BigInt::zero(), |acc, x| BigInt::mod_add(&acc, &x, order));

        let z_minus_zsq = BigInt::mod_sub(&z_bn, &z_squared, order);
        let z_minus_zsq_scalar_mul_yn = BigInt::mod_mul(&z_minus_zsq, &scalar_mul_yn, order);
        let delta = BigInt::mod_sub(&z_minus_zsq_scalar_mul_yn, &z_cubed_scalar_mul_2n, order);

        let yi_inv = (0..nm)
            .map(|i| yi[i].invert().unwrap())
            .collect::<Vec<Scalar<Secp256k1>>>();

        let hi_tag = (0..nm)
            .map(|i| &h_vec[i] * &yi_inv[i])
            .collect::<Vec<Point<Secp256k1>>>();

        let fs_challenge = Sha256::new()
            .chain_points([&self.T1, &self.T2, G, H])
            .result_scalar();
        let fs_challenge_square = &fs_challenge * &fs_challenge;

        // eq 65:
        let Gtx = G * Scalar::<Secp256k1>::from(&self.tx);
        let Htaux = H * Scalar::<Secp256k1>::from(&self.tau_x);
        let left_side = Gtx + Htaux;
        let delta_fe = Scalar::<Secp256k1>::from(&delta);
        let Gdelta = G * &delta_fe;
        let Tx = &self.T1 * &fs_challenge;
        let Tx_sq = &self.T2 * &fs_challenge_square;

        let mut vec_ped_zm = (0..num_of_proofs)
            .map(|i| {
                let z_2_m = BigInt::mod_pow(&z_bn, &BigInt::from((2 + i) as u32), order);
                let z_2_m_fe = Scalar::<Secp256k1>::from(&z_2_m);
                &ped_com[i] * &z_2_m_fe
            })
            .collect::<Vec<Point<Secp256k1>>>();
        let vec_ped_zm_1 = vec_ped_zm.remove(0);
        let ped_com_sum = vec_ped_zm.iter().fold(vec_ped_zm_1, |acc, x| acc + x);
        let right_side = ped_com_sum + Gdelta + Tx + Tx_sq;

        let challenge_x = Sha256::new()
            .chain_bigint(&self.tau_x)
            .chain_bigint(&self.miu)
            .chain_bigint(&self.tx)
            .result_scalar();
        let Gx = G * &challenge_x;
        // P' = u^{xc}

        let P = &Gx * Scalar::<Secp256k1>::from(&self.tx);
        let minus_miu = BigInt::mod_sub(
            Scalar::<Secp256k1>::group_order(),
            &self.miu,
            Scalar::<Secp256k1>::group_order(),
        );
        let minus_miu_fe = Scalar::<Secp256k1>::from(&minus_miu);
        let Hmiu = H * &minus_miu_fe;
        let Sx = &self.S * &fs_challenge;
        let P = Hmiu + P + self.A.clone() + Sx;

        let P1 = (0..nm)
            .map(|i| {
                let z_yn = BigInt::mod_mul(&z_bn, &yi[i].to_bigint(), order);
                let j = i / bit_length;
                let k = i % bit_length;
                let z_j = BigInt::mod_pow(&z_bn, &BigInt::from((2 + j) as u32), order);
                let z_j_2_n = BigInt::mod_mul(&z_j, &vec_2n[k].to_bigint(), order);
                // let z_sq_2n = BigInt::mod_mul(&z_squared, &vec_2n[i], &order);
                let zyn_zsq2n = BigInt::mod_add(&z_yn, &z_j_2_n, order);
                let zyn_zsq2n_fe = Scalar::<Secp256k1>::from(&zyn_zsq2n);
                &hi_tag[i] * &zyn_zsq2n_fe
            })
            .fold(P, |acc, x| acc + x);

        let P = (0..nm)
            .map(|i| &g_vec[i] * &z_minus_fe)
            .fold(P1, |acc, x| acc + x);
        let verify = self
            .inner_product_proof
            .fast_verify(g_vec, &hi_tag, &Gx, &P);
        if verify.is_ok() && left_side == right_side {
            Ok(())
        } else {
            Err(RangeProofError)
        }
    }

    pub fn aggregated_verify(
        &self,
        g_vec: &[Point<Secp256k1>],
        h_vec: &[Point<Secp256k1>],
        G: &Point<Secp256k1>,
        H: &Point<Secp256k1>,
        ped_com: &[Point<Secp256k1>],
        bit_length: usize,
    ) -> Result<(), Errors> {
        let n = bit_length;
        let m = ped_com.len();
        let nm = m * n;
        let lg_nm = self.inner_product_proof.L.len();
        let order = Scalar::<Secp256k1>::group_order();
        let two = BigInt::from(2);
        let one = BigInt::from(1);
        let zero = BigInt::zero();

        // All of the input vectors must have the same length.
        assert_eq!(g_vec.len(), nm);
        assert_eq!(h_vec.len(), nm);
        assert!(nm.is_power_of_two(), "(n*m) must be a power of two!");
        assert!(
            lg_nm <= 64,
            "Not compatible for vector sizes greater than 2^64!"
        );

        // regenerate challenges y, z, x, x_u from transcript
        let y = Sha256::new()
            .chain_points([&self.A, &self.S])
            .result_scalar();
        let y_bn = y.to_bigint();
        let y_inv_bn = BigInt::mod_inv(&y_bn, order).unwrap();
        let base_point = Point::<Secp256k1>::generator();
        let yG: Point<Secp256k1> = base_point * &y;
        let z: Scalar<Secp256k1> = Sha256::new().chain_points([&yG]).result_scalar();
        let z_bn = z.to_bigint();
        let z_squared = BigInt::mod_pow(&z_bn, &BigInt::from(2), order);

        let challenge_x: Scalar<Secp256k1> = Sha256::new()
            .chain_points([&self.T1, &self.T2, G, H])
            .result_scalar();
        let challenge_x_sq = &challenge_x * &challenge_x;

        let x_u_fe = Sha256::new()
            .chain_bigint(&self.tau_x)
            .chain_bigint(&self.miu)
            .chain_bigint(&self.tx)
            .result_scalar();

        // ux = g^{x_u}
        let ux = G * &x_u_fe;

        // generate a random scalar to combine 2 verification equations
        let challenge_ver: Scalar<Secp256k1> = Sha256::new()
            .chain_points([&self.A, &self.S, &self.T1, &self.T2, G, H])
            .result_scalar();
        let challenge_ver_bn = challenge_ver.to_bigint();

        // z2_vec = (z^2, z^3, z^4, ..., z^{m+1})
        let z2_vec = iterate(z_squared.clone(), |i| i.clone() * &z_bn)
            .take(m)
            .collect::<Vec<BigInt>>();

        // y_vec = (1, y, y^2, ..., y^{nm-1})
        let y_vec = iterate(one.clone(), |i| i.clone() * &y_bn)
            .take(nm)
            .collect::<Vec<BigInt>>();

        // sum_y_pow = 1 + y + ... + y^{nm}
        let sum_y_pow = y_vec
            .iter()
            .fold(zero.clone(), |acc, x| BigInt::mod_add(&acc, x, order));

        // vec_2n = (1, 2, 2^2, 2^3, ..., 2^{n})
        let vec_2n = iterate(one.clone(), |i| i.clone() * &two)
            .take(n)
            .collect::<Vec<BigInt>>();

        // y_inv_vec = (1, y^{-1}, y^{-2}, ..., y^{-(nm-1)})
        let y_inv_vec = iterate(one, |i| i.clone() * &y_inv_bn)
            .take(nm)
            .collect::<Vec<BigInt>>();

        // d = z^2 d1 + z^3 d2 + ... + z^{m+1} dm
        // where dj = (0^{(j-1)n} || 2^{n} || 0^{(m-j)n}) \in \Z_q^{mn}
        let d = (0..nm)
            .map(|i| {
                let k = i % n;
                let two_i = vec_2n[k].clone();
                let j = i / n;
                let z_j_2 = z2_vec[j].clone();
                BigInt::mod_mul(&two_i, &z_j_2, order)
            })
            .collect::<Vec<BigInt>>();

        // sum_d = <1^{mn}, d>
        let sum_d = d
            .iter()
            .fold(zero.clone(), |acc, x| BigInt::mod_add(&acc, x, order));

        // compute delta(y, z):
        let z_minus_zsq = BigInt::mod_sub(&z_bn, &z_squared, order);
        let z_minus_zsq_sum_y = BigInt::mod_mul(&z_minus_zsq, &sum_y_pow, order);
        let sum_d_z = BigInt::mod_mul(&sum_d, &z_bn, order);
        let delta = BigInt::mod_sub(&z_minus_zsq_sum_y, &sum_d_z, order);

        // compute sg and sh vectors (unrolling ipp verification)
        let mut x_sq_vec: Vec<BigInt> = Vec::with_capacity(lg_nm);
        let mut x_inv_sq_vec: Vec<BigInt> = Vec::with_capacity(lg_nm);
        let mut minus_x_sq_vec: Vec<BigInt> = Vec::with_capacity(lg_nm);
        let mut minus_x_inv_sq_vec: Vec<BigInt> = Vec::with_capacity(lg_nm);
        let mut allinv = BigInt::one();
        for (Li, Ri) in self
            .inner_product_proof
            .L
            .iter()
            .zip(self.inner_product_proof.R.iter())
        {
            let x: Scalar<Secp256k1> = Sha256::new().chain_points([Li, Ri, &ux]).result_scalar();
            let x_bn = x.to_bigint();
            let x_inv_fe = x.invert().unwrap();
            let x_inv_bn = x_inv_fe.to_bigint();
            let x_sq_bn = BigInt::mod_mul(&x_bn, &x_bn, order);
            let x_inv_sq_bn = BigInt::mod_mul(&x_inv_fe.to_bigint(), &x_inv_fe.to_bigint(), order);

            x_sq_vec.push(x_sq_bn.clone());
            x_inv_sq_vec.push(x_inv_sq_bn.clone());
            minus_x_sq_vec.push(BigInt::mod_sub(&BigInt::zero(), &x_sq_bn, order));
            minus_x_inv_sq_vec.push(BigInt::mod_sub(&BigInt::zero(), &x_inv_sq_bn, order));
            allinv *= x_inv_bn;
        }

        let mut s: Vec<BigInt> = Vec::with_capacity(nm);
        s.push(allinv);
        for i in 1..nm {
            let lg_i =
                (std::mem::size_of_val(&nm) * 8) - 1 - ((i as usize).leading_zeros() as usize);
            let k = 1 << lg_i;
            // The challenges are stored in "creation order" as [x_k,...,x_1],
            // so u_{lg(i)+1} = is indexed by (lg_n-1) - lg_i
            let x_lg_i_sq = x_sq_vec[(lg_nm - 1) - lg_i].clone();
            s.push(s[i - k].clone() * x_lg_i_sq);
        }

        let a_times_s: Vec<BigInt> = (0..nm)
            .map(|i| BigInt::mod_mul(&s[i], &self.inner_product_proof.a_tag, order))
            .collect();

        let b_times_sinv: Vec<BigInt> = (0..nm)
            .map(|i| {
                let s_inv_i = BigInt::mod_inv(&s[i], order).unwrap();
                BigInt::mod_mul(&s_inv_i, &self.inner_product_proof.b_tag, order)
            })
            .collect();

        // exponent of g_vec
        let scalar_g_vec: Vec<BigInt> = (0..nm)
            .map(|i| BigInt::mod_add(&a_times_s[i], &z_bn, order))
            .collect();

        // exponent of h_vec
        let scalar_h_vec: Vec<BigInt> = (0..nm)
            .map(|i| {
                let b_sinv_plus_di = BigInt::mod_sub(&b_times_sinv[i], &d[i], order);
                let y_inv_b_sinv_plus_di = BigInt::mod_mul(&y_inv_vec[i], &b_sinv_plus_di, order);
                BigInt::mod_sub(&y_inv_b_sinv_plus_di, &z_bn, order)
            })
            .collect();

        // exponent of G
        let ab = BigInt::mod_mul(
            &self.inner_product_proof.a_tag,
            &self.inner_product_proof.b_tag,
            order,
        );
        let ab_minus_tx = BigInt::mod_sub(&ab, &self.tx, order);
        let scalar_G1 = BigInt::mod_mul(&x_u_fe.to_bigint(), &ab_minus_tx, order);

        let delta_minus_tx = BigInt::mod_sub(&delta, &self.tx, order);
        let scalar_G2 = BigInt::mod_mul(&challenge_ver_bn, &delta_minus_tx, order);

        let scalar_G = BigInt::mod_add(&scalar_G1, &scalar_G2, order);

        // exponent of H
        let c_times_taux = BigInt::mod_mul(&challenge_ver_bn, &self.tau_x, order);
        let scalar_H = BigInt::mod_sub(&self.miu, &c_times_taux, order);

        // exponents of A, S
        // let scalar_A = BigInt::mod_sub(&zero, &one, &order);
        let scalar_S = BigInt::mod_sub(&zero, &challenge_x.to_bigint(), order);

        // exponent of L, R
        let scalar_L = minus_x_sq_vec.clone();
        let scalar_R = minus_x_inv_sq_vec.clone();

        // exponents of commitments
        let scalar_coms: Vec<BigInt> = (0..m)
            .map(|i| BigInt::mod_mul(&challenge_ver_bn, &z2_vec[i], order))
            .collect();

        // exponents of T_1, T_2
        let scalar_T1 = BigInt::mod_mul(&challenge_ver_bn, &challenge_x.to_bigint(), order);
        let scalar_T2 = BigInt::mod_mul(&challenge_ver_bn, &challenge_x_sq.to_bigint(), order);

        // compute concatenated exponent vector
        let mut scalars: Vec<BigInt> = Vec::with_capacity(2 * nm + 2 * lg_nm + m + 6);
        scalars.extend_from_slice(&scalar_g_vec);
        scalars.extend_from_slice(&scalar_h_vec);
        scalars.push(scalar_G);
        // scalars.push(scalar_H);
        // scalars.push(scalar_A);
        scalars.push(scalar_S);
        scalars.extend_from_slice(&scalar_L);
        scalars.extend_from_slice(&scalar_R);
        scalars.extend_from_slice(&scalar_coms);
        scalars.push(scalar_T1);
        scalars.push(scalar_T2);

        // compute concatenated base vector
        let mut points: Vec<Point<Secp256k1>> = Vec::with_capacity(2 * nm + 2 * lg_nm + m + 6);
        points.extend_from_slice(g_vec);
        points.extend_from_slice(h_vec);
        points.push(G.clone());
        // points.push(*H);
        // points.push(self.A);
        points.push(self.S.clone());
        points.extend_from_slice(&self.inner_product_proof.L);
        points.extend_from_slice(&self.inner_product_proof.R);
        points.extend_from_slice(ped_com);
        points.push(self.T1.clone());
        points.push(self.T2.clone());

        let H_times_scalar_H = H * &Scalar::<Secp256k1>::from(&scalar_H);
        let tot_len = points.len();
        let lhs = (0..tot_len)
            .map(|i| &points[i] * &Scalar::<Secp256k1>::from(&scalars[i]))
            .fold(H_times_scalar_H, |acc, x| acc + x as Point<Secp256k1>);

        // single multi-exponentiation check
        if lhs == self.A {
            Ok(())
        } else {
            Err(RangeProofError)
        }
    }
    pub fn verify_warpper(&self, pk: Point<Secp256k1>, ped_com:Point<Secp256k1>) -> Result<(), Errors> {
        let G = Point::base_point2();
        let H = pk;
        let g_vec: Vec<Point<Secp256k1>> = vec![
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"020d01d3c9e27471eb9cc5a47b1ecccb918b04d82c34074daa7d7e6c522747df0a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"029c2d729055e611d80efbd5d0480c06f972967b815e7e6bba103febee258e9ad3\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02e9f8bd09d2077eb938db28cf36573a55e2099dbb5ee8f53bc6c3d1a0029a70e1\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"022fff73f059ebc4406b85529a75029b8ee5b8b3bb5e8c1ffc2dd4a8634abe6559\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024837b26c996e1ad3a879f8fc3ad770cf08c64d31703cd1f78bb585fcbf752764\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02bbd167a864979d8ee813f538c27a3968d58b4eb441691c4ecd78531ae1544421\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"021dc248aeecc395ff4d22bed40a48c580d36b0acc69c33ef06da2b349764301ab\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02f797cb99597d7f46ad13aad9f815961018795cb68dce7bcf711e6fcd7d872599\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d227a14d72e517419b533354934ee99ecd24afc650dfd935ec8103f2993e851f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0229f75b227588a7e45f7245ad06d1a04969a51d3703470f12c9a6e8ffdf8bdb85\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"025806386aaea71ebdfbc4ad93c5ed02160fc0aa2069db8bad20dc0aff6c18e1e2\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0281179d4ca54a7545dba26d1c81dd581a4b16c86ccc5baf0bf10f1c63d04a2b5f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d266d366124d85cb4fe10a54291bb69428809dd1e7a475a536c74b1da7173019\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024bf8f9cb91bcfdd94a639917b4504ea0cc491b41d4d982e8d52a991e8f239e3b\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"022364c1834b1e912b73f767e1650f45cce6076e8a5915b718340e601ed9163ce4\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0226ea1e207f59e04c9271da55ca5f6f3cbe1c83a055b58542089c9e2aa3a0cee3\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024e735df955547c735e4aca2fea4b38508850ece86f7e4a5ee9c1875227a246a9\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0210514f544b3253d50e5d3864f9ada8fc9a60823e943721374e028ba49315a0e9\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02a458a5589f4d7852811e480490947de439857ee1b6bb297ecedba0f9f6185367\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0216708a40d47c0167075884ee6111d3c170c04ad91e37c0c517b4adb57b3be692\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024200a09e230d45ad38fa5be8c04d166e6ccc1d602596fd831298d3477d230070\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0299554a5399e76a15cd3504c25448e3e88bb4cfdb26ef56fed0d89bd50fd12e74\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02fc22357ff06f737b9431c244b63d2971b689daa4c62d92153f139dfd7df7c827\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02b4623459a4a545274de635234d09146ebb0b7ef5567247667f4429dc9d6d9c6a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0229eb853d8672ae0bc00930ec8158f1af547c57ff16bdab5ed08d28795576eee6\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d9c756eb91131d28387b1f7d756d4306978df4fa48253f10b95d7d4f1749a5f8\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"025b6bdd212e65977298b65043dacfb97826ec912401427e92ccd0ff80f2f33a4f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0225adbe28940d98140a9a452cbd6525a90564c47a2d0cdd619c01cfdba2c50614\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024b3a31fa09b0a1c89b44d252a6ebc05cce2549fb7306959491bd159c3b0073c5\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02088103e6dac035ab180244aafea0ca55890bac05518daa8b0968ed118ecaebb7\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02ecb3939af4c089ea0042356dbbd2fea9cf9febec0ef283a74bcc9f75a99a539c\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"029c7fb23a00af9358b3151163c9744b2a0eed934660da3f4925054126454ee66a\"}").unwrap(),
        ];
        let h_vec: Vec<Point<Secp256k1>> = vec![
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0258714ff3bde3fa308184a97e2be10b8602d7d4b63991db50c842546a5ede10ab\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02695db2b479cfe4fbad003dc4b3716185a89b8bb088c9a683f9c830f3e16ff3dd\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0240e6118507302626c18cedf7f557b7908ec13bdaf0f9a24d1e98cd9ddd27402e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02adb07d81cc84337e4c9c84675f6d3f08087234e12dbef21f1af90afde8f2032d\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0231812b2b9891c432c618a30653a81a8f02b14717cd84dc840cbd50f08e15fcbd\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02765053c718ccbdfa4716c32d9fe1f3e75d7414ae8d2f519ffa9735a46125d0c6\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"025f3e2eb992b3bb710b33031f17c338d17c7b7eead5e9857dde679c8c0563d414\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0234a1c7d43b38fb0044dc08810827b84229ac633c68572b89192122bb88f8ac6a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d7114f8266e0dded972a606ca1da660c2b23e0d7762ae7543020689bfb1a8668\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d080f064db0bf8be8a27df1359ad2cf400430bff5e1ccb2136ea6a34f522624e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02e07984db34a99c19c7bf6a5359086764b6234ea04761d33d13c5ba947180e96f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0215ae4fa0d39da97c9c78188a01f582aad1387afbed38849e77909b57f6fcd5b0\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0207c1871b5d714ba74124f50cf01ea6f71cf25e82a89216b7c8c962850886b23a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"023fb3a853a1e743ddcb020373a82a8009b660aa2c8491a723f153de564925f62c\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0202fc199149e967d48c09e904feb8ad9dd55e9ad3bbe3ff60a32a41c9cb68a5ab\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0260ff719e4186d3f66e0c1addfdcbd36017cdca290f994d8c10ef1d50fdcdbc1e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02bc0e7d9392f42e5b6c044812dc2a43db124de4d7862a7a4924fd06a3cc291262\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024b45a688dcf30487e9cdcbb5da4d67082e060046e6d1fe350988c82bd231d3a8\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02a54ea11201af6adb46116ff2b480edb3a038335f0094ef71ea515ec591b0e529\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02c50500d1be94881d183209db5c87830956d9b8ecd513b651e70db4b5c859a1d9\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0212e911e107b40265041aa77f275930610f4ab50a0cf3d02323d033749aab5b60\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02b909628ce1d7081b27279954889e2229806dcd34b18bf3f4ca8014b5ff1c92f7\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0251d62d8aa82fb65b2fd52ea23e95b3fb6a7abf27cb5b5a81c20f54ca0d9f882b\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02df02e25fb530982bb30330c7230c44cb81374bd14d969ace702b62d82cf73255\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02dc4fb76e8381152b206ee272146025b6a1bb74fdf3a2921652cccb81dd4394e5\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"023a50330a7f7616ee713cde46a0e1668709b26716fd5a06094080adfe293bcc36\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"028efec4f432abc2b196ac931726f9a8244604f65503372916d1916d07ff729826\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02c56cd07d5a5030532330d422bd146859ff2a22e3cb2b60fddb5476d2c474702a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0253e1f76f930412acb9a13b7a62416cefe0c1eb332167c5ae25d20622e16a1908\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0279ca51708212d42bfa325eef1d86834c2e2a80ffa6c4949b9719cee49344dc1e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"023d3a216c77e4a9c76839bbbfd117f7acf6fc30e54dab32bf1a2bc73319373572\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02c36d2905537ce46d02fd780ba57de5bee7546388ac2d965364a4279c8f609688\"}").unwrap(),
        ];

        let mut ped_com_vec = Vec::new();
        ped_com_vec.push(ped_com);
        Self::aggregated_verify(&self, &g_vec, &h_vec, &G, &H, &ped_com_vec, 32)
    }
    pub fn batch_verify_warpper(&self, pk: Point<Secp256k1>, ped_com_vec:Vec<Point<Secp256k1>>) -> Result<(), Errors> {
        let G = Point::base_point2();
        let H = pk;
        let g_vec: Vec<Point<Secp256k1>> = vec![
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"020d01d3c9e27471eb9cc5a47b1ecccb918b04d82c34074daa7d7e6c522747df0a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"029c2d729055e611d80efbd5d0480c06f972967b815e7e6bba103febee258e9ad3\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02e9f8bd09d2077eb938db28cf36573a55e2099dbb5ee8f53bc6c3d1a0029a70e1\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"022fff73f059ebc4406b85529a75029b8ee5b8b3bb5e8c1ffc2dd4a8634abe6559\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024837b26c996e1ad3a879f8fc3ad770cf08c64d31703cd1f78bb585fcbf752764\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02bbd167a864979d8ee813f538c27a3968d58b4eb441691c4ecd78531ae1544421\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"021dc248aeecc395ff4d22bed40a48c580d36b0acc69c33ef06da2b349764301ab\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02f797cb99597d7f46ad13aad9f815961018795cb68dce7bcf711e6fcd7d872599\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d227a14d72e517419b533354934ee99ecd24afc650dfd935ec8103f2993e851f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0229f75b227588a7e45f7245ad06d1a04969a51d3703470f12c9a6e8ffdf8bdb85\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"025806386aaea71ebdfbc4ad93c5ed02160fc0aa2069db8bad20dc0aff6c18e1e2\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0281179d4ca54a7545dba26d1c81dd581a4b16c86ccc5baf0bf10f1c63d04a2b5f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d266d366124d85cb4fe10a54291bb69428809dd1e7a475a536c74b1da7173019\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024bf8f9cb91bcfdd94a639917b4504ea0cc491b41d4d982e8d52a991e8f239e3b\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"022364c1834b1e912b73f767e1650f45cce6076e8a5915b718340e601ed9163ce4\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0226ea1e207f59e04c9271da55ca5f6f3cbe1c83a055b58542089c9e2aa3a0cee3\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024e735df955547c735e4aca2fea4b38508850ece86f7e4a5ee9c1875227a246a9\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0210514f544b3253d50e5d3864f9ada8fc9a60823e943721374e028ba49315a0e9\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02a458a5589f4d7852811e480490947de439857ee1b6bb297ecedba0f9f6185367\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0216708a40d47c0167075884ee6111d3c170c04ad91e37c0c517b4adb57b3be692\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024200a09e230d45ad38fa5be8c04d166e6ccc1d602596fd831298d3477d230070\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0299554a5399e76a15cd3504c25448e3e88bb4cfdb26ef56fed0d89bd50fd12e74\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02fc22357ff06f737b9431c244b63d2971b689daa4c62d92153f139dfd7df7c827\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02b4623459a4a545274de635234d09146ebb0b7ef5567247667f4429dc9d6d9c6a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0229eb853d8672ae0bc00930ec8158f1af547c57ff16bdab5ed08d28795576eee6\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d9c756eb91131d28387b1f7d756d4306978df4fa48253f10b95d7d4f1749a5f8\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"025b6bdd212e65977298b65043dacfb97826ec912401427e92ccd0ff80f2f33a4f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0225adbe28940d98140a9a452cbd6525a90564c47a2d0cdd619c01cfdba2c50614\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024b3a31fa09b0a1c89b44d252a6ebc05cce2549fb7306959491bd159c3b0073c5\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02088103e6dac035ab180244aafea0ca55890bac05518daa8b0968ed118ecaebb7\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02ecb3939af4c089ea0042356dbbd2fea9cf9febec0ef283a74bcc9f75a99a539c\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"029c7fb23a00af9358b3151163c9744b2a0eed934660da3f4925054126454ee66a\"}").unwrap(),
        ];
        let h_vec: Vec<Point<Secp256k1>> = vec![
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0258714ff3bde3fa308184a97e2be10b8602d7d4b63991db50c842546a5ede10ab\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02695db2b479cfe4fbad003dc4b3716185a89b8bb088c9a683f9c830f3e16ff3dd\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0240e6118507302626c18cedf7f557b7908ec13bdaf0f9a24d1e98cd9ddd27402e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02adb07d81cc84337e4c9c84675f6d3f08087234e12dbef21f1af90afde8f2032d\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0231812b2b9891c432c618a30653a81a8f02b14717cd84dc840cbd50f08e15fcbd\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02765053c718ccbdfa4716c32d9fe1f3e75d7414ae8d2f519ffa9735a46125d0c6\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"025f3e2eb992b3bb710b33031f17c338d17c7b7eead5e9857dde679c8c0563d414\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0234a1c7d43b38fb0044dc08810827b84229ac633c68572b89192122bb88f8ac6a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d7114f8266e0dded972a606ca1da660c2b23e0d7762ae7543020689bfb1a8668\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02d080f064db0bf8be8a27df1359ad2cf400430bff5e1ccb2136ea6a34f522624e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02e07984db34a99c19c7bf6a5359086764b6234ea04761d33d13c5ba947180e96f\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0215ae4fa0d39da97c9c78188a01f582aad1387afbed38849e77909b57f6fcd5b0\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0207c1871b5d714ba74124f50cf01ea6f71cf25e82a89216b7c8c962850886b23a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"023fb3a853a1e743ddcb020373a82a8009b660aa2c8491a723f153de564925f62c\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0202fc199149e967d48c09e904feb8ad9dd55e9ad3bbe3ff60a32a41c9cb68a5ab\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0260ff719e4186d3f66e0c1addfdcbd36017cdca290f994d8c10ef1d50fdcdbc1e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02bc0e7d9392f42e5b6c044812dc2a43db124de4d7862a7a4924fd06a3cc291262\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"024b45a688dcf30487e9cdcbb5da4d67082e060046e6d1fe350988c82bd231d3a8\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02a54ea11201af6adb46116ff2b480edb3a038335f0094ef71ea515ec591b0e529\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02c50500d1be94881d183209db5c87830956d9b8ecd513b651e70db4b5c859a1d9\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0212e911e107b40265041aa77f275930610f4ab50a0cf3d02323d033749aab5b60\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02b909628ce1d7081b27279954889e2229806dcd34b18bf3f4ca8014b5ff1c92f7\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0251d62d8aa82fb65b2fd52ea23e95b3fb6a7abf27cb5b5a81c20f54ca0d9f882b\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02df02e25fb530982bb30330c7230c44cb81374bd14d969ace702b62d82cf73255\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02dc4fb76e8381152b206ee272146025b6a1bb74fdf3a2921652cccb81dd4394e5\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"023a50330a7f7616ee713cde46a0e1668709b26716fd5a06094080adfe293bcc36\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"028efec4f432abc2b196ac931726f9a8244604f65503372916d1916d07ff729826\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02c56cd07d5a5030532330d422bd146859ff2a22e3cb2b60fddb5476d2c474702a\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0253e1f76f930412acb9a13b7a62416cefe0c1eb332167c5ae25d20622e16a1908\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"0279ca51708212d42bfa325eef1d86834c2e2a80ffa6c4949b9719cee49344dc1e\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"023d3a216c77e4a9c76839bbbfd117f7acf6fc30e54dab32bf1a2bc73319373572\"}").unwrap(),
            serde_json::from_str("{\"curve\":\"secp256k1\",\"point\":\"02c36d2905537ce46d02fd780ba57de5bee7546388ac2d965364a4279c8f609688\"}").unwrap(),
        ];
        let batch_g_vec:Vec<Point<Secp256k1>>  = g_vec.iter().cloned().cycle().take(g_vec.len() * ped_com_vec.len()).collect();
        let batch_h_vec:Vec<Point<Secp256k1>>  = h_vec.iter().cloned().cycle().take(h_vec.len() * ped_com_vec.len()).collect();
        Self::aggregated_verify(&self, &batch_g_vec, &batch_h_vec, &G, &H, &ped_com_vec, 32)
    }
}

pub fn generate_random_point(bytes: &[u8]) -> Point<Secp256k1> {
    let compressed_point_len =
        <<Secp256k1 as Curve>::Point as ECPoint>::CompressedPointLength::USIZE;
    let truncated = if bytes.len() > compressed_point_len - 1 {
        &bytes[0..compressed_point_len - 1]
    } else {
        &bytes
    };
    let mut buffer = GenericArray::<
        u8,
        <<Secp256k1 as Curve>::Point as ECPoint>::CompressedPointLength,
    >::default();
    buffer.as_mut_slice()[0] = 0x2;
    buffer.as_mut_slice()[1..1 + truncated.len()].copy_from_slice(truncated);
    if let Ok(point) = Point::from_bytes(buffer.as_slice()) {
        return point;
    }

    let bn = BigInt::from_bytes(bytes);
    let two = BigInt::from(2);
    let bn_times_two = BigInt::mod_mul(&bn, &two, Scalar::<Secp256k1>::group_order());
    let bytes = BigInt::to_bytes(&bn_times_two);
    generate_random_point(&bytes)
}

#[cfg(test)]
mod tests {
    use curv::arithmetic::traits::*;
    use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
    use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
    use curv::BigInt;
    use sha2::Sha512;

    use curv::elliptic::curves::secp256_k1::hash_to_curve::generate_random_point;
    use proofs::range_proof::RangeProof;

    pub fn test_helper(seed: &BigInt, n: usize, m: usize) {
        let nm = n * m;
        let G = Point::<Secp256k1>::generator();
        let label = BigInt::from(1);
        let hash = Sha512::new().chain_bigint(&label).result_bigint();
        let H = generate_random_point(&Converter::to_bytes(&hash));

        let g_vec = (0..nm)
            .map(|i| {
                let kzen_label_i = BigInt::from(i as u32) + seed;
                let hash_i = Sha512::new().chain_bigint(&kzen_label_i).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_i))
            })
            .collect::<Vec<Point<Secp256k1>>>();

        // can run in parallel to g_vec:
        let h_vec = (0..nm)
            .map(|i| {
                let kzen_label_j = BigInt::from(n as u32) + BigInt::from(i as u32) + seed;
                let hash_j = Sha512::new().chain_bigint(&kzen_label_j).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_j))
            })
            .collect::<Vec<Point<Secp256k1>>>();

        let range = BigInt::from(2).pow(n as u32);
        let v_vec = (0..m)
            .map(|_| Scalar::<Secp256k1>::from(&BigInt::sample_below(&range)))
            .collect::<Vec<Scalar<Secp256k1>>>();

        let r_vec = (0..m)
            .map(|_| Scalar::<Secp256k1>::random())
            .collect::<Vec<Scalar<Secp256k1>>>();

        let ped_com_vec = (0..m)
            .map(|i| &*G * &v_vec[i] + &H * &r_vec[i])
            .collect::<Vec<Point<Secp256k1>>>();

        let range_proof = RangeProof::prove(&g_vec, &h_vec, &G, &H, v_vec, &r_vec, n);
        let result = RangeProof::verify(&range_proof, &g_vec, &h_vec, &G, &H, &ped_com_vec, n);
        assert!(result.is_ok());
    }

    pub fn test_helper_aggregated(seed: &BigInt, n: usize, m: usize) {
        let nm = n * m;
        let G = Point::<Secp256k1>::generator();
        let label = BigInt::from(1);
        let hash = Sha512::new().chain_bigint(&label).result_bigint();
        let H = generate_random_point(&Converter::to_bytes(&hash));

        let g_vec = (0..nm)
            .map(|i| {
                let kzen_label_i = BigInt::from(i as u32) + seed;
                let hash_i = Sha512::new().chain_bigint(&kzen_label_i).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_i))
            })
            .collect::<Vec<Point<Secp256k1>>>();

        // can run in parallel to g_vec:
        let h_vec = (0..nm)
            .map(|i| {
                let kzen_label_j = BigInt::from(n as u32) + BigInt::from(i as u32) + seed;
                let hash_j = Sha512::new().chain_bigint(&kzen_label_j).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_j))
            })
            .collect::<Vec<Point<Secp256k1>>>();

        let range = BigInt::from(2).pow(n as u32);
        let v_vec = (0..m)
            .map(|_| Scalar::<Secp256k1>::from(&BigInt::sample_below(&range)))
            .collect::<Vec<Scalar<Secp256k1>>>();

        let r_vec = (0..m)
            .map(|_| Scalar::<Secp256k1>::random())
            .collect::<Vec<Scalar<Secp256k1>>>();

        let ped_com_vec = (0..m)
            .map(|i| &*G * &v_vec[i] + &H * &r_vec[i])
            .collect::<Vec<Point<Secp256k1>>>();

        let range_proof = RangeProof::prove(&g_vec, &h_vec, &G, &H, v_vec, &r_vec, n);
        let result =
            RangeProof::aggregated_verify(&range_proof, &g_vec, &h_vec, &G, &H, &ped_com_vec, n);
        assert!(result.is_ok());
    }

    #[test]
    pub fn test_batch_4_range_proof_32() {
        let n = 32;
        // num of proofs
        let m = 4;
        let nm = n * m;
        let KZen: &[u8] = &[75, 90, 101, 110];
        let kzen_label = BigInt::from_bytes(KZen);

        let G = Point::<Secp256k1>::generator();
        let label = BigInt::from(1);
        let hash = Sha512::new().chain_bigint(&label).result_bigint();
        let H = generate_random_point(&Converter::to_bytes(&hash));

        let g_vec = (0..nm)
            .map(|i| {
                let kzen_label_i = BigInt::from(i as u32) + &kzen_label;
                let hash_i = Sha512::new().chain_bigint(&kzen_label_i).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_i))
            })
            .collect::<Vec<Point<Secp256k1>>>();

        // can run in parallel to g_vec:
        let h_vec = (0..nm)
            .map(|i| {
                let kzen_label_j = BigInt::from(n as u32) + BigInt::from(i as u32) + &kzen_label;
                let hash_j = Sha512::new().chain_bigint(&kzen_label_j).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_j))
            })
            .collect::<Vec<Point<Secp256k1>>>();
        for h in h_vec.clone(){
            println!("h: {}", serde_json::to_string(&h).unwrap());
        }
        let range = BigInt::from(2).pow(n as u32);
        let v_vec = (0..m)
            .map(|_| Scalar::<Secp256k1>::from(&BigInt::sample_below(&range)))
            .collect::<Vec<Scalar<Secp256k1>>>();

        let r_vec = (0..m)
            .map(|_| Scalar::<Secp256k1>::random())
            .collect::<Vec<Scalar<Secp256k1>>>();

        let ped_com_vec = (0..m)
            .map(|i| &*G * &v_vec[i] + &H * &r_vec[i])
            .collect::<Vec<Point<Secp256k1>>>();

        let range_proof = RangeProof::prove(&g_vec, &h_vec, &G, &H, v_vec, &r_vec, n);
        let result = RangeProof::verify(&range_proof, &g_vec, &h_vec, &G, &H, &ped_com_vec, n);
        assert!(result.is_ok());
    }

    #[test]
    #[should_panic]
    pub fn test_batch_4_range_proof_32_out_of_range() {
        let n = 32;
        // num of proofs
        let m = 40;
        let nm = n * m;
        let KZen: &[u8] = &[75, 90, 101, 110];
        let kzen_label = BigInt::from_bytes(KZen);

        let G = Point::<Secp256k1>::generator();
        let label = BigInt::from(1);
        let hash = Sha512::new().chain_bigint(&label).result_bigint();
        let H = generate_random_point(&Converter::to_bytes(&hash));

        let g_vec = (0..nm)
            .map(|i| {
                let kzen_label_i = BigInt::from(i as u32) + &kzen_label;
                let hash_i = Sha512::new().chain_bigint(&kzen_label_i).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_i))
            })
            .collect::<Vec<Point<Secp256k1>>>();

        // can run in parallel to g_vec:
        let h_vec = (0..nm)
            .map(|i| {
                let kzen_label_j = BigInt::from(n as u32) + BigInt::from(i as u32) + &kzen_label;
                let hash_j = Sha512::new().chain_bigint(&kzen_label_j).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_j))
            })
            .collect::<Vec<Point<Secp256k1>>>();

        let range = BigInt::from(2).pow(n as u32);
        let mut v_vec = (0..m - 1)
            .map(|_| Scalar::<Secp256k1>::from(&BigInt::sample_below(&range)))
            .collect::<Vec<Scalar<Secp256k1>>>();

        let bad_v = BigInt::from(2).pow(33);
        v_vec.push(Scalar::<Secp256k1>::from(&bad_v));

        let r_vec = (0..m)
            .map(|_| Scalar::<Secp256k1>::random())
            .collect::<Vec<Scalar<Secp256k1>>>();

        let ped_com_vec = (0..m)
            .map(|i| &*G * &v_vec[i] + &H * &r_vec[i])
            .collect::<Vec<Point<Secp256k1>>>();

        let range_proof = RangeProof::prove(&g_vec, &h_vec, &G, &H, v_vec, &r_vec, n);
        let result = RangeProof::verify(&range_proof, &g_vec, &h_vec, &G, &H, &ped_com_vec, n);
        assert!(result.is_ok());
    }

    #[test]
    pub fn test_batch_2_range_proof_16() {
        let n = 16;
        // num of proofs
        let m = 2;
        let nm = n * m;
        let KZen: &[u8] = &[75, 90, 101, 110];
        let kzen_label = BigInt::from_bytes(KZen);

        let G = Point::<Secp256k1>::generator();
        let label = BigInt::from(1);
        let hash = Sha512::new().chain_bigint(&label).result_bigint();
        let H = generate_random_point(&Converter::to_bytes(&hash));

        let g_vec = (0..nm)
            .map(|i| {
                let kzen_label_i = BigInt::from(i as u32) + &kzen_label;
                let hash_i = Sha512::new().chain_bigint(&kzen_label_i).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_i))
            })
            .collect::<Vec<Point<Secp256k1>>>();

        // can run in parallel to g_vec:
        let h_vec = (0..nm)
            .map(|i| {
                let kzen_label_j = BigInt::from(n as u32) + BigInt::from(i as u32) + &kzen_label;
                let hash_j = Sha512::new().chain_bigint(&kzen_label_j).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_j))
            })
            .collect::<Vec<Point<Secp256k1>>>();

        let range = BigInt::from(2).pow(n as u32);
        let v_vec = (0..m)
            .map(|_| Scalar::<Secp256k1>::from(&BigInt::sample_below(&range)))
            .collect::<Vec<Scalar<Secp256k1>>>();

        let r_vec = (0..m)
            .map(|_| Scalar::<Secp256k1>::random())
            .collect::<Vec<Scalar<Secp256k1>>>();

        let ped_com_vec = (0..m)
            .map(|i| &*G * &v_vec[i] + &H * &r_vec[i])
            .collect::<Vec<Point<Secp256k1>>>();

        let range_proof = RangeProof::prove(&g_vec, &h_vec, &G, &H, v_vec, &r_vec, n);
        let result = RangeProof::verify(&range_proof, &g_vec, &h_vec, &G, &H, &ped_com_vec, n);
        assert!(result.is_ok());
    }

    #[test]
    pub fn test_batch_1_range_proof_32() {
        // bit range
        let n = 32;
        // batch size
        let m = 8;
        let nm = n * m;
        // some seed for generating g and h vectors
        let KZen: &[u8] = &[75, 90, 101, 110];
        let kzen_label = BigInt::from_bytes(KZen);

        // G,H - points for pederson commitment: com  = vG + rH
        let G = Point::<Secp256k1>::generator();
        let H = Point::<Secp256k1>::base_point2();

        let g_vec = (0..nm)
            .map(|i| {
                let kzen_label_i = BigInt::from(i as u32) + &kzen_label;
                let hash_i = Sha512::new().chain_bigint(&kzen_label_i).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_i))
            })
            .collect::<Vec<Point<Secp256k1>>>();

        // can run in parallel to g_vec:
        let h_vec = (0..nm)
            .map(|i| {
                let kzen_label_j = BigInt::from(n as u32) + BigInt::from(i as u32) + &kzen_label;
                let hash_j = Sha512::new().chain_bigint(&kzen_label_j).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_j))
            })
            .collect::<Vec<Point<Secp256k1>>>();

        let range = BigInt::from(2).pow(n as u32);
        let v_vec = (0..m)
            .map(|_| Scalar::<Secp256k1>::from(&BigInt::sample_below(&range)))
            .collect::<Vec<Scalar<Secp256k1>>>();

        let r_vec = (0..m)
            .map(|_| Scalar::<Secp256k1>::random())
            .collect::<Vec<Scalar<Secp256k1>>>();

        let ped_com_vec = (0..m)
            .map(|i| &*G * &v_vec[i] + H * &r_vec[i])
            .collect::<Vec<Point<Secp256k1>>>();
        let range_proof = RangeProof::prove(&g_vec, &h_vec, &G, &H, v_vec, &r_vec, n);
        let result = RangeProof::verify(&range_proof, &g_vec, &h_vec, &G, &H, &ped_com_vec, n);
        assert!(result.is_ok());
    }

    #[test]
    pub fn range_proof_warpper() {
        let pk = Point::generator() * Scalar::<Secp256k1>::random();
        let s = Scalar::<Secp256k1>::from(1000000);
        let r = Scalar::<Secp256k1>::random();
        let ped_com = Point::base_point2() * s.clone() + pk.clone() * r.clone();
        let range_proof = RangeProof::prove_warpper(pk.clone(), s, r);
        assert!(range_proof.verify_warpper(pk, ped_com).is_ok());
    }
    #[test]
    pub fn batch_range_proof_warpper() {
        let pk = Point::generator() * Scalar::<Secp256k1>::random();
        let mut s_vec = Vec::new();
        let mut r_vec = Vec::new();
        let mut ped_com_vec = Vec::new();
        for _i in 0 .. 10 {
            let s = Scalar::<Secp256k1>::from(1000000);
            let r = Scalar::<Secp256k1>::random();
            let ped_com = Point::base_point2() * s.clone() + pk.clone() * r.clone();
            s_vec.push(s);
            r_vec.push(r);
            ped_com_vec.push(ped_com);
        }
        let range_proof = RangeProof::batch_prove_warpper(pk.clone(), s_vec, r_vec);
        assert!(range_proof.batch_verify_warpper(pk, ped_com_vec).is_ok());
    }

    #[test]
    pub fn test_batch_1_range_proof_8() {
        // bit range
        let n = 8;
        // batch size
        let m = 1;
        let nm = n * m;
        // some seed for generating g and h vectors
        let KZen: &[u8] = &[75, 90, 101, 110];
        let kzen_label = BigInt::from_bytes(KZen);

        // G,H - points for pederson commitment: com  = vG + rH
        let G = Point::<Secp256k1>::generator();
        let label = BigInt::from(1);
        let hash = Sha512::new().chain_bigint(&label).result_bigint();
        let H = generate_random_point(&Converter::to_bytes(&hash));

        let g_vec = (0..nm)
            .map(|i| {
                let kzen_label_i = BigInt::from(i as u32) + &kzen_label;
                let hash_i = Sha512::new().chain_bigint(&kzen_label_i).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_i))
            })
            .collect::<Vec<Point<Secp256k1>>>();
        


        // can run in parallel to g_vec:
        let h_vec = (0..nm)
            .map(|i| {
                let kzen_label_j = BigInt::from(n as u32) + BigInt::from(i as u32) + &kzen_label;
                let hash_j = Sha512::new().chain_bigint(&kzen_label_j).result_bigint();
                generate_random_point(&Converter::to_bytes(&hash_j))
            })
            .collect::<Vec<Point<Secp256k1>>>();

        let range = BigInt::from(2).pow(n as u32);
        let v_vec = (0..m)
            .map(|_| Scalar::<Secp256k1>::from(&BigInt::sample_below(&range)))
            .collect::<Vec<Scalar<Secp256k1>>>();

        let r_vec = (0..m)
            .map(|_| Scalar::<Secp256k1>::random())
            .collect::<Vec<Scalar<Secp256k1>>>();

        let ped_com_vec = (0..m)
            .map(|i| &*G * &v_vec[i] + &H * &r_vec[i])
            .collect::<Vec<Point<Secp256k1>>>();

        let range_proof = RangeProof::prove(&g_vec, &h_vec, &G, &H, v_vec, &r_vec, n);
        let result = RangeProof::verify(&range_proof, &g_vec, &h_vec, &G, &H, &ped_com_vec, n);
        assert!(result.is_ok());
    }

    #[test]
    pub fn test_batch_4_range_proof_64() {
        let KZen: &[u8] = &[75, 90, 101, 110];
        let kzen_label = BigInt::from_bytes(KZen);
        test_helper(&kzen_label, 64, 4);
    }

    #[test]
    pub fn test_agg_batch_4_range_proof_64() {
        let KZen: &[u8] = &[75, 90, 101, 110];
        let kzen_label = BigInt::from_bytes(KZen);
        test_helper_aggregated(&kzen_label, 64, 4);
    }
}
