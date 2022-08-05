#![allow(non_snake_case)]
use std::prelude::v1::*;
/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

// Secp256k1 elliptic curve utility functions (se: https://en.bitcoin.it/wiki/Secp256k1).
//
// In Cryptography utilities, we need to manipulate low level elliptic curve members as Point
// in order to perform operation on them. As the library secp256k1 expose only SecretKey and
// PublicKey, we extend those with simple codecs.
//
// The Secret Key codec: BigInt <> SecretKey
// The Public Key codec: Point <> SecretKey
//

use super::traits::{ECPoint, ECScalar};
use crate::arithmetic::traits::*;
use crate::BigInt;
use crate::ErrorKey;

#[cfg(feature = "merkle")]
use crypto::digest::Digest;
#[cfg(feature = "merkle")]
use crypto::sha3::Sha3;
#[cfg(feature = "merkle")]
use merkle::Hashable;
//use secp256k1::constants::{
//    CURVE_ORDER, GENERATOR_X, GENERATOR_Y, SECRET_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE,
//};
//use secp256k1::{PublicKey, Secp256k1, SecretKey, VerifyOnly};

use secp256k1::curve::Scalar;
use secp256k1::{PublicKey, SecretKey};

use serde::de::{self, Error, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::ops::{Add, Mul};
use std::ptr;
use std::sync::atomic;
use zeroize::Zeroize;
/* X coordinate of a point of unknown discrete logarithm.
Computed using a deterministic algorithm with the generator as input.
See test_base_point2 */
const BASE_POINT2_X: [u8; 32] = [
    0x08, 0xd1, 0x32, 0x21, 0xe3, 0xa7, 0x32, 0x6a, 0x34, 0xdd, 0x45, 0x21, 0x4b, 0xa8, 0x01, 0x16,
    0xdd, 0x14, 0x2e, 0x4b, 0x5f, 0xf3, 0xce, 0x66, 0xa8, 0xdc, 0x7b, 0xfa, 0x03, 0x78, 0xb7, 0x95,
];

const BASE_POINT2_Y: [u8; 32] = [
    0x5d, 0x41, 0xac, 0x14, 0x77, 0x61, 0x4b, 0x5c, 0x08, 0x48, 0xd5, 0x0d, 0xbd, 0x56, 0x5e, 0xa2,
    0x80, 0x7b, 0xcb, 0xa1, 0xdf, 0x0d, 0xf0, 0x7a, 0x82, 0x17, 0xe9, 0xf7, 0xf7, 0xc2, 0xbe, 0x88,
];

pub type SK = SecretKey;
pub type PK = PublicKey;

#[derive(Clone, Debug, Copy)]
pub struct Secp256k1Scalar {
    purpose: &'static str,
    fe: SK,
}
#[derive(Clone, Debug, Copy)]
pub struct Secp256k1Point {
    purpose: &'static str,
    ge: Option<PK>,
}
pub type GE = Secp256k1Point;
pub type FE = Secp256k1Scalar;

impl Secp256k1Point {
    pub fn random_point() -> Secp256k1Point {
        let random_scalar: Secp256k1Scalar = Secp256k1Scalar::new_random();
        let base_point = Secp256k1Point::generator();
        let pk = base_point.scalar_mul(&random_scalar.get_element());
        Secp256k1Point {
            purpose: "random_point",
            ge: pk.get_element(),
        }
    }
}

impl Zeroize for Secp256k1Scalar {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, FE::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

use rand::Rng;
//use num_bigint::BigInt;

fn random_32_bytes<R: Rng + ?Sized>(rng: &mut R) -> [u32; 8] {
    let mut ret = [0u32; 8];
    rng.fill(&mut ret);
    ret
}

impl ECScalar for Secp256k1Scalar {
    type SecretKey = SK;

    fn new_random() -> Secp256k1Scalar {
        use rand::RngCore;
        #[cfg(feature = "wasm")]
        let mut rng = rand::rngs::OsRng;
        #[cfg(not(feature = "wasm"))]
        let mut rng = rand::thread_rng();
        let key = loop {
            let mut ret = [0u8; 32];
            rng.fill_bytes(&mut ret);
            if let Ok(key) = SecretKey::parse(&ret) {
                break key;
            }
        };
        Secp256k1Scalar {
            purpose: "random",
            fe: key,
        }
    }

    fn zero() -> Secp256k1Scalar {
        let zero_arr = [0u8; 32];
        let zero = unsafe { std::mem::transmute::<[u8; 32], SecretKey>(zero_arr) };
        Secp256k1Scalar {
            purpose: "zero",
            fe: zero,
        }
    }

    fn is_zero(&self) -> bool {
        self == &Self::zero()
    }

    fn get_element(&self) -> Self::SecretKey {
        self.fe.clone()
    }

    fn set_element(&mut self, element: Self::SecretKey) {
        self.fe = element
    }

    fn from(n: &BigInt) -> Secp256k1Scalar {
        let curve_order = FE::q();
        let n_reduced = BigInt::mod_add(n, &BigInt::from(0), &curve_order);
        let mut v = BigInt::to_bytes(&n_reduced);

        if v.len() < SECRET_KEY_SIZE {
            let mut template = vec![0; SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }
        if v != [0u8; 32] {
            Secp256k1Scalar {
                purpose: "from_big_int",
                fe: SK::parse_slice(&v).unwrap(),
            }
        } else {
            FE::zero()
        }
    }

    fn to_big_int(&self) -> BigInt {
        let scalar: Scalar = self.fe.clone().into();
        BigInt::from_bytes(&scalar.b32())
    }

    fn q() -> BigInt {
        BigInt::from_bytes(CURVE_ORDER.as_ref())
    }

    fn add(&self, other: &Self::SecretKey) -> Secp256k1Scalar {
        let mut other_scalar: FE = ECScalar::new_random();
        other_scalar.set_element(other.clone());
        let res: FE = ECScalar::from(&BigInt::mod_add(
            &self.to_big_int(),
            &other_scalar.to_big_int(),
            &FE::q(),
        ));
        Secp256k1Scalar {
            purpose: "add",
            fe: res.get_element(),
        }
    }

    fn mul(&self, other: &Self::SecretKey) -> Secp256k1Scalar {
        let mut other_scalar: FE = ECScalar::new_random();
        other_scalar.set_element(other.clone());
        let res: FE = ECScalar::from(&BigInt::mod_mul(
            &self.to_big_int(),
            &other_scalar.to_big_int(),
            &FE::q(),
        ));
        Secp256k1Scalar {
            purpose: "mul",
            fe: res.get_element(),
        }
    }

    fn sub(&self, other: &Self::SecretKey) -> Secp256k1Scalar {
        let mut other_scalar: FE = ECScalar::new_random();
        other_scalar.set_element(other.clone());
        let res: FE = ECScalar::from(&BigInt::mod_sub(
            &self.to_big_int(),
            &other_scalar.to_big_int(),
            &FE::q(),
        ));
        Secp256k1Scalar {
            purpose: "sub",
            fe: res.get_element(),
        }
    }

    fn invert(&self) -> Secp256k1Scalar {
        let bignum = self.to_big_int();
        let bn_inv = BigInt::mod_inv(&bignum, &FE::q()).unwrap();
        ECScalar::from(&bn_inv)
    }
}
impl Mul<Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn mul(self, other: Secp256k1Scalar) -> Secp256k1Scalar {
        (&self).mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn mul(self, other: &'o Secp256k1Scalar) -> Secp256k1Scalar {
        (&self).mul(&other.get_element())
    }
}

impl Add<Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn add(self, other: Secp256k1Scalar) -> Secp256k1Scalar {
        (&self).add(&other.get_element())
    }
}

impl<'o> Add<&'o Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn add(self, other: &'o Secp256k1Scalar) -> Secp256k1Scalar {
        (&self).add(&other.get_element())
    }
}

impl Serialize for Secp256k1Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_big_int().to_hex())
    }
}

impl<'de> Deserialize<'de> for Secp256k1Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Secp256k1Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Secp256k1ScalarVisitor)
    }
}

struct Secp256k1ScalarVisitor;

impl<'de> Visitor<'de> for Secp256k1ScalarVisitor {
    type Value = Secp256k1Scalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Secp256k1Scalar")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<Secp256k1Scalar, E> {
        let v = BigInt::from_hex(s).map_err(E::custom)?;
        Ok(ECScalar::from(&v))
    }
}

impl PartialEq for Secp256k1Scalar {
    fn eq(&self, other: &Secp256k1Scalar) -> bool {
        self.get_element() == other.get_element()
    }
}

impl PartialEq for Secp256k1Point {
    fn eq(&self, other: &Secp256k1Point) -> bool {
        self.get_element() == other.get_element()
    }
}

impl Zeroize for Secp256k1Point {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, GE::generator()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECPoint for Secp256k1Point {
    type SecretKey = SK;
    type PublicKey = Option<PK>;
    type Scalar = Secp256k1Scalar;

    fn zero() -> Secp256k1Point {
        Secp256k1Point {
            purpose: "zero",
            ge: None,
        }
    }

    fn is_zero(&self) -> bool {
        self.ge.is_none()
    }

    fn base_point2() -> Secp256k1Point {
        let mut v = vec![4_u8];
        v.extend(BASE_POINT2_X.as_ref());
        v.extend(BASE_POINT2_Y.as_ref());
        Secp256k1Point {
            purpose: "random",
            ge: Some(PK::parse_slice(&v, None).unwrap()),
        }
    }

    fn generator() -> Secp256k1Point {
        let mut v = vec![4_u8];
        v.extend(GENERATOR_X.as_ref());
        v.extend(GENERATOR_Y.as_ref());
        Secp256k1Point {
            purpose: "base_fe",
            ge: Some(PK::parse_slice(&v, None).unwrap()),
        }
    }

    fn get_element(&self) -> Self::PublicKey {
        self.ge
    }

    /// to return from BigInt to PK use from_bytes:
    /// 1) convert BigInt::to_vec
    /// 2) remove first byte [1..33]
    /// 3) call from_bytes
    fn bytes_compressed_to_big_int(&self) -> BigInt {
        match self.ge {
            Some(ge) => {
                let serial = ge.serialize_compressed();
                BigInt::from_bytes(&serial[0..33])
            }
            None => BigInt::zero(),
        }
    }

    fn x_coor(&self) -> Option<BigInt> {
        match self.ge {
            Some(ge) => {
                let serialized_pk = PK::serialize(&ge);
                let x = &serialized_pk[1..serialized_pk.len() / 2 + 1];
                let x_vec = x.to_vec();
                Some(BigInt::from_bytes(&x_vec[..]))
            }
            None => None,
        }
    }

    fn y_coor(&self) -> Option<BigInt> {
        match self.ge {
            Some(ge) => {
                let serialized_pk = PK::serialize(&ge);
                let y = &serialized_pk[(serialized_pk.len() - 1) / 2 + 1..serialized_pk.len()];
                let y_vec = y.to_vec();
                Some(BigInt::from_bytes(&y_vec[..]))
            }
            None => None,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Secp256k1Point, ErrorKey> {
        let bytes_vec = bytes.to_vec();
        let mut bytes_array_65 = [0u8; 65];
        let mut bytes_array_33 = [0u8; 33];

        let byte_len = bytes_vec.len();
        match byte_len {
            33..=63 => {
                let mut template = vec![0; 64 - bytes_vec.len()];
                template.extend_from_slice(&bytes);
                let mut bytes_vec = template;
                let mut template: Vec<u8> = vec![4];
                template.append(&mut bytes_vec);
                let bytes_slice = &template[..];

                bytes_array_65.copy_from_slice(&bytes_slice[0..65]);
                let ge = if bytes_array_65[1..] == [0u8; 64] {
                    None
                } else {
                    let result = PK::parse_slice(&bytes_array_65, None);
                    if result.is_err() {
                        return Err(ErrorKey::InvalidPublicKey);
                    }
                    Some(result.unwrap())
                };
                Ok(Secp256k1Point {
                    purpose: "random",
                    ge,
                })
            }

            0..=32 => {
                let mut template = vec![0; 32 - bytes_vec.len()];
                template.extend_from_slice(&bytes);
                let mut bytes_vec = template;
                let mut template: Vec<u8> = vec![2];
                template.append(&mut bytes_vec);
                let bytes_slice = &template[..];

                bytes_array_33.copy_from_slice(&bytes_slice[0..33]);
                let ge = if bytes_array_33[1..] == [0u8; 32] {
                    None
                } else {
                    let result = PK::parse_slice(&bytes_array_33, None);
                    if result.is_err() {
                        return Err(ErrorKey::InvalidPublicKey);
                    }
                    Some(result.unwrap())
                };
                Ok(Secp256k1Point {
                    purpose: "random",
                    ge,
                })
            }
            _ => {
                let bytes_slice = &bytes_vec[0..64];
                let mut bytes_vec = bytes_slice.to_vec();
                let mut template: Vec<u8> = vec![4];
                template.append(&mut bytes_vec);
                let bytes_slice = &template[..];

                bytes_array_65.copy_from_slice(&bytes_slice[0..65]);

                let ge = if bytes_array_65[1..] == [0u8; 64] {
                    None
                } else {
                    let result = PK::parse_slice(&bytes_array_65, None);
                    if result.is_err() {
                        return Err(ErrorKey::InvalidPublicKey);
                    }
                    Some(result.unwrap())
                };
                Ok(Secp256k1Point {
                    purpose: "random",
                    ge,
                })
            }
        }
    }
    fn pk_to_key_slice(&self) -> Vec<u8> {
        match self.ge {
            None => [0u8; 65].to_vec(),
            Some(_ge) => {
                let mut v = vec![4_u8];
                let x_vec = BigInt::to_bytes(&self.x_coor().unwrap());
                let y_vec = BigInt::to_bytes(&self.y_coor().unwrap());

                let mut raw_x: Vec<u8> = Vec::new();
                let mut raw_y: Vec<u8> = Vec::new();
                raw_x.extend(vec![0u8; 32 - x_vec.len()]);
                raw_x.extend(x_vec);

                raw_y.extend(vec![0u8; 32 - y_vec.len()]);
                raw_y.extend(y_vec);

                v.extend(raw_x);
                v.extend(raw_y);
                v
            }
        }
    }

    fn scalar_mul(&self, fe: &Self::SecretKey) -> Secp256k1Point {
        let mut res = self.clone();
        match &mut res.ge {
            None => (),
            Some(ge) => {
                ge.tweak_mul_assign(fe).unwrap();
            }
        }
        res
    }

    fn add_point(&self, other: &Self::PublicKey) -> Secp256k1Point {
        let ge = match (&self.ge, other) {
            (None, right) => *right,
            (left, None) => *left,
            (Some(left), Some(right)) => match PK::combine(&[left.clone(), right.clone()]) {
                Ok(pk) => Some(pk),
                Err(_) => None,
            },
        };
        Secp256k1Point {
            purpose: "combine",
            ge,
        }
    }

    fn sub_point(&self, other: &Self::PublicKey) -> Secp256k1Point {
        let minus_point = match &other {
            Some(ge) => {
                let point = Secp256k1Point {
                    purpose: "sub_point",
                    ge: Some(*ge),
                };
                let p: Vec<u8> = vec![
                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 252, 47,
                ];
                let order = BigInt::from_bytes(&p[..]);
                let x = point.x_coor().unwrap();
                let y = point.y_coor().unwrap();
                let minus_y = BigInt::mod_sub(&order, &y, &order);

                let x_vec = BigInt::to_bytes(&x);
                let y_vec = BigInt::to_bytes(&minus_y);

                let mut template_x = vec![0; 32 - x_vec.len()];
                template_x.extend_from_slice(&x_vec);
                let mut x_vec = template_x;

                let mut template_y = vec![0; 32 - y_vec.len()];
                template_y.extend_from_slice(&y_vec);
                let y_vec = template_y;

                x_vec.extend_from_slice(&y_vec);

                let minus_point: GE = ECPoint::from_bytes(&x_vec).unwrap();
                minus_point
            }
            None => Secp256k1Point {
                purpose: "sub_point",
                ge: None,
            },
        };
        let ge = ECPoint::add_point(self, &minus_point.get_element()).ge;
        Secp256k1Point {
            purpose: "sub_point",
            ge,
        }
    }

    fn from_coor(x: &BigInt, y: &BigInt) -> Secp256k1Point {
        let mut vec_x = BigInt::to_bytes(x);
        let mut vec_y = BigInt::to_bytes(y);
        let coor_size = (UNCOMPRESSED_PUBLIC_KEY_SIZE - 1) / 2;

        if vec_x.len() < coor_size {
            // pad
            let mut x_buffer = vec![0; coor_size - vec_x.len()];
            x_buffer.extend_from_slice(&vec_x);
            vec_x = x_buffer
        }

        if vec_y.len() < coor_size {
            // pad
            let mut y_buffer = vec![0; coor_size - vec_y.len()];
            y_buffer.extend_from_slice(&vec_y);
            vec_y = y_buffer
        }

        assert_eq!(x, &BigInt::from_bytes(vec_x.as_ref()));
        assert_eq!(y, &BigInt::from_bytes(vec_y.as_ref()));

        let mut v = vec![4_u8];
        v.extend(vec_x);
        v.extend(vec_y);
        let mut tmp = v.clone();
        tmp.remove(0);
        let ge = if tmp == vec![0; v.len() - 1 as usize] {
            None
        } else {
            Some(PK::parse_slice(&v, None).unwrap())
        };
        Secp256k1Point {
            purpose: "base_fe",
            ge,
        }
    }
}

//static mut CONTEXT: Option<Secp256k1<VerifyOnly>> = None;
//pub fn get_context() -> &'static Secp256k1<VerifyOnly> {
//    static INIT_CONTEXT: Once = Once::new();
//    INIT_CONTEXT.call_once(|| unsafe {
//        CONTEXT = Some(Secp256k1::verification_only());
//    });
//    unsafe { CONTEXT.as_ref().unwrap() }
//}

#[cfg(feature = "merkle")]
impl Hashable for Secp256k1Point {
    fn update_context(&self, context: &mut Sha3) {
        let bytes: Vec<u8> = self.pk_to_key_slice();
        context.input(&bytes[..]);
    }
}

impl Mul<Secp256k1Scalar> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, other: Secp256k1Scalar) -> Self::Output {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Secp256k1Scalar> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, other: &'o Secp256k1Scalar) -> Self::Output {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Secp256k1Scalar> for &'o Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, other: &'o Secp256k1Scalar) -> Self::Output {
        self.scalar_mul(&other.get_element())
    }
}

impl Add<Secp256k1Point> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn add(self, other: Secp256k1Point) -> Self::Output {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o Secp256k1Point> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn add(self, other: &'o Secp256k1Point) -> Self::Output {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o Secp256k1Point> for &'o Secp256k1Point {
    type Output = Secp256k1Point;
    fn add(self, other: &'o Secp256k1Point) -> Self::Output {
        self.add_point(&other.get_element())
    }
}

impl Serialize for Secp256k1Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Secp256k1Point", 2)?;
        state.serialize_field("x", &self.x_coor().unwrap().to_hex())?;
        state.serialize_field("y", &self.y_coor().unwrap().to_hex())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Secp256k1Point {
    fn deserialize<D>(deserializer: D) -> Result<Secp256k1Point, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = &["x", "y"];
        deserializer.deserialize_struct("Secp256k1Point", fields, Secp256k1PointVisitor)
    }
}

struct Secp256k1PointVisitor;

impl<'de> Visitor<'de> for Secp256k1PointVisitor {
    type Value = Secp256k1Point;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Secp256k1Point")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<Secp256k1Point, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let x = seq
            .next_element()?
            .ok_or_else(|| V::Error::invalid_length(0, &"a single element"))?;
        let y = seq
            .next_element()?
            .ok_or_else(|| V::Error::invalid_length(0, &"a single element"))?;

        let bx = BigInt::from_hex(x).map_err(V::Error::custom)?;
        let by = BigInt::from_hex(y).map_err(V::Error::custom)?;

        Ok(Secp256k1Point::from_coor(&bx, &by))
    }

    fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<Secp256k1Point, E::Error> {
        let mut x = String::new();
        let mut y = String::new();

        while let Some(ref key) = map.next_key::<String>()? {
            let v = map.next_value::<String>()?;
            if key == "x" {
                x = v
            } else if key == "y" {
                y = v
            } else {
                return Err(E::Error::unknown_field(key, &["x", "y"]));
            }
        }

        let bx = BigInt::from_hex(&x).map_err(E::Error::custom)?;
        let by = BigInt::from_hex(&y).map_err(E::Error::custom)?;

        Ok(Secp256k1Point::from_coor(&bx, &by))
    }
}

/// The order of the secp256k1 curve
pub const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
/// The X coordinate of the generator
pub const GENERATOR_X: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];

/// The Y coordinate of the generator
pub const GENERATOR_Y: [u8; 32] = [
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
];
/// The size (in bytes) of a secret key
pub const SECRET_KEY_SIZE: usize = 32;

/// The size (in bytes) of a serialized public key.
pub const PUBLIC_KEY_SIZE: usize = 33;

/// The size (in bytes) of an serialized uncompressed public key
pub const UNCOMPRESSED_PUBLIC_KEY_SIZE: usize = 65;

#[cfg(test)]
mod tests {
    use super::BigInt;
    use super::Secp256k1Point;
    use super::Secp256k1Scalar;
    use crate::arithmetic::traits::*;
    use crate::cryptographic_primitives::hashing::hash_sha256::HSha256;
    use crate::cryptographic_primitives::hashing::traits::Hash;
    use crate::elliptic::curves::traits::ECPoint;
    use crate::elliptic::curves::traits::ECScalar;

    #[test]
    fn is_zero_scalar() {
        let f_l = Secp256k1Scalar::new_random();
        let f_r = f_l.clone();
        let f_s = f_l.sub(&f_r.get_element());
        assert!(!f_l.is_zero());
        assert!(f_s.is_zero());

        let p_l = Secp256k1Point::generator();
        let p_r = p_l.clone();
        let p_s = p_l.sub_point(&p_r.get_element());
        assert!(p_s.is_zero());
    }

    #[test]
    fn test_zero_point() {
        let x_coor =
            BigInt::from_hex("3061d1723d83fa80d1082e1985216b59a7063873474200ce7d62a72ca8753725")
                .unwrap();
        let y_coor1 =
            BigInt::from_hex("7c8d9320237d50881ea1a12ddc75b269268b6cd08b82e1dcc13babbc720bcce9")
                .unwrap();
        let y_coor2 =
            BigInt::from_hex("83726cdfdc82af77e15e5ed2238a4d96d974932f747d1e233ec454428df42f46")
                .unwrap();
        let point1 = Secp256k1Point::from_coor(&x_coor, &y_coor1);
        let point2 = Secp256k1Point::from_coor(&x_coor, &y_coor2);

        //add point should not panic
        let point3 = point1.add_point(&point2.get_element());
        println!("get zero point: {:?}", point3);
        println!("zero point serialized: {:?}", point3.pk_to_key_slice());
        let point4 = GE::from_coor(&BigInt::zero(), &BigInt::zero());
        println!("point from zero bigint: {:?}", point4);
        let point5 = GE::from_bytes(&[0; 65]).unwrap();
        println!("zero point from &[u8]: {:?}", point5);
        println!(
            "zero point mul scalar: {:?}",
            point5.scalar_mul(&Secp256k1Scalar::new_random().get_element())
        );
    }

    #[test]
    fn serialize_sk() {
        let scalar: Secp256k1Scalar = ECScalar::from(&BigInt::from(123456));
        let s = serde_json::to_string(&scalar).expect("Failed in serialization");
        assert_eq!(s, "\"1e240\"");
    }

    #[test]
    fn serialize_rand_pk_verify_pad() {
        let vx = BigInt::from_hex(
            &"ccaf75ab7960a01eb421c0e2705f6e84585bd0a094eb6af928c892a4a2912508".to_string(),
        )
        .unwrap();

        let vy = BigInt::from_hex(
            &"e788e294bd64eee6a73d2fc966897a31eb370b7e8e9393b0d8f4f820b48048df".to_string(),
        )
        .unwrap();

        Secp256k1Point::from_coor(&vx, &vy); // x and y of size 32

        let x = BigInt::from_hex(
            &"5f6853305467a385b56a5d87f382abb52d10835a365ec265ce510e04b3c3366f".to_string(),
        )
        .unwrap();

        let y = BigInt::from_hex(
            &"b868891567ca1ee8c44706c0dc190dd7779fe6f9b92ced909ad870800451e3".to_string(),
        )
        .unwrap();

        Secp256k1Point::from_coor(&x, &y); // x and y not of size 32 each

        let r = Secp256k1Point::random_point();
        let r_expected = Secp256k1Point::from_coor(&r.x_coor().unwrap(), &r.y_coor().unwrap());

        assert_eq!(r.x_coor().unwrap(), r_expected.x_coor().unwrap());
        assert_eq!(r.y_coor().unwrap(), r_expected.y_coor().unwrap());
    }

    #[test]
    fn deserialize_sk() {
        let s = "\"1e240\"";
        let dummy: Secp256k1Scalar = serde_json::from_str(s).expect("Failed in serialization");

        let sk: Secp256k1Scalar = ECScalar::from(&BigInt::from(123456));

        assert_eq!(dummy, sk);
    }

    #[test]
    fn serialize_pk() {
        let pk = Secp256k1Point::generator();
        let x = pk.x_coor().unwrap();
        let y = pk.y_coor().unwrap();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");

        let expected = format!("{{\"x\":\"{}\",\"y\":\"{}\"}}", x.to_hex(), y.to_hex());
        assert_eq!(s, expected);

        let des_pk: Secp256k1Point = serde_json::from_str(&s).expect("Failed in serialization");
        assert_eq!(des_pk.ge, pk.ge);
    }

    #[test]
    fn bincode_pk() {
        let pk = Secp256k1Point::generator();
        let bin = bincode::serialize(&pk).unwrap();
        let decoded: Secp256k1Point = bincode::deserialize(bin.as_slice()).unwrap();
        assert_eq!(decoded, pk);
    }

    use crate::elliptic::curves::secp256_k1::{FE, GE};
    use crate::ErrorKey;

    #[test]
    fn test_serdes_pk() {
        let pk = GE::generator();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");
        let des_pk: GE = serde_json::from_str(&s).expect("Failed in deserialization");
        assert_eq!(des_pk, pk);

        let pk = GE::base_point2();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");
        let des_pk: GE = serde_json::from_str(&s).expect("Failed in deserialization");
        assert_eq!(des_pk, pk);
    }

    #[test]
    #[should_panic]
    fn test_serdes_bad_pk() {
        let pk = GE::generator();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");
        // we make sure that the string encodes invalid point:
        let s: String = s.replace("79be", "79bf");
        let des_pk: GE = serde_json::from_str(&s).expect("Failed in deserialization");
        assert_eq!(des_pk, pk);
    }

    #[test]
    fn test_from_bytes() {
        let g = Secp256k1Point::generator();
        let hash = HSha256::create_hash(&[&g.bytes_compressed_to_big_int()]);
        let hash_vec = BigInt::to_bytes(&hash);
        let result = Secp256k1Point::from_bytes(&hash_vec);
        assert_eq!(result.unwrap_err(), ErrorKey::InvalidPublicKey)
    }

    #[test]
    fn test_from_bytes_3() {
        let test_vec = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 2, 3, 4, 5, 6,
        ];
        let result = Secp256k1Point::from_bytes(&test_vec);
        assert!(result.is_ok() | result.is_err())
    }

    #[test]
    fn test_from_bytes_4() {
        let test_vec = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6,
        ];
        let result = Secp256k1Point::from_bytes(&test_vec);
        assert!(result.is_ok() | result.is_err())
    }

    #[test]
    fn test_from_bytes_5() {
        let test_vec = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5,
            6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4,
            5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3,
            4, 5, 6,
        ];
        let result = Secp256k1Point::from_bytes(&test_vec);
        assert!(result.is_ok() | result.is_err())
    }

    #[test]
    fn test_minus_point() {
        let a: FE = ECScalar::new_random();
        let b: FE = ECScalar::new_random();
        let b_bn = b.to_big_int();
        let order = FE::q();
        let minus_b = BigInt::mod_sub(&order, &b_bn, &order);
        let a_minus_b = BigInt::mod_add(&a.to_big_int(), &minus_b, &order);
        let a_minus_b_fe: FE = ECScalar::from(&a_minus_b);
        let base: GE = ECPoint::generator();
        let point_ab1 = base * a_minus_b_fe;

        let point_a = base * a;
        let point_b = base * b;
        let point_ab2 = point_a.sub_point(&point_b.get_element());
        assert_eq!(point_ab1.get_element(), point_ab2.get_element());
    }

    #[test]
    fn test_invert() {
        let a: FE = ECScalar::new_random();
        let a_bn = a.to_big_int();
        let a_inv = a.invert();
        let a_inv_bn_1 = BigInt::mod_inv(&a_bn, &FE::q()).unwrap();
        let a_inv_bn_2 = a_inv.to_big_int();
        assert_eq!(a_inv_bn_1, a_inv_bn_2);
    }

    #[test]
    fn test_scalar_mul_scalar() {
        let a: FE = ECScalar::new_random();
        let b: FE = ECScalar::new_random();
        let c1 = a.mul(&b.get_element());
        let c2 = a * b;
        assert_eq!(c1.get_element(), c2.get_element());
    }

    #[test]
    fn test_pk_to_key_slice() {
        for _ in 1..200 {
            let r = FE::new_random();
            let rg = GE::generator() * r;
            let key_slice = rg.pk_to_key_slice();

            assert!(key_slice.len() == 65);
            assert!(key_slice[0] == 4);

            let rg_prime: GE = ECPoint::from_bytes(&key_slice[1..65]).unwrap();
            assert_eq!(rg_prime.get_element(), rg.get_element());
        }
    }

    #[test]
    fn test_base_point2() {
        /* Show that base_point2() is returning a point of unknown discrete logarithm.
        It is done by using SHA256 repeatedly as a pseudo-random function, with the generator
        as the initial input, until receiving a valid Secp256k1 point. */

        let base_point2 = Secp256k1Point::base_point2();

        let g = Secp256k1Point::generator();
        let mut hash = HSha256::create_hash(&[&g.bytes_compressed_to_big_int()]);
        hash = HSha256::create_hash(&[&hash]);
        hash = HSha256::create_hash(&[&hash]);

        assert_eq!(hash, base_point2.x_coor().unwrap(),);

        // check that base_point2 is indeed on the curve (from_coor() will fail otherwise)
        assert_eq!(
            Secp256k1Point::from_coor(
                &base_point2.x_coor().unwrap(),
                &base_point2.y_coor().unwrap()
            ),
            base_point2
        );
    }
}
