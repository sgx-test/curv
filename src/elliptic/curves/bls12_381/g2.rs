/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

pub const SECRET_KEY_SIZE: usize = 32;
pub const COMPRESSED_SIZE: usize = 96;

use std::fmt;
use std::fmt::Debug;
use std::ops::{Add, Mul, Neg};
use std::str;

use ff_zeroize::{Field, PrimeField, PrimeFieldRepr, ScalarEngine};
use pairing_plus::bls12_381::Fr;
use pairing_plus::bls12_381::G2Compressed;
use pairing_plus::bls12_381::G2Uncompressed;
use pairing_plus::bls12_381::G2;
use pairing_plus::hash_to_curve::HashToCurve;
use pairing_plus::hash_to_field::ExpandMsgXmd;
use pairing_plus::serdes::SerDes;
use pairing_plus::EncodedPoint;
use pairing_plus::{CurveAffine, CurveProjective, Engine};
use sha2::Sha256;

use serde::de::{self, Error, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};

pub type SK = <pairing_plus::bls12_381::Bls12 as ScalarEngine>::Fr;
pub type PK = <pairing_plus::bls12_381::Bls12 as Engine>::G2Affine;

use crate::arithmetic::traits::*;
use crate::BigInt;
use crate::ErrorKey::{self};

use std::ptr;
use std::sync::atomic;
use zeroize::Zeroize;

use crate::elliptic::curves::traits::ECPoint;
use crate::elliptic::curves::traits::ECScalar;
#[cfg(feature = "merkle")]
use crypto::digest::Digest;
#[cfg(feature = "merkle")]
use crypto::sha3::Sha3;
#[cfg(feature = "merkle")]
use merkle::Hashable;
use std::io::Cursor;

#[derive(Clone, Copy)]
pub struct FieldScalar {
    purpose: &'static str,
    fe: SK,
}
#[derive(Clone, Copy)]
pub struct G2Point {
    purpose: &'static str,
    ge: PK,
}
pub type GE = G2Point;
pub type FE = FieldScalar;

impl Zeroize for FieldScalar {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, FE::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECScalar for FieldScalar {
    type SecretKey = SK;

    fn new_random() -> FieldScalar {
        let rnd_bn = BigInt::sample_below(&FE::q());
        ECScalar::from(&rnd_bn)
    }

    fn zero() -> FieldScalar {
        FieldScalar {
            purpose: "zero",
            fe: SK::default(),
        }
    }

    fn is_zero(&self) -> bool {
        self == &Self::zero()
    }

    fn get_element(&self) -> SK {
        self.fe
    }
    fn set_element(&mut self, element: SK) {
        self.fe = element
    }

    fn from(n: &BigInt) -> FieldScalar {
        let n_mod = BigInt::modulus(n, &FE::q());
        let mut v = BigInt::to_bytes(&n_mod);
        let mut bytes_array: [u8; SECRET_KEY_SIZE];
        if v.len() < SECRET_KEY_SIZE {
            let mut template = vec![0; SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }
        bytes_array = [0; SECRET_KEY_SIZE];
        let bytes = &v[..SECRET_KEY_SIZE];
        bytes_array.copy_from_slice(&bytes);

        // bytes_array.reverse();

        let mut repr = SK::default().into_repr();
        repr.read_be(Cursor::new(&bytes_array[..])).unwrap();
        FieldScalar {
            purpose: "from_big_int",
            fe: Fr::from_repr(repr).unwrap(),
        }
    }

    fn to_big_int(&self) -> BigInt {
        let tmp = self.fe.into_repr();
        let scalar_u64 = tmp.as_ref();

        let to_bn = scalar_u64.iter().rev().fold(BigInt::zero(), |acc, x| {
            let element_bn = BigInt::from(*x);
            element_bn + (acc << 64)
        });
        to_bn
    }

    fn q() -> BigInt {
        let q_u64: [u64; 4] = [
            0xffffffff00000001,
            0x53bda402fffe5bfe,
            0x3339d80809a1d805,
            0x73eda753299d7d48,
        ];
        let to_bn = q_u64.iter().rev().fold(BigInt::zero(), |acc, x| {
            let element_bn = BigInt::from(*x);
            element_bn + (acc << 64)
        });
        to_bn
    }

    fn add(&self, other: &SK) -> FieldScalar {
        let mut add_fe = FieldScalar {
            purpose: "other add",
            fe: *other,
        };
        add_fe.fe.add_assign(&self.fe);
        FieldScalar {
            purpose: "add",
            fe: add_fe.fe,
        }
    }

    fn mul(&self, other: &SK) -> FieldScalar {
        let mut mul_fe = FieldScalar {
            purpose: "other mul",
            fe: *other,
        };
        mul_fe.fe.mul_assign(&self.fe);
        FieldScalar {
            purpose: "mul",
            fe: mul_fe.fe,
        }
    }

    fn sub(&self, other: &SK) -> FieldScalar {
        let mut other_neg = *other;
        other_neg.negate();
        let sub_fe = FieldScalar {
            purpose: "other sub",
            fe: other_neg,
        };
        self.add(&sub_fe.get_element())
    }

    fn invert(&self) -> FieldScalar {
        let sc = self.fe;
        let inv_sc = sc.inverse().unwrap(); //TODO
        FieldScalar {
            purpose: "inverse",
            fe: inv_sc,
        }
    }
}

impl Debug for FieldScalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Point {{ purpose: {:?}, bytes: {:?} }}",
            self.purpose, self.fe,
        )
    }
}

impl PartialEq for FieldScalar {
    fn eq(&self, other: &FieldScalar) -> bool {
        self.get_element() == other.get_element()
    }
}

impl Mul<FieldScalar> for FieldScalar {
    type Output = FieldScalar;
    fn mul(self, other: FieldScalar) -> FieldScalar {
        (&self).mul(&other.get_element())
    }
}

impl<'o> Mul<&'o FieldScalar> for FieldScalar {
    type Output = FieldScalar;
    fn mul(self, other: &'o FieldScalar) -> FieldScalar {
        (&self).mul(&other.get_element())
    }
}

impl Add<FieldScalar> for FieldScalar {
    type Output = FieldScalar;
    fn add(self, other: FieldScalar) -> FieldScalar {
        (&self).add(&other.get_element())
    }
}

impl<'o> Add<&'o FieldScalar> for FieldScalar {
    type Output = FieldScalar;
    fn add(self, other: &'o FieldScalar) -> FieldScalar {
        (&self).add(&other.get_element())
    }
}

impl Serialize for FieldScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        serializer.serialize_str(&self.to_big_int().to_hex())
    }
}

impl<'de> Deserialize<'de> for FieldScalar {
    fn deserialize<D>(deserializer: D) -> Result<FieldScalar, D::Error>
        where
            D: Deserializer<'de>,
    {
        deserializer.deserialize_str(BLS12_381ScalarVisitor)
    }
}

struct BLS12_381ScalarVisitor;

impl<'de> Visitor<'de> for BLS12_381ScalarVisitor {
    type Value = FieldScalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("bls12_381")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<FieldScalar, E> {
        let v = BigInt::from_hex(s).map_err(E::custom)?;
        Ok(ECScalar::from(&v))
    }
}

impl Debug for G2Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Point {{ purpose: {:?}, bytes: {:?} }}",
            self.purpose,
            self.bytes_compressed_to_big_int().to_hex()
        )
    }
}

impl PartialEq for G2Point {
    fn eq(&self, other: &G2Point) -> bool {
        self.get_element() == other.get_element()
    }
}

impl Zeroize for G2Point {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, GE::generator()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECPoint for G2Point {
    type SecretKey = SK;
    type PublicKey = PK;
    type Scalar = FieldScalar;

    fn zero() -> Self {
        G2Point {
            purpose: "zero",
            ge: PK::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        self.ge.is_zero()
    }

    fn base_point2() -> G2Point {
        const BASE_POINT2: [u8; 192] = [
            0, 204, 165, 72, 21, 96, 36, 119, 117, 242, 58, 55, 105, 140, 136, 76, 180, 140, 92,
            212, 55, 3, 146, 72, 120, 181, 37, 205, 165, 221, 144, 86, 57, 124, 16, 19, 160, 215,
            21, 251, 236, 99, 91, 147, 237, 113, 223, 70, 14, 223, 81, 150, 157, 235, 107, 225,
            151, 227, 119, 53, 195, 46, 25, 54, 57, 158, 156, 122, 75, 152, 119, 51, 137, 131, 43,
            34, 68, 24, 24, 210, 18, 75, 36, 20, 232, 76, 38, 84, 44, 112, 213, 217, 192, 122, 177,
            186, 5, 113, 25, 229, 205, 55, 65, 191, 147, 1, 212, 194, 151, 141, 43, 223, 68, 185,
            183, 66, 163, 62, 96, 92, 36, 209, 216, 40, 16, 132, 231, 104, 179, 248, 189, 53, 154,
            106, 83, 159, 5, 54, 86, 87, 45, 68, 52, 247, 3, 90, 148, 187, 234, 213, 114, 244, 52,
            137, 201, 13, 165, 57, 217, 190, 150, 103, 223, 193, 129, 198, 47, 86, 122, 196, 22,
            200, 123, 89, 178, 216, 11, 238, 155, 106, 172, 125, 164, 95, 2, 136, 132, 137, 27,
            184, 237, 169,
        ];

        let mut point = G2Uncompressed::empty();
        point.as_mut().copy_from_slice(&BASE_POINT2);
        G2Point {
            purpose: "base_ge2",
            ge: point.into_affine().expect("invalid base_point"),
        }
    }

    fn generator() -> G2Point {
        G2Point {
            purpose: "base_fe",
            ge: PK::one(),
        }
    }

    fn get_element(&self) -> PK {
        self.ge
    }

    fn x_coor(&self) -> Option<BigInt> {
        let tmp = G2Uncompressed::from_affine(self.ge);
        let bytes = tmp.as_ref();
        let x_coor = &bytes[0..COMPRESSED_SIZE];
        let bn = BigInt::from_bytes(x_coor);
        Some(bn)
    }

    fn y_coor(&self) -> Option<BigInt> {
        let tmp = G2Uncompressed::from_affine(self.ge);
        let bytes = tmp.as_ref();
        let y_coor = &bytes[COMPRESSED_SIZE..2 * COMPRESSED_SIZE];
        let bn = BigInt::from_bytes(y_coor);
        Some(bn)
    }

    fn bytes_compressed_to_big_int(&self) -> BigInt {
        let tmp = G2Compressed::from_affine(self.ge);
        let bytes = tmp.as_ref();
        BigInt::from_bytes(bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<G2Point, ErrorKey> {
        let mut bytes_array_comp = [0u8; COMPRESSED_SIZE];
        match bytes.len() {
            0..=COMPRESSED_SIZE => {
                (&mut bytes_array_comp[COMPRESSED_SIZE - bytes.len()..]).copy_from_slice(bytes);
            }
            _ => {
                bytes_array_comp.copy_from_slice(&bytes[..COMPRESSED_SIZE]);
            }
        }

        let g2_comp = G2::deserialize(&mut bytes_array_comp[..].as_ref(), true).unwrap();

        let pk = G2Point {
            purpose: "from_bytes",
            ge: g2_comp.into_affine(), //TODO: handle error
        };

        Ok(pk)
    }

    // in this case the opposite of from_bytes: takes compressed pk to COMPRESSED_SIZE bytes.
    fn pk_to_key_slice(&self) -> Vec<u8> {
        let mut compressed_vec = vec![];
        PK::serialize(&self.ge, &mut compressed_vec, true)
            .expect("serializing into vec should always succeed");
        compressed_vec
    }

    fn scalar_mul(&self, fe: &SK) -> G2Point {
        let mut ge_proj: G2 = self.ge.into();
        ge_proj.mul_assign(fe.into_repr());
        G2Point {
            purpose: "scalar_point_mul",
            ge: ge_proj.into_affine(),
        }
    }

    fn add_point(&self, other: &PK) -> G2Point {
        let mut ge_proj: G2 = self.ge.into();
        ge_proj.add_assign_mixed(other);
        G2Point {
            purpose: "combine",
            ge: ge_proj.into_affine(),
        }
    }

    fn sub_point(&self, other: &PK) -> G2Point {
        let mut ge_proj: G2 = self.ge.into();
        ge_proj.sub_assign_mixed(other);
        G2Point {
            purpose: "sub",
            ge: ge_proj.into_affine(),
        }
    }

    fn from_coor(_x: &BigInt, _y: &BigInt) -> G2Point {
        // TODO
        unimplemented!();
    }
}

impl From<pairing_plus::bls12_381::G2Affine> for G2Point {
    fn from(point: PK) -> Self {
        G2Point {
            purpose: "from_point",
            ge: point,
        }
    }
}

impl Mul<FieldScalar> for G2Point {
    type Output = G2Point;
    fn mul(self, other: FieldScalar) -> G2Point {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o FieldScalar> for G2Point {
    type Output = G2Point;
    fn mul(self, other: &'o FieldScalar) -> G2Point {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o FieldScalar> for &'o G2Point {
    type Output = G2Point;
    fn mul(self, other: &'o FieldScalar) -> G2Point {
        self.scalar_mul(&other.get_element())
    }
}

impl Add<G2Point> for G2Point {
    type Output = G2Point;
    fn add(self, other: G2Point) -> G2Point {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o G2Point> for G2Point {
    type Output = G2Point;
    fn add(self, other: &'o G2Point) -> G2Point {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o G2Point> for &'o G2Point {
    type Output = G2Point;
    fn add(self, other: &'o G2Point) -> G2Point {
        self.add_point(&other.get_element())
    }
}

impl Neg for G2Point {
    type Output = Self;
    fn neg(mut self) -> Self {
        self.ge.negate();
        self.purpose = "negated";
        self
    }
}

#[cfg(feature = "merkle")]
impl Hashable for G2Point {
    fn update_context(&self, context: &mut Sha3) {
        let bytes: Vec<u8> = self.pk_to_key_slice();
        context.input(&bytes[..]);
    }
}

impl Serialize for G2Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let bytes = self.pk_to_key_slice();
        let bytes_as_bn = BigInt::from_bytes(&bytes[..]);
        let mut state = serializer.serialize_struct("Bls12381G2Point", 1)?;
        state.serialize_field("bytes_str", &bytes_as_bn.to_hex())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for G2Point {
    fn deserialize<D>(deserializer: D) -> Result<G2Point, D::Error>
        where
            D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["bytes_str"];
        deserializer.deserialize_struct("Bls12381G2Point", FIELDS, Bls12381G2PointVisitor)
    }
}

struct Bls12381G2PointVisitor;

impl<'de> Visitor<'de> for Bls12381G2PointVisitor {
    type Value = G2Point;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Bls12381G2Point")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<G2Point, V::Error>
        where
            V: SeqAccess<'de>,
    {
        let bytes_str = seq
            .next_element()?
            .ok_or_else(|| V::Error::invalid_length(0, &"a single element"))?;
        let bytes_bn = BigInt::from_hex(bytes_str).map_err(V::Error::custom)?;
        let bytes = BigInt::to_bytes(&bytes_bn);
        G2Point::from_bytes(&bytes[..]).map_err(|_| V::Error::custom("failed to parse g2 point"))
    }

    fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<G2Point, E::Error> {
        let mut bytes_str: String = "".to_string();

        while let Some(key) = map.next_key::<&'de str>()? {
            let v = map.next_value::<&'de str>()?;
            match key {
                "bytes_str" => {
                    bytes_str = String::from(v);
                }
                _ => return Err(E::Error::unknown_field(key, &["bytes_str"])),
            }
        }
        let bytes_bn = BigInt::from_hex(&bytes_str).map_err(E::Error::custom)?;
        let bytes = BigInt::to_bytes(&bytes_bn);

        G2Point::from_bytes(&bytes[..]).map_err(|_| E::Error::custom("failed to parse g2 point"))
    }
}

impl G2Point {
    /// Converts message to G1 point.
    ///
    /// Uses [expand_message_xmd][xmd] based on sha256.
    ///
    /// [xmd]: https://www.ietf.org/id/draft-irtf-cfrg-hash-to-curve-10.html#name-expand_message_xmd-2
    pub fn hash_to_curve(message: &[u8]) -> Self {
        let cs:&[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let point = <G2 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(message, cs);
        G2Point {
            purpose: "hash_to_curve",
            ge: point.into_affine(),
        }
    }
}

#[cfg(test)]
mod tests {
    use pairing_plus::bls12_381::{G2Uncompressed, G2};
    use pairing_plus::hash_to_curve::HashToCurve;
    use pairing_plus::hash_to_field::ExpandMsgXmd;
    use pairing_plus::{CurveProjective, SubgroupCheck};
    use sha2::Sha256;

    use super::G2Point;
    use crate::arithmetic::traits::*;
    use crate::elliptic::curves::bls12_381::g2::{FE, GE};
    use crate::elliptic::curves::traits::ECPoint;
    use crate::elliptic::curves::traits::ECScalar;
    use crate::BigInt;

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
    fn bincode_pk() {
        let pk = GE::generator();
        let bin = bincode::serialize(&pk).unwrap();
        let decoded: G2Point = bincode::deserialize(bin.as_slice()).unwrap();
        assert_eq!(decoded, pk);
    }

    #[test]
    #[should_panic]
    #[allow(clippy::op_ref)] // Enables type inference.
    fn test_serdes_bad_pk() {
        let pk = GE::generator();
        let s = serde_json::to_string(&pk).expect("Failed in serialization");
        // we make sure that the string encodes invalid point:
        let s: String = s.replace("30", "20");
        let des_pk: GE = serde_json::from_str(&s).expect("Failed in deserialization");
        let eight = ECScalar::from(&BigInt::from(8));
        assert_eq!(des_pk, pk * &eight);
    }

    #[test]
    fn test_from_mpz() {
        let rand_scalar: FE = ECScalar::new_random();
        let rand_bn = rand_scalar.to_big_int();
        let rand_scalar2: FE = ECScalar::from(&rand_bn);
        assert_eq!(rand_scalar, rand_scalar2);
    }

    #[test]
    fn test_minus_point() {
        let a: FE = ECScalar::new_random();
        let b: FE = ECScalar::new_random();
        let a_minus_b_fe: FE = a.sub(&b.get_element());
        let base: GE = ECPoint::generator();

        let point_ab1 = base * a_minus_b_fe;
        let point_a = base * a;
        let point_b = base * b;
        let point_ab2 = point_a.sub_point(&point_b.get_element());
        println!(
            "point ab1: {:?}",
            point_ab1.bytes_compressed_to_big_int().to_hex()
        );
        println!(
            "point ab2: {:?}",
            point_ab2.bytes_compressed_to_big_int().to_hex()
        );

        assert_eq!(point_ab1, point_ab2);
    }

    #[test]
    fn test_add_point() {
        let a: FE = ECScalar::new_random();
        let b: FE = ECScalar::new_random();
        let a_plus_b_fe = a + b;
        let base: GE = ECPoint::generator();
        let point_ab1 = base * a_plus_b_fe;
        let point_a = base * a;
        let point_b = base * b;
        let point_ab2 = point_a.add_point(&point_b.get_element());

        assert_eq!(point_ab1, point_ab2);
    }

    #[test]
    fn test_add_scalar() {
        let a: FE = ECScalar::new_random();
        let zero: FE = FE::zero();
        let a_plus_zero: FE = a + zero;

        assert_eq!(a_plus_zero, a);
    }

    #[test]
    fn test_mul_scalar() {
        let a = [
            10, 10, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 10, 10, 10,
        ];

        let a_bn = BigInt::from_bytes(&a[..]);
        let a_fe: FE = ECScalar::from(&a_bn);

        let five = BigInt::from(5);
        let five_fe: FE = ECScalar::from(&five);
        println!("five_fe: {:?}", five_fe.clone());
        let five_a_bn = BigInt::mod_mul(&a_bn, &five, &FE::q());
        let five_a_fe = five_fe * a_fe;
        let five_a_fe_2: FE = ECScalar::from(&five_a_bn);

        assert_eq!(five_a_fe, five_a_fe_2);
    }

    #[test]
    fn test_mul_point() {
        let a: FE = ECScalar::new_random();
        let b: FE = ECScalar::new_random();
        let a_mul_b_fe = a * b;
        let base: GE = ECPoint::generator();
        let point_ab1 = base * a_mul_b_fe;
        let point_a = base * a;
        let point_ab2 = point_a.scalar_mul(&b.get_element());

        assert_eq!(point_ab1, point_ab2);
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
    fn test_scalar_mul_multiply_by_1() {
        let g: GE = ECPoint::generator();

        let fe: FE = ECScalar::from(&BigInt::from(1));
        let b_tag = g * fe;
        assert_eq!(b_tag, g);
    }

    #[test]
    fn base_point2_nothing_up_my_sleeve() {
        // Generate base_point2
        let cs = &[1u8];
        let msg = &[1u8];
        let point = <G2 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, cs).into_affine();
        assert!(point.in_subgroup());

        // Print in uncompressed form
        use pairing_plus::EncodedPoint;
        let point_uncompressed = G2Uncompressed::from_affine(point);
        println!("Uncompressed base_point2: {:?}", point_uncompressed);

        // Check that ECPoint::base_point2() returns generated point
        let base_point2: GE = ECPoint::base_point2();
        assert_eq!(point, base_point2.ge);
    }
}