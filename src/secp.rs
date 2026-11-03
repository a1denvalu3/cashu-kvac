use bitcoin::hashes::serde::{Serialize, Serializer};
use bitcoin::secp256k1::constants::CURVE_ORDER;
use bitcoin::secp256k1::{rand, All, PublicKey, Scalar as SecpScalar, Secp256k1, SecretKey};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::Signed;
use num_traits::{One, Zero};
use once_cell::sync::Lazy;
use serde::{Deserialize, Deserializer};
use std::cmp::PartialEq;
use std::hash::{Hash, Hasher};
use std::ops::{AddAssign, BitAnd, Shr, ShrAssign, SubAssign};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::errors::Error;
use crate::generators::GENERATORS;

pub const SCALAR_ZERO: [u8; 32] = [0; 32];
pub const SCALAR_ONE: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
pub const GROUP_ELEMENT_ZERO: [u8; 33] = [0; 33];

/// Secp256k1 global context
pub static SECP256K1: Lazy<Secp256k1<All>> = Lazy::new(|| {
    let mut ctx = Secp256k1::new();
    let mut rng = rand::thread_rng();
    ctx.randomize(&mut rng);
    ctx
});

/// Defines different kinds of tweaks to be applied to `GroupElement` or `Scalar`
pub enum TweakKind {
    AMOUNT,
}

/// Wraps a `secp256k1::key::SecretKey` or `None`
#[derive(Clone, Debug, Eq, PartialEq, Default, Copy)]
#[wasm_bindgen]
pub struct Scalar {
    inner: Option<SecretKey>,
}

/// Wraps a `secp256k1::key::PublicKey` or `None`
#[derive(Hash, Clone, Debug, Eq, PartialEq, Default, Copy)]
#[wasm_bindgen]
pub struct GroupElement {
    inner: Option<PublicKey>,
}

fn div2(m: &BigInt, mut x: BigInt) -> BigInt {
    if (&x).bitand(&BigInt::one()) == BigInt::one() {
        x += m;
    }
    x.shr(1)
}

fn euclidean_mod(a: &BigInt, m: &BigInt) -> BigInt {
    let r = a % m;
    if r.is_negative() {
        r + m
    } else {
        r
    }
}

fn modinv(m: &BigInt, x: &BigInt) -> BigInt {
    assert!(m.bitand(&BigInt::one()) == BigInt::one(), "M must be odd");
    let mut delta = 1;
    let mut f = m.clone();
    let mut g = x.clone();
    let mut d = BigInt::zero();
    let mut e = BigInt::one();

    while !g.is_zero() {
        if delta > 0 && (&g).bitand(&BigInt::one()) == BigInt::one() {
            let tmp_g = g.clone();
            g.sub_assign(&f);
            g.shr_assign(1);
            f = tmp_g;
            let tmp_e = e.clone();
            e = div2(m, e - &d);
            d = tmp_e;
            delta = 1 - delta;
        } else if (&g).bitand(&BigInt::one()) == BigInt::one() {
            g.add_assign(&f);
            g.shr_assign(1);
            e = div2(m, e + &d);
            delta += 1;
        } else {
            g.shr_assign(1);
            e = div2(m, e);
            delta += 1;
        }
    }

    // Result: (d * f) % m using Euclidean modulus
    euclidean_mod(&(d * f), m)
}

impl Scalar {
    /// Creates a new `Scalar` instance from the provided byte slice.
    ///
    /// If the provided data is equal to `SCALAR_ZERO`, the `Scalar` will be initialized
    /// with `inner` set to `None`. Otherwise, it attempts to create a `SecretKey` from
    /// the byte slice and wraps it in `Some`.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice representing the scalar value.
    ///
    /// # Returns
    ///
    /// A new `Scalar` instance.
    pub fn new(data: &[u8]) -> Self {
        if *data == SCALAR_ZERO {
            Scalar { inner: None }
        } else {
            let inner = SecretKey::from_slice(data).expect("Could not instantiate Scalar");
            Scalar { inner: Some(inner) }
        }
    }

    /// Generates a new random `Scalar` instance.
    ///
    /// This method uses `rand::thread_rng` to create a new `SecretKey` and wraps
    /// it in `Some`.
    ///
    /// # Returns
    ///
    /// A new `Scalar` instance with a random value.
    pub fn random() -> Self {
        #[cfg(feature = "proof-debug")]
        {
            let inner = SecretKey::from_slice(&SCALAR_ONE).expect("1 is a valid scalar");
            Scalar { inner: Some(inner) }
        }
        #[cfg(not(feature = "proof-debug"))]
        {
            let inner = SecretKey::new(&mut rand::thread_rng());
            Scalar { inner: Some(inner) }
        }
    }

    /// Multiplies the current `Scalar` by another `Scalar` using a tweak.
    ///
    /// If either `self` or `other` is zero (i.e., `inner` is `None`), the result will
    /// be set to zero. Otherwise, it performs the multiplication and updates `self`.
    ///
    /// # Arguments
    ///
    /// * `other` - A reference to another `Scalar` to multiply with.
    ///
    /// # Returns
    ///
    /// A mutable reference to `self`.
    pub fn tweak_mul(&mut self, other: &Scalar) -> &Self {
        if other.inner.is_none() || self.inner.is_none() {
            self.inner = None;
            return self;
        }
        let b = SecpScalar::from_be_bytes(other.inner.unwrap().secret_bytes()).unwrap();
        let result = self
            .inner
            .unwrap()
            .mul_tweak(&b)
            .expect("Could not multiply Scalars");
        self.inner = Some(result);
        self
    }

    /// Adds another `Scalar` to the current `Scalar` using a tweak.
    ///
    /// If `other` is zero, it returns `self`. If `self` is zero, it sets `self` to
    /// `other`. Otherwise, it performs the addition and updates `self`.
    ///
    /// # Arguments
    ///
    /// * `other` - A reference to another `Scalar` to add.
    ///
    /// # Returns
    ///
    /// A mutable reference to `self`.
    pub fn tweak_add(&mut self, other: &Scalar) -> &Self {
        let Some(other_inner) = other.inner else {
            return self;
        };
        match self.inner {
            None => {
                self.inner = Some(other_inner);
                self
            }
            Some(self_inner) => {
                let b = SecpScalar::from_be_bytes(other_inner.secret_bytes()).unwrap();
                let result_key = self_inner.add_tweak(&b).expect("Could not add to Scalar");
                self.inner = Some(result_key);
                self
            }
        }
    }

    /// Negates the current `Scalar`.
    ///
    /// If `self` is zero, it returns `self` unchanged. Otherwise, it negates the value
    /// and updates `self`.
    ///
    /// # Returns
    ///
    /// A mutable reference to `self`.
    pub fn tweak_neg(&mut self) -> &Self {
        if self.inner.is_none() {
            self
        } else {
            let result = self.inner.unwrap().negate();
            self.inner = Some(result);
            self
        }
    }

    /// Computes the multiplicative inverse of the current `Scalar`.
    ///
    /// If `self` is zero, it panics with an error message. Otherwise, it calculates
    /// the inverse and returns a new `Scalar` instance containing the result.
    ///
    /// # Returns
    ///
    /// A new `Scalar` instance representing the inverse of `self`.
    pub fn invert(self) -> Self {
        let Some(inner) = self.inner else {
            panic!("Scalar 0 doesn't have an inverse")
        };
        {
            let x = BigUint::from_bytes_be(&inner.secret_bytes());
            let q = BigUint::from_bytes_be(&CURVE_ORDER);
            let x_inv = modinv(
                &q.to_bigint().expect("Can convert BigUint to BigInt"),
                &x.to_bigint().expect("Can convert BigUint to BigInt"),
            );
            let (_sign, mut vec) = x_inv.to_bytes_le();
            if vec.len() < 32 {
                vec.extend(vec![0; 32 - vec.len()]);
            }
            vec.reverse();
            let inner = SecretKey::from_slice(&vec).expect("Could not instantiate Scalar");
            Scalar { inner: Some(inner) }
        }
    }

    /// Converts the current `Scalar` to a byte vector.
    ///
    /// If `self` is zero, it returns a vector containing `SCALAR_ZERO`. Otherwise, it
    /// returns the byte representation of the `SecretKey` wrapped in `self`.
    ///
    /// # Returns
    ///
    /// A vector of bytes representing the scalar value.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.inner {
            None => Vec::from(SCALAR_ZERO),
            Some(inner) => Vec::from(inner.secret_bytes()),
        }
    }

    /// Checks if the current `Scalar` is zero.
    ///
    /// This method returns `true` if `self` is zero (i.e., `inner` is `None`), and
    /// `false` otherwise.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether the scalar is zero.
    pub fn is_zero(&self) -> bool {
        self.inner.is_none()
    }
}

impl GroupElement {
    /// Creates a new `GroupElement` instance from the provided byte slice.
    ///
    /// If the provided data is equal to `GROUP_ELEMENT_ZERO`, the `GroupElement` will be
    /// initialized with `inner` set to `None`. Otherwise, it attempts to create a `PublicKey`
    /// from the byte slice and wraps it in `Some`.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice representing the group element value.
    ///
    /// # Returns
    ///
    /// A new `GroupElement` instance.
    pub fn new(data: &[u8]) -> Self {
        if *data == GROUP_ELEMENT_ZERO {
            GroupElement { inner: None }
        } else {
            let inner = PublicKey::from_slice(data).expect("Cannot create GroupElement");
            GroupElement { inner: Some(inner) }
        }
    }

    /// Combines the current `GroupElement` with another `GroupElement` using addition.
    ///
    /// If `other` is zero (i.e., `inner` is `None`), it returns `self`. If `self` is zero,
    /// it sets `self` to `other`. Otherwise, it performs the combination and updates `self`.
    ///
    /// # Arguments
    ///
    /// * `other` - A reference to another `GroupElement` to combine with.
    ///
    /// # Returns
    ///
    /// A mutable reference to `self`.
    pub fn combine_add(&mut self, other: &GroupElement) -> &Self {
        let Some(other_inner) = other.inner else {
            return self;
        };
        match self.inner {
            None => {
                self.inner = Some(other_inner);
                self
            }
            Some(self_inner) => {
                let result = self_inner
                    .combine(&other_inner)
                    .expect("Error combining GroupElements");
                self.inner = Some(result);
                self
            }
        }
    }

    /// Multiplies the current `GroupElement` by a scalar.
    ///
    /// If either `scalar` or `self` is zero (i.e., `inner` is `None`), the result will be
    /// set to zero. Otherwise, it performs the multiplication and updates `self`.
    ///
    /// # Arguments
    ///
    /// * `scalar` - A reference to a `Scalar` to multiply with.
    ///
    /// # Returns
    ///
    /// A mutable reference to `self`.
    pub fn multiply(&mut self, scalar: &Scalar) -> &Self {
        let (Some(scalar_inner), Some(self_inner)) = (scalar.inner, self.inner) else {
            self.inner = None;
            return self;
        };
        {
            let b = bitcoin::secp256k1::Scalar::from_be_bytes(scalar_inner.secret_bytes()).unwrap();
            let result = self_inner
                .mul_tweak(&SECP256K1, &b)
                .expect("Could not multiply Scalar to GroupElement");
            self.inner = Some(result);
            self
        }
    }

    /// Negates the current `GroupElement`.
    ///
    /// If `self` is zero, it returns `self` unchanged. Otherwise, it negates the value
    /// and updates `self`.
    ///
    /// # Returns
    ///
    /// A mutable reference to `self`.
    pub fn negate(&mut self) -> &Self {
        if self.inner.is_none() {
            self
        } else {
            let result = self.inner.unwrap().negate(&SECP256K1);
            self.inner = Some(result);
            self
        }
    }

    /// Converts the current `GroupElement` to a byte vector.
    ///
    /// If `self` is zero, it returns a vector containing `GROUP_ELEMENT_ZERO`. Otherwise,
    /// it returns the byte representation of the `PublicKey` wrapped in `self`.
    ///
    /// # Returns
    ///
    /// A vector of bytes representing the group element value.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.inner {
            None => Vec::from(GROUP_ELEMENT_ZERO),
            Some(inner) => Vec::from(inner.serialize()),
        }
    }

    /// Applies a tweak to the current `GroupElement`.
    ///
    /// This method modifies `self` based on the specified `tweak_kind` and `tweak` value.
    /// Currently, it only supports the `TweakKind::AMOUNT` variant, which combines `self`
    /// with a generator multiplied by the given tweak.
    ///
    /// # Arguments
    ///
    /// * `tweak_kind` - The kind of tweak to apply.
    /// * `tweak` - A `u64` value representing the tweak.
    ///
    /// # Returns
    ///
    /// A mutable reference to `self`.
    pub fn tweak(&mut self, tweak_kind: TweakKind, tweak: u64) -> &Self {
        match tweak_kind {
            TweakKind::AMOUNT => {
                let mut ge = GENERATORS.G_amount;
                let scalar = Scalar::from(tweak);
                self.combine_add(ge.multiply(&scalar));
                self
            }
        }
    }

    /// Checks if the current `GroupElement` is zero.
    ///
    /// This method returns `true` if `self` is zero (i.e., `inner` is `None`), and
    /// `false` otherwise.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether the group element is zero.
    pub fn is_zero(&self) -> bool {
        self.inner.is_none()
    }
}

impl std::ops::Add<&Scalar> for Scalar {
    type Output = Scalar;

    fn add(mut self, other: &Scalar) -> Scalar {
        self.tweak_add(other);
        self
    }
}

impl std::ops::AddAssign<&Scalar> for Scalar {
    fn add_assign(&mut self, rhs: &Scalar) {
        self.tweak_add(rhs);
    }
}

impl std::ops::Neg for Scalar {
    type Output = Scalar;

    fn neg(mut self) -> Scalar {
        self.tweak_neg();
        self
    }
}

impl std::ops::Sub<&Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        if other.inner.is_none() {
            self
        } else if self.inner.is_none() {
            -*other
        } else {
            let other_neg = -*other;
            self + &other_neg
        }
    }
}

impl std::ops::Mul<&Scalar> for Scalar {
    type Output = Scalar;

    fn mul(mut self, other: &Scalar) -> Scalar {
        if other.inner.is_none() || self.inner.is_none() {
            self.inner = None;
            self
        } else {
            self.tweak_mul(other);
            self
        }
    }
}

impl From<&Scalar> for Vec<u8> {
    fn from(val: &Scalar) -> Self {
        match val.inner {
            None => SCALAR_ZERO.to_vec(),
            Some(inner) => inner.secret_bytes().to_vec(),
        }
    }
}

impl From<&Scalar> for [u8; 32] {
    fn from(val: &Scalar) -> Self {
        match val.inner {
            None => SCALAR_ZERO,
            Some(inner) => inner.secret_bytes(),
        }
    }
}

impl From<&Scalar> for u64 {
    fn from(val: &Scalar) -> Self {
        if val.inner.is_none() {
            0
        } else {
            let bytes: [u8; 32] = val.into();
            let mut result: u64 = 0;
            for i in 0..8 {
                result <<= 8;
                result |= bytes[24 + i] as u64;
            }
            result
        }
    }
}

impl From<&Scalar> for String {
    fn from(val: &Scalar) -> Self {
        match val.inner {
            None => hex::encode(SCALAR_ZERO),
            Some(inner) => hex::encode(inner.secret_bytes()),
        }
    }
}

impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24] = (value >> 56) as u8;
        bytes[25] = (value >> 48) as u8;
        bytes[26] = (value >> 40) as u8;
        bytes[27] = (value >> 32) as u8;
        bytes[28] = (value >> 24) as u8;
        bytes[29] = (value >> 16) as u8;
        bytes[30] = (value >> 8) as u8;
        bytes[31] = value as u8;
        Scalar::new(&bytes)
    }
}

impl std::str::FromStr for Scalar {
    type Err = Error;
    fn from_str(hex_string: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex_string)?;
        if bytes.len() > 32 {
            return Err(Error::HexStringTooLong);
        }
        let mut padded_bytes = [0u8; 32];
        padded_bytes[32 - bytes.len()..32].copy_from_slice(&bytes);
        if padded_bytes == SCALAR_ZERO {
            return Err(Error::ScalarZero);
        }
        Ok(Scalar::new(&padded_bytes))
    }
}

impl TryFrom<&BigInt> for Scalar {
    type Error = Error;
    fn try_from(value: &BigInt) -> Result<Self, Error> {
        let (_, mut value_bytes) = value.to_bytes_le();
        if value_bytes.len() < 32 {
            value_bytes.resize(32, 0u8);
        }
        value_bytes.reverse();
        Ok(Scalar::new(&value_bytes))
    }
}

impl TryFrom<&str> for Scalar {
    type Error = Error;
    fn try_from(hex_string: &str) -> Result<Self, Error> {
        std::str::FromStr::from_str(hex_string)
    }
}

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let scalar_hex: String = self.into();
        serializer.serialize_str(&scalar_hex)
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex: String = String::deserialize(deserializer)?;
        let scalar =
            Scalar::try_from(hex.as_str()).map_err(|e| serde::de::Error::custom(format!("{e}")))?;
        Ok(scalar)
    }
}

impl Hash for Scalar {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.is_none().hash(state);
        if let Some(inner) = self.inner {
            inner.secret_bytes().hash(state);
        }
    }
}

impl std::ops::Add<&GroupElement> for GroupElement {
    type Output = GroupElement;

    fn add(mut self, other: &GroupElement) -> GroupElement {
        self.combine_add(other);
        self
    }
}

impl std::ops::AddAssign<&GroupElement> for GroupElement {
    fn add_assign(&mut self, rhs: &GroupElement) {
        self.combine_add(rhs);
    }
}

impl std::ops::Neg for GroupElement {
    type Output = GroupElement;

    fn neg(mut self) -> GroupElement {
        self.negate();
        self
    }
}

impl std::ops::Sub<&GroupElement> for GroupElement {
    type Output = GroupElement;

    fn sub(self, other: &GroupElement) -> GroupElement {
        if other.inner.is_none() {
            self
        } else if self.inner.is_none() {
            -*other
        } else {
            let other_neg = -*other;
            self + &other_neg
        }
    }
}

impl std::ops::Mul<&Scalar> for GroupElement {
    type Output = GroupElement;

    fn mul(mut self, other: &Scalar) -> GroupElement {
        if self.inner.is_none() || other.inner.is_none() {
            self.inner = None;
            self
        } else {
            // Multiplication is masked with random `r`
            let r = Scalar::random();
            let r_copy = r;
            let mut self_copy = self;
            self.multiply(&(r + other));
            self_copy.multiply(&r_copy);
            self - &self_copy
        }
    }
}

impl std::str::FromStr for GroupElement {
    type Err = Error;
    fn from_str(hex_string: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex_string)?;
        if bytes.len() > 33 {
            return Err(Error::HexStringTooLong);
        }
        let mut padded_bytes = [0u8; 33];
        padded_bytes[33 - bytes.len()..33].copy_from_slice(&bytes);
        if padded_bytes == GROUP_ELEMENT_ZERO {
            return Err(Error::GroupElementZero);
        }
        Ok(GroupElement::new(&padded_bytes))
    }
}

impl TryFrom<&str> for GroupElement {
    type Error = Error;
    fn try_from(hex_string: &str) -> Result<Self, Error> {
        std::str::FromStr::from_str(hex_string)
    }
}

impl From<&GroupElement> for [u8; 33] {
    fn from(val: &GroupElement) -> Self {
        match val.inner {
            None => GROUP_ELEMENT_ZERO,
            Some(inner) => inner.serialize(),
        }
    }
}

impl From<&GroupElement> for String {
    fn from(val: &GroupElement) -> Self {
        match val.inner {
            None => hex::encode(GROUP_ELEMENT_ZERO),
            Some(inner) => hex::encode(inner.serialize()),
        }
    }
}

impl AsRef<GroupElement> for GroupElement {
    fn as_ref(&self) -> &GroupElement {
        self
    }
}

impl Serialize for GroupElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ge_hex: String = self.into();
        serializer.serialize_str(&ge_hex)
    }
}

impl<'de> Deserialize<'de> for GroupElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex: String = String::deserialize(deserializer)?;
        let ge = GroupElement::try_from(hex.as_str())
            .map_err(|e| serde::de::Error::custom(format!("{e}")))?;
        Ok(ge)
    }
}

#[cfg(test)]
mod tests {
    use crate::generators::hash_to_curve;

    use super::*;

    #[test]
    fn test_new_scalar() {
        let data = [1u8; 32];
        let scalar = Scalar::new(&data);
        assert!(!scalar.is_zero());
    }

    #[test]
    fn test_new_zero_scalar() {
        let scalar = Scalar::new(&SCALAR_ZERO);
        assert!(scalar.is_zero());
    }

    #[test]
    fn test_random_scalar() {
        let scalar = Scalar::random();
        assert!(!scalar.is_zero());
    }

    #[test]
    fn test_clone_scalar() {
        let scalar = Scalar::random();
        let cloned_scalar = scalar;
        assert_eq!(scalar.inner, cloned_scalar.inner);
        assert_eq!(scalar.is_zero(), cloned_scalar.is_zero());
    }

    #[test]
    fn test_scalar_tweak_mul() {
        let mut scalar1 = Scalar::try_from("02").unwrap();
        let scalar2 = Scalar::try_from("03").unwrap();
        let result = Scalar::try_from("06").unwrap();
        let result_ = scalar1.tweak_mul(&scalar2);
        assert!(*result_ == result);
    }

    #[test]
    fn test_scalar_tweak_add() {
        let mut scalar1 = Scalar::try_from("02").unwrap();
        let scalar2 = Scalar::try_from("03").unwrap();
        let result = Scalar::try_from("05").unwrap();
        let result_ = scalar1.tweak_add(&scalar2);
        assert!(result == *result_);
    }

    #[test]
    fn test_scalar_add() {
        let scalar1 = Scalar::try_from("02").unwrap();
        let scalar2 = Scalar::try_from("03").unwrap();
        let result = Scalar::try_from("05").unwrap();
        let result_ = scalar1 + &scalar2;
        assert!(result_ == result);
    }

    #[test]
    fn test_scalar_sub() {
        let scalar1 = Scalar::try_from("10").unwrap();
        let scalar2 = Scalar::try_from("02").unwrap();
        let result = Scalar::try_from("0e").unwrap();
        let result_ = scalar1 - &scalar2;
        assert!(result == result_);
    }

    #[test]
    fn test_scalar_mul() {
        let scalar1 = Scalar::try_from("02").unwrap();
        let scalar2 = Scalar::try_from("03").unwrap();
        let result = Scalar::try_from("06").unwrap();
        let result_ = scalar1 * &scalar2;
        assert!(result_ == result);
    }

    #[test]
    fn test_scalar_mul_zero() {
        let scalar1 = Scalar::random();
        let scalar2 = Scalar::new(&SCALAR_ZERO);
        let result = scalar1 * &scalar2;
        assert!(result.is_zero());
    }

    #[test]
    fn test_scalar_mul_by_zero() {
        let scalar1 = Scalar::new(&SCALAR_ZERO);
        let scalar2 = Scalar::random();
        let result = scalar1 * &scalar2;
        assert!(result.is_zero());
    }

    #[test]
    fn test_mul_cmp() {
        let a = Scalar::random();
        let b = Scalar::random();
        let mut a_clone = a;
        let c = a_clone.tweak_mul(&b);
        let c_ = a * &b;
        assert!(*c == c_);
    }

    #[test]
    fn test_scalar_into_vec() {
        let scalar = Scalar::random();
        let bytes: Vec<u8> = scalar.as_ref().into();
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().any(|&b| b != 0)); // Ensure it's not all zeros
    }

    #[test]
    fn test_zero_scalar_into_vec() {
        let scalar = Scalar::new(&SCALAR_ZERO);
        let bytes: Vec<u8> = scalar.as_ref().into();
        assert_eq!(bytes, SCALAR_ZERO.to_vec());
    }

    #[test]
    fn test_scalar_into_string() {
        let scalar = Scalar::random();
        let hex_str: String = scalar.as_ref().into();
        assert_eq!(hex_str.len(), 64);
        assert!(hex::decode(&hex_str).is_ok());
    }

    #[test]
    fn test_zero_scalar_into_string() {
        let scalar = Scalar::new(&SCALAR_ZERO);
        let hex_str: String = scalar.as_ref().into();
        assert_eq!(hex_str, hex::encode(SCALAR_ZERO));
    }

    #[test]
    fn test_div2_even() {
        let m = BigInt::from(29);
        let x = BigInt::from(20);
        assert_eq!(div2(&m, x), BigInt::from(10));
    }

    #[test]
    fn test_div2_odd() {
        let m = BigInt::from(29);
        let x = BigInt::from(21);
        assert_eq!(div2(&m, x), BigInt::from(25));
    }

    #[test]
    fn test_scalar_modular_inversion() {
        let one = Scalar::new(&SCALAR_ONE);
        let scalar = Scalar::try_from("deadbeef").unwrap();
        let scalar_inv = scalar.invert();
        let prod = scalar * &scalar_inv;
        assert!(one == prod);
    }

    #[test]
    fn test_invert_scalar_one() {
        let one = Scalar::new(&SCALAR_ONE);
        let one_inv = one.invert();
        assert!(one == one_inv)
    }

    #[test]
    fn test_scalar_serialization() {
        let scalar = Scalar::random();

        // Serialize the Scalar instance
        let serialized = serde_json::to_string(&scalar).expect("Failed to serialize");
        println!("{}", serialized);
        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_scalar_deserialization() {
        let scalar = Scalar::random();

        // Serialize the Scalar instance to JSON
        let serialized = serde_json::to_string(&scalar).expect("Failed to serialize");

        // Deserialize back to Scalar
        let deserialized: Scalar =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Check that the deserialized Scalar matches the original
        assert_eq!(scalar.is_zero(), deserialized.is_zero());
        assert_eq!(scalar.inner.is_some(), deserialized.inner.is_some());
    }

    #[test]
    fn test_ge_from_hex() {
        let g = GroupElement::try_from(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        assert!(!g.is_zero())
    }

    #[test]
    fn test_ge_into() {
        let hex_str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let g = GroupElement::try_from(hex_str).unwrap();
        let g_string: String = g.as_ref().into();
        assert!(hex_str == g_string)
    }

    #[test]
    fn test_cmp_neq() {
        let g1 = GroupElement::try_from(
            "0264f39fbee428ab6165e907b5d463a17e315b9f06f6200ed7e9c4bcbe0df73383",
        )
        .unwrap();
        let g2 = GroupElement::try_from(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        assert!(g1 != g2);
    }

    #[test]
    fn test_ge_add_mul() {
        let g = GroupElement::try_from(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let scalar_2 = Scalar::try_from("02").unwrap();
        let result = g + &g;
        let result_ = g * &scalar_2;
        assert!(result == result_)
    }

    #[test]
    fn test_ge_sub_mul() {
        let g = GroupElement::try_from(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let scalar_2 = Scalar::try_from("02").unwrap();
        let result = g * &scalar_2 - &g;
        assert!(result == g)
    }

    #[test]
    fn test_ge_serialization() {
        let ge = hash_to_curve(b"deadbeef").unwrap();

        // Serialize the Scalar instance
        let serialized = serde_json::to_string(&ge).expect("Failed to serialize");
        println!("{}", serialized);
        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_ge_deserialization() {
        let ge = hash_to_curve(b"deadbeef").unwrap();

        let serialized = serde_json::to_string(&ge).expect("Failed to serialize");

        let deserialized: GroupElement =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        assert_eq!(ge.is_zero(), deserialized.is_zero());
        assert_eq!(ge.inner.is_some(), deserialized.inner.is_some());
    }

    #[test]
    fn test_ge_amount_tweak() {
        let mut ge = GENERATORS.G_amount;
        ge = ge * &Scalar::from(2);

        let tweak = 4_u64;

        ge.tweak(TweakKind::AMOUNT, tweak);
        assert_eq!(ge, GENERATORS.G_amount * &Scalar::from(6));
    }
}
