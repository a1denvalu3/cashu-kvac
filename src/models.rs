//! # Model Module
//! Module containing models involved in KVAC operations

use crate::{
    bulletproof::BulletProof,
    errors::Error,
    generators::{hash_to_curve, GENERATORS},
    secp::{GroupElement, Scalar},
};
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use wasm_bindgen::prelude::wasm_bindgen;

/// The maximum allowed range for values.
pub const RANGE_LIMIT: u64 = u32::MAX as u64;

/// Public minting key used for verifying coin issuance.
#[allow(non_snake_case)]
#[derive(Clone, Serialize, Hash, Deserialize, Debug, Eq, PartialEq, Copy)]
#[wasm_bindgen]
pub struct MintPublicKey {
    pub Cw: GroupElement,
    pub I: GroupElement,
}

/// Private minting key used for signing coins.
#[allow(non_snake_case)]
#[derive(Clone, Serialize, Hash, Deserialize, Debug, Eq, PartialEq)]
#[wasm_bindgen]
pub struct MintPrivateKey {
    pub w: Scalar,
    pub w_: Scalar,
    pub x0: Scalar,
    pub x1: Scalar,
    pub ya: Scalar,
    pub ys: Scalar,
    pub public_key: MintPublicKey,
}

#[allow(non_snake_case)]
impl MintPrivateKey {
    /// Constructs a `MintPrivateKey` from an array of scalars.
    ///
    /// # Arguments
    ///
    /// * `scalars` - A slice containing six `Scalar` values.
    ///
    /// # Returns
    ///
    /// Returns `Ok(MintPrivateKey)` if the input has exactly six scalars.
    /// Returns `Err(Error::InvalidMintPrivateKey)` if the input length is incorrect.
    ///
    /// # Errors
    ///
    /// This function will return `Error::InvalidMintPrivateKey` if `scalars` does not contain exactly six elements.
    pub fn from_scalars(scalars: &[Scalar]) -> Result<Self, Error> {
        if let [w, w_, x0, x1, ya, ys] = scalars {
            let Cw = GENERATORS.W * w + &(GENERATORS.W_ * w_);
            let I = GENERATORS.Gz_mac
                - &(GENERATORS.X0 * x0
                    + &(GENERATORS.X1 * x1)
                    + &(GENERATORS.Gz_attribute * ya)
                    + &(GENERATORS.Gz_script * ys));
            let public_key = MintPublicKey { Cw, I };
            Ok(MintPrivateKey {
                w: *w,
                w_: *w_,
                x0: *x0,
                x1: *x1,
                ya: *ya,
                ys: *ys,
                public_key,
            })
        } else {
            Err(Error::InvalidMintPrivateKey)
        }
    }

    /// Serializes the private key into an array of scalars.
    ///
    /// # Returns
    ///
    /// A `Vec<Scalar>` containing six elements representing the private key components.
    ///
    /// # Panics
    ///
    /// This function does **not** panic under normal conditions.
    pub fn to_scalars(&self) -> Vec<Scalar> {
        vec![self.w, self.w_, self.x0, self.x1, self.ya, self.ys]
    }
}

/// Represents a zero-knowledge proof (ZKP) with commitment scalars.
#[derive(Serialize, Deserialize, Hash, Debug, Clone, PartialEq, Eq)]
#[wasm_bindgen]
pub struct ZKP {
    s: Vec<Scalar>,
    pub c: Scalar,
}

impl ZKP {
    pub fn new(responses: Vec<Scalar>, challenge: Scalar) -> Self {
        Self {
            s: responses,
            c: challenge,
        }
    }

    pub fn take_responses(self) -> Vec<Scalar> {
        self.s
    }
}

/// Zero-knowledge proof (ZKP) with `s` responses and `c` challenge.
#[derive(Serialize, Deserialize, Hash, Debug, Clone, PartialEq, Eq)]
pub enum RangeZKP {
    BULLETPROOF(BulletProof),
}

/// Structure holding the secret values for pedersen commitment encoding a script (spending conditions)
#[allow(non_snake_case)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize, Copy)]
#[wasm_bindgen]
pub struct ScriptAttribute {
    pub s: Scalar,
    pub r: Scalar,
}

#[allow(non_snake_case)]
impl ScriptAttribute {
    /// Creates a new script attribute from a given script and optional blinding factor.
    ///
    /// # Arguments
    ///
    /// * `script` - A slice of bytes representing the script. This is used to generate the scalar `s`.
    /// * `blinding_factor` - An optional reference to a 32-byte array that serves as the blinding factor.
    ///   If provided, it is used to create the scalar `r`. If not provided, a random
    ///   scalar `r` is generated.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `ScriptAttribute` containing the computed scalars `r` and `s`.
    pub fn new(script: &[u8], blinding_factor: Option<&[u8]>) -> Self {
        let s = Scalar::new(&Sha256Hash::hash(script).to_byte_array());
        if let Some(b_factor) = blinding_factor {
            let r = Scalar::new(b_factor);

            ScriptAttribute { r, s }
        } else {
            let r = Scalar::random();
            ScriptAttribute { r, s }
        }
    }

    /// Computes the commitment of the script attribute.
    ///
    /// # Returns
    ///
    /// Returns a `GroupElement` representing the commitment of the script attribute, calculated
    /// as the linear combination of the generators `G_script` and `G_blind` with the scalars `s` and `r`.
    pub fn commitment(&self) -> GroupElement {
        GENERATORS.G_script * &self.s + &(GENERATORS.G_blind * &self.r)
    }
}

/// Structure holding the secret values for pedersen commitments encoding amounts
#[allow(non_snake_case)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize, Copy)]
#[wasm_bindgen]
pub struct AmountAttribute {
    #[serde(
        serialize_with = "serialize_amount",
        deserialize_with = "deserialize_amount"
    )]
    pub a: Scalar,
    pub r: Scalar,
}

fn serialize_amount<S>(a: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let amount: u64 = a.into();
    serializer.serialize_u64(amount)
}

fn deserialize_amount<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
where
    D: Deserializer<'de>,
{
    let amount = u64::deserialize(deserializer)?;
    Ok(Scalar::from(amount))
}

#[allow(non_snake_case)]
impl AmountAttribute {
    /// Creates a new amount attribute from a given amount and optional blinding factor.
    ///
    /// # Arguments
    ///
    /// * `amount` - A `u64` representing the amount to be associated with the attribute. This is used to create the scalar `a`.
    /// * `blinding_factor` - An optional reference to a 32-byte array that serves as the blinding factor.
    ///   If provided, it is used to create the scalar `r`. If not provided, a random
    ///   scalar `r` is generated.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `AmountAttribute` containing the computed scalars `r` and `a`.
    pub fn new(amount: u64, blinding_factor: Option<&[u8]>) -> Self {
        let a = Scalar::from(amount);
        if let Some(b_factor) = blinding_factor {
            let r = Scalar::new(b_factor);
            AmountAttribute { r, a }
        } else {
            let r = Scalar::random();
            AmountAttribute { r, a }
        }
    }

    /// Computes the commitment of the amount attribute.
    ///
    /// # Returns
    ///
    /// Returns a `GroupElement` representing the commitment of the amount attribute, calculated
    /// as the linear combination of the generators `G_amount` and `G_blind` with the scalars `a` and `r`.
    pub fn commitment(&self) -> GroupElement {
        GENERATORS.G_amount * &self.a + &(GENERATORS.G_blind * &self.r)
    }

    /// Changes the amount in this attribute by adding values to the secret `a` scalar.
    ///
    /// # Arguments
    ///
    /// * `amount` - A `u64` value to be added to the current amount represented by the scalar `a`.
    ///
    /// # Returns
    ///
    /// Returns a mutable reference to `Self`, allowing for method chaining.
    pub fn tweak_amount(&mut self, amount: u64) -> &Self {
        self.a.tweak_add(&Scalar::from(amount));
        self
    }
}

/// Structure holding the key components of an algebraic MAC, used
/// by the Mint to verify authenticity of the tokens
#[allow(non_snake_case)]
#[wasm_bindgen]
pub struct MAC {}

impl MAC {
    /// Generate a new MAC from the Mint's private key, for a particular amount commitment and
    /// script commitment pair, together with the unique tag that identifies this issuance.
    ///
    /// The tag is *derived by the Mint*, not chosen by the wallet. It is computed as
    /// `t = HMAC-SHA256(key = SHA256(sk), msg = nonce ‖ compress(M_a) ‖ compress(M_s))`
    /// where `sk` is the Mint's private scalars and `nonce` an unguessable, per-request value
    /// supplied by the wallet (32 random bytes, stored with the coin for recovery).
    ///
    /// This makes every issuance statelessly produce a distinct tag for distinct request
    /// contents, and -- crucially -- removes the wallet's ability to pick a tag it has already
    /// seen issued. Repeating an issuance requires repeating `nonce`, in which case the
    /// identical `t` is reproduced and the MAC is *the same group element* the Mint already
    /// issued: the holder gains nothing new, while the affine-combination forgery over two
    /// *distinct* `(t, V)` pairs on related promises is impossible.
    ///
    /// # Arguments
    ///
    /// * `privkey` - A reference to the `MintPrivateKey` used to generate the MAC.
    /// * `nonce` - A per-request nonce chosen by the wallet (not a secret).
    /// * `amount_commitment` - A `GroupElement` representing the amount commitment.
    /// * `script_commitment` - An optional `GroupElement` representing the script commitment.
    ///   If not provided, the origin `GroupElement` is used.
    ///
    /// # Returns
    ///
    /// Returns a `Result<(Scalar, GroupElement), Error>`: the tag `t` the Mint computed and
    /// the `GroupElement` MAC.
    #[allow(non_snake_case)]
    pub fn generate(
        privkey: &MintPrivateKey,
        nonce: &[u8],
        amount_commitment: GroupElement,
        script_commitment: Option<GroupElement>,
    ) -> Result<(Scalar, GroupElement), Error> {
        // Derive a per-request tag from the Mint's private key material and the request.
        let mut key_engine = Sha256Hash::engine();
        for scalar in privkey.to_scalars().iter() {
            key_engine.input(&<[u8; 32]>::from(scalar));
        }
        let tag_key = Sha256Hash::from_engine(key_engine);
        let mut hmac = HmacEngine::<Sha256Hash>::new(&tag_key.to_byte_array());
        hmac.input(b"cashu-kvac-tag-v1");
        hmac.input(nonce);
        hmac.input(&<[u8; 33]>::from(amount_commitment.as_ref()));
        let script_bytes: [u8; 33] = match script_commitment {
            Some(com) => com.as_ref().into(),
            None => GENERATORS.O.as_ref().into(),
        };
        hmac.input(&script_bytes);
        let tag_digest = Hmac::<Sha256Hash>::from_engine(hmac);
        let tag = Scalar::new(&tag_digest.to_byte_array());

        let t_bytes: [u8; 32] = tag.as_ref().into();
        let U = hash_to_curve(&t_bytes)?;
        let Ma = amount_commitment;
        let Ms: GroupElement = match script_commitment {
            Some(com) => com,
            None => GENERATORS.O,
        };
        let V = GENERATORS.W * &privkey.w
            + &(U * &privkey.x0)
            + &(U * &(tag * &privkey.x1))
            + &(Ma * &privkey.ya + &(Ms * &privkey.ys));
        Ok((tag, V))
    }
}

/// Contains the randomized commitments of a `Coin`.
#[allow(non_snake_case)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct RandomizedCommitments {
    /// Randomized Attribute Commitment
    pub Ca: GroupElement,
    /// Randomized Script Commitment
    pub Cs: GroupElement,
    /// Randomized MAC-specific Generator "U"
    pub Cx0: GroupElement,
    /// Randomized tag commitment
    pub Cx1: GroupElement,
    /// Randomized MAC
    pub Cv: GroupElement,
}

impl RandomizedCommitments {
    /// Create randomized commitments from AmountAttribute, ScriptAttribute and MAC.
    ///
    /// `reveal_script` must be set to true if the script inside the `ScriptAttribute`
    /// will be revealed to the Mint/server.
    ///
    /// # Arguments
    ///
    /// * `amount_attribute` - A reference to an `AmountAttribute` containing the amount information.
    /// * `script_attribute` - An optional reference to a `ScriptAttribute` containing script information.
    /// * `tag` - A `Scalar` value representing the unique tag for the note.
    /// * `mac` - A `GroupElement` representing the MAC issued by the Mint.
    /// * `reveal_script` - A boolean indicating whether the script inside the `ScriptAttribute`
    ///   will be revealed. If true, the randomized script commitment will be void,
    ///   leaving space for the Mint to "fill in" the blank with the hash of the
    ///   script (spending conditions) provided by the user
    ///
    /// # Returns
    ///
    /// Returns a `Result<Self, Error>`, where `Self` is the newly created `RandomizedCommitments` instance
    /// on success, or an `Error` if the creation of the randomized commitments fails (e.g., if hashing to
    /// curve fails).
    #[allow(non_snake_case)]
    pub fn from_attributes_and_mac(
        amount_attribute: &AmountAttribute,
        script_attribute: Option<&ScriptAttribute>,
        tag: Scalar,
        mac: GroupElement,
        reveal_script: bool,
    ) -> Result<Self, Error> {
        let t = tag;
        let V = mac;
        let t_bytes: [u8; 32] = tag.as_ref().into();
        let U = hash_to_curve(&t_bytes)?;
        let Ma = amount_attribute.commitment();
        let r = &amount_attribute.r;
        let Ms: GroupElement;
        if let Some(attr) = script_attribute {
            if reveal_script {
                Ms = GENERATORS.G_blind * attr.r.as_ref();
            } else {
                Ms = attr.commitment();
            }
        } else {
            Ms = GENERATORS.O;
        }

        let Ca = GENERATORS.Gz_attribute * r + &Ma;
        let Cs = GENERATORS.Gz_script * r + &Ms;
        let Cx0 = GENERATORS.X0 * r + &U;
        let Cx1 = GENERATORS.X1 * r + &(U * &t);
        let Cv = GENERATORS.Gz_mac * r + &V;

        Ok(RandomizedCommitments {
            Ca,
            Cs,
            Cx0,
            Cx1,
            Cv,
        })
    }

    pub fn get_nullifier(&self) -> GroupElement {
        self.Cv
    }
}

/// Structure that holds information about an equation to be proven
/// or for which a proof has to be verified.
pub struct Equation {
    /// Left-hand side of the equation (public input)
    pub lhs: GroupElement,
    /// Right-hand side of the equation (construction of the relation)
    rhs: Vec<Vec<GroupElement>>,
}

impl Equation {
    pub fn new(lhs: GroupElement, rhs: Vec<Vec<GroupElement>>) -> Self {
        Self { lhs, rhs }
    }

    pub fn take_rhs(self) -> Vec<Vec<GroupElement>> {
        self.rhs
    }
}

/// A statement is a collection of relations (equations)
pub struct Statement {
    /// Domain Separator of the proof
    pub domain_separator: &'static [u8],
    /// Relations
    equations: Vec<Equation>,
}

impl Statement {
    pub fn new(domain_separator: &'static [u8], equations: Vec<Equation>) -> Self {
        Self {
            domain_separator,
            equations,
        }
    }

    pub fn take_equations(self) -> Vec<Equation> {
        self.equations
    }
}

#[allow(unused_imports)]
mod tests {
    use crate::{generators::hash_to_curve, models::ScriptAttribute, secp::Scalar};

    use super::{AmountAttribute, MAC};

    #[allow(dead_code)]
    const B_FACTOR: &[u8; 32] = b"deadbeefdeadbeefdeadbeefdeadbeef";

    #[test]
    fn test_serialize_amount_attr() {
        let a = AmountAttribute::new(10, Some(B_FACTOR));
        let serialized = serde_json::to_string(&a).unwrap();
        let target =
            "{\"a\":10,\"r\":\"6465616462656566646561646265656664656164626565666465616462656566\"}";
        assert_eq!(serialized.as_str(), target);
    }

    #[test]
    fn test_deserialize_amount_attr() {
        let a = AmountAttribute::new(10, Some(B_FACTOR));
        let serialized =
            "{\"a\":10,\"r\":\"6465616462656566646561646265656664656164626565666465616462656566\"}";
        let deserialized: AmountAttribute =
            serde_json::from_str(serialized).expect("Cannot deserialize");
        assert!(deserialized.a == a.a);
    }

    #[test]
    fn test_serialize_script_attr() {
        let script_attr = ScriptAttribute::new(b"38c3", Some(B_FACTOR));
        let serialized = serde_json::to_string(&script_attr).unwrap();
        let target = "{\"s\":\"c87557af1c5e640a085df471d68a5a97c9aaf4d379add58da3d7d5e0fe0df487\",\"r\":\"6465616462656566646561646265656664656164626565666465616462656566\"}";
        assert_eq!(serialized.as_str(), target);
    }

    #[test]
    fn test_deserialize_script_attr() {
        let script_attr = ScriptAttribute::new(b"38c3", Some(B_FACTOR));
        let serialized = "{\"s\":\"c87557af1c5e640a085df471d68a5a97c9aaf4d379add58da3d7d5e0fe0df487\",\"r\":\"6465616462656566646561646265656664656164626565666465616462656566\"}";
        let deserialized: ScriptAttribute = serde_json::from_str(serialized).unwrap();
        assert!(deserialized.s == script_attr.s);
    }

    /// Issue #1 regression: distinct issuance requests must produce distinct tags,
    /// and replaying the *same* request (same nonce, same commitments) must
    /// deterministically reproduce the same tag, so that a repeated issuance
    /// yields the same MAC and never a fresh affine-combination point.
    #[test]
    fn test_mac_tags_are_distinct_and_deterministic() {
        use crate::models::MintPrivateKey;

        let scalars: Vec<Scalar> = (0..6).map(|_| Scalar::random()).collect();
        let privkey = MintPrivateKey::from_scalars(&scalars).unwrap();

        let r = Scalar::random();
        let m0 = crate::generators::GENERATORS.G_blind * &r;
        let m1 = m0 + &crate::generators::GENERATORS.G_amount;
        let nonce_a: &[u8] = b"nonce-A";
        let nonce_b: &[u8] = b"nonce-B";

        let (t0, v0) = MAC::generate(&privkey, nonce_a, m0, None).unwrap();
        let (t1, v1) = MAC::generate(&privkey, nonce_a, m1, None).unwrap();
        let (t0b, v0b) = MAC::generate(&privkey, nonce_b, m0, None).unwrap();

        // Two related messages under one nonce now get *different* tags, so the
        // affine-combination forgery (which requires a shared tag) fails.
        assert_ne!(t0, t1);
        let forged = v0 + &((v1 - &v0) * &Scalar::from(1_000_000u64));
        assert_ne!(forged, v1);

        // Same content + same nonce -> identical tag/MAC (no new oracle output).
        let (t_again, v_again) = MAC::generate(&privkey, nonce_a, m0, None).unwrap();
        assert_eq!(t0, t_again);
        assert_eq!(v0, v_again);

        // A different nonce on the *same* content yields a fresh tag/MAC.
        assert_ne!(t0, t0b);
        assert_ne!(v0, v0b);
    }
}
