use crate::bulletproof::BulletProof;
use crate::errors::Error;
use crate::generators::{hash_to_curve, GENERATORS};
use crate::models::{
    AmountAttribute, Equation, MintPrivateKey, MintPublicKey, RandomizedCommitments, RangeZKP,
    ScriptAttribute, Statement, ZKP,
};
use crate::secp::{GroupElement, Scalar, GROUP_ELEMENT_ZERO, SCALAR_ZERO};
use crate::transcript::CashuTranscript;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;
use wasm_bindgen::prelude::wasm_bindgen;

/// Checks if all the elements in the provided slice of `Scalar` values are non-zero.
///
/// # Arguments
/// * `scalars` - A slice of `Scalar` values to be checked.
///
/// # Returns
/// * `true` if all the `Scalar` values in the slice are non-zero, `false` otherwise.
fn check_scalars_non_zero(scalars: &[Scalar]) -> bool {
    scalars.iter().all(|scalar| !scalar.is_zero())
}

pub struct SchnorrProver<'a> {
    random_terms: Vec<Scalar>,
    secrets: Vec<Scalar>,
    transcript: &'a mut CashuTranscript,
}

impl<'a> SchnorrProver<'a> {
    /// Creates a new `SchnorrProver` instance with a given transcript and secrets.
    ///
    /// # Arguments
    ///
    /// * `transcript` - A mutable reference to a `CashuTranscript` that will be used for the proof process.
    /// * `secrets` - A vector of `Scalar` values representing the secrets that will be used in the proof.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `SchnorrProver` initialized with the provided transcript and secrets,
    /// along with randomly generated terms corresponding to the number of secrets.
    pub fn new(transcript: &'a mut CashuTranscript, secrets: Vec<Scalar>) -> Self {
        SchnorrProver {
            random_terms: (0..secrets.len()).map(|_| Scalar::random()).collect(),
            secrets,
            transcript,
        }
    }

    /// Adds a statement to the prover, updating the transcript with proof-specific information.
    ///
    /// # Arguments
    ///
    /// * `statement` - A `Statement` containing equations that will be added to the proof.
    ///
    /// # Returns
    ///
    /// Returns the updated `SchnorrProver` instance, allowing for method chaining.
    #[allow(non_snake_case)]
    pub fn add_statement(self, statement: Statement) -> Self {
        // Append proof-specific domain separator to the transcript
        self.transcript.domain_sep(statement.domain_separator);

        for equation in statement.take_equations().into_iter() {
            let mut R = GroupElement::new(&GROUP_ELEMENT_ZERO);
            let V = equation.lhs;

            for row in equation.take_rhs().into_iter() {
                for (k, P) in self.random_terms.iter().zip(row) {
                    R = R + (P * k).as_ref();
                }
            }

            self.transcript.append_element(b"R_", &R);
            self.transcript.append_element(b"V_", &V);
        }
        self
    }

    /// Generates a zero-knowledge proof (ZKP) based on the added statements and the transcript.
    ///
    /// # Returns
    ///
    /// Returns a `ZKP` instance containing the responses to the challenge and the challenge itself.
    /// The challenge is drawn from the running transcript.
    #[allow(non_snake_case)]
    pub fn prove(self) -> ZKP {
        // Draw a challenge from the running transcript
        let c = self.transcript.get_challenge(b"chall_");

        // Create responses to the challenge
        let mut responses: Vec<Scalar> = vec![];
        for (k, s) in self.random_terms.into_iter().zip(self.secrets) {
            responses.push(k + (s * c.as_ref()).as_ref());
        }

        ZKP::new(responses, c)
    }
}

pub struct SchnorrVerifier<'a> {
    responses: Vec<Scalar>,
    challenge: Scalar,
    transcript: &'a mut CashuTranscript,
}

impl<'a> SchnorrVerifier<'a> {
    /// Creates a new `SchnorrVerifier` instance with a given transcript and proof.
    ///
    /// # Arguments
    ///
    /// * `transcript` - A mutable reference to a `CashuTranscript` that will be used for the verification process.
    /// * `proof` - A `ZKP` instance containing the responses and challenge from the prover.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `SchnorrVerifier` initialized with the provided transcript and proof.
    pub fn new(transcript: &'a mut CashuTranscript, proof: ZKP) -> Self {
        SchnorrVerifier {
            challenge: proof.c,
            responses: proof.take_responses(),
            transcript,
        }
    }

    /// Adds a statement to the verifier, updating the transcript with proof-specific information.
    ///
    /// # Arguments
    ///
    /// * `statement` - A `Statement` containing equations that will be verified.
    ///
    /// # Returns
    ///
    /// Returns the updated `SchnorrVerifier` instance, allowing for method chaining.
    #[allow(non_snake_case)]
    pub fn add_statement(self, statement: Statement) -> Self {
        // Append proof-specific domain separator to the transcript
        self.transcript.domain_sep(statement.domain_separator);

        for equation in statement.take_equations().into_iter() {
            let mut R = GroupElement::new(&GROUP_ELEMENT_ZERO);
            let V = equation.lhs;

            for row in equation.take_rhs().into_iter() {
                for (s, P) in self.responses.iter().zip(row) {
                    R = R + (P * s).as_ref();
                }
            }
            R = R - (V * self.challenge.as_ref()).as_ref();

            self.transcript.append_element(b"R_", &R);
            self.transcript.append_element(b"V_", &V);
        }
        self
    }

    /// Verifies the proof against the statements added to the verifier.
    ///
    /// # Returns
    ///
    /// Returns a boolean indicating whether the proof is valid (`true`) or invalid (`false`).
    pub fn verify(&mut self) -> bool {
        if !check_scalars_non_zero(&self.responses) {
            return false;
        }
        let challenge_ = self.transcript.get_challenge(b"chall_");
        challenge_ == self.challenge
    }
}

#[wasm_bindgen]
pub struct BootstrapProof;

impl BootstrapProof {
    /// Creates a statement for the bootstrap proof, which includes the amount commitment.
    ///
    /// # Arguments
    ///
    /// * `amount_commitment` - A reference to a `GroupElement` representing the amount commitment.
    ///
    /// # Returns
    ///
    /// Returns a `Statement` containing the domain separator and the equations related to the bootstrap proof.
    pub fn statement(amount_commitment: &GroupElement) -> Statement {
        let equation = Equation::new(
            // (lhs) Ma = r*G_blind (rhs)
            *amount_commitment,
            vec![vec![GENERATORS.G_blind]],
        );
        Statement::new(b"Bootstrap_Statement_", vec![equation])
    }

    /// Creates a zero-knowledge proof (ZKP) for the given amount attribute using the provided transcript.
    ///
    /// # Arguments
    ///
    /// * `amount_attribute` - A reference to an `AmountAttribute` that contains the amount and its blinding factor.
    /// * `transcript` - A mutable reference to a `CashuTranscript` that will be used during the proof creation.
    ///
    /// # Returns
    ///
    /// Returns a `ZKP` instance containing the proof generated for the bootstrap statement.
    pub fn create(amount_attribute: &AmountAttribute, transcript: &mut CashuTranscript) -> ZKP {
        let statement = BootstrapProof::statement(&amount_attribute.commitment());
        SchnorrProver::new(transcript, vec![amount_attribute.r])
            .add_statement(statement)
            .prove()
    }

    /// Verifies the bootstrap proof against the provided amount commitment and transcript.
    ///
    /// # Arguments
    ///
    /// * `amount_commitment` - A reference to a `GroupElement` representing the amount commitment to verify against.
    /// * `proof` - A `ZKP` instance containing the proof to be verified.
    /// * `transcript` - A mutable reference to a `CashuTranscript` that will be used during the verification.
    ///
    /// # Returns
    ///
    /// Returns a boolean indicating whether the proof is valid (`true`) or invalid (`false`).
    pub fn verify(
        amount_commitment: &GroupElement,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        let statement = BootstrapProof::statement(amount_commitment);
        SchnorrVerifier::new(transcript, proof)
            .add_statement(statement)
            .verify()
    }
}

#[wasm_bindgen]
pub struct MacProof;

#[allow(non_snake_case)]
impl MacProof {
    /// Creates a statement for the MAC proof, which includes the necessary equations.
    ///
    /// # Arguments
    ///
    /// * `Z` - A `GroupElement` representing the left-hand side of the first equation.
    /// * `I` - A `GroupElement` representing the public key component used in the proof.
    /// * `randomized_coin` - A reference to a `RandomizedCoin` that contains the commitments needed for the proof.
    /// * `script_revealed` - Whether the holder reveals the script to the verifier on this
    ///   presentation. When `true`, the `Cs` equation drops the `G_script` witness so that
    ///   the verifier's own completion `Cs' = Cs + H(script) * G_script` pins the revealed
    ///   script to the one the MAC was issued over. When `false` the full
    ///   `Cs = r_a*Gz_script + s*G_script + r_s*G_blind` relation is proven as before.
    ///
    /// # Returns
    ///
    /// Returns a `Statement` containing the domain separator and the equations related to the MAC proof.
    pub fn statement(
        Z: GroupElement,
        I: GroupElement,
        randomized_commitments: &RandomizedCommitments,
        script_revealed: bool,
    ) -> Statement {
        let Cx0 = randomized_commitments.Cx0;
        let Cx1 = randomized_commitments.Cx1;
        let Ca = randomized_commitments.Ca;
        let Cs = randomized_commitments.Cs;
        let O = GENERATORS.O;
        // Can you change the initialization of Equation in the last two entries to use `new` like the first?
        let mut equations = vec![
            // Z = r*I
            Equation::new(Z, vec![vec![I]]),
            Equation::new(
                // Cx1 = t*Cx0 + (-tr)*X0 + r*X1
                Cx1,
                vec![vec![GENERATORS.X1, GENERATORS.X0, Cx0]],
            ),
            Equation::new(
                // Ca = r_a*Gz_attribute + r_a*G_blind + a*G_amount
                // MULTI-ROW: `r` witness is used twice for Gz_amount and G_blind
                Ca,
                vec![
                    vec![GENERATORS.Gz_attribute, O, O, GENERATORS.G_amount],
                    vec![GENERATORS.G_blind],
                ],
            ),
        ];
        if script_revealed {
            // Reveal path: the holder commits to only (r_a, r_s); the verifier adds
            // s_revealed*G_script itself when computing Z. Cs must therefore be
            // constrained to span(Gz_script, G_blind), so that the mint-controlled
            // shift by s_revealed*G_script lands on the issued script commitment.
            // If the s*G_script witness were still present here, a prover could
            // absorb s_issued - s_revealed into Cs and have a coin bound to one
            // script verified against another.
            equations.push(Equation::new(
                // Cs = r_a*Gz_script + r_s*G_blind
                Cs,
                vec![vec![GENERATORS.Gz_script, O, O, O, GENERATORS.G_blind]],
            ));
        } else {
            equations.push(Equation::new(
                // Cs = r_a*Gz_script + s*G_script + r_s*G_blind
                Cs,
                vec![vec![
                    GENERATORS.Gz_script,
                    O,
                    O,
                    O,
                    GENERATORS.G_script,
                    GENERATORS.G_blind,
                ]],
            ));
        }
        Statement::new(b"MAC_Statement_", equations)
    }

    /// Creates a zero-knowledge proof (ZKP) for the MAC proof using the provided parameters.
    ///
    /// # Arguments
    ///
    /// * `mint_publickey` - A reference to the `MintPublicKey` used for generating the proof.
    /// * `amount_attribute` - A reference to an `AmountAttribute` containing the amount information.
    /// * `script_attribute` - An optional reference to a `ScriptAttribute` containing script information.
    /// * `tag` - A `Scalar` value representing the unique tag for the note.
    /// * `randomized_commitments` - A reference to `RandomizedCommitments` that contains the commitments needed for the proof.
    /// * `transcript` - A mutable reference to a `CashuTranscript` that will be used during the proof creation.
    ///
    /// # Returns
    ///
    /// Returns a `ZKP` instance containing the proof generated for the MAC statement.
    pub fn create(
        mint_publickey: &MintPublicKey,
        amount_attribute: &AmountAttribute,
        script_attribute: Option<&ScriptAttribute>,
        tag: Scalar,
        randomized_commitments: &RandomizedCommitments,
        reveal_script: bool,
        transcript: &mut CashuTranscript,
    ) -> ZKP {
        let r_a = amount_attribute.r;
        let a = amount_attribute.a;
        let r_s = match script_attribute {
            Some(script_attribute) => script_attribute.r,
            None => Scalar::new(&SCALAR_ZERO),
        };
        let s = match script_attribute {
            Some(script_attribute) => script_attribute.s,
            None => Scalar::new(&SCALAR_ZERO),
        };
        let t = tag;
        let r0 = -r_a * t.as_ref();
        let (_Cw, I) = (mint_publickey.Cw.as_ref(), mint_publickey.I.as_ref());
        let Z = *I * &amount_attribute.r;
        let statement = MacProof::statement(Z, *I, randomized_commitments, reveal_script);
        // On the reveal path the `s` witness is not proven; the verifier supplies
        // H(script)*G_script itself, so the secrets vector drops `s`.
        let secrets = if reveal_script {
            vec![r_a, r0, t, a, r_s]
        } else {
            vec![r_a, r0, t, a, s, r_s]
        };
        SchnorrProver::new(transcript, secrets)
            .add_statement(statement)
            .prove()
    }

    /// Verifies the MAC proof against the provided parameters and transcript.
    ///
    /// # Arguments
    ///
    /// * `mint_privkey` - A reference to the `MintPrivateKey` used for verification.
    /// * `randomized_commitments` - A reference to `RandomizedCommitments` that contains the commitments needed for verification.
    /// * `script` - An optional reference to a byte slice representing the script, if applicable.
    ///   When `Some`, the verification runs in reveal mode and the `G_script` witness term is
    ///   dropped from the `Cs` equation, so the verifier's own `Cs + H(script)*G_script` in the
    ///   issuer-side check pins the revealed script to the script the MAC was issued over.
    /// * `proof` - A `ZKP` instance containing the proof to be verified.
    /// * `transcript` - A mutable reference to a `CashuTranscript` that will be used during the verification.
    ///
    /// # Returns
    ///
    /// Returns a boolean indicating whether the proof is valid (`true`) or invalid (`false`).
    pub fn verify(
        mint_privkey: &MintPrivateKey,
        randomized_coin: &RandomizedCommitments,
        script: Option<&[u8]>,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        let (w, x0, x1, ya, ys) = (
            &mint_privkey.w,
            &mint_privkey.x0,
            &mint_privkey.x1,
            &mint_privkey.ya,
            &mint_privkey.ys,
        );
        let (Cx0, Cx1, Ca, Cs, Cv) = (
            randomized_coin.Cx0,
            randomized_coin.Cx1,
            randomized_coin.Ca,
            randomized_coin.Cs,
            randomized_coin.Cv,
        );
        let mut S = GroupElement::new(&GROUP_ELEMENT_ZERO);
        if let Some(scr) = script {
            let s = Scalar::new(&Sha256Hash::hash(scr).to_byte_array());
            S = GENERATORS.G_script * s.as_ref();
        }
        let Z =
            Cv - &(GENERATORS.W * w + &(Cx0 * x0 + &(Cx1 * x1 + &(Ca * ya + &((Cs + &S) * ys)))));
        let (_Cw, I) = (
            mint_privkey.public_key.Cw.as_ref(),
            mint_privkey.public_key.I.as_ref(),
        );
        let statement = MacProof::statement(Z, *I, randomized_coin, script.is_some());
        SchnorrVerifier::new(transcript, proof)
            .add_statement(statement)
            .verify()
    }
}

#[wasm_bindgen]
pub struct IssuanceProof;

#[allow(non_snake_case)]
impl IssuanceProof {
    /// Creates a statement for the IParams proof, which includes the necessary equations.
    ///
    /// # Arguments
    ///
    /// * `mint_publickey` - A reference to the `MintPublicKey` used in the proof.
    /// * `tag` - A reference to the tag `Scalar` value used for unique identification of the note.
    /// * `mac` - A reference to the MAC `GroupElement` issued by the Mint.
    /// * `amount_commitment` - A reference to a `GroupElement` representing the amount commitment.
    /// * `script_commitment` - A reference to a `GroupElement` representing the script commitment.
    ///
    /// # Returns
    ///
    /// Returns a `Statement` containing the domain separator and the equations related to the IParams proof.
    pub fn statement(
        mint_publickey: &MintPublicKey,
        tag: Scalar,
        mac: GroupElement,
        amount_commitment: GroupElement,
        script_commitment: GroupElement,
    ) -> Statement {
        let O = GroupElement::new(&GROUP_ELEMENT_ZERO);
        let t_tag_bytes: [u8; 32] = tag.as_ref().into();
        let t = tag;
        let U = hash_to_curve(&t_tag_bytes).expect("Couldn't get map MAC tag to GroupElement");
        let V = mac;
        let (Cw, I) = (mint_publickey.Cw.as_ref(), mint_publickey.I.as_ref());
        let Ma = amount_commitment;
        let Ms = script_commitment;
        Statement::new(
            b"Iparams_Statement_",
            vec![
                Equation::new(*Cw, vec![vec![GENERATORS.W, GENERATORS.W_]]),
                Equation::new(
                    *I - &GENERATORS.Gz_mac,
                    vec![vec![
                        O,
                        O,
                        -GENERATORS.X0,
                        -GENERATORS.X1,
                        -GENERATORS.Gz_attribute,
                        -GENERATORS.Gz_script,
                    ]],
                ),
                Equation::new(V, vec![vec![GENERATORS.W, O, U, U * &t, Ma, Ms]]),
            ],
        )
    }

    /// Creates a zero-knowledge proof (ZKP) for the IParams proof using the provided parameters.
    ///
    /// # Arguments
    ///
    /// * `mint_privkey` - A reference to the `MintPrivateKey` used for generating the proof.
    /// * `tag` - A `Scalar` value representing the unique tag for the note.
    /// * `mac` - A `GroupElement` representing the MAC issued by the Mint.
    /// * `amount_commitment` - A `GroupElement` representing the amount commitment.
    /// * `script_commitment` - An optional `GroupElement` representing the script commitment.
    ///
    /// # Returns
    ///
    /// Returns a `ZKP` instance containing the proof generated for the IParams statement.
    pub fn create(
        mint_privkey: &MintPrivateKey,
        tag: Scalar,
        mac: GroupElement,
        amount_commitment: GroupElement,
        script_commitment: Option<GroupElement>,
    ) -> ZKP {
        let mut transcript = CashuTranscript::new();
        let script_commitment: GroupElement = match script_commitment {
            Some(scr) => scr,
            None => GENERATORS.O,
        };
        let statement = IssuanceProof::statement(
            &mint_privkey.public_key,
            tag,
            mac,
            amount_commitment,
            script_commitment,
        );
        SchnorrProver::new(&mut transcript, mint_privkey.to_scalars())
            .add_statement(statement)
            .prove()
    }

    /// Verifies the IParams proof against the provided parameters.
    ///
    /// # Arguments
    ///
    /// * `mint_publickey` - A reference to the `MintPublicKey` used for verification.
    /// * `tag` - A `Scalar` value representing the unique tag for the note.
    /// * `mac` - A `GroupElement` representing the MAC issued by the Mint.
    /// * `amount_attribute` - A reference to an `AmountAttribute` containing the amount information.
    /// * `script_attribute` - An optional reference to a `ScriptAttribute` containing script information.
    /// * `proof` - A `ZKP` instance containing the proof to be verified.
    ///
    /// # Returns
    ///
    /// Returns a boolean indicating whether the proof is valid (`true`) or invalid (`false`).
    pub fn verify(
        mint_publickey: &MintPublicKey,
        tag: Scalar,
        mac: GroupElement,
        amount_attribute: &AmountAttribute,
        script_attribute: Option<&ScriptAttribute>,
        proof: ZKP,
    ) -> bool {
        let mut transcript = CashuTranscript::new();
        let script_commitment: GroupElement = match script_attribute {
            Some(scr) => scr.commitment(),
            None => GENERATORS.O,
        };
        let statement = IssuanceProof::statement(
            mint_publickey,
            tag,
            mac,
            amount_attribute.commitment(),
            script_commitment,
        );
        SchnorrVerifier::new(&mut transcript, proof)
            .add_statement(statement)
            .verify()
    }
}

#[wasm_bindgen]
pub struct BalanceProof;

#[allow(non_snake_case)]
impl BalanceProof {
    /// Creates a balance statement based on a given group element.
    ///
    /// # Parameters
    /// - `B`: The `GroupElement` representing the balance.
    ///
    /// # Returns
    /// A `Statement` containing the domain separator and the equations that represent the balance proof.
    pub fn statement(B: GroupElement) -> Statement {
        // Can you change this to use Statement::new and Equation::new?
        Statement::new(
            b"Balance_Statement_",
            vec![Equation::new(
                B,
                vec![vec![GENERATORS.Gz_attribute, GENERATORS.G_blind]],
            )],
        )
    }

    /// Creates a zero-knowledge proof (ZKP) for the balance of inputs and outputs.
    ///
    /// # Parameters
    /// - `inputs`: A slice of `AmountAttribute` with the inputs to a transaction.
    /// - `outputs`: A slice of `AmountAttribute` with the outputs to a transaction.
    /// - `transcript`: A mutable reference to a `CashuTranscript` used for the proof generation.
    ///
    /// # Returns
    /// A `ZKP` representing the zero-knowledge proof of the balance.
    pub fn create(
        inputs: &[AmountAttribute],
        outputs: &[AmountAttribute],
        transcript: &mut CashuTranscript,
    ) -> ZKP {
        let mut r_sum = Scalar::new(&SCALAR_ZERO);
        for input in inputs.iter() {
            r_sum = r_sum + &input.r;
        }
        let mut r_sum_ = Scalar::new(&SCALAR_ZERO);
        for output in outputs.iter() {
            r_sum_ = r_sum_ + &output.r;
        }
        let delta_r = (-r_sum_) + r_sum.as_ref();
        let B = GENERATORS.Gz_attribute * r_sum.as_ref()
            + (GENERATORS.G_blind * delta_r.as_ref()).as_ref();
        let statement = BalanceProof::statement(B);
        SchnorrProver::new(transcript, vec![r_sum, delta_r])
            .add_statement(statement)
            .prove()
    }

    /// Verifies a zero-knowledge proof for the balance of inputs and outputs.
    ///
    /// # Parameters
    /// - `inputs`: A slice of `RandomizedCommitments` with the randomized inputs to a transaction.
    /// - `outputs`: A slice of `GroupElement` with the outputs to a transaction.
    /// - `delta_amount`: An integer representing the net change in amount (positive or negative).
    /// - `proof`: A `ZKP` representing the zero-knowledge balance proof to be verified.
    /// - `transcript`: A mutable reference to a `CashuTranscript` used for the verification process.
    ///
    /// # Returns
    /// A boolean indicating whether the proof is valid (`true`) or invalid (`false`).
    pub fn verify(
        inputs: &[RandomizedCommitments],
        outputs: &[GroupElement],
        delta_amount: i64,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        let delta_a = Scalar::from(delta_amount.unsigned_abs());
        let mut B = GENERATORS.G_amount * &delta_a;
        if delta_amount >= 0 {
            B.negate();
        }
        for input in inputs.iter() {
            B = B + input.Ca.as_ref();
        }
        for output in outputs.iter() {
            B = B - output;
        }
        let statement = BalanceProof::statement(B);
        SchnorrVerifier::new(transcript, proof)
            .add_statement(statement)
            .verify()
    }
}

#[wasm_bindgen]
pub struct ScriptEqualityProof;

#[allow(non_snake_case)]
impl ScriptEqualityProof {
    /// Creates a statement for the script equality proof based on the given inputs and outputs.
    ///
    /// # Parameters
    /// - `inputs`: A slice of `RandomizedCommitments` representing the randomized input commitments.
    /// - `outputs`: A slice of tuples containing `GroupElement` commitments for amounts and scripts.
    ///
    /// # Returns
    /// A `Statement` containing the domain separator and the equations that represent the script equality proof.
    pub fn statement(
        inputs: &[RandomizedCommitments],
        outputs: &[(GroupElement, GroupElement)],
    ) -> Statement {
        let O: GroupElement = GENERATORS.O;
        let mut equations: Vec<Equation> = Vec::new();

        for (i, zcoin) in inputs.iter().enumerate() {
            let construction = vec![
                vec![GENERATORS.G_script],
                vec![O; i],
                vec![GENERATORS.Gz_script],
                vec![O; inputs.len() - 1],
                vec![GENERATORS.G_blind],
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

            equations.push(Equation::new(zcoin.Cs, vec![construction]));
        }
        for (i, commitments) in outputs.iter().enumerate() {
            let construction = vec![
                vec![GENERATORS.G_script],
                vec![O; 2 * inputs.len() + i],
                vec![GENERATORS.G_blind],
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

            let (_Ma, Ms) = commitments;
            equations.push(Equation::new(*Ms, vec![construction]));
        }
        Statement::new(b"Script_Equality_Statement_", equations)
    }

    /// Creates a zero-knowledge proof (ZKP) for the equality of scripts in the given inputs and outputs.
    ///
    /// # Parameters
    /// - `inputs`: A slice of tuples containing `AmountAttribute` and `ScriptAttribute` representing the original input attributes.
    /// - `randomized_inputs`: A slice of `RandomizedCommitments` representing the randomized input commitments.
    /// - `outputs`: A slice of tuples containing `AmountAttribute` and `ScriptAttribute` for the outputs.
    /// - `transcript`: A mutable reference to a `CashuTranscript` used for the proof generation.
    ///
    /// # Returns
    /// A `Result` containing a `ZKP` representing the zero-knowledge proof of script equality, or an `Error` if the input lists are empty.
    pub fn create(
        inputs: &[(AmountAttribute, ScriptAttribute)],
        randomized_inputs: &[RandomizedCommitments],
        outputs: &[(AmountAttribute, ScriptAttribute)],
        transcript: &mut CashuTranscript,
    ) -> Result<ZKP, Error> {
        if inputs.is_empty() || randomized_inputs.is_empty() || outputs.is_empty() {
            return Err(Error::EmptyList);
        }
        let commitments: Vec<(GroupElement, GroupElement)> = outputs
            .iter()
            .map(|(aa, sa)| (aa.commitment(), sa.commitment()))
            .collect();
        let statement = ScriptEqualityProof::statement(randomized_inputs, &commitments);
        let s = inputs[0].1.s;
        let r_a_list = inputs.iter().map(|input| input.0.r).collect();
        let r_s_list = inputs.iter().map(|input| input.1.r).collect();
        let new_r_s_list = outputs
            .iter()
            .map(|(_, script_attr)| script_attr.r)
            .collect();
        Ok(SchnorrProver::new(
            transcript,
            vec![vec![s], r_a_list, r_s_list, new_r_s_list]
                .into_iter()
                .flatten()
                .collect(),
        )
        .add_statement(statement)
        .prove())
    }

    /// Verifies a zero-knowledge proof for the equality of scripts in the given randomized inputs and outputs.
    ///
    /// # Parameters
    /// - `randomized_inputs`: A slice of `RandomizedCommitments` representing the randomized input commitments.
    /// - `outputs`: A slice of tuples containing `GroupElement` commitments for amounts and scripts.
    /// - `proof`: A `ZKP` representing the zero-knowledge proof to be verified.
    /// - `transcript`: A mutable reference to a `CashuTranscript` used for the verification process.
    ///
    /// # Returns
    /// A boolean indicating whether the proof is valid (`true`) or invalid (`false`).
    pub fn verify(
        randomized_inputs: &[RandomizedCommitments],
        outputs: &[(GroupElement, GroupElement)],
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        if randomized_inputs.is_empty() || outputs.is_empty() {
            return false;
        }
        let statement = ScriptEqualityProof::statement(randomized_inputs, outputs);
        SchnorrVerifier::new(transcript, proof)
            .add_statement(statement)
            .verify()
    }
}

pub struct RangeProof;

#[allow(non_snake_case)]
impl RangeProof {
    /// Creates a bulletproof for the given attributes.
    ///
    /// # Parameters
    /// - `transcript`: A mutable reference to a `CashuTranscript` used for the proof generation.
    /// - `attributes`: A slice of `AmountAttribute` representing the attributes for which the range proof is created.
    ///
    /// # Returns
    /// A `RangeZKP` representing the bulletproof for the specified attributes.
    pub fn create_bulletproof(
        transcript: &mut CashuTranscript,
        attributes: &[AmountAttribute],
    ) -> RangeZKP {
        let bulletproof = BulletProof::new(transcript, attributes);
        RangeZKP::BULLETPROOF(bulletproof)
    }

    /// Verifies a range proof against the provided attribute commitments.
    ///
    /// # Parameters
    /// - `transcript`: A mutable reference to a `CashuTranscript` used for the verification process.
    /// - `attribute_commitments`: A vector of tuples containing `GroupElement` amount commitments to be verified.
    /// - `proof`: A `RangeZKP` representing the range proof to be verified.
    ///
    /// # Returns
    /// A boolean indicating whether the proof is valid (`true`) or invalid (`false`).
    pub fn verify(
        transcript: &mut CashuTranscript,
        attribute_commitments: &[GroupElement],
        proof: RangeZKP,
    ) -> bool {
        match proof {
            RangeZKP::BULLETPROOF(bulletproof) => {
                bulletproof.verify(transcript, attribute_commitments)
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        errors::Error,
        generators::{hash_to_curve, GENERATORS},
        models::{AmountAttribute, MintPrivateKey, RandomizedCommitments, ScriptAttribute, MAC},
        secp::{GroupElement, Scalar, GROUP_ELEMENT_ZERO},
        transcript::CashuTranscript,
    };

    use super::{BalanceProof, BootstrapProof, IssuanceProof, MacProof, ScriptEqualityProof};

    fn transcripts() -> (CashuTranscript, CashuTranscript) {
        let mint_transcript = CashuTranscript::new();
        let client_transcript = CashuTranscript::new();
        (mint_transcript, client_transcript)
    }

    fn privkey() -> MintPrivateKey {
        let scalars: Vec<Scalar> = (0..6).map(|_| Scalar::random()).collect();
        MintPrivateKey::from_scalars(&scalars).expect("Could not generate private key")
    }

    #[test]
    fn test_bootstrap() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let bootstrap_attr = AmountAttribute::new(0, None);
        let proof = BootstrapProof::create(&bootstrap_attr, client_transcript.as_mut());
        assert!(BootstrapProof::verify(
            &bootstrap_attr.commitment(),
            proof,
            &mut mint_transcript
        ))
    }

    #[test]
    fn test_wrong_bootstrap() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let bootstrap_attr = AmountAttribute::new(1, None);
        let proof = BootstrapProof::create(&bootstrap_attr, client_transcript.as_mut());
        assert!(!BootstrapProof::verify(
            &bootstrap_attr.commitment(),
            proof,
            &mut mint_transcript
        ))
    }

    #[test]
    fn test_iparams() {
        let mint_privkey = privkey();
        let amount_attr = AmountAttribute::new(12, None);
        let tag = Scalar::random();
        let mac = MAC::generate(&mint_privkey, amount_attr.commitment(), None, tag)
            .expect("Couldn't generate MAC");
        let proof = IssuanceProof::create(&mint_privkey, tag, mac, amount_attr.commitment(), None);
        tag.invert();
        assert!(IssuanceProof::verify(
            &mint_privkey.public_key,
            tag,
            mac,
            &amount_attr,
            None,
            proof,
        ));
    }

    #[test]
    fn test_wrong_iparams() {
        let mint_privkey = privkey();
        let mint_privkey_1 = privkey();
        let amount_attr = AmountAttribute::new(12, None);
        let tag = Scalar::random();
        let mac = MAC::generate(&mint_privkey, amount_attr.commitment(), None, tag)
            .expect("Couldn't generate MAC");
        let proof = IssuanceProof::create(&mint_privkey, tag, mac, amount_attr.commitment(), None);
        assert!(!IssuanceProof::verify(
            &mint_privkey_1.public_key,
            tag,
            mac,
            &amount_attr,
            None,
            proof,
        ))
    }

    #[test]
    fn test_mac() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let mint_privkey = privkey();
        let amount_attr = AmountAttribute::new(12, None);
        let tag = Scalar::random();
        let mac = MAC::generate(&mint_privkey, amount_attr.commitment(), None, tag)
            .expect("Couldn't generate MAC");
        let randomized_coms =
            RandomizedCommitments::from_attributes_and_mac(&amount_attr, None, tag, mac, false)
                .expect("Expected a randomized coin");
        let proof = MacProof::create(
            &mint_privkey.public_key,
            &amount_attr,
            None,
            tag,
            &randomized_coms,
            false,
            &mut client_transcript,
        );
        assert!(MacProof::verify(
            &mint_privkey,
            &randomized_coms,
            None,
            proof,
            &mut mint_transcript
        ));
    }

    #[test]
    fn test_wrong_mac() {
        #[allow(non_snake_case)]
        fn generate_custom_rand(
            amount_attr: &AmountAttribute,
            tag: Scalar,
            mac: GroupElement,
        ) -> Result<RandomizedCommitments, Error> {
            let t = tag;
            let V = mac.as_ref();
            let t_bytes: [u8; 32] = tag.as_ref().into();
            let U = hash_to_curve(&t_bytes)?;
            let Ma = amount_attr.commitment();
            // We try and randomize differently.
            let z = Scalar::random();
            let Ms: GroupElement = GroupElement::new(&GROUP_ELEMENT_ZERO);

            let Ca = GENERATORS.Gz_attribute * z.as_ref() + &Ma;
            let Cs = GENERATORS.Gz_script * z.as_ref() + &Ms;
            let Cx0 = GENERATORS.X0 * z.as_ref() + &U;
            let Cx1 = GENERATORS.X1 * z.as_ref() + &(U * &t);
            let Cv = GENERATORS.Gz_mac * z.as_ref() + V;

            Ok(RandomizedCommitments {
                Ca,
                Cs,
                Cx0,
                Cx1,
                Cv,
            })
        }

        let (mut mint_transcript, mut client_transcript) = transcripts();
        let mint_privkey = privkey();
        let amount_attr = AmountAttribute::new(12, None);
        let tag = Scalar::random();
        let mac = MAC::generate(&mint_privkey, amount_attr.commitment(), None, tag)
            .expect("Couldn't generate MAC");
        let randomized_coms = generate_custom_rand(&amount_attr, tag, mac).unwrap();
        let proof = MacProof::create(
            &mint_privkey.public_key,
            &amount_attr,
            None,
            tag,
            &randomized_coms,
            false,
            &mut client_transcript,
        );
        assert!(!MacProof::verify(
            &mint_privkey,
            &randomized_coms,
            None,
            proof,
            &mut mint_transcript
        ));
    }

    #[test]
    fn test_balance() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let privkey = privkey();
        let inputs = vec![
            AmountAttribute::new(12, None),
            AmountAttribute::new(11, None),
        ];
        let outputs = vec![AmountAttribute::new(23, None)];
        // We assume the inputs were already attributed a MAC previously
        let tags: Vec<Scalar> = inputs.iter().map(|_| Scalar::random()).collect();
        let macs: Vec<GroupElement> = inputs
            .iter()
            .zip(tags.iter())
            .map(|(input, tag)| {
                MAC::generate(&privkey, input.commitment(), None, *tag).expect("MAC expected")
            })
            .collect();
        let proof = BalanceProof::create(&inputs, &outputs, &mut client_transcript);
        let randomized_coms: Vec<RandomizedCommitments> = tags
            .iter()
            .zip(macs.iter())
            .zip(inputs.iter())
            .map(|((tag, mac), amount_attr)| {
                RandomizedCommitments::from_attributes_and_mac(amount_attr, None, *tag, *mac, false)
                    .expect("RandomzedCommittment expected")
            })
            .collect();
        let outputs: Vec<GroupElement> = outputs
            .into_iter()
            .map(|output| output.commitment())
            .collect();
        assert!(BalanceProof::verify(
            &randomized_coms,
            &outputs,
            0,
            proof,
            &mut mint_transcript
        ));
    }

    #[test]
    fn test_wrong_balance() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let privkey = privkey();
        let inputs = vec![
            AmountAttribute::new(12, None),
            AmountAttribute::new(11, None),
        ];
        let outputs = vec![AmountAttribute::new(23, None)];
        // We assume the inputs were already attributed a MAC previously
        let tags: Vec<Scalar> = inputs.iter().map(|_| Scalar::random()).collect();
        let macs: Vec<GroupElement> = inputs
            .iter()
            .zip(tags.iter())
            .map(|(input, tag)| {
                MAC::generate(&privkey, input.commitment(), None, *tag).expect("MAC expected")
            })
            .collect();
        let proof = BalanceProof::create(&inputs, &outputs, &mut client_transcript);
        let randomized_coms: Vec<RandomizedCommitments> = tags
            .iter()
            .zip(macs.iter())
            .zip(inputs.iter())
            .map(|((tag, mac), amount_attr)| {
                RandomizedCommitments::from_attributes_and_mac(amount_attr, None, *tag, *mac, false)
                    .expect("RandomzedCommittment expected")
            })
            .collect();
        let outputs: Vec<GroupElement> = outputs
            .into_iter()
            .map(|output| output.commitment())
            .collect();
        assert!(!BalanceProof::verify(
            &randomized_coms,
            &outputs,
            1,
            proof,
            &mut mint_transcript
        ));
    }

    #[test]
    fn test_script_equality() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let script = b"testscript";
        let privkey = privkey();
        let inputs = vec![
            (
                AmountAttribute::new(12, None),
                ScriptAttribute::new(script, None),
            ),
            (
                AmountAttribute::new(11, None),
                ScriptAttribute::new(script, None),
            ),
        ];
        let outputs = vec![
            (
                AmountAttribute::new(6, None),
                ScriptAttribute::new(script, None),
            ),
            (
                AmountAttribute::new(11, None),
                ScriptAttribute::new(script, None),
            ),
            (
                AmountAttribute::new(12, None),
                ScriptAttribute::new(script, None),
            ),
        ];
        // We assume the inputs were already attributed a MAC previously
        let tags: Vec<Scalar> = inputs.iter().map(|_| Scalar::random()).collect();
        let macs: Vec<GroupElement> = inputs
            .iter()
            .zip(tags.iter())
            .map(|(input, tag)| {
                MAC::generate(
                    &privkey,
                    input.0.commitment(),
                    Some(input.1.commitment()),
                    *tag,
                )
                .expect("MAC expected")
            })
            .collect();
        let randomized_coms: Vec<RandomizedCommitments> = tags
            .iter()
            .zip(macs.iter())
            .zip(inputs.iter())
            .map(|((tag, mac), attr)| {
                RandomizedCommitments::from_attributes_and_mac(
                    &attr.0,
                    Some(&attr.1),
                    *tag,
                    *mac,
                    false,
                )
                .expect("RandomzedCommittment expected")
            })
            .collect();
        let proof = ScriptEqualityProof::create(
            &inputs,
            &randomized_coms,
            &outputs,
            client_transcript.as_mut(),
        )
        .expect("");
        let outputs: Vec<(GroupElement, GroupElement)> = outputs
            .into_iter()
            .map(|(aa, sa)| (aa.commitment(), sa.commitment()))
            .collect();
        assert!(ScriptEqualityProof::verify(
            &randomized_coms,
            &outputs,
            proof,
            mint_transcript.as_mut()
        ))
    }

    #[test]
    fn test_script_inequality() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let script = b"testscript";
        let privkey = privkey();
        let inputs = vec![
            (
                AmountAttribute::new(12, None),
                ScriptAttribute::new(script, None),
            ),
            (
                AmountAttribute::new(11, None),
                ScriptAttribute::new(script, None),
            ),
        ];
        let outputs = vec![
            (
                AmountAttribute::new(6, None),
                ScriptAttribute::new(b"testscript_", None),
            ),
            (
                AmountAttribute::new(11, None),
                ScriptAttribute::new(script, None),
            ),
            (
                AmountAttribute::new(12, None),
                ScriptAttribute::new(script, None),
            ),
        ];
        // We assume the inputs were already attributed a MAC previously
        let tags: Vec<Scalar> = inputs.iter().map(|_| Scalar::random()).collect();
        let macs: Vec<GroupElement> = inputs
            .iter()
            .zip(tags.iter())
            .map(|(input, tag)| {
                MAC::generate(
                    &privkey,
                    input.0.commitment(),
                    Some(input.1.commitment()),
                    *tag,
                )
                .expect("MAC expected")
            })
            .collect();
        let randomized_coms: Vec<RandomizedCommitments> = tags
            .iter()
            .zip(macs.iter())
            .zip(inputs.iter())
            .map(|((tag, mac), attr)| {
                RandomizedCommitments::from_attributes_and_mac(
                    &attr.0,
                    Some(&attr.1),
                    *tag,
                    *mac,
                    false,
                )
                .expect("RandomzedCommittment expected")
            })
            .collect();
        let proof = ScriptEqualityProof::create(
            &inputs,
            &randomized_coms,
            &outputs,
            client_transcript.as_mut(),
        )
        .expect("");
        let outputs: Vec<(GroupElement, GroupElement)> = outputs
            .into_iter()
            .map(|(aa, sa)| (aa.commitment(), sa.commitment()))
            .collect();
        assert!(!ScriptEqualityProof::verify(
            &randomized_coms,
            &outputs,
            proof,
            mint_transcript.as_mut()
        ))
    }

    /// Regression for issue #2 (script substitution on the reveal path).
    ///
    /// A coin honestly bound to script A (its MAC covers `M_s = s_A*G_script + r_s*G_blind`)
    /// was previously spendable while revealing an unrelated script B, because the
    /// prover could absorb `s_A - s_B` into the free `G_script` witness of the `Cs`
    /// equation. With the reveal-path statement dropping `G_script`, that freedom is gone
    /// and the attack presentation must fail, while an honest reveal succeeds.
    #[test]
    fn test_reveal_path_binds_script() {
        use bitcoin::hashes::sha256::Hash as Sha256Hash;
        use bitcoin::hashes::Hash;

        let key = privkey();
        let script_a: &[u8] = b"spending-condition-A";
        let script_b: &[u8] = b"totally-unrelated-script-B";
        let s_a = Scalar::new(&Sha256Hash::hash(script_a).to_byte_array());
        let s_b = Scalar::new(&Sha256Hash::hash(script_b).to_byte_array());

        // Coin with amount 12 honestly bound to script A.
        let amount_attr = AmountAttribute::new(12, None);
        let script_attr = ScriptAttribute::new(script_a, None);
        let tag = Scalar::random();
        let mac = MAC::generate(
            &key,
            amount_attr.commitment(),
            Some(script_attr.commitment()),
            tag,
        )
        .expect("MAC expected");

        // --- Honest reveal of the bound script A verifies. ---
        let rc_honest = RandomizedCommitments::from_attributes_and_mac(
            &amount_attr,
            Some(&script_attr),
            tag,
            mac,
            true, // reveal_script
        )
        .expect("randomized commitments");
        let mut tm0 = CashuTranscript::new();
        let mut tw0 = CashuTranscript::new();
        let p0 = MacProof::create(
            &key.public_key,
            &amount_attr,
            Some(&script_attr),
            tag,
            &rc_honest,
            true,
            &mut tw0,
        );
        assert!(
            MacProof::verify(&key, &rc_honest, Some(script_a), p0, &mut tm0),
            "honest reveal of the bound script must verify"
        );

        // --- Attack: craft Cs absorbing (s_A - s_B) and reveal B. ---
        let crafted = RandomizedCommitments {
            Ca: rc_honest.Ca,
            Cs: GENERATORS.Gz_script * &amount_attr.r
                + &(GENERATORS.G_script * &(s_a - &s_b))
                + &(GENERATORS.G_blind * &script_attr.r),
            Cx0: rc_honest.Cx0,
            Cx1: rc_honest.Cx1,
            Cv: rc_honest.Cv,
        };
        let shifted = ScriptAttribute {
            s: s_a - &s_b,
            r: script_attr.r,
        };
        let mut tm1 = CashuTranscript::new();
        let mut tw1 = CashuTranscript::new();
        let p1 = MacProof::create(
            &key.public_key,
            &amount_attr,
            Some(&shifted),
            tag,
            &crafted,
            true,
            &mut tw1,
        );
        assert!(
            !MacProof::verify(&key, &crafted, Some(script_b), p1, &mut tm1),
            "crafted presentation revealing a different script must be rejected"
        );

        // --- Control: the same coin presented on the hidden path still verifies. ---
        let rc_hidden = RandomizedCommitments::from_attributes_and_mac(
            &amount_attr,
            Some(&script_attr),
            tag,
            mac,
            false,
        )
        .expect("randomized commitments");
        let mut tm2 = CashuTranscript::new();
        let mut tw2 = CashuTranscript::new();
        let p2 = MacProof::create(
            &key.public_key,
            &amount_attr,
            Some(&script_attr),
            tag,
            &rc_hidden,
            false,
            &mut tw2,
        );
        assert!(
            MacProof::verify(&key, &rc_hidden, None, p2, &mut tm2),
            "hidden-path presentation of the same coin must still verify"
        );
    }
}
