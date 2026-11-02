use crate::{
    generators::{hash_to_curve, GENERATORS},
    models::AmountAttribute,
    secp::{GroupElement, Scalar, SCALAR_ONE, SCALAR_ZERO},
    transcript::CashuTranscript,
};
use itertools::izip;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

// Maximum allowed for a single attribute
pub const RANGE_LIMIT: u64 = 1 << 32;
pub const LOG_RANGE_LIMIT: usize = 32;

pub static POWERS_OF_TWO: Lazy<Vec<Scalar>> = Lazy::new(|| {
    let mut result = Vec::new();
    for i in 0..LOG_RANGE_LIMIT {
        let pow = (1 << i) as u64;
        result.push(Scalar::from(pow));
    }
    result
});
pub static G: Lazy<Vec<GroupElement>> = Lazy::new(|| {
    let mut result = Vec::new();
    for i in 0..32 {
        result.push(
            hash_to_curve(format!("IPA_G_{i}_").as_bytes())
                .expect("Couldn't map hash to point on the curve"),
        );
    }
    result
});
pub static H: Lazy<Vec<GroupElement>> = Lazy::new(|| {
    let mut result = Vec::new();
    for i in 0..32 {
        result.push(
            hash_to_curve(format!("IPA_H_{i}_").as_bytes())
                .expect("Couldn't map hash to point on the curve"),
        );
    }
    result
});
pub static U: Lazy<GroupElement> =
    Lazy::new(|| hash_to_curve(b"IPA_U_").expect("Couldn't map hash to point on the curve"));

#[allow(non_snake_case)]
fn get_generators(n: usize) -> (Vec<GroupElement>, Vec<GroupElement>, GroupElement) {
    let (mut G_, mut H_, U_) = (G.clone(), H.clone(), *U);
    if n > G_.len() {
        for i in G.len()..n {
            G_.push(
                hash_to_curve(format!("IPA_G_{i}_").as_bytes())
                    .expect("Couldn't map hash to point on the curve"),
            );
            H_.push(
                hash_to_curve(format!("IPA_H_{i}_").as_bytes())
                    .expect("Couldn't map hash to point on the curve"),
            );
        }
    }
    (G_, H_, U_)
}

fn pad_zeros(mut l: Vec<Scalar>, to: usize) -> Vec<Scalar> {
    let pad_len = to - (l.len() % to);
    let scalar_zero = Scalar::new(&SCALAR_ZERO);
    l.extend(vec![scalar_zero; pad_len]);
    l
}

fn pad_ones(mut l: Vec<Scalar>, to: usize) -> Vec<Scalar> {
    let pad_len = to - (l.len() % to);
    let scalar_one = Scalar::new(&SCALAR_ONE);
    l.extend(vec![scalar_one; pad_len]);
    l
}

fn inner_product(l: &[Scalar], r: &[Scalar]) -> Scalar {
    let mut result = Scalar::from(0);
    for (left, right) in l.iter().zip(r.iter()) {
        result += (*left * right).as_ref();
    }
    result
}

#[derive(Serialize, Deserialize, Hash, Debug, Clone, PartialEq, Eq)]
#[wasm_bindgen]
pub struct InnerProductArgument {
    recursion_inputs_left: Vec<GroupElement>,
    recursion_inputs_right: Vec<GroupElement>,
    pub recursion_end_scalar_left: Scalar,
    pub recursion_end_scalar_right: Scalar,
}

// https://eprint.iacr.org/2017/1066.pdf
#[allow(non_snake_case)]
impl InnerProductArgument {
    pub fn new(
        transcript: &mut CashuTranscript,
        generators: (Vec<GroupElement>, Vec<GroupElement>, GroupElement),
        P: GroupElement,
        mut a: Vec<Scalar>,
        mut b: Vec<Scalar>,
    ) -> Self {
        assert!(a.len() == b.len());

        // Extract generators
        let (mut G_, mut H_, U_) = generators;

        // ## PROTOCOL 1 ##
        // `get_folded_IPA` implements Protocol 2, a proof system for relation (3).
        // Protocol 1 (here) makes Protocol 2 into a proof system for relation (2).
        transcript.append_element(b"Com(P)_", &P);
        let tetha = transcript.get_challenge(b"tetha_chall_");

        // Switch generator U
        let U_ = U_ * &tetha;
        // ## END PROTOCOL 1 ##

        // Ensure len is a power of 2
        assert!(a.len().count_ones() == 1);
        let mut n = a.len();

        let mut recursion_inputs_left = Vec::new();
        let mut recursion_inputs_right = Vec::new();

        // Recursive subdivision
        while n > 1 {
            n >>= 1;
            let c_left = inner_product(&a[..n], &b[n..]);
            let c_right = inner_product(&a[n..], &b[..n]);
            let mut L = U_ * &c_left;
            for (a_i, G_i, b_i, H_i) in izip!(
                a[..n].iter(),
                G_[n..2 * n].iter(),
                b[n..].iter(),
                H_[..n].iter()
            ) {
                L += &(*G_i * a_i + &(*H_i * b_i))
            }
            let mut R = U_ * &c_right;
            for (a_i, G_i, b_i, H_i) in izip!(
                a[n..].iter(),
                G_[..n].iter(),
                b[..n].iter(),
                H_[n..2 * n].iter()
            ) {
                R += &(*G_i * a_i + &(*H_i * b_i))
            }

            // Prover -> Verifier : L, R
            // Verifier -> Prover : x (challenge)

            transcript.append_element(b"IPA_L_", &L);
            transcript.append_element(b"IPA_R_", &R);
            recursion_inputs_left.push(L);
            recursion_inputs_right.push(R);

            let x = transcript.get_challenge(b"IPA_chall_");
            let x_inv = x.invert();

            // fold a and b
            let mut new_a: Vec<Scalar> = Vec::new();
            for i in 0..n {
                let a_i = std::mem::take(&mut a[i]);
                let a_n_i = std::mem::take(&mut a[i + n]);
                new_a.push(a_i * &x + &(a_n_i * &x_inv));
            }
            let mut new_b: Vec<Scalar> = Vec::new();
            for i in 0..n {
                let b_i = std::mem::take(&mut b[i]);
                let b_n_i = std::mem::take(&mut b[i + n]);
                new_b.push(b_i * &x_inv + &(b_n_i * &x));
            }

            a = new_a;
            b = new_b;

            // fold generators
            let mut new_G: Vec<GroupElement> = Vec::new();
            for i in 0..n {
                let G_i = std::mem::take(&mut G_[i]);
                let G_n_i = std::mem::take(&mut G_[i + n]);
                new_G.push(G_i * &x_inv + &(G_n_i * &x));
            }
            let mut new_H: Vec<GroupElement> = Vec::new();
            for i in 0..n {
                let H_i = std::mem::take(&mut H_[i]);
                let H_n_i = std::mem::take(&mut H_[i + n]);
                new_H.push(H_i * &x + &(H_n_i * &x_inv));
            }

            G_ = new_G;
            H_ = new_H;
        }

        assert!(a.len() == 1 && b.len() == 1);

        Self {
            recursion_inputs_left,
            recursion_inputs_right,
            recursion_end_scalar_left: a.pop().unwrap(),
            recursion_end_scalar_right: b.pop().unwrap(),
        }
    }

    pub fn verify(
        self,
        transcript: &mut CashuTranscript,
        generators: (Vec<GroupElement>, Vec<GroupElement>, GroupElement),
        mut P: GroupElement,
        c: Scalar,
    ) -> bool {
        // Extract generators
        let (G_, H_, U_) = generators;

        // ## PROTOCOL 1 ##
        // `verify_folded_IPA` implements Protocol 2, a proof system for relation (3).
        // Protocol 1 (here) makes Protocol 2 into a proof system for relation (2).
        transcript.append_element(b"Com(P)_", &P);
        let tetha = transcript.get_challenge(b"tetha_chall_");

        // Switch generator U
        let U_ = U_ * &tetha;
        // Tweak commitment P
        P += &(U_ * &c);
        // ## END PROTOCOL 1 ##

        // ## PROTOCOL 2 ##
        // Extract scalars of the recursion end from IPA
        let a = self.recursion_end_scalar_left;
        let b = self.recursion_end_scalar_right;

        if self.recursion_inputs_left.len() != self.recursion_inputs_right.len() {
            return false;
        }

        // Get challenges
        let mut challenges = Vec::new();
        for (L, R) in self
            .recursion_inputs_left
            .into_iter()
            .zip(self.recursion_inputs_right)
        {
            transcript.append_element(b"IPA_L_", &L);
            transcript.append_element(b"IPA_R_", &R);
            let x = transcript.get_challenge(b"IPA_chall_");
            let x_inv = x.invert();

            P = P + &(L * &(x * &x)) + &(R * &(x_inv * &x_inv));
            challenges.push((x, x_inv));
        }

        // Recursion unrolling - We reduce O(n*log_2(n)) GroupElement multiplications
        // to O(n) by unrolling the prover's loop (we can do that since have the challenges)
        // and performing the O(log_2(n)) arithmetic operations on scalars instead.
        let mut G_aH_b = GENERATORS.O;
        for (i, (G_i, H_i)) in G_.into_iter().zip(H_).enumerate() {
            let mut s = Scalar::new(&SCALAR_ONE);
            for (j, x) in challenges.iter().rev().enumerate() {
                // Use x if the j-th bit of i is 1
                // else use x^-1
                let bit = ((i >> j) & 1) == 1;
                if bit {
                    s = s * &x.0;
                } else {
                    s = s * &x.1;
                }
            }
            G_aH_b = G_aH_b + &(G_i * &(s * &a)) + &(H_i * &(s.invert() * &b));
        }

        G_aH_b + &(U_ * &(a * &b)) == P
    }

    pub fn public_inputs_len(&self) -> usize {
        assert_eq!(
            self.recursion_inputs_left.len(),
            self.recursion_inputs_right.len()
        );
        self.recursion_inputs_left.len()
    }
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Hash, Debug, Clone, PartialEq, Eq)]
#[wasm_bindgen]
pub struct BulletProof {
    A: GroupElement,
    S: GroupElement,
    T1: GroupElement,
    T2: GroupElement,
    t_x: Scalar,
    tau_x: Scalar,
    mu: Scalar,
    ipa: InnerProductArgument,
}

#[allow(non_snake_case)]
impl BulletProof {
    pub fn new(transcript: &mut CashuTranscript, attributes: &[AmountAttribute]) -> Self {
        // Domain separation
        transcript.domain_sep(b"Bulletproof_Statement_");

        let mut m = attributes.len();
        let n = LOG_RANGE_LIMIT;

        // Decompose attribute's amounts into bits.
        let mut a_left = Vec::new();
        let mut a_right = Vec::new();
        for attribute in attributes {
            let amount: u64 = attribute.a.as_ref().into();
            for i in 0..n {
                let bit = (amount >> i) & 1;
                a_left.push(Scalar::from(bit));
                a_right.push(Scalar::from(1 - bit));
            }
        }

        // pad a_left and a_right to a len power of 2
        let next_len_pow2: usize = 1 << ((n * m).ilog2() + 1);
        if a_left.len().count_ones() != 1 {
            a_left = pad_zeros(a_left, next_len_pow2);
            a_right = pad_ones(a_right, next_len_pow2);
            m = next_len_pow2 / n;
        }

        // Append Ma and bit-length to the transcript
        for attribute_pair in attributes.iter() {
            let amount_commitment = attribute_pair.commitment();
            transcript.append_element(b"Com(V)_", &amount_commitment);
        }
        transcript.append_element(
            b"Com(m)_",
            &hash_to_curve(&(m as u32).to_be_bytes())
                .expect("Couldn't map m length to GroupElement"),
        );

        // Get generators
        let (G_, mut H_, U_) = get_generators(m * n);

        // Compute Com(A)
        let alpha = Scalar::random();
        let mut A = GENERATORS.G_blind * &alpha;
        for (a_l_i, G_i, a_r_i, H_i) in izip!(
            a_left.iter(),
            G_.clone().into_iter(),
            a_right.iter(),
            H_.clone().into_iter()
        ) {
            A += &(G_i * a_l_i + &(H_i * a_r_i));
        }

        // s_l and s_r are the bits commitment blinding vectors
        let (s_l, s_r): (Vec<Scalar>, Vec<Scalar>) = (
            (0..a_left.len()).map(|_| Scalar::random()).collect(),
            (0..a_right.len()).map(|_| Scalar::random()).collect(),
        );

        // Compute Com(S)
        let rho = Scalar::random();
        let mut S = GENERATORS.G_blind * &rho;
        for (s_l_i, G_i, s_r_i, H_i) in izip!(
            s_l.iter(),
            G_.clone().into_iter(),
            s_r.iter(),
            H_.clone().into_iter()
        ) {
            S += &(G_i * s_l_i + &(H_i * s_r_i));
        }

        // Prover -> Verifier: A, S
        // Verifier -> Prover: y, z

        // Append A and S to transcript
        transcript.append_element(b"Com(A)_", &A);
        transcript.append_element(b"Com(S)_", &S);

        // Get y challenge
        let y = transcript.get_challenge(b"y_chall_");

        // Commit y
        let y_bytes: [u8; 32] = y.as_ref().into();
        transcript.append_element(b"Com(y)_", &hash_to_curve(&y_bytes).unwrap());

        // Get z challenge
        let z = transcript.get_challenge(b"z_chall_");

        let mut z_list = vec![Scalar::new(&SCALAR_ONE)];
        for _ in 1..(3 + m) {
            z_list.push(z * z_list.last().unwrap());
        }

        // Calculate ẟ(y, z)     Definition (between 71-72)
        let p = z + &z_list[2];

        let mut y_list = vec![Scalar::new(&SCALAR_ONE)];
        for _ in 1..(n * m) {
            y_list.push(y * y_list.last().unwrap());
        }

        let mut delta_y_z = Scalar::new(&SCALAR_ZERO);
        for (i, y_i) in y_list.iter().enumerate() {
            delta_y_z += &(p * y_i + &(z_list[3] * &z_list[i / n] * &POWERS_OF_TWO[i % n]));
        }

        // l(X) and r(X) linear vector polynomials   (70-71)
        // (of degree 1)
        let mut l: Vec<Vec<Scalar>> = vec![Vec::new(), Vec::new()];
        let mut r: Vec<Vec<Scalar>> = vec![Vec::new(), Vec::new()];
        for j in 0..m {
            for i in 0..n {
                l[0].push(a_left[j * n + i] + &z); // vector coefficient for X^0
                l[1].push(s_l[j * n + i]); // vector coefficient for X^1

                r[0].push(
                    y_list[j*n+i] * &(a_right[j*n+i] + &z) +    // vector coefficient for X^0
                    &(z_list[2] * &z_list[j] * &POWERS_OF_TWO[i]), // vector coefficient for X^1
                );
                r[1].push(y_list[j * n + i] * &s_r[j * n + i])
            }
        }

        // t(X) = <l(X), r(X)> = t_0 + t_1 * X + t_2 * X^2

        // Calculate constant term t_0
        // let t_0 = inner_product(&l[0], &r[0]);

        // Calculate coefficient t_1. From definition (1)
        let t_1 = inner_product(&l[1], &r[0]) + &inner_product(&l[0], &r[1]);

        // Calculate coefficient t_2. From definition (1)
        let t_2 = inner_product(&l[1], &r[1]);

        // Hide t_1, t_2 coefficients of t(x)
        // into Pedersen commitments     (52-53)
        let (tau_1, tau_2) = (Scalar::random(), Scalar::random());
        let T1 = GENERATORS.G_amount * &t_1 + &(GENERATORS.G_blind * &tau_1);
        let T2 = GENERATORS.G_amount * &t_2 + &(GENERATORS.G_blind * &tau_2);

        // Prover -> Verifier: T_1, T_2
        // Verifier -> Prover: x

        // Append T_1, T_2 to transcript
        transcript.append_element(b"Com(T_1)_", &T1);
        transcript.append_element(b"Com(T_2)_", &T2);

        // Get challenge x (named x because used for evaluation of t(x))
        let x = transcript.get_challenge(b"x_chall_");
        let x_2 = x * &x;

        // now evaluate t(x) at x    (58-60)
        let mut l_x = Vec::new();
        let l0 = std::mem::take(&mut l[0]);
        let l1 = std::mem::take(&mut l[1]);
        for (l_0, l_1) in izip!(l0.into_iter(), l1.into_iter()) {
            l_x.push(l_0 + &(l_1 * &x));
        }
        let mut r_x = Vec::new();
        let r0 = std::mem::take(&mut r[0]);
        let r1 = std::mem::take(&mut r[1]);
        for (r_0, r_1) in izip!(r0.into_iter(), r1.into_iter()) {
            r_x.push(r_0 + &(r_1 * &x));
        }
        let t_x = inner_product(&l_x, &r_x);

        // and compute tau_x (the blinding part of t_x)    (61)
        let mut tau_0 = Scalar::new(&SCALAR_ZERO);
        let z_2 = z_list[2];
        for (attribute_pair, z_j) in izip!(attributes.iter(), z_list.into_iter()) {
            tau_0 += &(z_j * &attribute_pair.r);
        }
        tau_0 = tau_0 * &z_2;
        let tau_x = tau_0 + &(tau_1 * &x) + &(tau_2 * &x_2);

        // blinding factors for A, S     (62)
        let mu = alpha + &(rho * &x);

        // Switch generators H -> y^-n*H    (64)
        let mut H_new = Vec::new();
        let y_inv = y.invert();
        let mut y_inv_geometric = Scalar::new(&SCALAR_ONE);
        for H_i in H_.into_iter() {
            H_new.push(H_i * &y_inv_geometric);
            y_inv_geometric = y_inv_geometric * &y_inv;
        }
        H_ = H_new;

        // Compute commitment to l(x) and r(x): P = l(x)*G + r(x)*H'
        let mut P = GENERATORS.O;
        for (l_x_i, G_i, r_x_i, H_i) in izip!(
            l_x.iter(),
            G_.clone().into_iter(),
            r_x.iter(),
            H_.clone().into_iter()
        ) {
            P = P + &(G_i * l_x_i) + &(H_i * r_x_i);
        }

        // Now instead of sending l and r we fold them and send logarithmically fewer commitments
        // We get the IPA for l, r.
        let ipa = InnerProductArgument::new(transcript, (G_, H_, U_), P, l_x, r_x);

        // Prover -> Verifier: t_x, tau_x, mu, ipa
        BulletProof {
            A,
            S,
            T1,
            T2,
            t_x,
            tau_x,
            mu,
            ipa,
        }
    }

    pub fn verify(
        self,
        transcript: &mut CashuTranscript,
        attribute_commitments: &[GroupElement],
    ) -> bool {
        transcript.domain_sep(b"Bulletproof_Statement_");

        // Prover -> Verifier: A, S
        // Verifier -> Prover: y, z

        let n = LOG_RANGE_LIMIT;
        let len_pow2 = 1 << self.ipa.public_inputs_len();
        let m = len_pow2 / n;

        // This check shouldn't be necessary but better safe than sorry
        // plus we save some computation in case this is not satisfied.
        let check = n * attribute_commitments.len();
        if (check.count_ones() == 1 && check.ilog2() != self.ipa.public_inputs_len() as u32)
            || (check.count_ones() != 1 && check.ilog2() + 1 != self.ipa.public_inputs_len() as u32)
        {
            return false;
        }

        // Get generators
        let (G_, mut H_, U_) = get_generators(n * m);

        // Append amount commitments to the transcript
        for V in attribute_commitments.iter() {
            transcript.append_element(b"Com(V)_", V);
        }
        // Commit to the padded-to-pow2 number of attributes
        transcript.append_element(
            b"Com(m)_",
            &hash_to_curve(&(m as u32).to_be_bytes())
                .expect("Couldn't map m length to GroupElement"),
        );

        // Append A and S to transcript
        let A = self.A;
        let S = self.S;
        transcript.append_element(b"Com(A)_", &A);
        transcript.append_element(b"Com(S)_", &S);

        // Get y challenge
        let y = transcript.get_challenge(b"y_chall_");

        // Commit y
        let y_bytes: [u8; 32] = y.as_ref().into();
        transcript.append_element(b"Com(y)_", &hash_to_curve(&y_bytes).unwrap());

        // Get z challenge
        let z = transcript.get_challenge(b"z_chall_");

        let mut z_list = vec![Scalar::new(&SCALAR_ONE)];
        for _ in 1..(3 + m) {
            z_list.push(z * z_list.last().unwrap());
        }

        // Calculate ẟ(y, z)     Definition (between 71-72)
        let p = z + &z_list[2];

        let mut y_list = vec![Scalar::new(&SCALAR_ONE)];
        for _ in 1..(n * m) {
            y_list.push(y * y_list.last().unwrap());
        }

        let mut delta_y_z = Scalar::new(&SCALAR_ZERO);
        for (i, y_i) in y_list.iter().enumerate() {
            delta_y_z += &(p * y_i + &(z_list[3] * &z_list[i / n] * &POWERS_OF_TWO[i % n]));
        }

        // Prover -> Verifier: T_1, T_2
        // Verifier -> Prover: x

        // Append T_1, T_2 to transcript
        let (T1, T2) = (self.T1, self.T2);
        transcript.append_element(b"Com(T_1)_", &T1);
        transcript.append_element(b"Com(T_2)_", &T2);

        // Get challenge x (named x because used for evaluation of t(x))
        let x = transcript.get_challenge(b"x_chall_");
        let x_2 = x * &x;

        let t_x = self.t_x;
        let tau_x = self.tau_x;
        // Check that t_x = t(x) = t_0 + t_1*x + t_2*x^2     (72)
        let mut V_z_m = GENERATORS.O;
        for (commitment_pair, z_j) in izip!(attribute_commitments.iter(), z_list.iter()) {
            V_z_m += &(*commitment_pair * z_j);
        }
        if GENERATORS.G_amount * &t_x + &(GENERATORS.G_blind * &tau_x)
            != V_z_m * &z_list[2] + &(GENERATORS.G_amount * &delta_y_z) + &(T1 * &x) + &(T2 * &x_2)
        {
            return false;
        }

        // Switch generators H -> y^(-n)*H)    (64)
        let mut H_new = Vec::new();
        let y_inv = y.invert();
        let mut y_inv_geometric = Scalar::new(&SCALAR_ONE);
        for H_i in H_.into_iter() {
            H_new.push(H_i * &y_inv_geometric);
            y_inv_geometric = y_inv_geometric * &y_inv;
        }
        H_ = H_new;

        // Compute commitment to l(x) and r(x)   (72)
        let mu = self.mu;
        let mut P = GENERATORS.G_blind * &(-mu) + &A + &(S * &x);
        for j in 0..m {
            for i in 0..n {
                P = P
                    + &(G_[j * n + i] * &z)
                    + &(H_[j * n + i] * &(y_list[j * n + i] * &z))
                    + &(H_[j * n + i] * &(z_list[2] * &z_list[j] * &POWERS_OF_TWO[i]))
            }
        }

        // Check l and r are correct using IPA   (67)
        // Check t_x is correct                  (68)
        self.ipa.verify(transcript, (G_, H_, U_), P, t_x)
    }
}

#[allow(unused_imports)]
mod tests {
    use super::{get_generators, inner_product, pad_zeros, BulletProof, InnerProductArgument};
    use crate::{
        generators::GENERATORS,
        models::{AmountAttribute, ScriptAttribute},
        secp::Scalar,
        transcript::CashuTranscript,
    };
    use itertools::izip;

    #[allow(non_snake_case)]
    #[test]
    fn test_ipa() {
        let mut cli_tscr = CashuTranscript::new();
        let mut mint_tscr = CashuTranscript::new();

        let a = (0..96).map(|_| Scalar::random()).collect();
        let b = (0..96).map(|_| Scalar::random()).collect();
        let a = pad_zeros(a, 128);
        let b = pad_zeros(b, 128);
        let (G_, H_, _) = get_generators(128);
        let mut P = GENERATORS.O;
        for (G_i, a_i, H_i, b_i) in izip!(G_.into_iter(), a.iter(), H_.into_iter(), b.iter()) {
            P = P + &(G_i * a_i) + &(H_i * b_i);
        }

        let ipa =
            InnerProductArgument::new(&mut cli_tscr, get_generators(128), P, a.clone(), b.clone());

        let c = inner_product(&a, &b);
        assert!(ipa.verify(&mut mint_tscr, get_generators(128), P, c))
    }

    #[test]
    fn test_range_proof() {
        let mut cli_tscr = CashuTranscript::new();
        let mut mint_tscr = CashuTranscript::new();

        let attributes: Vec<AmountAttribute> = vec![
            AmountAttribute::new(2, None),
            AmountAttribute::new(1, None),
            AmountAttribute::new(14, None),
        ];
        let mut attribute_commitments = Vec::new();
        for attr in attributes.iter() {
            attribute_commitments.push(attr.commitment());
        }
        let range_proof = BulletProof::new(&mut cli_tscr, &attributes);
        assert!(range_proof.verify(&mut mint_tscr, &attribute_commitments))
    }
    #[test]
    fn test_range_proof_zero() {
        let mut cli_tscr = CashuTranscript::new();
        let mut mint_tscr = CashuTranscript::new();

        let attributes: Vec<AmountAttribute> =
            vec![AmountAttribute::new(0, None), AmountAttribute::new(0, None)];
        let mut attribute_commitments = Vec::new();
        for attr in attributes.iter() {
            attribute_commitments.push(attr.commitment());
        }
        let range_proof = BulletProof::new(&mut cli_tscr, &attributes);
        //println!("{:?}", serde_json::to_string_pretty(&range_proof).unwrap());
        assert!(range_proof.verify(&mut mint_tscr, &attribute_commitments))
    }
    #[test]
    fn test_wrong_range() {
        let mut cli_tscr = CashuTranscript::new();
        let mut mint_tscr = CashuTranscript::new();

        let attributes: Vec<AmountAttribute> = vec![
            AmountAttribute::new(1 << 32, None),
            AmountAttribute::new(11, None),
        ];
        let mut attribute_commitments = Vec::new();
        for attr in attributes.iter() {
            attribute_commitments.push(attr.commitment());
        }
        let range_proof = BulletProof::new(&mut cli_tscr, &attributes);
        assert!(!range_proof.verify(&mut mint_tscr, &attribute_commitments))
    }
}
