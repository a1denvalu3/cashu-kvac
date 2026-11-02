//! SharpPoSO relaxed range proofs (CCS 2022, ePrint 2022/1153), instantiated
//! over secp256k1 (no group switching; `G_com = G_3sq`).
//!
//! A proof shows that the amounts `a_i` inside a batch of `AmountAttribute`
//! commitments are in `[0, B]`, modulo the *relaxed* soundness semantics of
//! the paper: the extractor binds the prover to a rational representative
//! `[a_i]_Q ∈ [−1/(4B), B + 1/(4B)]` with denominator bounded by `Γ = 4B − 1`
//! and numerator bounded by `K'`, with knowledge error `((2+8R)/(Γ+1))^R`
//! (Theorem 5.1). This suffices for the Cashu/KVAC use case: outputs are
//! range-proven at issuance, never re-proven after homomorphic combination,
//! and only non-negativity of the commitment's rational representative is
//! load-bearing for mint solvency.
//!
//! The structure follows Algorithms 2 and 3 of the paper, with the paper's
//! hash-compression optimization for the verifier-recomputable commitments
//! (Section 5.4 "Reducing communication"): `D_x`, `D_y`, `D_star`, and the
//! `d_k` are re-derived by the verifier; the prover only sends a 32-byte
//! challenge-derived digest `d_h` that commits to all of them at once.

use crate::{
    errors::Error,
    generators::{hash_to_curve, GENERATORS},
    models::AmountAttribute,
    secp::{GroupElement, Scalar, SCALAR_ZERO},
    transcript::CashuTranscript,
};
use bitcoin::secp256k1::constants::CURVE_ORDER;
use num_bigint::{BigInt, Sign};
use num_traits::Zero;

// ---------------------------------------------------------------------------
// Parameter derivation (Section 4.1 / 5.1, Theorem 5.1 of the paper)
// ---------------------------------------------------------------------------

/// Parameters for a SharpPoSO proof over range `[0, B]`.
///
/// All bounds are enforced at construction and again at verification, so a
/// proof is self-describing: given `(B, R)` the verifier re-derives everything
/// else and rejects parameter sets where the security conditions of the paper
/// do not hold.
#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct SharpParams {
    /// Upper bound of the proven range `[0, B]`.
    pub range_max: u64,
    /// Short-challenge space for the RAST is `[0, Γ]`, with `Γ = 4B − 1`.
    pub Gamma: BigInt,
    /// Number of internal repetitions (RAST invocations).
    pub R: u64,
    /// Masking overhead for the short witnesses.
    pub L_x: BigInt,
    /// Phase-2 challenge space is `[0, Γ_hat]` with `Γ_hat = (Γ+1)^R − 1`.
    pub Gamma_hat: BigInt,
}

/// Smallest `k` such that the product of the first `k` primes is ≥ `n`
/// (paper's `primlmin`, Definition 2.1 — note it returns the *count* of
/// primes, not the product itself).
fn primorial_index(n: &BigInt) -> u64 {
    const PRIMES: [u64; 16] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];
    let mut k: u64 = 0;
    let mut acc = BigInt::from(1u64);
    while &acc < n {
        if (k as usize) < PRIMES.len() {
            acc *= PRIMES[k as usize];
            k += 1;
        } else {
            // For any n that matters here we have never consumed all known
            // primes; fall back to a strict upper bound of k + 64.
            return k + 64;
        }
    }
    k
}

impl SharpParams {
    /// Security parameter (bits of knowledge error) enforced by the stack.
    pub const SECURITY_BITS: u32 = 128;

    /// Derive parameters for proving batch values lie in `[0, B]`, checking
    /// every condition of Theorem 5.1 and the unique-representative condition
    /// `2(B·Γ² + 1)·L_x < p` from Section 1.2.1 / Lemma 2.4.
    ///
    /// Returns `Err(InvalidRangeBound)` for `B == 0` and
    /// `Err(ParameterSetupFailure)` when the group order cannot support the
    /// derived parameters.
    #[allow(non_snake_case)]
    pub fn new(range_max: u64, batch_size: u64) -> Result<Self, Error> {
        if range_max == 0 || batch_size == 0 {
            return Err(Error::InvalidRangeBound);
        }
        let p = BigInt::from_bytes_be(Sign::Plus, &CURVE_ORDER);
        let B = BigInt::from(range_max);
        let Gamma = 4u32 * &B - 1u32;

        // R: smallest repetition count with knowledge error
        //   ((2 + 8R) / (Γ+1))^R  <=  2^{-128}
        let two128 = BigInt::from(1u64) << 128;
        let mut R: u64 = 1;
        loop {
            let num = BigInt::from(2u64 + 8 * R);
            let den = &Gamma + 1u32;
            // (num/den)^R <= 1/2^128  ⟺  num^R * 2^128 <= den^R
            let lhs = num.pow(R as u32) * &two128;
            let rhs = den.pow(R as u32);
            if lhs <= rhs {
                break;
            }
            R += 1;
            if R > 512 {
                return Err(Error::ParameterSetupFailure);
            }
        }

        // Γ_hat = (Γ+1)^R − 1 must fit the scalar field (phase-2 challenge).
        let Gamma_hat = (&Gamma + 1u32).pow(R as u32) - 1u32;
        if Gamma_hat >= p {
            return Err(Error::ParameterSetupFailure);
        }

        // β = min(4N, primlmin(Γ+1)) (Theorem 5.1).  K' = (1 + 2β)·K,
        // K = (B·Γ + 1)·L.
        let beta = std::cmp::min(4 * batch_size, primorial_index(&(&Gamma + 1u32)));
        let kprime_factor = BigInt::from(1u64 + 2 * beta);

        // L_x: greatest *even* masking overhead with
        //   (a) 2·(B·Γ² + 1)·L_x < p                        (unique rational rep)
        //   (b) 18·K'² < p   with K' = (1 + 2β)(B·Γ + 1)L_x  (decomp lifts to Z)
        //
        // We sample over uniform [0, (V+1)·L_x]; an even L_x keeps both sides of
        // the binary search integral. Start from a generous upper bound and
        // shrink by halving.
        let mut lo = BigInt::from(1u64);
        let mut hi = &p >> 8; // conservative: L_x << p
        let big_b = B.clone();
        let gamma_c = Gamma.clone();
        let cond_ok = |l: &BigInt, big_b: &BigInt, gamma_c: &BigInt| -> bool {
            let k = (big_b * gamma_c + 1u32) * l;
            let kprime = &kprime_factor * &k;
            let cond_b = 18u32 * &kprime * &kprime < p;
            let gamma2 = gamma_c * gamma_c;
            let cond_a = 2u32 * (big_b * &gamma2 + 1u32) * l < p;
            cond_a && cond_b
        };
        if !cond_ok(&lo, &big_b, &gamma_c) {
            return Err(Error::ParameterSetupFailure);
        }
        while &hi - &lo > BigInt::from(1u64) {
            let mid = ((&lo + &hi) >> 1) + 1u32;
            if cond_ok(&mid, &big_b, &gamma_c) {
                lo = mid;
            } else {
                hi = &mid - 1u32;
            }
        }
        let L_x = lo;

        Ok(Self {
            range_max,
            Gamma,
            R,
            L_x,
            Gamma_hat,
        })
    }
}

// ---------------------------------------------------------------------------
// Three-square decomposition (Legendre)
// ---------------------------------------------------------------------------

/// Find `y1, y2, y3` with `y1² + y2² + y3² = value`.
///
/// Every value the prover feeds here is of the form `4·x·(B − x) + 1 ≡ 1 (mod 8)`
/// and hence always representable by Legendre's three-square theorem; the
/// search below is the naive O(B) enumeration, which is acceptable for the
/// (small) amounts this library proves.
pub fn find_3_squares(value: u64) -> Result<(u64, u64, u64), Error> {
    if value == 0 {
        return Ok((0, 0, 0));
    }
    // Legendre: representable iff NOT of the form 4^a(8b + 7).
    let mut n = value;
    while n % 4 == 0 {
        n /= 4;
    }
    if n % 8 == 7 {
        return Err(Error::ThreeSquaresFailure);
    }
    let vmax = (value as f64).sqrt() as u64 + 1;
    for x in 0..=vmax {
        let x2 = (x as u128) * (x as u128);
        if x2 > value as u128 {
            break;
        }
        let rem1 = value as u128 - x2;
        let ymax = (rem1 as f64).sqrt() as u64 + 1;
        for y in x..=ymax {
            let y2 = (y as u128) * (y as u128);
            if y2 > rem1 {
                break;
            }
            let rem2 = rem1 - y2;
            let z = (rem2 as f64).sqrt() as u64;
            for cand in z..=z + 1 {
                if (cand as u128) * (cand as u128) == rem2 {
                    return Ok((x, y, cand));
                }
            }
        }
    }
    Err(Error::ThreeSquaresFailure)
}

// ---------------------------------------------------------------------------
// Generators (transparent setup — Section 2.2.3/4.1 CRS made of random points)
// ---------------------------------------------------------------------------

fn poso_generators(n: u64) -> Vec<GroupElement> {
    (0..3 * n)
        .map(|k| {
            hash_to_curve(format!("CASHU_SHARP_POSO_G_{}", k).as_bytes())
                .expect("Could not map hash to point")
        })
        .collect()
}

fn poso_mask_generators(r: u64) -> Vec<GroupElement> {
    (0..r)
        .map(|k| {
            hash_to_curve(format!("CASHU_SHARP_POSO_MASK_{}", k).as_bytes())
                .expect("Could not map hash to point")
        })
        .collect()
}

fn podec_generators(n: u64) -> Vec<GroupElement> {
    (0..=n)
        .map(|k| {
            hash_to_curve(format!("CASHU_SHARP_PODEC_H_{}", k).as_bytes())
                .expect("Could not map hash to point")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// BigInt ↔ Scalar helpers for short ranges
// ---------------------------------------------------------------------------

fn scalar_to_bigint(s: &Scalar) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, &s.to_bytes())
}

fn bigint_to_scalar(v: &BigInt) -> Result<Scalar, Error> {
    Scalar::try_from(v)
}

fn scalar_is_le(s: &Scalar, bound: &BigInt) -> bool {
    scalar_to_bigint(s) <= *bound
}

// ---------------------------------------------------------------------------
// SharpPoSO proof
// ---------------------------------------------------------------------------

/// A SharpPoSO proof over a batch of `AmountAttribute`s (Algorithms 2 & 3).
#[allow(non_snake_case)]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SharpPOSO {
    /// Commitment to the 3-square decompositions plus the RAST masks μ_k.
    pub C_y: GroupElement,
    /// RAST answers ζ_k = μ_k + Σ γ·(x, y) over the integers (short).
    pub zeta_list: Vec<Scalar>,
    /// Garbage-term commitment C* = r*·H_0 + Σ α*_1,i·H_i.
    pub C_star: GroupElement,
    /// Phase-2 masked amounts z_i = γ·x_i + x̃_i.
    pub z_x_list: Vec<Scalar>,
    /// Phase-2 masked decomposition z_{i,j} = γ·y_{i,j} + ỹ_{i,j}.
    pub z_y_list: Vec<Scalar>,
    /// Phase-2 masked Pedersen blinding of the amount commitments.
    pub t_x_list: Vec<Scalar>,
    /// Phase-2 masked Pedersen blinding of C_y.
    pub t_y: Scalar,
    /// Phase-2 masked blinding of C*.
    pub t_star: Scalar,
    /// Phase-2 masked μ_k blinding terms τ_k = γ·μ_k + μ̃_k.
    pub tau_list: Vec<Scalar>,
    /// Hash-derived challenge digest committing to (D_x, D_y, D*, d_k).
    pub d_h: Scalar,
}

impl PartialEq for SharpPOSO {
    fn eq(&self, other: &Self) -> bool {
        self.C_y == other.C_y
            && self.C_star == other.C_star
            && self.t_y == other.t_y
            && self.t_star == other.t_star
            && self.d_h == other.d_h
            && self.zeta_list == other.zeta_list
            && self.z_x_list == other.z_x_list
            && self.z_y_list == other.z_y_list
            && self.t_x_list == other.t_x_list
            && self.tau_list == other.tau_list
    }
}

impl std::hash::Hash for SharpPOSO {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.C_y.hash(state);
        self.C_star.hash(state);
        self.t_y.hash(state);
        self.t_star.hash(state);
        self.d_h.hash(state);
        self.zeta_list.hash(state);
        self.z_x_list.hash(state);
        self.z_y_list.hash(state);
        self.t_x_list.hash(state);
        self.tau_list.hash(state);
    }
}

#[allow(non_snake_case)]
impl SharpPOSO {
    /// Upper bound on the short witnesses, `(4·N·B·Γ + 1)·L_x`
    /// (Algorithm 2 line 2 of the verifier).
    fn zeta_bound(params: &SharpParams, n: u64) -> BigInt {
        let b = BigInt::from(params.range_max);
        (4u64 * n * &b * &params.Gamma + 1u32) * &params.L_x
    }

    /// Create a SharpPoSO proof.
    ///
    /// Rejection sampling: masking of `ζ_k` fails with probability at most
    /// `1/L_x` per repetition (Section 2.4), so with the parameters derived
    /// for this group, abort probability is negligible in practice. The loop
    /// is nevertheless hard-bounded to keep this function total; on Saturn-
    /// style exhaustion it returns `Error::MaskingFailure`.
    pub fn new(
        transcript: &mut CashuTranscript,
        amount_attributes: &[AmountAttribute],
        params: &SharpParams,
    ) -> Result<Self, Error> {
        if amount_attributes.is_empty() {
            return Err(Error::EmptyList);
        }
        let n = amount_attributes.len() as u64;
        // Re-derive to guard against a caller-constructed inconsistent params.
        let params = SharpParams::new(params.range_max, n)?;
        let B = params.range_max;
        let rast_bound = 4u64 * n * B * &params.Gamma; // V_poso

        transcript.domain_sep(b"SharpPOSO_Statement_");

        let c_x_list: Vec<GroupElement> = amount_attributes
            .iter()
            .map(|att| att.commitment())
            .collect();
        for c in c_x_list.iter() {
            transcript.append_element(b"C_x_i", c);
        }

        // --- Phase 1, line 1: decompose  4·a_i·(B − a_i) + 1 = Σ_j y_{i,j}² ---
        let mut y_list: Vec<Scalar> = Vec::with_capacity(3 * n as usize);
        for attr in amount_attributes.iter() {
            let a: u64 = (&attr.a).into();
            if a > B {
                return Err(Error::OutOfRangeError);
            }
            let v = 4u128 * (a as u128) * ((B - a) as u128) + 1;
            if v > u64::MAX as u128 {
                return Err(Error::OutOfRangeError);
            }
            let (y1, y2, y3) = find_3_squares(v as u64)?;
            y_list.extend_from_slice(&[y1, y2, y3].map(Scalar::from));
        }

        // --- Phase 1, lines 2-3: C_y commits to y_{i,j} and the RAST masks μ_k ---
        let g_decomp = poso_generators(n);
        let g_masks = poso_mask_generators(params.R);
        let r_y = Scalar::random();

        // Rejection-sampling loop: refresh μ_k until all R masked ζ_k are short.
        let mut attempts: u64 = 0;
        let (c_y, mu_list, gamma_list, zeta_list) = loop {
            attempts += 1;
            if attempts > 1 << 20 {
                return Err(Error::MaskingFailure);
            }

            let mut c_y_try = GENERATORS.G_blind * &r_y;
            for i in 0..n as usize {
                for j in 0..3 {
                    c_y_try += &(g_decomp[3 * i + j] * &y_list[3 * i + j]);
                }
            }

            // μ_k ← uniform([0, (V_poso + 1)·L_x])
            let mut tmp_t = transcript.clone();
            let mut mu_try: Vec<Scalar> = Vec::with_capacity(params.R as usize);
            let mut c_y_masked = c_y_try;
            for gm in g_masks.iter() {
                let big = scalar_to_bigint(&Scalar::random())
                    % ((&rast_bound + 1u32) * &params.L_x + 1u32);
                let mu = bigint_to_scalar(&big)?;
                c_y_masked += &((*gm) * &mu);
                mu_try.push(mu);
            }

            tmp_t.append_element(b"C_y", &c_y_masked);

            // Short challenges γ^{(k)}_{i,j} ← [0, Γ]
            let mut gamma_try: Vec<Scalar> = Vec::with_capacity((4 * n * params.R) as usize);
            for _ in 0..(4 * n * params.R) {
                let chall = scalar_to_bigint(&tmp_t.get_challenge(b"sharp_rast_chall"));
                gamma_try.push(bigint_to_scalar(&(chall % (&params.Gamma + 1u32)))?);
            }

            // ζ_k = mask_poso( Σ_{i,j} γ^{(k)}_{i,j} · y_{i,j} , μ_k )
            let mut zeta_try: Vec<Scalar> = Vec::with_capacity(params.R as usize);
            let mut abort = false;
            // k indexes both `mu_try` and every block of 4 gammas (offset math),
            // so a plain zip is not expressible without re-deriving offsets.
            #[allow(clippy::needless_range_loop)]
            for k in 0..params.R as usize {
                let mut sum = BigInt::zero();
                for i in 0..n as usize {
                    // j = 0 term is the amount itself (y_{i,0} := x_i).
                    let gamma_idx = (k as u64 * n * 4 + i as u64 * 4) as usize;
                    let a: u64 = (&amount_attributes[i].a).into();
                    sum += scalar_to_bigint(&gamma_try[gamma_idx]) * BigInt::from(a);
                    for j in 0..3 {
                        let gi = gamma_idx + j + 1;
                        sum +=
                            scalar_to_bigint(&gamma_try[gi]) * scalar_to_bigint(&y_list[3 * i + j]);
                    }
                }
                let masked = &sum + &scalar_to_bigint(&mu_try[k]);
                let upper = (&rast_bound + 1u32) * &params.L_x;
                if masked > upper {
                    abort = true;
                    break;
                }
                zeta_try.push(bigint_to_scalar(&masked)?);
            }
            if abort {
                continue;
            }

            // Commit to the transcript on success.
            transcript.append_element(b"C_y", &c_y_masked);
            for _ in 0..(4 * n * params.R) {
                transcript.get_challenge(b"sharp_rast_chall");
            }
            break (c_y_masked, mu_try, gamma_try, zeta_try);
        };

        // --- Phase 2 (Algorithm 3) ---
        let rr_y = Scalar::random();
        let rr_x_list: Vec<Scalar> = (0..n).map(|_| Scalar::random()).collect();
        let xr_list: Vec<Scalar> = (0..n).map(|_| Scalar::random()).collect();
        let yr_list: Vec<Scalar> = (0..3 * n).map(|_| Scalar::random()).collect();
        let mu_r_list: Vec<Scalar> = (0..params.R).map(|_| Scalar::random()).collect();

        // d_k = Σ γ^{(k)}_{i,j}·ỹ_{i,j} + μ̃_k  (line 11)
        let mut d_list: Vec<Scalar> = Vec::with_capacity(params.R as usize);
        #[allow(clippy::needless_range_loop)]
        for k in 0..params.R as usize {
            let mut sum = Scalar::new(&SCALAR_ZERO);
            for i in 0..n as usize {
                let gamma_idx = (k as u64 * n * 4 + i as u64 * 4) as usize;
                sum += &(gamma_list[gamma_idx] * &xr_list[i]);
                for j in 0..3 {
                    sum += &(gamma_list[gamma_idx + j + 1] * &yr_list[3 * i + j]);
                }
            }
            d_list.push(sum + &mu_r_list[k]);
        }

        let d_x: Vec<GroupElement> = (0..n as usize)
            .map(|i| GENERATORS.G_blind * &rr_x_list[i] + &(GENERATORS.G_amount * &xr_list[i]))
            .collect();
        let mut d_y = GENERATORS.G_blind * &rr_y;
        for i in 0..n as usize {
            for j in 0..3 {
                d_y += &(g_decomp[3 * i + j] * &yr_list[3 * i + j]);
            }
        }
        for (gm, mur) in g_masks.iter().zip(mu_r_list.iter()) {
            d_y += &((*gm) * mur);
        }

        let (r_star, rr_star) = (Scalar::random(), Scalar::random());
        let h_list = podec_generators(n);
        let scalar_4b = Scalar::from(4u64) * &Scalar::from(B);
        let scalar_8 = Scalar::from(8u64);
        let scalar_4 = Scalar::from(4u64);
        let scalar_2 = Scalar::from(2u64);

        let mut c_star = h_list[0] * &r_star;
        let mut d_star = h_list[0] * &rr_star;
        for i in 0..n as usize {
            // α*_{1,i} = 4·x̃_i·B − 8·x_i·x̃_i − 2 Σ_j y_{i,j}·ỹ_{i,j}
            let mut alpha1 =
                xr_list[i] * &scalar_4b - &(xr_list[i] * &amount_attributes[i].a * &scalar_8);
            // α*_{0,i} = −(4·x̃_i² + Σ_j ỹ_{i,j}²)
            let mut alpha0 = -(scalar_4 * &xr_list[i] * &xr_list[i]);
            let mut s1 = Scalar::new(&SCALAR_ZERO);
            let mut s2 = Scalar::new(&SCALAR_ZERO);
            for j in 0..3 {
                s1 += &(y_list[3 * i + j] * &yr_list[3 * i + j]);
                s2 += &(yr_list[3 * i + j] * &yr_list[3 * i + j]);
            }
            alpha1 += &(-s1 * &scalar_2);
            alpha0 += &-s2;
            c_star += &(h_list[i + 1] * &alpha1);
            d_star += &(h_list[i + 1] * &alpha0);
        }

        transcript.append_element(b"C_star", &c_star);

        // Large phase-2 challenge γ ← [0, Γ_hat]
        let gamma = {
            let raw = scalar_to_bigint(&transcript.get_challenge(b"sharp_gamma"));
            bigint_to_scalar(&(raw % (&params.Gamma_hat + 1u32)))?
        };

        let t_y = gamma * &r_y + &rr_y;
        let t_x_list: Vec<Scalar> = (0..n as usize)
            .map(|i| gamma * &amount_attributes[i].r + &rr_x_list[i])
            .collect();
        let z_x_list: Vec<Scalar> = (0..n as usize)
            .map(|i| gamma * &amount_attributes[i].a + &xr_list[i])
            .collect();
        let mut z_y_list: Vec<Scalar> = Vec::with_capacity(3 * n as usize);
        for i in 0..n as usize {
            for j in 0..3 {
                z_y_list.push(gamma * &y_list[3 * i + j] + &yr_list[3 * i + j]);
            }
        }
        let t_star = gamma * &r_star + &rr_star;
        let tau_list: Vec<Scalar> = mu_list
            .iter()
            .zip(mu_r_list.iter())
            .map(|(mu, mur)| gamma * mu + mur)
            .collect();

        // Hash-compressed commitments (Section 5.4 optimization): the verifier
        // recomputes (D_x, D_y, D*, d_k) and we only include a digest.
        for dx in d_x.iter() {
            transcript.append_element(b"Dx", dx);
        }
        transcript.append_element(b"Dy", &d_y);
        transcript.append_element(b"D*", &d_star);
        for dk in d_list.iter() {
            transcript.append_element(b"d_k", &point_from_scalar(dk)?);
        }
        let d_h = transcript.get_challenge(b"sharp_D_hash");

        Ok(Self {
            C_y: c_y,
            zeta_list,
            C_star: c_star,
            z_x_list,
            z_y_list,
            t_x_list,
            t_y,
            t_star,
            tau_list,
            d_h,
        })
    }

    /// Verify a SharpPoSO proof. Returns `true` iff every acceptance condition
    /// of Algorithms 2–3 holds.
    pub fn verify(
        &self,
        transcript: &mut CashuTranscript,
        amount_commitments: &[GroupElement],
        params: &SharpParams,
    ) -> bool {
        if amount_commitments.is_empty() {
            return false;
        }
        let n = amount_commitments.len() as u64;
        let params = match SharpParams::new(params.range_max, n) {
            Ok(p) => p,
            Err(_) => return false,
        };

        if self.zeta_list.len() != params.R as usize
            || self.tau_list.len() != params.R as usize
            || self.t_x_list.len() != n as usize
            || self.z_x_list.len() != n as usize
            || self.z_y_list.len() != (3 * n) as usize
        {
            return false;
        }

        // Shortness of every RAST answer (Algorithm 2, verifier line 2):
        //   ζ_k ∈ [0, (4·N·B·Γ + 1)·L_x].
        let bound = Self::zeta_bound(&params, n);
        for zeta in self.zeta_list.iter() {
            if !scalar_is_le(zeta, &bound) {
                return false;
            }
        }

        transcript.domain_sep(b"SharpPOSO_Statement_");
        for c in amount_commitments.iter() {
            transcript.append_element(b"C_x_i", c);
        }
        transcript.append_element(b"C_y", &self.C_y);

        // RAST challenges must be re-derived identically.
        let gamma_list: Vec<Scalar> = (0..(4 * n * params.R))
            .map(|_| {
                let raw = scalar_to_bigint(&transcript.get_challenge(b"sharp_rast_chall"));
                bigint_to_scalar(&(raw % (&params.Gamma + 1u32)))
            })
            .collect::<Result<Vec<Scalar>, Error>>()
            .expect("RAST challenge scalar");

        transcript.append_element(b"C_star", &self.C_star);
        let gamma = {
            let raw = scalar_to_bigint(&transcript.get_challenge(b"sharp_gamma"));
            match bigint_to_scalar(&(raw % (&params.Gamma_hat + 1u32))) {
                Ok(g) => g,
                Err(_) => return false,
            }
        };

        let b = params.range_max;
        let g_decomp = poso_generators(n);
        let g_masks = poso_mask_generators(params.R);

        // F_{x,i} = −γ·C_{x,i} + t_{x,i}·G_blind + z_{x,i}·G_amount
        let f_x: Vec<GroupElement> = (0..n as usize)
            .map(|i| {
                -(amount_commitments[i] * &gamma)
                    + &(GENERATORS.G_blind * &self.t_x_list[i])
                    + &(GENERATORS.G_amount * &self.z_x_list[i])
            })
            .collect();

        // F_y = −γ·C_y + t_y·G_blind + Σ z_{i,j}·G_{i,j} + Σ τ_k·G̃_k
        let mut f_y = -(self.C_y * &gamma) + &(GENERATORS.G_blind * &self.t_y);
        for i in 0..n as usize {
            for j in 0..3 {
                f_y += &(g_decomp[3 * i + j] * &self.z_y_list[3 * i + j]);
            }
        }
        for k in 0..params.R as usize {
            f_y += &(g_masks[k] * &self.tau_list[k]);
        }

        // f_k = −γ·ζ_k + Σ γ^{(k)}·z + τ_k  (Algorithm 3, line 8)
        let mut f_list: Vec<Scalar> = Vec::with_capacity(params.R as usize);
        for k in 0..params.R as usize {
            let mut f_k = -(self.zeta_list[k] * &gamma);
            for i in 0..n as usize {
                let gi = (k as u64 * n * 4 + i as u64 * 4) as usize;
                f_k += &(self.z_x_list[i] * &gamma_list[gi]);
                for j in 0..3 {
                    f_k += &(self.z_y_list[3 * i + j] * &gamma_list[gi + j + 1]);
                }
            }
            f_list.push(f_k + &self.tau_list[k]);
        }

        // f*_i = 4·z_i·(γB − z_i) + γ² − Σ_j z_{i,j}²  (line 9)
        let scalar_4 = Scalar::from(4u64);
        let scalar_b = Scalar::from(b);
        let gamma_sq = gamma * &gamma;
        let f_star: Vec<Scalar> = (0..n as usize)
            .map(|i| {
                let z = self.z_x_list[i];
                let mut acc = scalar_4 * &z * &((gamma * &scalar_b) - &z) + &gamma_sq;
                for j in 0..3 {
                    let zij = self.z_y_list[3 * i + j];
                    acc += &(-zij * &zij);
                }
                acc
            })
            .collect();

        let h_list = podec_generators(n);
        let mut f_star_point = -(self.C_star * &gamma) + &(h_list[0] * &self.t_star);
        for (i, fs) in f_star.iter().enumerate() {
            f_star_point += &(h_list[i + 1] * fs);
        }

        // Recompute the hashed commitments and re-derive d_h.
        for fx in f_x.iter() {
            transcript.append_element(b"Dx", fx);
        }
        transcript.append_element(b"Dy", &f_y);
        transcript.append_element(b"D*", &f_star_point);
        for fk in f_list.iter() {
            match point_from_scalar(fk) {
                Ok(pt) => transcript.append_element(b"d_k", &pt),
                Err(_) => return false,
            }
        }
        let f_h = transcript.get_challenge(b"sharp_D_hash");

        f_h == self.d_h
    }
}

/// Mirror of the prover-side `hash_to_curve(d_k.to_bytes())` digest used in the
/// compressed-commitment transcript. Private helper, kept in one place so
/// prover and verifier cannot drift.
fn point_from_scalar(s: &Scalar) -> Result<GroupElement, Error> {
    hash_to_curve(&s.to_bytes())
}

// ---------------------------------------------------------------------------
// RangeZKP integration
// ---------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_3_squares() {
        let samples: &[u64] = &[1, 5, 9, 13, 21, 101, 1001, 4 * 12345 + 1, 4 * 1_000_000 + 1];
        for &n in samples {
            let (a, b, c) = find_3_squares(n).expect("decomposition");
            assert_eq!(
                (a as u128) * (a as u128) + (b as u128) * (b as u128) + (c as u128) * (c as u128),
                n as u128,
                "wrong decomposition for {n}"
            );
        }
    }

    #[test]
    fn test_primorial_index() {
        assert_eq!(primorial_index(&BigInt::from(2u64)), 1);
        assert_eq!(primorial_index(&BigInt::from(6u64)), 2);
        assert_eq!(primorial_index(&BigInt::from(7u64)), 3);
        assert_eq!(primorial_index(&BigInt::from(210u64)), 4);
        assert_eq!(primorial_index(&BigInt::from(2310u64)), 5);
        assert_eq!(primorial_index(&BigInt::from(2311u64)), 6);
    }

    #[test]
    fn test_params_small_range_feasible() {
        // B = 2^24 is the smallest "realistic" range where a 128-bit SharpPoSO
        // proof fits in one secp256k1-order group (R = 6, Gamma_hat ≈ 2^156 < p).
        let p = SharpParams::new(1u64 << 24, 1).expect("params");
        assert!(p.R >= 5 && p.R <= 10);
        assert!(p.L_x > BigInt::zero());
    }

    #[test]
    fn test_params_tiny_range_infeasible() {
        // At B = 2^8, a 128-bit proof would need R = 26, making the phase-2
        // challenge space (Gamma+1)^R ≈ 2^260 exceed the group order. The
        // parameter derivation must refuse to construct an unsound instance.
        assert!(matches!(
            SharpParams::new(1u64 << 8, 1),
            Err(Error::ParameterSetupFailure)
        ));
    }

    #[test]
    fn test_params_full_range() {
        // B = 2^32: matches RANGE_LIMIT; knowledge error must be ≥ 128 bits.
        let p = SharpParams::new(1u64 << 32, 8).expect("params");
        assert!(p.R >= 5 && p.R <= 12);
        // Knowledge error check: ((2+8R)/(Γ+1))^R ≤ 2^-128.
        let num = BigInt::from(2u64 + 8 * p.R);
        let den = &p.Gamma + 1u32;
        assert!(num.pow(p.R as u32) * (BigInt::from(1u64) << 128) <= den.pow(p.R as u32));
    }

    #[test]
    fn test_proof_roundtrip() {
        let mut cli = CashuTranscript::new();
        let mut mint = CashuTranscript::new();
        let attributes: Vec<AmountAttribute> = vec![
            AmountAttribute::new(2, None),
            AmountAttribute::new(1, None),
            AmountAttribute::new(14, None),
        ];
        let commitments: Vec<GroupElement> = attributes.iter().map(|a| a.commitment()).collect();
        let params = SharpParams::new(1 << 32, attributes.len() as u64).expect("params");
        let proof = SharpPOSO::new(&mut cli, &attributes, &params).expect("sharp proof");
        assert!(proof.verify(&mut mint, &commitments, &params));
    }

    #[test]
    fn test_witness_out_of_range_rejected() {
        let mut cli = CashuTranscript::new();
        let attributes = vec![AmountAttribute::new((1u64 << 32) + 5, None)];
        let params = SharpParams::new(1 << 32, 1).expect("params");
        assert!(matches!(
            SharpPOSO::new(&mut cli, &attributes, &params),
            Err(Error::OutOfRangeError)
        ));
    }

    #[test]
    fn test_tampered_proof_rejected() {
        let mut cli = CashuTranscript::new();
        let mut mint = CashuTranscript::new();
        let attributes = vec![AmountAttribute::new(3, None), AmountAttribute::new(7, None)];
        let commitments: Vec<GroupElement> = attributes.iter().map(|a| a.commitment()).collect();
        let params = SharpParams::new(1 << 32, attributes.len() as u64).expect("params");
        let mut proof = SharpPOSO::new(&mut cli, &attributes, &params).expect("sharp proof");
        // Flip one bit of one z_x response (keeps the same Scalar type).
        proof.z_x_list[0] += &Scalar::from(1u64);
        assert!(!proof.verify(&mut mint, &commitments, &params));
    }
}
