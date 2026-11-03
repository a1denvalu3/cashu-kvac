//! Helper to recover the amount from a list of `GroupElement` pedersen commitments

use std::collections::HashMap;

use crate::{
    generators::GENERATORS,
    secp::{GroupElement, Scalar},
};

/// Recover the amounts encoded in a list of Pedersen commitments using the Baby-step giant-step algorithm.
///
/// This function takes a list of `GroupElement` commitments and their corresponding blinding factors,
/// and attempts to recover the original amounts that were committed. The recovery process is based on
/// the Baby-step giant-step algorithm, which is an efficient method for solving the discrete logarithm
/// problem in a group. The algorithm works by precomputing a table of values to speed up the search
/// for the original amounts.
///
/// # Arguments
///
/// * `commitments` - A slice of `GroupElement` representing the Pedersen commitments from which the
///   amounts are to be recovered.
/// * `blinding_factors` - A slice of `Scalar` representing the blinding factors corresponding to each
///   commitment. These factors are used to unblind the commitments to retrieve the original amounts.
/// * `hypothesized_max_amount` - A `u64` value that serves as an upper bound for the amounts. This value
///   is used to determine the size of the precomputed table and limits the range of possible amounts
///   that can be recovered.
///
/// # Returns
///
/// A `Vec<Option<u64>>` where each element corresponds to the recovered amount for each commitment. If
/// an amount could not be recovered, the corresponding entry will be `None`. Otherwise, it will contain
/// the recovered amount as a `u64`.
///
/// # References
///
/// For more information on the Baby-step giant-step algorithm, see:
/// [Wikipedia: Baby-step giant-step algorithm](https://en.wikipedia.org/wiki/Baby-step_giant-step)
#[allow(non_snake_case)]
pub fn recover_amounts(
    commitments: &[GroupElement],
    blinding_factors: &[Scalar],
    hypothesized_max_amount: u64,
) -> Vec<Option<u64>> {
    let B = hypothesized_max_amount;
    let m = (B as f64).sqrt().ceil() as u64;

    let scalar_m = Scalar::from(m);
    let G_m_inv = -GENERATORS.G_amount * &scalar_m;

    // Build table
    let mut table = HashMap::new();
    let mut index = GENERATORS.G_blind;
    table.insert(index, 0);

    let one = GENERATORS.G_amount;

    for j in 1..m {
        index += &one;
        table.insert(index, j);
    }

    let mut recovered_amounts = Vec::<Option<u64>>::new();
    // Process commitments
    for (Ma, r_a) in commitments.iter().zip(blinding_factors.iter()) {
        // Unblind the amount commitment
        let mut A = GENERATORS.G_blind * &(Scalar::from(1) - r_a) + Ma;

        let mut a = None;
        // Look for a match on the table
        for i in 0..m {
            match table.get(&A) {
                Some(j) => {
                    a = Some(i * m + j);
                    break;
                }
                None => A += &G_m_inv,
            }
        }

        recovered_amounts.push(a);
    }

    recovered_amounts
}

#[cfg(test)]
mod tests {
    use crate::{
        models::AmountAttribute,
        secp::{GroupElement, Scalar},
    };

    use super::recover_amounts;

    #[test]
    fn test_recovery_amounts() {
        // Say we have the blinding factors from a derivation path and index
        let blinding_factors: Vec<Scalar> = (0..3).map(|_| Scalar::random()).collect();

        // Suppose we have the amount commitments (recovered from the Mint)
        let amount_attributes = [
            AmountAttribute::new(19, Some(&blinding_factors[0].to_bytes())),
            AmountAttribute::new(763, Some(&blinding_factors[1].to_bytes())),
            AmountAttribute::new(22001, Some(&blinding_factors[2].to_bytes())),
        ];
        let amount_commitments: Vec<GroupElement> = amount_attributes
            .iter()
            .map(|attr| attr.commitment())
            .collect();

        // We know or hypothesize that the amount must have been within a certain upper bound
        let upper_bound = 100_000_u64;

        // Recover the amounts encoded in those commitments, given the blinding factors
        let recovered_amounts =
            recover_amounts(&amount_commitments, &blinding_factors, upper_bound);

        let recovered_amounts: Vec<u64> = recovered_amounts
            .iter()
            .map(|recovered_amount| recovered_amount.expect("amount is within 100000"))
            .collect();

        assert!(recovered_amounts[0] == 19);
        assert!(recovered_amounts[1] == 763);
        assert!(recovered_amounts[2] == 22001);
    }

    #[test]
    fn test_recovery_amounts_with_one_failure() {
        // Say we have the blinding factors from a derivation path and index
        let blinding_factors: Vec<Scalar> = (0..3).map(|_| Scalar::random()).collect();

        // Suppose we have the amount commitments (recovered from the Mint)
        let amount_attributes = [
            AmountAttribute::new(1997, Some(&blinding_factors[0].to_bytes())),
            AmountAttribute::new(110224, Some(&blinding_factors[1].to_bytes())),
            AmountAttribute::new(22001, Some(&blinding_factors[2].to_bytes())),
        ];
        let amount_commitments: Vec<GroupElement> = amount_attributes
            .iter()
            .map(|attr| attr.commitment())
            .collect();

        // We know or hypothesize that the amount must have been within a certain upper bound
        let upper_bound = 100_000_u64;

        // Recover the amounts encoded in those commitments, given the blinding factors
        let recovered_amounts =
            recover_amounts(&amount_commitments, &blinding_factors, upper_bound);

        assert!(recovered_amounts[0].expect("amount is recovered") == 1997);
        assert!(recovered_amounts[1].is_none());
        assert!(recovered_amounts[2].expect("amount is recovered") == 22001);
    }
}
