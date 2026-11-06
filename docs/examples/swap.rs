use bitcoin::secp256k1::rand::random;
use cashu_kvac::{
    errors::Error,
    kvac::{BalanceProof, IssuanceProof, MacProof, RangeProof},
    models::{AmountAttribute, MintPrivateKey, RandomizedCommitments, MAC},
    secp::{GroupElement, Scalar},
    transcript::CashuTranscript,
};

fn main() -> Result<(), Error> {
    let scalars: [Scalar; 6] = std::array::from_fn(|_| Scalar::random());
    let mint_private_key = MintPrivateKey::from_scalars(&scalars)?;
    let mint_public_key = mint_private_key.public_key;
    let inputs = [
        AmountAttribute::new(12, None),
        AmountAttribute::new(11, None),
    ];
    let outputs = [AmountAttribute::new(23, None)];
    let input_nonces: [[u8; 32]; 2] = std::array::from_fn(|_| random());
    let mut wallet_transcript = CashuTranscript::new();
    let mut mint_transcript = CashuTranscript::new();
    let mut randomized_inputs = Vec::new();
    let mut mac_proofs = Vec::new();

    for (input, nonce) in inputs.iter().zip(&input_nonces) {
        // Setup: obtain and verify the input credentials before using them.
        let (tag, mac) = MAC::generate(&mint_private_key, nonce, input.commitment(), None)?;
        let issuance_proof =
            IssuanceProof::create(&mint_private_key, tag, mac, input.commitment(), None);
        assert!(IssuanceProof::verify(
            &mint_public_key,
            tag,
            mac,
            input,
            None,
            issuance_proof,
        ));

        // Wallet: randomize each input and prove possession of its actual issued tag.
        let randomized =
            RandomizedCommitments::from_attributes_and_mac(input, None, tag, mac, false)?;
        let proof = MacProof::create(
            &mint_public_key,
            input,
            None,
            tag,
            &randomized,
            false,
            &mut wallet_transcript,
        );
        randomized_inputs.push(randomized);
        mac_proofs.push(proof);
    }

    // Wallet: prove conservation of value and that the output amount fits in 32 bits.
    let balance_proof = BalanceProof::create(&inputs, &outputs, &mut wallet_transcript);
    let range_proof = RangeProof::create_bulletproof(&mut wallet_transcript, &outputs);
    let output_commitments: Vec<GroupElement> =
        outputs.iter().map(AmountAttribute::commitment).collect();

    // Mint: verify in the same order used by the wallet's transcript.
    for (randomized, proof) in randomized_inputs.iter().zip(mac_proofs) {
        assert!(MacProof::verify(
            &mint_private_key,
            randomized,
            None,
            proof,
            &mut mint_transcript,
        ));
    }
    let delta_amount = 0; // Total inputs (12 + 11) minus total outputs (23).
    assert!(BalanceProof::verify(
        &randomized_inputs,
        &output_commitments,
        delta_amount,
        balance_proof,
        &mut mint_transcript,
    ));
    assert!(RangeProof::verify(
        &mut mint_transcript,
        &output_commitments,
        range_proof,
    ));

    // In a real swap, the mint also checks and atomically records input nullifiers
    // together with issuance of the outputs. This example has no persistent state.
    let output = &outputs[0];
    let output_nonce = random::<[u8; 32]>();
    let (tag, mac) = MAC::generate(&mint_private_key, &output_nonce, output.commitment(), None)?;
    let issuance_proof =
        IssuanceProof::create(&mint_private_key, tag, mac, output.commitment(), None);

    // Wallet: verify the newly issued output before storing it with its nonce.
    assert!(IssuanceProof::verify(
        &mint_public_key,
        tag,
        mac,
        output,
        None,
        issuance_proof,
    ));

    println!("Verified a swap from 12 + 11 to 23 successfully.");
    Ok(())
}
