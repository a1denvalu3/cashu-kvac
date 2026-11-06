use bitcoin::secp256k1::rand::random;
use cashu_kvac::{
    errors::Error,
    kvac::{IssuanceProof, MacProof},
    models::{AmountAttribute, MintPrivateKey, RandomizedCommitments, ScriptAttribute, MAC},
    secp::Scalar,
    transcript::CashuTranscript,
};

fn main() -> Result<(), Error> {
    // Mint: create a keyset. A real mint persists these keys across requests.
    let scalars: [Scalar; 6] = std::array::from_fn(|_| Scalar::random());
    let mint_private_key = MintPrivateKey::from_scalars(&scalars)?;
    let mint_public_key = mint_private_key.public_key;

    // Wallet: retain the attributes and nonce; send only commitments and nonce.
    let amount = AmountAttribute::new(10, None);
    let script = b"example spending condition";
    let script_attribute = ScriptAttribute::new(script, None);
    let nonce = random::<[u8; 32]>();
    let amount_commitment = amount.commitment();
    let script_commitment = Some(script_attribute.commitment());

    // Mint: issue the credential and prove that it uses the advertised keyset.
    let (tag, mac) = MAC::generate(
        &mint_private_key,
        &nonce,
        amount_commitment,
        script_commitment,
    )?;
    let issuance_proof = IssuanceProof::create(
        &mint_private_key,
        tag,
        mac,
        amount_commitment,
        script_commitment,
    );

    // Wallet: verify before accepting and storing the returned tag and MAC.
    assert!(IssuanceProof::verify(
        &mint_public_key,
        tag,
        mac,
        &amount,
        Some(&script_attribute),
        issuance_proof,
    ));

    // Demonstrate two alternative presentations: hidden and revealed script.
    // A real mint accepts at most one spend of this credential's nullifier.
    for reveal_script in [false, true] {
        let mut wallet_transcript = CashuTranscript::new();
        let mut mint_transcript = CashuTranscript::new();
        let randomized = RandomizedCommitments::from_attributes_and_mac(
            &amount,
            Some(&script_attribute),
            tag,
            mac,
            reveal_script,
        )?;
        let proof = MacProof::create(
            &mint_public_key,
            &amount,
            Some(&script_attribute),
            tag,
            &randomized,
            reveal_script,
            &mut wallet_transcript,
        );

        let revealed_script = reveal_script.then_some(script.as_slice());
        assert!(MacProof::verify(
            &mint_private_key,
            &randomized,
            revealed_script,
            proof,
            &mut mint_transcript,
        ));
    }

    println!("Verified issuance and both script presentation modes successfully.");
    Ok(())
}
