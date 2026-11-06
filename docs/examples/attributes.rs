use cashu_kvac::{
    models::{AmountAttribute, ScriptAttribute},
    secp::Scalar,
};

fn main() {
    let script = b"example spending condition";

    // Omitting the blinding factor generates a fresh random scalar.
    let amount = AmountAttribute::new(10, None);
    let script_attribute = ScriptAttribute::new(script, None);
    let _amount_commitment = amount.commitment();
    let _script_commitment = script_attribute.commitment();

    // Explicit factors must be valid scalars encoded as 32 big-endian bytes.
    // A wallet can also derive these from its seed instead of generating them here.
    let amount_blinding_factor: [u8; 32] = (&Scalar::random()).into();
    let script_blinding_factor: [u8; 32] = (&Scalar::random()).into();
    let amount = AmountAttribute::new(10, Some(&amount_blinding_factor));
    let script_attribute = ScriptAttribute::new(script, Some(&script_blinding_factor));

    // Keeping the factors lets the wallet reconstruct the same attributes.
    assert_eq!(
        amount,
        AmountAttribute::new(10, Some(&amount_blinding_factor))
    );
    assert_eq!(
        script_attribute,
        ScriptAttribute::new(script, Some(&script_blinding_factor))
    );

    println!("Created commitments and reconstructed attributes successfully.");
}
