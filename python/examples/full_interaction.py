from kvac import *
import os
from transcript import CashuTranscript
from secp import Scalar
from models import *
from bitcoinlib.scripts import *

# Mint's private/public keys
sk = [Scalar() for _ in range(6)]
mint_privkey = MintPrivateKey(*sk)
mint_pubkey = (mint_privkey.Cw, mint_privkey.I)

# Bitcoin P2PKH
stack = [
    op.op_dup,
    op.op_hash160,
    op.op_pushdata1,
    b"\x14",
    bytes.fromhex("55ae51684c43435da751ac8d2173b2652eb64105"),
    op.op_equalverify,
    op.op_checksig,
]

sigstack = [
    op.op_pushdata1,
    b"\x48",
    bytes.fromhex("3045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a772401"),
    op.op_pushdata1,
    b"\x21",
    bytes.fromhex("03f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31")
]

script = Script(stack)
sigscript = Script(sigstack)

'''
print("\nScript %s" % script)
print("\nSigScript %s" % sigscript)
'''

# Client's transcript
client_tscr = CashuTranscript()

# Mint's transcript
mint_tscr = CashuTranscript()

# Create attributes with 0 value that commit to a script
bootstrap = AmountAttribute.create(0)
script_attr = ScriptAttribute.create(script.as_bytes())
proof_bootstrap = prove_bootstrap(client_tscr, bootstrap)

## SEND(bootstrap.Ma, script_attr.Ms)

# Mint generates MAC after verifying the bootstrap attribute
assert verify_bootstrap(mint_tscr, bootstrap.Ma, proof_bootstrap), (
    "Couldn't verify bootstrap attr"
)
mac_0 = MAC.generate(mint_privkey, os.urandom(32), bootstrap.Ma, script_attr.Ms)
proof_iparams = prove_iparams(mint_tscr, mint_privkey, mac_0, bootstrap.Ma, script_attr.Ms)

## RECEIVE(mac_0, proof_iparams)
assert verify_iparams(client_tscr, mac_0, mint_pubkey, proof_iparams, bootstrap.Ma, script_attr.Ms), (
    "Couldn't verify iparams"
)

# Now we want credentials with some value. Create a new attribute pair:
attr_16 = AmountAttribute.create(16)    # <-- different value attribute
new_script_attr = ScriptAttribute.create(script.as_bytes())  # <-- same script, but differently blinded.

# Prove attr_16 encodes an amount within [0, 2**32-1]
range_proof = prove_range(client_tscr, attr_16)

# Randomize previous credentials
randomized_creds = RandomizedCredentails.create(mac_0, bootstrap, script_attr)

# Prove MAC was generated from mint and binds the attributes
MAC_proof = prove_MAC(client_tscr, mint_pubkey, randomized_creds, mac_0, bootstrap)

# Prove the 𝚫 between bootstrap and attr_16 is in fact 16
balance_proof = prove_balance(client_tscr, [bootstrap], [attr_16])

# Prove the script is the same
script_proof = prove_script_equality(client_tscr, [bootstrap], [script_attr], [new_script_attr])

## SEND(
# randomized_creds,
# attr_16.Ma,
# script_attr.Ms,
# range_proof, balance_proof, script_proof, MAC_proof)

# Mint verifies all of the proofs
assert verify_range(mint_tscr, attr_16.Ma, range_proof), (
    "Couldn't verify range proof"
)
assert verify_MAC(
    mint_tscr,
    mint_privkey,
    randomized_creds,
    MAC_proof
), "Couldn't verify MAC"
delta_amount = -16
assert verify_balance(mint_tscr, [randomized_creds], [attr_16.Ma], balance_proof, delta_amount), (
    f"Couldn't verify balance proof for {delta_amount}"
)
assert verify_script_equality(mint_tscr, [randomized_creds], [new_script_attr.Ms], script_proof), (
    "Couldn't verify script equality"
)

# Then Mint can safely issue new credentials now
mac_16 = MAC.generate(mint_privkey, os.urandom(32), attr_16.Ma, new_script_attr.Ms)
proof_iparams = prove_iparams(mint_tscr, mint_privkey, mac_16, attr_16.Ma, new_script_attr.Ms)

## RECEIVE(mac_16, proof_iparams)
assert verify_iparams(client_tscr, mac_16, mint_pubkey, proof_iparams, attr_16.Ma, new_script_attr.Ms)