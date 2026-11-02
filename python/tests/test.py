from src.kvac import *
import os
from src.transcript import CashuTranscript
from src.models import *
from src.secp import Scalar
import random
import pytest

@pytest.fixture
def transcripts():
    prove_transcript = CashuTranscript()
    verify_transcript = CashuTranscript()
    return prove_transcript, verify_transcript

@pytest.fixture
def mint_privkey():
    sk = [Scalar() for _ in range(6)]
    mint_privkey = MintPrivateKey(*sk)
    return mint_privkey

def test_iparams(transcripts, mint_privkey):   
    
    mint_publickey = (mint_privkey.Cw, mint_privkey.I)
    cli_transcript, mint_transcript = transcripts

    # User creates 1 attribute worth 16
    attribute = AmountAttribute.create(16)

    # Mint verifies: range proof, balance proof and issues a MAC with a proof of mint_publickey. 
    mac = MAC.generate(mint_privkey, os.urandom(32), attribute.Ma)
    proof = prove_iparams(mint_transcript, mint_privkey, mac, attribute.Ma)

    # User verifies mint_publickey for issued attribute
    assert verify_iparams(cli_transcript, mac, mint_publickey, proof, attribute.Ma)

def test_wrong_iparams(transcripts, mint_privkey):
    mint_publickey = (mint_privkey.Cw, mint_privkey.I)
    cli_transcript, mint_transcript = transcripts

    sk = [Scalar() for _ in range(6)]
    different_mint_privkey = MintPrivateKey(*sk)

    # User creates 1 attribute worth 16
    attribute = AmountAttribute.create(16)

    # Mint verifies: range proof, balance proof and issues a MAC with a proof of mint_publickey. 
    mac = MAC.generate(mint_privkey, os.urandom(32), attribute.Ma)
    proof = prove_iparams(mint_transcript, different_mint_privkey, mac, attribute.Ma)

    # User verifies mint_publickey for issued attribute
    assert not verify_iparams(cli_transcript, mac, mint_publickey, proof, attribute.Ma)

def test_mac(transcripts, mint_privkey):
    mint_publickey = (mint_privkey.Cw, mint_privkey.I)
    cli_transcript, mint_transcript = transcripts

    # User creates 1 attribute worth 16
    attribute = AmountAttribute.create(16)

    # Mint generates MAC
    mac = MAC.generate(mint_privkey, os.urandom(32), attribute.Ma)

    # User randomizes commitment and produces proof of MAC for it
    credentials = RandomizedCredentials.create(mac, attribute)
    proof_MAC = prove_MAC(cli_transcript, mint_publickey, credentials, mac, attribute)
    assert verify_MAC(mint_transcript, mint_privkey, credentials, proof_MAC)

def test_different_randomization(transcripts, mint_privkey):
    mint_publickey = (mint_privkey.Cw, mint_privkey.I)
    cli_transcript, mint_transcript = transcripts

    # User creates 1 attribute worth 16
    attribute = AmountAttribute.create(16)

    # Mint generates MAC
    mac = MAC.generate(mint_privkey, os.urandom(32), attribute.Ma)

    # user tries to randomize with another scalar
    k = Scalar()
    U = hash_to_curve(mac.t.to_bytes())
    Ca = k*Gz_attribute + attribute.Ma
    Cs = k*Gz_script + O
    Cx0 = k*X0 + U
    Cx1 = k*X1 + mac.t*U
    Cv = k*Gz_mac + mac.V

    credentials = RandomizedCredentials(Ca=Ca, Cs=Cs, Cx0=Cx0, Cx1=Cx1, Cv=Cv)

    proof_MAC = prove_MAC(cli_transcript, mint_publickey, credentials, mac, attribute)
    assert not verify_MAC(mint_transcript, mint_privkey, credentials, proof_MAC)

def test_balance(transcripts, mint_privkey):
    mint_publickey = (mint_privkey.Cw, mint_privkey.I)
    cli_transcript, mint_transcript = transcripts

    # User creates 1 attribute worth 16
    attribute = AmountAttribute.create(16)

    mac = MAC.generate(mint_privkey, os.urandom(32), attribute.Ma)
    credentials = RandomizedCredentials.create(mac, attribute)
    
    # Compute another credential worth 8
    new_attribute = AmountAttribute.create(8)

    # Prove the balance between randomized commitments and new attributes
    balance_proof = prove_balance(cli_transcript, [attribute], [new_attribute])

    assert verify_balance(mint_transcript,
        [credentials],
        [new_attribute.Ma],
        balance_proof,
        8
    )

def test_wrong_balance(transcripts, mint_privkey):
    mint_publickey = (mint_privkey.Cw, mint_privkey.I)
    cli_transcript, mint_transcript = transcripts

    # User creates 1 attribute worth 16
    attribute = AmountAttribute.create(16)

    mac = MAC.generate(mint_privkey, os.urandom(32), attribute.Ma)
    credentials = RandomizedCredentials.create(mac, attribute)
    
    # Compute another credential worth 8
    new_attribute = AmountAttribute.create(8)

    # Prove the balance between randomized commitments and new attributes
    balance_proof = prove_balance(cli_transcript, [attribute], [new_attribute])

    assert not verify_balance(mint_transcript,
        [credentials],
        [new_attribute.Ma],
        balance_proof,
        7
    )

def test_range(transcripts, mint_privkey):
    mint_publickey = (mint_privkey.Cw, mint_privkey.I)
    cli_transcript, mint_transcript = transcripts

    # User creates 1 attribute worth 16
    attribute = AmountAttribute.create(16)

    range_proof = prove_range(cli_transcript, [attribute])
    assert verify_range(mint_transcript, [attribute.Ma], range_proof)

def test_wrong_range(transcripts, mint_privkey):
    mint_publickey = (mint_privkey.Cw, mint_privkey.I)
    cli_transcript, mint_transcript = transcripts

    attribute = AmountAttribute.create(2**51)

    range_proof = prove_range(cli_transcript, [attribute])
    assert not verify_range(mint_transcript, [attribute.Ma], range_proof)

def test_multiple_range(transcripts):
    cli_transcript, mint_transcript = transcripts

    attributes = [AmountAttribute.create(1), AmountAttribute.create(3), AmountAttribute.create(16)]

    range_proof = prove_range(cli_transcript, attributes)
    assert verify_range(mint_transcript, [att.Ma for att in attributes], range_proof)

def test_bootstrap(transcripts):
    cli_transcript, mint_transcript = transcripts

    bootstrap = AmountAttribute.create(0)
    proof_bootstrap = prove_bootstrap(cli_transcript, bootstrap)
    assert verify_bootstrap(mint_transcript, bootstrap.Ma, proof_bootstrap)

def test_wrong_bootstrap(transcripts):
    cli_transcript, mint_transcript = transcripts

    wrong_bootstrap = AmountAttribute.create(1)
    wrong_proof_bootstrap = prove_bootstrap(cli_transcript, wrong_bootstrap)
    assert not verify_bootstrap(mint_transcript, wrong_bootstrap.Ma, wrong_proof_bootstrap)

def test_script(transcripts, mint_privkey):
    cli_transcript, mint_transcript = transcripts
    amount_attr = AmountAttribute.create(10)
    script = random.randbytes(32)
    script_attr = ScriptAttribute.create(script)
    new_script_attr = [ScriptAttribute.create(script) for _ in range(6)]
    mac = MAC.generate(mint_privkey, os.urandom(32), amount_attr.Ma, script_attr.Ms)
    randomized_creds = RandomizedCredentials.create(mac, amount_attr, script_attr)
    script_proof = prove_script_equality(cli_transcript, [amount_attr], [script_attr], new_script_attr)
    assert verify_script_equality(mint_transcript, [randomized_creds], [att.Ms for att in new_script_attr], script_proof)

def test_wrong_script(transcripts, mint_privkey):
    cli_transcript, mint_transcript = transcripts
    amount_attr = AmountAttribute.create(10)
    script = random.randbytes(32)
    script_attr = ScriptAttribute.create(script)
    new_script_attr = [ScriptAttribute.create(b'\x99') for _ in range(6)]
    mac = MAC.generate(mint_privkey, os.urandom(32), amount_attr.Ma, script_attr.Ms)
    randomized_creds = RandomizedCredentials.create(mac, amount_attr, script_attr)
    script_proof = prove_script_equality(cli_transcript, [amount_attr], [script_attr], new_script_attr)
    assert not verify_script_equality(mint_transcript, [randomized_creds], [att.Ms for att in new_script_attr], script_proof)
