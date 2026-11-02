import timeit
import os
import random
from src.kvac import *

# Mint's private/public keys
sk = [Scalar() for _ in range(6)]
mint_privkey = MintPrivateKey(*sk)
mint_pubkey = (mint_privkey.Cw, mint_privkey.I)

# Client's transcript
client_tscr = CashuTranscript()

# Mint's transcript
mint_tscr = CashuTranscript()

bootstrap = AmountAttribute.create(0)
script_attr = ScriptAttribute.create(b"\x00"*32)
mac_0 = MAC.generate(mint_privkey, os.urandom(32), bootstrap.Ma, script_attr.Ms)

attr_16 = AmountAttribute.create(16)
new_script_attr = ScriptAttribute.create(b"\x00"*32)
randomized_creds = RandomizedCredentials.create(mac_0, bootstrap, script_attr)

proof = []

def bench_bootstrap_prove():
    proof.append(prove_bootstrap(client_tscr, bootstrap))

def bench_bootstrap_verify():
    global proof
    assert verify_bootstrap(mint_tscr, bootstrap.Ma, proof[0])
    proof = proof[1:]

def bench_iparams_prove():
    proof.append(prove_iparams(mint_tscr, mint_privkey, mac_0, bootstrap.Ma, script_attr.Ms))

def bench_iparams_verify():
    global proof
    assert verify_iparams(client_tscr, mac_0, mint_pubkey, proof[0], bootstrap.Ma, script_attr.Ms)
    proof = proof[1:]

def bench_range_prove():
    proof.append(prove_range(client_tscr, attr_16))

def bench_range_verify():
    global proof 
    assert verify_range(mint_tscr, attr_16.Ma, proof[0])
    proof = proof[1:]

def bench_mac_prove():
    proof.append(prove_MAC(client_tscr, mint_pubkey, randomized_creds, mac_0, bootstrap))

def bench_mac_verify():
    global proof
    assert verify_MAC(mint_tscr, mint_privkey, randomized_creds, proof[0])
    proof = proof[1:]

def bench_balance_prove():
    proof.append(prove_balance(client_tscr, [bootstrap], [attr_16]))

def bench_balance_verify():
    global proof
    delta_amount = -16
    assert verify_balance(mint_tscr, [randomized_creds], [attr_16.Ma], proof[0], delta_amount)
    proof = proof[1:]

def bench_script_prove():
    proof.append(prove_script_equality(client_tscr, [bootstrap], [script_attr], [new_script_attr]))

def bench_script_verify():
    global proof
    assert verify_script_equality(mint_tscr, [randomized_creds], [new_script_attr.Ms], proof[0])
    proof = proof[1:]

def run_benchmark(func_name, repeat=100, number=1):
    """Runs a benchmark and returns average, min, and max execution times."""
    times = timeit.repeat(f"{func_name}()", globals=globals(), repeat=repeat, number=number)
    tot_time = sum(times)
    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)
    return tot_time, avg_time, min_time, max_time

benchmarks = [
    ("Bootstrap Prove", "bench_bootstrap_prove"),
    ("Bootstrap Verify", "bench_bootstrap_verify"),
    ("Iparams Prove", "bench_iparams_prove"),
    ("Iparams Verify", "bench_iparams_verify"),
    ("Range Prove", "bench_range_prove"),
    ("Range Verify", "bench_range_verify"),
    ("MAC Prove", "bench_mac_prove"),
    ("MAC Verify", "bench_mac_verify"),
    ("Balance Prove", "bench_balance_prove"),
    ("Balance Verify", "bench_balance_verify"),
    ("Script Equality Prove", "bench_script_prove"),
    ("Script Equality Verify", "bench_script_verify")
]

print(f"{'Benchmark':<30}{'Average Time (s)':<20}{'Min Time (s)':<20}{'Max Time (s)':<20}{'Total Time (s)':<20}")
print("=" * 100)
for name, func in benchmarks:
    tot_time, avg, min_time, max_time = run_benchmark(func)
    print(f"{name:<30}{avg:<20.9f}{min_time:<20.9f}{max_time:<20.9f}{tot_time:<20.9f}")
