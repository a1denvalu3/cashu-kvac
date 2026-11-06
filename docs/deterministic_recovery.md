# Deterministic recovery of Amount Attributes

### Normal execution:

During a normal swap/mint/melt operation, each requested output carries a fresh
per-request nonce $\rho^i$ (unguessable, e.g. 32 random bytes). The Mint derives
the output's tag statelessly as $t^i = \text{HMAC-SHA2}(\text{SHA256}(sk),\
\text{"cashu-kvac-tag-v1"} \,\|\, \rho^i \,\|\, M_a^i \,\|\, M_s^i)$. The wallet
stores $(\rho^i, r_a^i)$ with each coin (or derives $\rho^i$ from its own seed,
e.g. $\rho^i \leftarrow \text{HMAC-SHA2}(\text{seed}, \text{"rho"}, i)$, to keep the
per-coin state seed-only). After the request is successful, the Mint stores the
attributes in the outputs of the request $(M_a^i, t^i)$ in its database.

### Recovery:

Recovery works as follows:

* For each possible output $i$ the client derives its blinding factor $r_a^i$ and its
  nonce $\rho^i$, then recomputes the tag $t^i$ with the Mint (the Mint re-evaluates
  the HMAC over $(\rho^i, M_a^i, M_s^i)$; the round trip is needed because the HMAC
  key is Mint-side, which is what made wallet-chosen tags safe to remove).

* The Client then requests the server (Mint) for the $M_a^i$ associated with each $t^i$

* Once obtained the attributes, the client unblinds them: $A^i = M_a^i - r_a^i\cdot G_\text{blind}$.

* Now $A = a\cdot G_\text{amount}$ with $a \in [0, B]$.

$B$ is smaller or equal to the largest amount that the wallet ever contained. So for example $B < 100000 \ \text{sats}$.

At this point all the client has to do to find the correct amount is attack the DL. This is extremely easy since $B$ is so small. In the case of $B < 100000$, it's doable with less than $316$ iterations of the [Baby-Step-Giant-Step algorithm](https://en.wikipedia.org/wiki/Baby-step_giant-step).

Here follows an example implementation:
```python
from sympy.ntheory import nextprime
from random import getrandbits
from math import sqrt, ceil

p = nextprime(getrandbits(256))
print(f"{p = }")

# Amount to find
a = 1097

# Generator (G_amount)
g = 2

# Unblinded amount commitment
A = pow(g, a, p)

# Bound on the amounts
B = 100000

m = ceil(sqrt(B))
g_m_inv = pow(g, -m, p)

table = {}
iterations = 0
for j in range(m):
    iterations += 1
    index = pow(g, j, p)
    table[index] = j

x = -1
V = A
for i in range(m):
    iterations += 1
    if V in table:
        x = i*m + table[V]
        break
    else:
        V *= g_m_inv
        V %= p

print(f"{x = }")
print(f"{iterations = }")
```

### Recovery Spent Checks:

As with normal ecash, the client will later have to requestsep arate "nullifier state check" to the Mint in order to determine the spendability of each output they just recovered. This has privacy compromising implications