import hashlib
import hmac
from .secp import GroupElement, Scalar
from typing import List, Optional, Dict, Tuple
from .generators import *

from dataclasses import dataclass

RANGE_LIMIT = 1 << 51

@dataclass
class MintPrivateKey:
    w: Scalar
    w_: Scalar
    x0: Scalar
    x1: Scalar
    ya: Scalar
    ys: Scalar

    @property
    def sk(self):
        return [
            self.w,
            self.w_,
            self.x0,
            self.x1,
            self.ya,
            self.ys,
        ]

    @property
    def Cw(self):
        return W*self.w + W_*self.w_

    @property
    def I(self):
        return Gz_mac - (
            X0*self.x0
            + X1*self.x1
            + Gz_attribute*self.ya  # amount
            + Gz_script*self.ys     # script
        )

@dataclass
class ZKP:
    s: List[bytes]
    c: bytes

@dataclass
class ScriptAttribute:
    r: Optional[Scalar] = None
    s: Optional[Scalar] = None

    _Ms: Optional[GroupElement] = None

    @classmethod
    def create(
        cls,
        script: bytes,
        blinding_factor: Optional[bytes] = None,
    ):
        """
        Creates a script attribute that encodes the hash of a given script.

        This function takes as input an array of bytes and returns an attribute.

        Parameters:
            script (bytes): The script
            blinding_factor (Optional[bytes]): Optionally a blinding_factor derived from a BIP32 derivation path

        Returns:
            ScriptAttribute: The created attribute.
        """        
        s = Scalar(hashlib.sha256(script).digest())
        r = (
            Scalar(blinding_factor) if blinding_factor
            else Scalar()
        )

        return cls(r, s)
    
    @property
    def Ms(self):
        assert self.r and self.s
        if not self._Ms:
            self._Ms = self.r * G_blind + self.s * G_script
        return self._Ms

    @property
    def serial(self) -> GroupElement:
        assert self.r, "Serial preimage unknown"
        return self.r * G_serial

@dataclass
class AmountAttribute:
    r: Optional[Scalar] = None
    a: Optional[Scalar] = None

    _Ma: Optional[GroupElement] = None

    @classmethod
    def create(
        cls,
        amount: int,
        blinding_factor: Optional[bytes] = None,
    ):
        """
        Creates an attribute worth the given amount.

        This function takes as input an amount and returns an attribute that represents the given amount.

        Parameters:
            amount (int): The amount
            blinding_factor (Optional[bytes]): Optionally a blinding_factor derived from a BIP32 derivation path

        Returns:
            AmountAttribute: The created attribute.
        """
        
        a = Scalar(amount.to_bytes(32, 'big'))
        r = (
            Scalar(blinding_factor) if blinding_factor
            else Scalar()
        )

        return cls(r, a)
    
    @property
    def Ma(self):
        assert self.r and self.a
        if not self._Ma:
            self._Ma = self.r * G_blind + self.a * G_amount
        return self._Ma

    @classmethod
    def tweak_amount(cls, Ma: GroupElement, delta: int) -> GroupElement:
        d = Scalar(abs(delta).to_bytes(32, 'big'))
        D = d * G_amount if delta >= 0 else -d * G_amount
        return Ma+D

@dataclass
class MAC:
    t: Scalar
    V: GroupElement

    @classmethod
    def generate(
        cls,
        privkey: MintPrivateKey,
        nonce: bytes,
        attribute: GroupElement,
        script: Optional[GroupElement] = None,
    ):
        """
        Issue a MAC for the given amount/script commitments.

        The tag is *derived by the Mint* as
            t = HMAC-SHA256(key = SHA256(sk), msg = "cashu-kvac-tag-v1" || nonce || Ma || Ms)
        so every distinct issuance yields a distinct tag statelessly, and the
        wallet can no longer pick a tag it has already seen issued. Repeating an
        issuance requires repeating ``nonce``; that deterministically reproduces
        the same tag/MAC pair, so the affine-combination forgery over two
        distinct (t, V) MACs on related commitments is impossible.

        Parameters:
            privkey (MintPrivateKey): The mint's secret parameters.
            nonce (bytes): A per-request nonce chosen by the wallet.
            attribute (GroupElement): The amount attribute.
            script (Optional[GroupElement]): The optional script commitment.

        Returns:
            MAC: The generated MAC (tag, V).
        """
        sk = privkey.sk
        sk_bytes = b"".join(int(x).to_bytes(32, "big") for x in sk)
        tag_key = hashlib.sha256(sk_bytes).digest()
        Ma = attribute
        Ms = script if script else O
        msg = b"cashu-kvac-tag-v1" + nonce + Ma.serialize(True) + Ms.serialize(True)
        t = Scalar(hmac.new(tag_key, msg, hashlib.sha256).digest())
        U = hash_to_curve(t.to_bytes())
        V = (
            sk[0] * W
            + sk[2] * U
            + sk[3] * t * U
            + sk[4] * Ma
            + sk[5] * Ms
        )
        return cls(t=t, V=V)

@dataclass
class RandomizedCredentials:
    Ca: GroupElement
    Cs: GroupElement
    Cx0: GroupElement
    Cx1: GroupElement
    Cv: GroupElement

    @classmethod
    def create(cls,
        mac: MAC,
        amount_attribute: AmountAttribute,
        script_attribute: Optional[ScriptAttribute] = None,
        reveal_script: bool = False,
    ) -> "RandomizedCredentials":
        """
        Produces randomized commitments for the given attribute and MAC.

        This function takes as input an attribute and a MAC, and returns a randomized commitment set.

        Parameters:
            mac (MAC): The MAC. 
            attribute (AmountAttribute): The amount attribute.
            script (Optional[ScriptAttribute], optional): The optional script attribute (use if you don't want to reveal the script)
            reveal_script (bool, optional): If True, only randomize blinding factor for the script commitment. Defaults to False

        Returns:
            RandomizedCredentials: The randomized commitment set.
        """
        t = mac.t
        V = mac.V
        Ma = amount_attribute.Ma
        Ms = O
        if script_attribute:
            if reveal_script:
                # Mint will be able to open `s` so we only randomize the r*G_blind part
                Ms = script_attribute.r*G_blind
            else:
                Ms = script_attribute.Ms

        U = hash_to_curve(t.to_bytes())
        r = amount_attribute.r  

        Ca = r*Gz_attribute + Ma
        Cs = r*Gz_script + Ms
        Cx0 = r*X0 + U
        Cx1 = r*X1 + t*U
        Cv = r*Gz_mac + V

        return cls(Ca=Ca, Cs=Cs, Cx0=Cx0, Cx1=Cx1, Cv=Cv)

@dataclass
class Equation:
    value: Optional[GroupElement]
    construction: List[List[GroupElement]]

@dataclass
class Statement:
    domain_separator: bytes
    equations: List[Equation]

@dataclass
class RangeZKP(ZKP):
    B: List[GroupElement]