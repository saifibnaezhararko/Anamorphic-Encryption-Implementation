pip install pycryptodome
import random
from Crypto.Cipher import AES

#This if public Parameters
class PublicParams:
    def __init__(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g

#this is anamorphic Parameters
class AnamParams:
    def __init__(self, l, s, t):
        self.F = lambda pp, K, x, y: \
            int.from_bytes(AES.new(K, AES.MODE_ECB) \
            .encrypt(x.to_bytes(8, 'little') + y.to_bytes(8, 'little')), "little") % pp.p
        self.d = lambda ap, x: x % ap.t
        self.l = l
        self.s = s
        self.t = t

#key Pair for ElGamal
class KeyPair:
    def __init__(self, sk, pk):
        self.sk = sk
        self.pk = pk

#double Key for anamorphic encryption
class DoubleKey:
    def __init__(self, K, T, pk):
        self.K = K
        self.T = T
        self.pk = pk

# standard ElGamal key generation
def Gen(pp):
    sk = random.randint(0, pp.q - 1)
    pk = pow(pp.g, sk, pp.p)
    return KeyPair(sk, pk)

#standard ElGamal encryption
def Enc(pp, pk, msg):
    r = random.randint(0, pp.q - 1)
    c0 = (msg * pow(pk, r, pp.p)) % pp.p
    c1 = pow(pp.g, r, pp.p)
    return c0, c1

#standard ElGamal decryption
def Dec(pp, sk, c):
    return (c[0] * pow(c[1], -sk, pp.p)) % pp.p

#anamorphic key generation
def aGen(pp, ap, pk):
    K = random.randbytes(16)
    T = dict()
    for i in range(ap.l):
        T[pow(pp.g, i, pp.p)] = i
    return DoubleKey(K, T, pk)

# anamorphic encryption with counter
def aEncCtr(pp, ap, dk, msg, cm, ctr):
    found = False
    for x in range(ctr[0], ap.s):
        for y in range(ctr[1], ap.t):
            t = ap.F(pp, dk.K, x, y)
            r = (cm + t) % pp.q
            if ap.d(ap, pow(pp.g, r, pp.p)) == y:
                found = True
                break
        if found:
            break
    ctr[1] = 0
    ctr[0] = (x + (1 if y == ap.t - 1 else 0)) % ap.s
    ctr[1] = (y + 1) % ap.t
    c0 = (msg * pow(dk.pk, r, pp.p)) % pp.p
    c1 = pow(pp.g, r, pp.p)
    ctx = (c0, c1)
    return ctx, ctr

#anamorphic encyption
def aEnc(pp, ap, dk, msg, cm):
    while True:
        x = random.randint(0, ap.s - 1)
        y = random.randint(0, ap.t - 1)
        t = ap.F(pp, dk.K, x, y)
        r = (cm + t) % pp.q
        if ap.d(ap, pow(pp.g, r, pp.p)) == y:
            break
    c0 = (msg * pow(dk.pk, r, pp.p)) % pp.p
    c1 = pow(pp.g, r, pp.p)
    return (c0, c1)

#anamorphic decryption
def aDec(pp, ap, dk, ctx):
    y = ap.d(ap, ctx[1])
    for x in range(ap.s):
        t = ap.F(pp, dk.K, x, y)
        s = (ctx[1] * pow(pp.g, -t, pp.p)) % pp.p
        if s in dk.T:
            return dk.T[s]
    return -1

# -----------------------------------
# THis is the test script
# -----------------------------------

if __name__ == "__main__":
    runs = 5  
    p, g = 1000000007, 5
    q = p - 1
    pp = PublicParams(p, q, g)

    l = 100
    s = 100
    t = 100
    ap = AnamParams(l, s, t)

    kp = Gen(pp)
    dk = aGen(pp, ap, kp.pk)


    print("Public Parameters:")
    print(f"p = {pp.p}\nq = {pp.q}\ng = {pp.g}")
    print("\nKeys:")
    print(f"(sk, pk) = ({kp.sk}, {kp.pk})")
    print(f"Secret Key K = {dk.K.hex()}")

    print("\n--- Testing aEnc -> Dec and aEnc -> aDec ---")
    for _ in range(runs):
        msg = random.randint(1, pp.p - 1)
        cm = random.randint(0, l - 1)
        ctx = aEnc(pp, ap, dk, msg, cm)
        msg_ = Dec(pp, kp.sk, ctx)
        cm_ = aDec(pp, ap, dk, ctx)
        print(f"msg={msg}, cm={cm} -> aEnc -> ctx={ctx} -> Dec -> msg_={msg_}, aDec -> cm_={cm_}")

    print("\n--- Testing Enc -> Dec and Enc -> aDec ---")
    for _ in range(runs):
        m = random.randint(1, pp.p - 1)
        ctx = Enc(pp, kp.pk, m)
        msg_ = Dec(pp, kp.sk, ctx)
        cm_ = aDec(pp, ap, dk, ctx)
        print(f"m={m} -> Enc -> ctx={ctx} -> Dec -> msg_={msg_}, aDec -> cm_={cm_} {'(!)' if cm_ != -1 else ''}")
