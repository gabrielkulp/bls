'''
:Boneh-Lynn-Shacham Identity Based Signature

| From: "D. Boneh, B. Lynn, H. Shacham Short Signatures from the Weil Pairing"
| Published in: Journal of Cryptology 2004
| Available from: http://
| Notes: This is the IBE (2-level HIBE) implementation of the HIBE scheme BB_2.

* type:           signature (identity-based)
* setting:        bilinear groups (asymmetric)

:Authors:    J. Ayo Akinyele
:Date:       1/2011
 '''
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from charm.core.engine.util import objectToBytes
from charm.toolbox.IBSig import IBSig

debug = False


class BLSTHS(IBSig):
    def __init__(self, groupObj):
        IBSig.__init__(self)
        global group
        group = groupObj

    def dump(self, obj):
        return objectToBytes(obj, group)

    def poly_eval(self, coeffs, point):
        eval = coeffs[0]
        deg = len(coeffs)-1

        temp = point
        for i in range(1, deg+1):
            eval = eval + temp*coeffs[i]
            temp = temp*point
        return eval

    def gen_shares(self, N, t, g, secret):
        coeffs = [None]*(t+1)
        coeffs[0] = secret
        for i in range(t):
            coeffs[i+1] = group.random(ZR)

        shares = [None]*N
        for i in range(N):
            shares[i] = self.poly_eval(coeffs, group.init(ZR, i+1))

        return shares

    def keygen(self, N, t, secparam=None):
        g, x = group.random(G2), group.random()
        g_x = g ** x
        pk = {'g^x': g_x, 'g': g, 'identity': str(g_x), 'secparam': secparam}
        shares = self.gen_shares(N, t, g, x)
        return (pk, shares)

    def sign(self, sk, message):
        M = self.dump(message)
        if debug:
            print("Message => '%s'" % M)
        return group.hash(M, G1) ** sk

    def verify(self, pk, sig, message):
        M = self.dump(message)
        h = group.hash(M, G1)
        if pair(sig, pk['g']) == pair(h, pk['g^x']):
            return True
        return False

    def aggregate(self, shares):
        sign = group.init(G1, 1)
        for (idx, data) in shares:
            cidx = group.init(ZR, 1)
            for iidx, _ in shares:
                if idx != iidx:
                    gi = (group.init(ZR, iidx) - group.init(ZR, idx))
                    cidx = cidx*group.init(ZR, iidx) * gi.__invert__()
            sign = sign*(data**cidx)
        return sign


if __name__ == "__main__":
    groupObj = PairingGroup('MNT224')
    
    m = { 'a':"hello world!!!" , 'b':"test message" }
    bls = BLSTHS(groupObj)
    
    n, t = 24, 18
    (pk, shares) = bls.keygen(n, t)
    
    signs = []
    for i in range(t+1):
        psign = bls.sign(shares[i], m)
        signs.append((i+1, psign))

    sig = bls.aggregate(signs)
    
    print("Message: '%s'" % m)
    print("Signature: '%s'" % sig)     
    if bls.verify(pk, sig, m):
        print('SUCCESS!!!')
    else:
        print("Failure!!!")
