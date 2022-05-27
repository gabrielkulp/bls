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


import sys
import time
if __name__ == "__main__":
    delay = 10
    oneshot = True
    if len(sys.argv) == 2:
        delay = float(sys.argv[1])
        oneshot = False

    groupObj = PairingGroup('MNT224')
    
    messages = [b"hello world!!!", b"test message", b"third one"]

    bls = BLSTHS(groupObj)
    
    n, t = 10, 7
    (pk, shares) = bls.keygen(n, t)

    sig_count = 0
    time_end = 0
    time_start = time.time()
    cont = True
    while cont:
        signs = []
        for m in messages:
            for i in range(t+1):
                psign = bls.sign(shares[i], m)
                signs.append((i+1, psign))

            sig = bls.aggregate(signs)
            
            if oneshot:
                print("Message: '%s'" % m)
                print("Signature: '%s'" % sig)     
            if bls.verify(pk, sig, m):
                sig_count += 1
                if oneshot:
                    print("success!")
                    exit(0)
            elif oneshot:
                print("failure!")
                exit(1)
            time_end = time.time()
            if time_end-time_start > delay:
                cont = False
                break
    
    print(f"Completed {sig_count} in {round(time_end-time_start, 2)} seconds")
    print(f"Average is {round(sig_count/(time_end-time_start), 2)} signatures per second")            
