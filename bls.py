#!/usr/bin/env python3
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

import sys
import socket
import asyncio

PORT = 5005
REQUESTER_ADDR = ("10.0.0.254", PORT)

debug = False


class BLSTHS(IBSig):
    """
    >>> from charm.toolbox.pairinggroup import PairingGroup
    >>> group = PairingGroup('MNT224')
    >>> messages = { 'a':"hello world!!!" , 'b':"test message" }
    >>> ib = BLS01(group)
    >>> (public_key, secret_key) = ib.keygen()
    >>> signature = ib.sign(secret_key['x'], messages)
    >>> ib.verify(public_key, signature, messages)
    True
    """
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


class ResponderServer:
    def __init__(self, bls, share):
        self.bls = bls
        self.share = share

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        idx = data[0]
        m = data[1:]
        psign = self.bls.sign(self.share, m)
        res = idx.to_bytes(1, "big") + psign
        self.transport.sendto(psign, res)


class InitiatorServer:
    def __init__(self, bls, sock, n, t, pk, ms):
        self.bls = bls
        self.sock = sock
        self.n = n
        self.t = t
        self.pk = pk
        self.ms = ms

        self.idx = -1
        self.m = None
        self.signs = []
        self.initiate_new()  # kickstart the whole process

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        (ip, _) = addr
        res_idx = int(ip.split('.')[-1]) - 2
        req_idx = data[0]
        share = data[1:]

        if req_idx == self.idx:
            self.signs.append((res_idx+1, share))

        if len(self.signs) == self.threshold:
            self.aggregate_and_verify()
            self.initiate_new()

    def aggregate_and_verify(self):
        sig = self.bls.aggregate(self.signs)
        print("Message: '%s'" % self.m)
        print("Signature: '%s'" % sig)
        assert self.bls.verify(self.pk, sig, self.m), "Failure!!!"

    def initiate_new(self):
        self.idx += 1
        self.idx %= 256
        self.idx %= len(self.ms)
        self.m = self.ms[self.idx]

        # send requests to all responders
        for i in range(self.n):
            msg = self.idx.to_bytes(1, "big") + self.m
            self.sock.sendto(msg, (f"10.0.0.{i+2}", PORT))


def main():
    server = None
    groupObj = PairingGroup('MNT224')
    bls = BLSTHS(groupObj)

    messages = ["hello world!!!", "test message", "third one"]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    if len(sys.argv) == 1:  # responder
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        (share_raw, _) = sock.recvfrom(1024)  # get share from initiator
        share = PairingGroup.deserialize(share_raw)
        sock.sendto(b'1', REQUESTER_ADDR)  # reply with ack
        loop.create_datagram_endpoint(
            lambda: ResponderServer(bls, sock, share),
            local_addr=('0.0.0.0', PORT))

    else:  # initiator
        if len(sys.argv) != 3:
            print("Must specify number and threshold")
            exit(1)
        n = int(sys.argv[1])
        t = int(sys.argv[2])

        (pk, shares) = bls.keygen(n, t)
        loop.create_datagram_endpoint(
            lambda: InitiatorServer(bls, sock, n, t, pk, messages),
            local_addr=('0.0.0.0', PORT))

        # send shares to all responders
        responders = []
        for i in range(n):
            ip = f"10.0.0.{i+2}"
            responders.append(ip)
            share_raw = PairingGroup.serialize(shares[i])
            sock.sendto(share_raw, (ip, PORT))

        # wait for ack
        for i in range(n):
            (_, (ip, _)) = sock.recvfrom(1024)
            responders.remove(ip)

        if len(responders) != 0:
            print("Handshake failed", responders)
            exit(1)

    loop.create_datagram_endpoint(server, local_addr=('0.0.0.0', 5000))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    debug = True
    main()
