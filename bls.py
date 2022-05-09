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
import time

PORT_SIGN = 5005  # port for signature requests
PORT_SHARE = 5006  # port for sending shares
REQUESTER_ADDR = ("10.0.0.254", PORT_SIGN)

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
    def __init__(self, go, bls):
        self.go = go
        self.bls = bls

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", PORT_SHARE))
        print("sending share request")
        sock.sendto(b'\xff', REQUESTER_ADDR)
        (data, _) = sock.recvfrom(1024)
        self.share = go.deserialize(data)
        sock.close()
        print("got my share")

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        idx = data[0]
        m = data[1:]
        psign = self.bls.sign(self.share, m)
        res = idx.to_bytes(1, "big") + self.go.serialize(psign)
        time.sleep(1)
        self.transport.sendto(res, addr)
        print("sent signature")


class InitiatorServer:
    def __init__(self, go, bls, all_shares, n, t, pk, ms):
        self.go = go
        self.bls = bls
        self.all_shares = all_shares
        self.n = n
        self.t = t
        self.pk = pk
        self.ms = ms

        self.seq = -1
        self.m = None
        self.signs = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.sock.bind(("0.0.0.0", PORT_SHARE))
        self.initiate_new()  # kickstart the whole process

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        (ip, _) = addr

        res_idx = int(ip.split('.')[-1]) - 2

        if data == b'\xff':
            # this is actually a request for a share
            print("got share request")
            res = self.go.serialize(self.all_shares[res_idx])
            self.transport.sendto(res, (ip, PORT_SHARE))
            print("sent share")
            return

        if data == b'\xfe':
            # this is actually a request to start over
            self.initiate_new()
            return

        seq = data[0]
        share = self.go.deserialize(data[1:])

        if seq == self.seq:
            print("got signature from", res_idx)
            self.signs.append((res_idx+1, share))
        else:
            print("sequence number mismatch. Expected", self.seq, "got", seq)

        if len(self.signs) >= self.t:
            self.aggregate_and_verify()
            self.initiate_new()

    def aggregate_and_verify(self):
        sig = self.bls.aggregate(self.signs)
        print("Message: '%s'" % self.m)
        print("Signature: '%s'" % sig)
        assert self.bls.verify(self.pk, sig, self.m), "Failure!!!"

    def initiate_new(self):
        if len(self.signs) < self.t:
            print("aborted", self.seq)
        self.seq += 1
        self.seq %= 0xff-2
        self.seq %= len(self.ms)
        self.m = self.ms[self.seq]

        # send requests to all responders
        self.signs = []
        time.sleep(1)
        for i in range(self.n):
            msg = self.seq.to_bytes(1, "big") + self.m
            self.sock.sendto(msg, (f"10.0.0.{i+2}", PORT_SIGN))


def main():
    server = None
    groupObj = PairingGroup('MNT224')
    bls = BLSTHS(groupObj)

    messages = [b"hello world!!!", b"test message", b"third one"]
    print("socket bound")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    server = None

    if len(sys.argv) == 1:  # responder
        server = loop.create_datagram_endpoint(
            lambda: ResponderServer(groupObj, bls),
            local_addr=('0.0.0.0', PORT_SIGN))
        time.sleep(2)

    else:  # initiator
        if len(sys.argv) != 3:
            print("Must specify number and threshold")
            exit(1)
        n = int(sys.argv[1])
        t = int(sys.argv[2])

        (pk, shares) = bls.keygen(n, t)
        server = loop.create_datagram_endpoint(
            lambda: InitiatorServer(groupObj, bls, shares, n, t, pk, messages),
            local_addr=('0.0.0.0', PORT_SIGN))

    # srv = loop.create_datagram_endpoint(server, local_addr=('0.0.0.0', 5000))
    loop.run_until_complete(server)

    print("starting loop")
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    debug = True
    main()
