#!/usr/bin/env python3
import sys
import socket
import asyncio
import time

from bls import BLSTHS, PairingGroup

PORT_SIG = 5005   # port the initializer sends signature shares to
PORT_INIT = 5007  # port that the initializer listens on
INITIALIZER_ADDR = ("10.0.0.254", PORT_INIT)

PORT_SIGN = 5006  # port the initializer sends signing requests to
MCAST_SIGN = "224.1.1.1"  # multicast group for signeng requests


class ResponderServer:
    def __init__(self, go, bls):
        self.go = go
        self.bls = bls

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", PORT_SIG))
        print("sending share request")
        sock.sendto(b'\xff', INITIALIZER_ADDR)
        (data, _) = sock.recvfrom(1024)
        self.share = go.deserialize(data)
        sock.close()
        print("got my share:", self.share)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        idx = data[0]
        m = data[1:]
        psign = self.bls.sign(self.share, m)
        res = idx.to_bytes(1, "big") + self.go.serialize(psign)
        #time.sleep(.1)
        self.transport.sendto(res, INITIALIZER_ADDR)
        print("sent signature for", idx)


class InitiatorServer:
    def __init__(self, go, bls, all_shares, n, t, pk, ms):
        self.go = go
        self.bls = bls
        self.all_shares = all_shares
        self.n = n
        self.t = t
        self.pk = pk
        self.ms = ms
        if len(ms) > 0xff:
            print("Too many messages! Sequence number will be too long.")
            exit(1)

        self.seq = -1
        self.m = None
        self.signs = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        self.initiate_new()  # kickstart the whole process

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        (ip, _) = addr
        res_idx = int(ip.split('.')[-1]) - 2

        if data == b'\xff':
            # this is a request for a share
            print("got share request")
            res = self.go.serialize(self.all_shares[res_idx])
            self.transport.sendto(res, (ip, PORT_SIG))
            print("sent share:", self.all_shares[res_idx])
            self.initiate_new()
            return

        if data == b'\xfe':
            # this is a request to start over
            print("initiating new")
            self.initiate_new()
            return

        # otherwise this is a signature share!
        seq = data[0]
        share = self.go.deserialize(data[1:])

        if seq == self.seq:
            print(f"got signature {seq} from {res_idx}")
            self.signs.append((res_idx+1, share))
        else:
            #print(f"sequence number mismatch. Expected {self.seq} got {seq} from {res_idx}")
            print("discarding extra share")

        if len(self.signs) >= self.t:
            self.aggregate_and_verify()
            self.initiate_new()

    def aggregate_and_verify(self):
        sig = self.bls.aggregate(self.signs)
        print(f"Message: '{self.m}'")
        print(f"Signature: {sig}")
        #if self.bls.verify(self.pk, sig, self.m):
        #    print("Valid signature!")
        #else:
        #    print("INVALID")

    def initiate_new(self):
        if len(self.signs) < self.t and self.seq != -1:
            print("aborted", self.seq)
        self.seq += 1
        self.seq %= len(self.ms)
        self.m = self.ms[self.seq]

        # send requests to all responders
        self.signs = []
        #time.sleep(.1)
        msg = self.seq.to_bytes(1, "big") + self.m
        print("sending request for", self.seq)
        self.sock.sendto(msg, (MCAST_SIGN, PORT_SIGN))


def main():
    server = None
    groupObj = PairingGroup('MNT224')
    bls = BLSTHS(groupObj)

    messages = [b"hello world!!!", b"test message", b"third one"]

    server = None
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    if len(sys.argv) == 1:  # responder
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        sock.bind((MCAST_SIGN, PORT_SIGN))
        host = socket.gethostbyname(socket.gethostname())
        sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host))
        sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP,
            socket.inet_aton(MCAST_SIGN)+socket.inet_aton(host))
        server = loop.create_datagram_endpoint(
            lambda: ResponderServer(groupObj, bls), sock=sock)
        print("Starting responder")
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
            local_addr=('0.0.0.0', PORT_INIT))
        print("starting initiator")

    loop.run_until_complete(server)

    print("starting loop")
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    debug = True
    main()
