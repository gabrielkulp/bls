#!/usr/bin/env python3
import sys
import socket
import asyncio
import time
import os
from threading import Timer

from bls import BLSTHS, PairingGroup

PORT_KEY = 5005   # port for signature share exchange
PORT_INITIALIZER = 5007  # port that the initializer listens on
KEY_SHARE_SRC = ("10.0.0.254", PORT_KEY)
SIG_SHARE_DEST = ("10.0.0.254", PORT_INITIALIZER)

MCAST_CHANNEL = ("224.1.1.1", 5006)  # multicast for signing requests

KEY_SHARE_PATH = "./share.key"

WATCHDOG_TIMEOUT = .05  # seconds of silence until abort


class ResponderServer:
    def __init__(self, go, bls):
        self.go = go
        self.bls = bls

        if os.path.isfile(KEY_SHARE_PATH):
            print("key share exists; loading from file")
            with open(KEY_SHARE_PATH, "rb") as f:
                self.share = go.deserialize(f.read())
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", PORT_KEY))
            # print("sending share request")
            sock.sendto(b'\xff', KEY_SHARE_SRC)
            (data, _) = sock.recvfrom(1024)
            self.share = go.deserialize(data)
            sock.close()
            # print("got my share:", self.share)
            with open(KEY_SHARE_PATH, "wb") as f:
                f.write(data)
            print("wrote key share to file")

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if data == b"\xff":
            exit(0)
        idx = data[0]
        m = data[1:]
        psign = self.bls.sign(self.share, m)
        res = idx.to_bytes(1, "big") + self.go.serialize(psign)
        # time.sleep(.1)
        self.transport.sendto(res, SIG_SHARE_DEST)
        # print("sent signature for", idx)


class KeyShareServer:
    def __init__(self, go, all_shares):
        self.go = go
        self.all_shares = all_shares
        self.remaining = [n for n in range(len(all_shares))]

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        (ip, _) = addr
        res_idx = int(ip.split('.')[-1]) - 2

        if data == b'\xff':
            # this is a request for a share
            print("got share request from", res_idx)
            res = self.go.serialize(self.all_shares[res_idx])
            self.transport.sendto(res, (ip, PORT_KEY))
            self.remaining.remove(res_idx)
            # print("sent share:", self.all_shares[res_idx])
        if not self.remaining:
            print("all key shares sent!")
            loop = asyncio.get_event_loop()
            loop.stop()


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
        self.sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)

        global sig_count
        global abort_count
        sig_count = 0
        abort_count = 0

        self.timer = Timer(WATCHDOG_TIMEOUT, self.abort)
        self.timer.start()

        self.initiate_new()  # kickstart the whole process

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.timer.cancel()
        self.timer = Timer(WATCHDOG_TIMEOUT, self.abort)
        self.timer.start()

        (ip, _) = addr
        res_idx = int(ip.split('.')[-1]) - 2

        if data == b'\xfe':
            # this is a request to start over
            self.abort()
            return

        # otherwise this is a signature share!
        seq = data[0]
        share = self.go.deserialize(data[1:])

        if seq == self.seq:
            # print(f"got signature {seq} from {res_idx}")
            self.signs.append((res_idx+1, share))
            if len(self.signs) >= self.t:
                self.aggregate_and_verify()
                self.initiate_new()
        # else:
        #     print(f"sequence number mismatch. \
        #         Expected {self.seq} got {seq} from {res_idx}")
        #     print("discarding extra share")
    
    def abort(self):
        global abort_count
        abort_count += 1
        self.initiate_new()

    def aggregate_and_verify(self):
        self.bls.aggregate(self.signs)
        global sig_count
        sig_count += 1
        # print(f"Message: '{self.m}'")
        # print(f"Signature: {sig}")
        # if self.bls.verify(self.pk, sig, self.m):
        #    print("Valid signature!")
        # else:
        #    print("INVALID")

    def initiate_new(self):
        if len(self.signs) < self.t and self.seq != -1:
            print("aborted", self.seq)
        self.seq += 1
        self.seq %= len(self.ms)
        self.m = self.ms[self.seq]

        # send requests to all responders
        self.signs = []
        # time.sleep(.1)
        msg = self.seq.to_bytes(1, "big") + self.m
        # print("sending request for", self.seq)
        self.sock.sendto(msg, MCAST_CHANNEL)


def main():
    groupObj = PairingGroup('MNT224')
    bls = BLSTHS(groupObj)

    messages = [b"hello world!!!", b"test message", b"third one"]

    server = None
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    if len(sys.argv) == 1:  # responder
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        sock.bind(MCAST_CHANNEL)
        host = socket.gethostbyname(socket.gethostname())
        sock.setsockopt(
            socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host))
        sock.setsockopt(
            socket.SOL_IP, socket.IP_ADD_MEMBERSHIP,
            socket.inet_aton(MCAST_CHANNEL[0])+socket.inet_aton(host))
        server = loop.create_datagram_endpoint(
            lambda: ResponderServer(groupObj, bls), sock=sock)

        loop.run_until_complete(server)
        print("Starting responder")
        loop.run_forever()

    else:  # initiator
        if len(sys.argv) != 4:
            print("Must specify number, threshold, and test length")
            exit(1)
        n = int(sys.argv[1])
        t = int(sys.argv[2])
        delay = float(sys.argv[3])

        (pk, shares) = bls.keygen(n, t)

        # share keys first
        server = loop.create_datagram_endpoint(
            lambda: KeyShareServer(groupObj, shares),
            local_addr=('0.0.0.0', PORT_KEY))
        loop.run_until_complete(server)
        loop.run_forever()
        print("done with key distribution")
        server.close()

        time.sleep(3)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        server = loop.create_datagram_endpoint(
            lambda: InitiatorServer(groupObj, bls, shares, n, t, pk, messages),
            local_addr=('0.0.0.0', PORT_INITIALIZER))

        loop.run_until_complete(server)
        print("starting initiator")
        try:
            loop.run_until_complete(asyncio.sleep(delay))
        except TimeoutError:
            print("done")
        finally:
            server.close()
        global sig_count
        global abort_count
        print(f"Completed {sig_count} in {delay:0.2f} seconds.")
        print(f"Average is {sig_count/delay:0.2f} signatures per second")
        print(f"There were {abort_count} aborts ({100*abort_count/sig_count:0.5f}%)")

        # ask responders to die
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        sock.sendto(b"\xff", MCAST_CHANNEL)
        sock.close()


if __name__ == "__main__":
    debug = True
    main()
