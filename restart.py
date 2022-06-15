#!/usr/bin/env python3
import logging
import subprocess
import sys
import os
import signal

exe = "./server.py"
OVERLAP = 1


def getIP():
    import socket
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)


def findNextPrime(n):
    if(n <= 1):
        return 2
    prime = n
    while(1):
        prime += 1
        if(isPrime(prime)):
            break
    return prime


def isPrime(n):
    if (n <= 1):
        return False
    if (n <= 3):
        return True
    if (n % 2 == 0 or n % 3 == 0):
        return False
    i = 5
    while(i*i <= n):
        if(n % i == 0 or n % (i+2) == 0):
            return False
        i = i+6
    return True


def getCurrNodeIdx(ips, ip):
    current_node = -1
    for i in range(len(ips)):
        if(ips[i] == ip):
            current_node = i
            break
    return current_node


class RandomNodePicker:
    def __init__(self, n):
        self.n = n
        self.prime = findNextPrime(n)
        self.generators = []
        for i in range(1, n+1):
            generatedNums = []
            generatedNums = self.findGeneratedNums(i, generatedNums)
            if(len(generatedNums) == n):
                self.generators.append((i, generatedNums))
                break
            self.currGeneratorIdx = 0
            self.nextGeneratedNumIdx = 0

    def nextNode(self):
        nodeNum = self.generators[
            self.currGeneratorIdx][1][self.nextGeneratedNumIdx]
        self.nextGeneratedNumIdx += 1
        if(self.nextGeneratedNumIdx == n):
            self.nextGeneratedNumIdx = 0
            self.currGeneratorIdx = (
                self.currGeneratorIdx + 1) % len(self.generators)
        return nodeNum

    def findGeneratedNums(self, i, generatedNums):
        generatedNumsSet = []
        powersOfiModPrime = 1
        for x in range(0, self.prime):
            if(powersOfiModPrime not in generatedNumsSet):
                generatedNumsSet.append(powersOfiModPrime)
                if(powersOfiModPrime >= 1 and powersOfiModPrime <= self.n):
                    generatedNums.append(powersOfiModPrime-1)
            powersOfiModPrime = (powersOfiModPrime * i) % self.prime
        return generatedNums


class Algorithm:
    def __init__(self, ips, n, attackTime, rebootTime, t, nodePicker):
        self.ip = getIP()
        self.mIntervals = max(1, attackTime//rebootTime)
        self.currNodeIdx = getCurrNodeIdx(ips, self.ip)
        self.t = t
        self.attackTime = attackTime
        self.rebootTime = rebootTime
        self.nodePicker = nodePicker
        self.n = n
        self.numRebootsSoFar = 0

    def rebootAfterTime(self, timeToReboot):
        import time
        self.numRebootsSoFar += 1
        print("Going up")

        # Reboot logic
        # timetoReboot is the time after which the node is
        # scheduled to be rebooted.
        try:
            subprocess.run([exe], timeout=timeToReboot+OVERLAP)
            sys.stdout.flush()
            print("received exit signal")
            exit(0)
        except subprocess.TimeoutExpired:
            print("Went down")
        finally:
            time.sleep(self.rebootTime-OVERLAP)

    def run(self):
        if ((self.t) < self.mIntervals):
            subsetSize = self.t
            # print("here")
            # print("subset size:", subsetSize, "mIntervals:", self.mIntervals)
            logging.debug("node number: " + str(self.currNodeIdx))
            logging.debug("subset size: " + str(subsetSize))
            logging.debug(" mIntervals:" + str(self.mIntervals))
            N = self.numRebootsSoFar*n
            while(self.nodePicker.nextNode() != self.currNodeIdx):
                N += 1
            # print("N",N)
            logging.debug("N" + str(N))
            if(self.numRebootsSoFar == 0):
                N = ((N//subsetSize) * self.mIntervals) + (N % subsetSize)
                timeToReboot = N * rebootTime
            else:
                M = N - self.n
                N = ((N//subsetSize) * self.mIntervals) + (N % subsetSize)
                M = ((M//subsetSize) * self.mIntervals) + (M % subsetSize)
                timeToReboot = (N - M-1) * self.rebootTime
            # print("timeToReboot: ", timeToReboot)
            logging.debug("timeToReboot: " + str(timeToReboot))
            if(self.numRebootsSoFar > 0):
                timeToReboot += 10
            self.rebootAfterTime(timeToReboot)

        else:
            import math
            subsetSize = int(math.ceil(self.t/self.mIntervals))
            # print("subset size:", subsetSize, "mIntervals:", self.mIntervals)
            logging.debug("node number: " + str(self.currNodeIdx))
            logging.debug("subset size: " + str(subsetSize))
            logging.debug("mIntervals: " + str(self.mIntervals))
            N = self.numRebootsSoFar*n
            while(self.nodePicker.nextNode() != self.currNodeIdx):
                N += 1
            # print("N",N)
            logging.debug("N" + str(N))
            if(self.numRebootsSoFar == 0):
                timeToReboot = N//subsetSize * rebootTime
            else:
                M = N - self.n
                M = (M//subsetSize)*subsetSize + subsetSize
                N = (N//subsetSize)*subsetSize
                # print(N,M)
                timeToReboot = ((N-M)//subsetSize)*self.rebootTime

            # print("timeToReboot: ", timeToReboot)
            logging.debug("timeToReboot: " + str(timeToReboot))
            if(self.numRebootsSoFar > 0):
                timeToReboot += 10
            self.rebootAfterTime(timeToReboot)


if "disable" in sys.argv:
    print("running without reboots")
    os.execlp(exe, exe)

if len(sys.argv) != 1+5:
    print("Missing arguments:")
    print("[# nodes] [# threshold] [attack t] [reboot t] [test duration]")
    exit(1)

# get key first before running main loop
try:
    subprocess.run([exe], timeout=1)
    sys.stdout.flush()
except subprocess.TimeoutExpired:
    print("got key")

node_count = int(sys.argv[1])
threshold = int(sys.argv[2])
attackTime = int(sys.argv[3])
rebootTime = int(sys.argv[4])
total_time = int(sys.argv[5])

ips = []
for i in range(node_count):
    ips.append("10.0.0." + str(i+2))

n = node_count
nodePicker = RandomNodePicker(n)
# print(nodePicker.generators)
logging.debug(nodePicker.generators)
algo = Algorithm(ips, n, attackTime, rebootTime, threshold, nodePicker)


def handler(signum, frame):
    print("Timer ran out")
    exit(0)
signal.signal(signal.SIGALRM, handler)
signal.alarm(total_time+10) # 10 extra seconds of leeway
while True:
    algo.run()
