#!/usr/bin/env python3

import sys
import subprocess
from dataclasses import dataclass
from typing import List, Tuple

ERROR_LOG = "error.log"


@dataclass
class Input:
    count: int
    threshold: int
    runtime: int
    attack: int
    reboot: int


@dataclass
class Output:
    signatures: int
    aborts: int


@dataclass
class Record:
    input: Input
    output: Output
    reboots: bool


def execute(inp: Input, reboots: bool) -> Record:
    env = {
        "SERVER_COUNT": str(inp.count),
        "THRESHOLD":    str(inp.threshold),
        "RUNTIME":      str(inp.runtime),
    }
    if reboots:
        if not inp.attack or not inp.reboot:
            raise ValueError("reboot requires attack and reboot time")
        env |= {
            "ATTACKTIME":   str(inp.attack),
            "REBOOTTIME":   str(inp.reboot),
        }
    else:
        # env["SERVER_COUNT"] = str(inp.threshold+1)
        env["REBOOTTIME"] = "disable"

    print("running with", env)
    proc = subprocess.Popen(
        ["docker-compose", "up"], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    output = []
    with proc.stdout as out:
        for line in iter(out.readline, b''):
            output.append(line)
            if b"Completed" in line:
                sigs_line = line
            elif b"aborts" in line:
                aborts_line = line
    if proc.wait() != 0:
        print("non-zero exit!")
        with open(ERROR_LOG, "wb") as f:
            f.write(b''.join(output))
        print("log dumped to", ERROR_LOG)
        print("check `docker ps -a` to see if manual cleanup is needed.")
        return None

    proc = subprocess.run(
        ["docker-compose", "down"],
        env=env,
        capture_output=True
    )
    if proc.returncode != 0:
        print("Automatic cleanup failed.")
        print("check `docker ps -a` to see if manual cleanup is needed.")
        return None

    signatures = int(sigs_line.split(b'|')[1].strip().split(b' ')[1])
    aborts = int(aborts_line.split(b'|')[1].strip().split(b' ')[2])
    print(f"{signatures} signatures, {aborts} aborts")
    return Record(inp, Output(signatures, aborts), reboots)


def stats(rec: Record) -> Tuple[float, float]:
    success_rate = rec.output.signatures / rec.input.runtime
    abort_rate = rec.output.aborts / (rec.output.signatures+rec.output.aborts)
    return success_rate, abort_rate


def save_records(filename: str, records: List[Record]):
    with open(filename, "w") as f:
        f.write("count,threshold,runtime,attack,reboot;")
        f.write("signatures,aborts;")
        f.write("reboots\n")
        for rec in records:
            inp = [
                rec.input.count, rec.input.threshold, rec.input.runtime,
                rec.input.attack, rec.input.reboot]
            out = [rec.output.signatures, rec.output.aborts]
            r = "yes" if rec.reboots else "no"
            fields = [",".join(map(str, inp)), ",".join(map(str, out)), r]
            f.write(";".join(fields) + "\n")


def load_records(filename: str) -> List[Record]:
    records = []
    with open(filename, "r") as f:
        f.readline()
        for line in f:
            inp, out, r = line.split(";")
            inputs = Input(*map(int, inp.split(",")))
            outputs = Output(*map(int, out.split(",")))
            reboots = (r == "yes")
            records.append(Record(inputs, outputs, reboots))
    return records


if __name__ == "__main__":
    if "--build" in sys.argv:
        p = subprocess.Popen(["docker", "build", ".", "-t", "gabrielkulp/bls"])
        if p.wait() != 0:
            print("non-zero exit code during build. Exiting.")
            exit(1)

    runtime = 120
    attack = 60
    reboot = 30
    records_baseline = []
    records_reboots = []

    if "--run" in sys.argv:
        inputs = [
            Input(8,  2,  runtime, attack, reboot),
            Input(8,  3,  runtime, attack, reboot),
            Input(8,  4,  runtime, attack, reboot),
            Input(8,  5,  runtime, attack, reboot),
            Input(8,  6,  runtime, attack, reboot),
            Input(8,  7,  runtime, attack, reboot),
            Input(8,  8,  runtime, attack, reboot),
            Input(12, 1,  runtime, attack, reboot),
            Input(12, 2,  runtime, attack, reboot),
            Input(12, 4,  runtime, attack, reboot),
            Input(12, 6,  runtime, attack, reboot),
            Input(12, 8,  runtime, attack, reboot),
            Input(12, 10, runtime, attack, reboot),
            Input(12, 11, runtime, attack, reboot),
            Input(12, 12, runtime, attack, reboot),
            Input(18, 1,  runtime, attack, reboot),
            Input(18, 2,  runtime, attack, reboot),
            Input(18, 3,  runtime, attack, reboot),
            Input(18, 6,  runtime, attack, reboot),
            Input(18, 9,  runtime, attack, reboot),
            Input(18, 12, runtime, attack, reboot),
            Input(18, 16, runtime, attack, reboot),
            Input(18, 17, runtime, attack, reboot),
            Input(18, 18, runtime, attack, reboot),
        ]

        # run tests
        for inp in inputs:
            records_baseline.append(execute(inp, False))
            records_reboots.append(execute(inp, True))
        save_records("records_baseline.csv", records_baseline)
        save_records("records_reboots.csv", records_reboots)

    else:  # load last data
        records_baseline = load_records("records_baseline.csv")
        records_reboots = load_records("records_reboots.csv")

    print("\n== SUMMARY ==\n")
    print("All tests run with")
    print("\tAttack time:", attack)
    print("\tReboot time:", reboot)
    print("\tRuntime:", runtime)
    print("\n")
    for rb, rr in zip(records_baseline, records_reboots):
        b_sigs, b_aborts = stats(rb)
        r_sigs, r_aborts = stats(rr)
        print(f"count {rb.input.count}, threshold {rb.input.threshold}:")
        print("\t[baseline] ", end="")
        print(f"{rb.output.signatures} signatures, {rb.output.aborts} aborts")
        print(f"\t--> {b_sigs:0.2f} sigs/sec, {b_aborts*100:0.2f}% failed")
        print("\t[reboots] ", end="")
        print(f"{rr.output.signatures} signatures, {rr.output.aborts} aborts")
        print(f"\t--> {r_sigs:0.2f} sigs/sec, {r_aborts*100:0.2f}% failed")
        print(f"\tReboots are {100*r_sigs/b_sigs:0.1f}% of baseline speed.")
        print()

    if "--plot" in sys.argv:
        import matplotlib.pyplot as plt
        fix, ax = plt.subplots()
        for n in [8, 12, 18]:
            ax.plot(
                # [0.1, 0.33, 0.5, 0.67, 0.9],
                [
                    r.input.threshold/r.input.count
                    for r in records_reboots
                    if r.input.count == n
                ],
                [stats(r)[0] for r in records_reboots if r.input.count == n],
                label=f"n={n} with reboots"
            )
            ax.plot(
                # [0.1, 0.33, 0.5, 0.67, 0.9],
                [
                    r.input.threshold/r.input.count
                    for r in records_baseline
                    if r.input.count == n
                ],
                [stats(r)[0] for r in records_baseline if r.input.count == n],
                label=f"n={n} baseline"
            )
            ax.legend()
        ax.set_xlim(0, 1)
        ax.set_xlabel("Threshold Fraction (t/n)")
        ax.set_ylabel("Signatures per Second")
        t = f"Attack time {attack}s, Reboot time {reboot}s, Runtime {runtime}s"
        ax.set_title(t)
        plt.show()
