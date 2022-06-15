#!/usr/bin/env python3

import subprocess
from dataclasses import dataclass

ERROR_LOG = "error.log"

@dataclass
class Input:
	count: int
	threshold: int
	attack: int
	reboot: int
	runtime: int


@dataclass
class Output:
	signatures: int
	aborts: int


@dataclass
class Record:
	input: Input
	output: Output
	reboots: bool


def execute(inp: Input, reboots: bool):
	env = {
		"SERVER_COUNT": str(inp.count),
		"THRESHOLD":    str(inp.threshold),
		"RUNTIME":      str(inp.runtime),
		"ATTACKTIME":   str(inp.attack),
		"REBOOTTIME":   str(inp.reboot),
	}
	if not reboots:
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

	proc = subprocess.run(["docker-compose", "down"], env=env, capture_output=True)
	if proc.returncode != 0:
		print("Automatic cleanup failed.")
		print("check `docker ps -a` to see if manual cleanup is needed.")
		return None

	signatures = int(sigs_line.split(b'|')[1].strip().split(b' ')[1])
	aborts = int(aborts_line.split(b'|')[1].strip().split(b' ')[2])
	return Record(inp, Output(signatures, aborts), reboots)

def stats(rec: Record):
	success_rate = rec.output.signatures / rec.input.runtime
	abort_rate = rec.output.aborts / rec.input.runtime
	return success_rate, abort_rate

inputs = [
	Input(5, 2, 10, 3, 15),
	Input(5, 3, 10, 3, 15),
	Input(5, 4, 10, 3, 15),
]

records = []

for inp in inputs:
	for r in [True, False]:
		records.append(execute(inp, r))

print("summary:")
for rec in records:
	print(stats(rec))