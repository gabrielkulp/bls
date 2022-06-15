#!/usr/bin/env python3

import subprocess

ERROR_LOG = "error.log"

def run_once(server_count, threshold, attack, reboot, runtime):
	env = {
		"SERVER_COUNT": str(server_count),
		"THRESHOLD": str(threshold),
		"ATTACKTIME": str(attack),
		"REBOOTTIME": str(reboot),
		"RUNTIME": str(runtime)
	}
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
		exit(1)

	proc = subprocess.run(["docker-compose", "down"], env=env, capture_output=True)
	if proc.returncode != 0:
		print("Automatic cleanup failed.")
		print("check `docker ps -a` to see if manual cleanup is needed.")
		exit(2)

	signatures = int(sigs_line.split(b'|')[1].strip().split(b' ')[1])
	aborts = int(aborts_line.split(b'|')[1].strip().split(b' ')[2])
	return signatures, aborts

print(run_once(5, 2, 10, 3, 15))