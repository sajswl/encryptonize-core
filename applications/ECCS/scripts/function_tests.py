#!/usr/bin/env python3

# Copyright 2021 CYBERCRYPT
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Test all functions of ECCS. Requires an Encryption Server to be running. Usage:
#   ./scripts/function_tests.py
#
# By default the tests are run on a local server. To change this behaviour, the following
# environment variables can be set:
#
# - ECCS_TEST_ADMIN_AT: Admin user access token. As default it uses the following token:
#                         UUID   00000000-0000-4000-8000-000000000002
#                         scopes [UserManagement]
#                         nonce  00000000000000000000000000000002
#                         ASK    0000000000000000000000000000000000000000000000000000000000000001
#                         which is the same one as in the authn unit test
# - ECCS_ENDPOINT:      Address of the server (e.g.: 127.0.0.1:9000)
# - ECCS_CRT:           Certification used by the Encryption server
#                         leave unset for HTTP
#                         "insecure" for HTTPS ignoring certificate errors

import os
import subprocess
import sys
import re

# Initializes the server
# Sets the endpoint if it is unset
# Extracts the admin token from the environment if it is set
def init():
	ENDPOINT_ENV = "ECCS_ENDPOINT"
	if ENDPOINT_ENV not in os.environ:
		os.environ[ENDPOINT_ENV] = "127.0.0.1:9000"
	
	ADMIN_TOKEN_ENV = "ECCS_TEST_ADMIN_AT"
	admin_token = "ChAAAAAAAABAAIAAAAAAAAACEgEE.AAAAAAAAAAAAAAAAAAAAAg.OWQcxNqqdofSXdBMaeiXaM4BV1bgusy-umfJGhOQI5g"
	if ADMIN_TOKEN_ENV in os.environ:
		admin_token = os.environ[ADMIN_TOKEN_ENV]

	return admin_token

def create_user(token, flags=None):
	cmd = ["./eccs", "-a", token, "createuser"]
	if flags is not None:
		cmd.append(flags)

	# uid and token are returned on stderr so we need to get that
	res = subprocess.run(cmd, capture_output=True, check=True, text=True)

	uid = None
	at = None
	for match in re.finditer(r"user_id:\"([^\"]+)\"", res.stderr):
		if uid is not None:
			print(f"multiple matches for the UID, aborting")
			sys.exit(1)
		uid = match.group(1)

	for match in re.finditer(r"access_token:\"([^\"]+)", res.stderr):
		if at is not None:
			print(f"multiple matches for the AT, aborting")
			print(at)
			print(match.group(0))
			sys.exit(1)
		at = match.group(1)

	if uid is None or at is None:
		print(f"unable to match UID or AT in {res}")
		sys.exit(1)

	return uid, at

def create_object(token, data):
	cmd = ["./eccs", "-a", token, "store", "-s"]
	if data is not None:
		cmd += ["-d", data]

	res = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, check=True, text=True)

	oid = None
	for match in re.finditer(r"ObjectID:\s+([0-9a-zA-Z]{8}(?:-[0-9a-zA-Z]{4}){3}-[0-9a-zA-Z]{12})", res.stderr):
		if oid is not None:
			print(f"multiple matches for the OID, aborting")
			print(oid)
			print(match.group(0))
			sys.exit(1)
		oid = match.group(1)

	if oid is None:
		print(f"unable to match oid in {res}")
		sys.exit(1)

	return oid

if __name__ == "__main__":
	at = init()
	_, at1 = create_user(at, "-rcip")
	print("[+] created first user")
	uid2, _ = create_user(at)
	print("[+] created second user")
	oid = create_object(at1, "no one has the intention to store bytes here.")
	print("[+] object created")
	subprocess.run(["./eccs", "-a", at1, "store", "-f", "README.md", "-d", "asdf"], check=True)
	subprocess.run(["./eccs", "-a", at1, "retrieve", "-o", oid], check=True)
	subprocess.run(["./eccs", "-a", at1, "addpermission", "-o", oid, "-t", uid2], check=True)
	subprocess.run(["./eccs", "-a", at1, "getpermissions", "-o", oid], check=True)
	subprocess.run(["./eccs", "-a", at1, "removepermission", "-o", oid, "-t", uid2], check=True)
	print("[+] all tests succeeded")
