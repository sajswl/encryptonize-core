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
# - E2E_TEST_UID:       UID of a user with USERMANAGMENT scope
# - E2E_TEST_PASS:      Password of the above mentioned user
# - ECCS_ENDPOINT:      Address of the server (e.g.: 127.0.0.1:9000)
# - ECCS_CRT:           Certification used by the Encryption server
#                         leave unset for HTTP
#                         "insecure" for HTTPS ignoring certificate errors

import os
import subprocess
import sys
import re
import uuid
import json

# Initializes the server
# Sets the endpoint if it is unset
# Logs in the admin user
def init():
	ENDPOINT_ENV = "ECCS_ENDPOINT"
	if ENDPOINT_ENV not in os.environ:
		os.environ[ENDPOINT_ENV] = "127.0.0.1:9000"
	
	ADMIN_UID_ENV = "E2E_TEST_UID"
	if ADMIN_UID_ENV in os.environ:
		admin_uid = os.environ[ADMIN_UID_ENV]
	else:
		print(f"{ADMIN_UID_ENV} must be set")
		sys.exit(1)

	ADMIN_PASS_ENV = "E2E_TEST_PASS"
	if ADMIN_PASS_ENV in os.environ:
		admin_pass = os.environ[ADMIN_PASS_ENV]
	else:
		print(f"{ADMIN_PASS_ENV} must be set")
		sys.exit(1)

	return login_user(admin_uid, admin_pass)

def create_user(token, flags=None):
	cmd = ["./eccs", "-a", token, "createuser"]
	if flags is not None:
		cmd.append(flags)

	# uid and password are returned on stderr so we need to get that
	res = subprocess.run(cmd, capture_output=True, check=True, text=True)

	uid = None
	password = None
	for match in re.finditer(r"\"userId\": \"([^\"]+)\"", res.stderr):
		if uid is not None:
			print(f"multiple matches for the UID, aborting")
			sys.exit(1)
		uid = match.group(1)

	for match in re.finditer(r"\"password\": \"([^\"]+)\"", res.stderr):
		if password is not None:
			print(f"multiple matches for the Password, aborting")
			print(at)
			print(match.group(0))
			sys.exit(1)
		password = match.group(1)

	if uid is None or at is None:
		print(f"unable to match UID or Password in {res}")
		sys.exit(1)

	return uid, password

def login_user(uid, password):
	cmd = ["./eccs", "-u", uid, "-p", password, "--token", "\"\"", "loginuser"]

	res = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, check=True, text=True)

	at = None
	for match in re.finditer(r"\"accessToken\": \"([^\"]+)\"", res.stderr):
		if at is not None:
			print(f"multiple matches for the AT, aborting")
			print(at)
			print(match.group(0))
			sys.exit(1)
		at = match.group(1)

	return at

def create_group(token, flags=None):
	cmd = ["./eccs", "-a", token, "creategroup"]
	if flags is not None:
		cmd.append(flags)

	# groupID is returned on stderr so we need to get that
	res = subprocess.run(cmd, capture_output=True, check=True, text=True)

	gid = None
	for match in re.finditer(r"\"groupId\": \"([^\"]+)\"", res.stderr):
		if gid is not None:
			print(f"multiple matches for the groupID, aborting")
			sys.exit(1)
		gid = match.group(1)

	if gid is None or at is None:
		print(f"unable to match groupID in {res}")
		sys.exit(1)

	return gid

def create_object(token, data, associated_data):
	cmd = ["./eccs", "-a", token, "store", "-s"]
	if associated_data is not None:
		cmd += ["-d", associated_data]

	res = subprocess.run(cmd, input=data, capture_output=True, check=True, text=True)

	oid = None
	for match in re.finditer(r"\"objectId\": \"([0-9a-zA-Z]{8}(?:-[0-9a-zA-Z]{4}){3}-[0-9a-zA-Z]{12})\"", res.stderr):
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

def retrieve_object(token, oid):
	cmd = ["./eccs", "-a", token, "retrieve", "-o", oid]

	res = subprocess.run(cmd, capture_output=True, check=True, text=True)

	obj = re.search(r"\"plaintext\":\"(.*)\",\"associated_data\":\"(.*)\"", res.stderr)

	return obj.group(1), obj.group(2)

def update_object(token, oid, new_data, new_associated_data):
	cmd = ["./eccs", "-a", token, "update", "-o", oid, "-s"]

	if new_associated_data is not None:
		cmd += ["-d", new_associated_data]

	subprocess.run(cmd, input=new_data, check=True, text=True)

def delete_object(token, oid):
	cmd = ["./eccs", "-a", token, "delete", "-o", oid]

	res = subprocess.run(cmd, check=True, text=True)

def encrypt_object(token, plaintext, aad, filename):
	cmd = ["./eccs", "-a", token, "encrypt", "-s"]
	if aad is not None:
		cmd += ["-d", aad]
	
	with open(filename, 'w') as outfile:
		res = subprocess.run(cmd, input=plaintext, stdout=outfile, check=True, text=True)
	
	with open(filename, 'r') as readfile:
		encrypted_json = readfile.read()
		parsed = json.loads(encrypted_json)
		if parsed['objectId'] is None:
			print(f"unable to match oid in {res}")
			sys.exit(1)
		
		return parsed['objectId']

def decrypt_object(token, filename):
	cmd = ["./eccs", "-a", token, "decrypt", "-f", filename]
	res = subprocess.run(cmd, check=True, text=True)

if __name__ == "__main__":
	at = init()
	uid1, password1 = create_user(at, "-rcudip")
	print(f"[+] created first user:  UID {uid1}, Password {password1}")
	uid2, password2 = create_user(at, "-r")
	print(f"[+] created second user: UID {uid2}, Password {password2}")
	try:
		create_user(at) # expecting a subprocess.CalledProcessError when calling without scope
		print(f"[-] a user without any scope was created, but an error was expected, aborting")
		sys.exit(1)
	except subprocess.CalledProcessError:
		print("[+] did not create a third user without scopes")

	at1 = login_user(uid1, password1)
	print(f"[+] logged in as first user:  UID {uid1}, AT {at1}")

	plaintext = "hello encryption algorithm"
	aad = "AES"
	filename = "encrypted-object"
	oid2 = encrypt_object(at1, plaintext, aad, filename)
	print(f"[+] object encrypted:      OID {oid2}")

	decrypt_object(at1, filename)
	print(f"[+] object decrypted:      OID {oid2}")

	delete_object(at1, oid2)
	try:
		retrieve_object(at1, oid2)
		print(f"[-] retrieving an object should fail after deletion, aborting")
		sys.exit(1)
	except subprocess.CalledProcessError:
		print(f"[+] object was deleted successfully")

	obj = {"data": "dat", "associated_data": "no one has the intention to store bytes here."}

	oid = create_object(at1, obj["data"], obj["associated_data"])
	print(f"[+] object created:      OID {oid}")

	new_obj = {"data": "new data", "associated_data": "this was updated"}
	update_object(at1, oid, new_obj["data"], new_obj["associated_data"])

	d, ad = retrieve_object(at1, oid)
	if(d != new_obj['data'] or ad != new_obj['associated_data']):
		print(f"[-] failed to update object")
		sys.exit(1)

	subprocess.run(["./eccs", "-a", at1, "addpermission", "-o", oid, "-t", uid2], check=True)
	subprocess.run(["./eccs", "-a", at1, "getpermissions", "-o", oid], check=True)
	subprocess.run(["./eccs", "-a", at1, "removepermission", "-o", oid, "-t", uid2], check=True)
	subprocess.run(["./eccs", "-a", at, "removeuser", "-t", uid2], check=True)

	gid = create_group(at, "-rcudip")
	print(f"[+] created group:  GroupID {gid}")

	subprocess.run(["./eccs", "-a", at, "addusertogroup", "-t", uid1, "-g", gid], check=True)
	subprocess.run(["./eccs", "-a", at, "removeuserfromgroup", "-t", uid1, "-g", gid], check=True)

	subprocess.run(["./eccs", "-a", at1, "addpermission", "-o", oid, "-t", gid], check=True)
	subprocess.run(["./eccs", "-a", at1, "getpermissions", "-o", oid], check=True)
	subprocess.run(["./eccs", "-a", at1, "removepermission", "-o", oid, "-t", gid], check=True)

	print("[+] all tests succeeded")
