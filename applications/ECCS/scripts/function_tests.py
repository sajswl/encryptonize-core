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
# - E2E_TEST_URL:       Endpoint of Encryptonize (defaults to localhost:9000)

import os
import subprocess
import sys
import re
import uuid
import json

endpoint = "localhost:9000"

# Initializes the server
# Sets the endpoint if it is unset
# Logs in the admin user
def init():
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

	global endpoint
	ENDPOINT_ENV = "E2E_TEST_URL"
	if ENDPOINT_ENV in os.environ:
		endpoint = os.environ[ENDPOINT_ENV]

	return admin_uid, admin_pass

#########################################################################
##                           User Management                           ##
#########################################################################
def create_user(uid, password, scopes):
	cmd = ["./eccs", "-e", endpoint, "-u", uid, "-p", password, "createuser", "-s", scopes]
	res = subprocess.run(cmd, capture_output=True, check=True, text=True)
	parsed = json.loads(res.stdout)

	uid = parsed.get("userId")
	password = parsed.get("password")

	if uid is None or password is None:
		print(f"unable to match UID or Password in {res}")
		sys.exit(1)

	return uid, password

def remove_user(uid, password, target):
	cmd = ["./eccs", "-e", endpoint, "-u", uid, "-p", password, "removeuser", "-t", target]
	subprocess.run(cmd, capture_output=True, check=True, text=True)

def create_group(uid, password, scopes):
	cmd = ["./eccs", "-e", endpoint, "-u", uid, "-p", password, "creategroup", "-s", scopes]
	res = subprocess.run(cmd, capture_output=True, check=True, text=True)
	parsed = json.loads(res.stdout)

	gid = parsed.get("groupId")

	if gid is None:
		print(f"unable to match groupID in {res}")
		sys.exit(1)

	return gid

def add_user_to_group(uid, password, target, gid):
	cmd = ["./eccs", "-e", endpoint, "-u", uid, "-p", password, "addusertogroup", "-t", target, "-g", gid]
	subprocess.run(cmd, capture_output=True, check=True, text=True)

def remove_user_from_group(uid, password, target, gid):
	cmd = ["./eccs", "-e", endpoint, "-u", uid, "-p", password, "removeuserfromgroup", "-t", target, "-g", gid]
	subprocess.run(cmd, capture_output=True, check=True, text=True)

#########################################################################
##                              Encryption                             ##
#########################################################################
def encrypt(uid, password, data, associated_data):
	cmd = ["./eccs", "-e", endpoint, "-u", uid, "-p", password, "encrypt", "-d", data, "-a", associated_data]
	res = subprocess.run(cmd, input=data, capture_output=True, check=True, text=True)
	parsed = json.loads(res.stdout)

	oid = parsed.get("objectId")
	ciphertext = parsed.get("ciphertext")
	associated_data= parsed.get("associatedData")
	if oid is None or ciphertext is None or associated_data is None:
		print(f"unable to match oid, ciphertext, or associated data in {res}")
		sys.exit(1)

	return oid, ciphertext, associated_data

def decrypt(uid, password, data, associated_data, oid):
	cmd = ["./eccs", "-e", endpoint, "-u", uid, "-p", password, "decrypt", "-d", data, "-a", associated_data, "-o", oid]
	res = subprocess.run(cmd, capture_output=True, check=True, text=True)
	parsed = json.loads(res.stdout)

	plaintext = parsed.get("plaintext")
	associated_data = parsed.get("associatedData")
	if plaintext is None or associated_data is None:
		print(f"unable to match plaintext or associated data in {res}")
		sys.exit(1)

	return plaintext, associated_data

#########################################################################
##                               Storage                               ##
#########################################################################
def store(uid, password, data, associated_data):
	cmd = ["./eccs", "-e", endpoint, "-u", uid, "-p", password, "store", "-d", data, "-a", associated_data]
	res = subprocess.run(cmd, capture_output=True, check=True, text=True)
	parsed = json.loads(res.stdout)

	oid = parsed.get("objectId")
	if oid is None:
		print(f"unable to match oid in {res}")
		sys.exit(1)

	return oid

def retrieve(uid, password, oid):
	cmd = ["./eccs", "-e", endpoint, "-u", uid, "-p", password, "retrieve", "-o", oid]
	res = subprocess.run(cmd, capture_output=True, check=True, text=True)
	parsed = json.loads(res.stdout)

	plaintext = parsed.get("plaintext")
	associated_data = parsed.get("associatedData")
	if plaintext is None or associated_data is None:
		print(f"unable to match plaintext or associated data in {res}")
		sys.exit(1)

	return plaintext, associated_data

def update(uid, password, oid, data, associated_data):
	cmd = ["./eccs", "-e", endpoint, "-u", uid, "-p", password, "update", "-o", oid, "-d", data, "-a", associated_data]
	subprocess.run(cmd, capture_output=True, check=True, text=True)

def delete(uid, password, oid):
	cmd = ["./eccs", "-e", endpoint, "-u", uid, "-p", password, "delete", "-o", oid]
	subprocess.run(cmd, capture_output=True, check=True, text=True)

#########################################################################
##                             Permissions                             ##
#########################################################################

def get_permissions(uid, password, oid):
	cmd = ["./eccs", "-e", endpoint, "-u", uid, "-p", password, "getpermissions", "-o", oid]
	res = subprocess.run(cmd, capture_output=True, check=True, text=True)
	parsed = json.loads(res.stdout)

	gids = parsed.get("groupIds")
	if gids is None:
		print(f"unable to match group IDs in {res}")
		sys.exit(1)

	return gids

def add_permission(uid, password, target, oid):
	cmd = ["./eccs", "-e", endpoint, "-u", uid, "-p", password, "addpermission", "-t", target, "-o", oid]
	subprocess.run(cmd, capture_output=True, check=True, text=True)

def remove_permission(uid, password, target, oid):
	cmd = ["./eccs", "-e", endpoint, "-u", uid, "-p", password, "removepermission", "-t", target, "-o", oid]
	subprocess.run(cmd, capture_output=True, check=True, text=True)

#########################################################################
##                                Tests                                ##
#########################################################################

if __name__ == "__main__":
	admin_uid, admin_pass = init()

	# User management
	uid1, password1 = create_user(admin_uid, admin_pass, "rcudiom")
	print(f"[+] created first user:  UID {uid1}, Password {password1}")

	uid2, password2 = create_user(admin_uid, admin_pass, "r")
	print(f"[+] created second user: UID {uid2}, Password {password2}")

	gid = create_group(admin_uid, admin_pass, "rcudiom")
	print(f"[+] created group: GID {gid}")

	add_user_to_group(admin_uid, admin_pass, uid2, gid)
	print(f"[+] added user {uid2} to group {gid}")

	remove_user_from_group(admin_uid, admin_pass, uid2, gid)
	print(f"[+] removed user {uid2} from group {gid}")

	remove_user(admin_uid, admin_pass, uid2)
	print(f"[+] removed user {uid2}")

	# Encrypt
	data = "hello encryption algorithm"
	associated_data = "AES"

	oid, ciphertext, aad = encrypt(uid1, password1, data, associated_data)
	print(f"[+] encrypted object {oid}")

	plaintext, aad = decrypt(uid1, password1, ciphertext, aad, oid)
	print(f"[+] decrypted object {oid}")

	if plaintext != data:
		print(f"[-] decryption failed: {plaintext} != {data}")
		sys.exit(1)

	if aad != associated_data:
		print(f"[-] decryption failed: {aad} != {associated_data}")
		sys.exit(1)

	# Storage
	oid = store(uid1, password1, data, associated_data)
	print(f"[+] stored object {oid}")

	plaintext, aad = retrieve(uid1, password1, oid)
	print(f"[+] retrieved object {oid}")

	if plaintext != data:
		print(f"[-] decryption failed: {plaintext} != {data}")
		sys.exit(1)

	if aad != associated_data:
		print(f"[-] decryption failed: {aad} != {associated_data}")
		sys.exit(1)

	update(uid1, password1, oid, "new data", "new associated data")
	print(f"[+] updated object {oid}")

	plaintext, aad = retrieve(uid1, password1, oid)
	if(plaintext != "new data" or aad != "new associated data"):
		print(f"[-] failed to update object")
		sys.exit(1)

	delete(uid1, password1, oid)
	try:
		retrieve(uid1, password1, oid)
		print(f"[-] retrieving an object should fail after deletion, aborting")
		sys.exit(1)
	except subprocess.CalledProcessError:
		print(f"[+] object {oid} was deleted successfully")

	# Permissions
	uid3, password3 = create_user(admin_uid, admin_pass, "r")
	print(f"[+] created third user: UID {uid3}, Password {password3}")

	oid = store(uid1, password1, data, associated_data)
	print(f"[+] stored object {oid}")

	add_permission(uid1, password1, uid3, oid)
	print(f"[+] added permissions for user {uid3} on object {oid}")

	gids = get_permissions(uid1, password1, oid)
	if uid1 not in gids or uid3 not in gids:
		print(f"[-] wrong IDs in permission list")
		sys.exit(1)
	else:
		print(f"[+] got correct permissions {gids}")

	remove_permission(uid1, password1, uid3, oid)
	gids = get_permissions(uid1, password1, oid)
	if uid3 in gids:
		print(f"[-] user not removed from permission list")
		sys.exit(1)
	else:
		print(f"[+] removed permissions for user {uid3} on object {oid}")

	print("[+] all tests succeeded")
