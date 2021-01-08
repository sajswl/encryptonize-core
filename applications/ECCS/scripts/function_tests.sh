#!/bin/bash

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
#   ./tests/function_tests.sh
#
# By default the tests are run on a local server. To change this behaviour, the following
# environment variables can be set:
#
# - ECCS_TEST_ADMIN_AT : Admin user access token
# - ECCS_ENDPOINT:        Address of the server (e.g.: 127.0.0.1:9000)
# - ECCS_CRT:             Certification used by the Encryption server
#                         leave unset for HTTP
#                         "insecure" for HTTPS ignoring certificate errors

# set defaults for the testing paramters
export ECCS_ENDPOINT="${ECCS_ENDPOINT:-127.0.0.1:9000}"
#ECCS_TEST_ADMIN_AT="${ECCS_TEST_ADMIN_AT:-Error}"
ECCS_TEST_ADMIN_AT="${ECCS_TEST_ADMIN_AT:-ChAAAAAAAABAAIAAAAAAAAACEgEE.AAAAAAAAAAAAAAAAAAAAAg.OWQcxNqqdofSXdBMaeiXaM4BV1bgusy-umfJGhOQI5g}"

########### Create the first user
# create a user, combine multiple spaces to one, and remove color codes
RESULT=$(./eccs -a "${ECCS_TEST_ADMIN_AT}" createuser -rcip 2>&1)
echo "${RESULT}"
RESULT=$(tr -s ' ' <<< ${RESULT} | sed -E 's/\x1b\[[0-9;]+[A-Za-z]//g' )
STATUS=$(head -n 1 <<< ${RESULT} | cut -d' ' -f4)
if [[ "${STATUS}" == "failed:" ]]
then
	exit 1
fi
VALUE=$(tail -n 1 <<< ${RESULT})

UserID=$(cut -d' ' -f2 <<< ${VALUE})
UserID1=$(tr -d '"' <<< ${UserID#"user_id:"})

AccessToken=$(cut -d' ' -f3 <<< ${VALUE})
AccessToken1=$(tr -d '"' <<< ${AccessToken#"access_token:"})

########### Create the second user
RESULT=$(./eccs -a "${ECCS_TEST_ADMIN_AT}" createuser -rcip 2>&1)
echo "${RESULT}"
RESULT=$(tr -s ' ' <<< ${RESULT} | sed -E 's/\x1b\[[0-9;]+[A-Za-z]//g' )
STATUS=$(head -n 1 <<< ${RESULT} | cut -d' ' -f4)
if [[ "${STATUS}" == "failed:" ]]
then
	exit 1
fi
VALUE=$(tail -n 1 <<< ${RESULT})

UserID=$(cut -d' ' -f2 <<< ${VALUE})
UserID2=$(tr -d '"' <<< ${UserID#"user_id:"})

AccessToken=$(cut -d' ' -f3 <<< ${VALUE})
AccessToken2=$(tr -d '"' <<< ${AccessToken#"access_token:"})

########### Store Object and record OID for later retrieval
RESULT=$(./eccs -a "${AccessToken1}" store -s -d "data" <<< "asdf" 2>&1)
echo "${RESULT}"
RESULT=$(tr -s ' ' <<< ${RESULT} | sed -E 's/\x1b\[[0-9;]+[A-Za-z]//g' )
STATUS=$(head -n 1 <<< ${RESULT} | cut -d' ' -f4)
if [[ "${STATUS}" == "failed:" ]]
then
	exit 1
fi
OID=$(tail -n 1 <<< ${RESULT} | cut -d' ' -f2)

# test the remaining functions disregarding their output
./eccs -a "${AccessToken1}" store -f "README.md" -d "asdf" || exit 1
./eccs -a "${AccessToken1}" retrieve -o "${OID}" || exit 1
./eccs -a "${AccessToken1}" addpermission -o "${OID}" -t "${UserID2}" || exit 1
./eccs -a "${AccessToken1}" getpermissions -o "${OID}" || exit 1
./eccs -a "${AccessToken1}" removepermission -o "${OID}" -t "${UserID2}" || exit 1
