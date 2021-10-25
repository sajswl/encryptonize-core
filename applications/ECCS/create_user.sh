#!/bin/bash

source ./env.sh

if [ $SECURE == 1 ]
then
  grpcurl -proto services/authn/authn.proto \
    -cacert ./data/encryptonize.crt \
    -H "authorization:bearer ${USER_AT}" \
    -d '{"userScopes": ["READ", "CREATE", "INDEX", "OBJECTPERMISSIONS", "USERMANAGEMENT"]}' \
    ${HOSTNAME}:9000 authn.Encryptonize.CreateUser
else
  grpcurl -proto services/authn/authn.proto \
    -plaintext \
    -H "authorization:bearer ${USER_AT}" \
    -d '{"userScopes": ["READ", "CREATE", "INDEX", "OBJECTPERMISSIONS", "USERMANAGEMENT"]}' \
    ${HOSTNAME}:9000 authn.Encryptonize.CreateUser
fi
