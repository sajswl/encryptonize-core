# admin credentials -- From: Create an Initial Admin User
ADMIN_USER_ID='FILL_ME_IN'
ADMIN_PASSWORD='FILL_ME_IN'

# login as admin user
echo '[+] login admin user'
OUTPUT=$(grpcurl -plaintext \
  -d "{\"userId\": \"${ADMIN_USER_ID}\", \"password\": \"${ADMIN_PASSWORD}\"}" \
  localhost:9000 authn.Encryptonize.LoginUser)
echo "output: $OUTPUT"
echo "-------------------------------------"
export ADMIN_ACCESS_TOKEN=$(jq -r '.accessToken' <<< "${OUTPUT}")


# create a regular user
echo '[+] create regular user'
OUTPUT=$(grpcurl -plaintext \
  -H "authorization:bearer ${ADMIN_ACCESS_TOKEN}" \
  -d '{"userScopes": ["READ", "CREATE", "INDEX", "OBJECTPERMISSIONS", "USERMANAGEMENT"]}' \
  localhost:9000 authn.Encryptonize.CreateUser)
echo "output: $OUTPUT"
echo "-------------------------------------"
export USER_ID=$(jq -r '.userId' <<< "${OUTPUT}")
export PASSWORD=$(jq -r '.password' <<< "${OUTPUT}")


# login as regular user
echo '[+] login regular user'
OUTPUT=$(grpcurl -plaintext \
  -d "{\"userId\": \"${USER_ID}\", \"password\": \"${PASSWORD}\"}" \
  localhost:9000 authn.Encryptonize.LoginUser)
echo "output: $OUTPUT"
echo "-------------------------------------"
export ACCESS_TOKEN=$(jq -r '.accessToken' <<< "${OUTPUT}")


# store data
export PLAINTEXT=$(echo 'plaintext data to be stored' | base64)
export ASSOCIATED_DATA=$(echo 'associated data to be stored' | base64)

echo '[+] storing data'
OUTPUT=$(grpcurl -plaintext \
  -H "authorization:bearer ${ACCESS_TOKEN}" \
  -d "{\"plaintext\": \"${PLAINTEXT}\", \"associatedData\": \"${ASSOCIATED_DATA}\"}" \
  localhost:9000 storage.Encryptonize.Store)
echo "output: $OUTPUT"
echo "-------------------------------------"
export OBJECT_ID=$(jq -r '.objectId' <<< "${OUTPUT}")


# retrieve data
echo '[+] retrieving data'
OUTPUT=$(grpcurl -plaintext \
  -H "authorization:bearer ${ACCESS_TOKEN}" \
  -d "{\"objectId\": \"${OBJECT_ID}\"}" \
  localhost:9000 storage.Encryptonize.Retrieve)
echo "output: $OUTPUT"

export RETRIEVED_PLAINTEXT=$(jq -r '.plaintext' <<< "${OUTPUT}")
export RETRIEVED_ASSOCIATED_DATA=$(jq -r '.associatedData' <<< "${OUTPUT}")

echo "plaintext: $(echo $RETRIEVED_PLAINTEXT| base64 -d)"
echo "associated data: $(echo $RETRIEVED_ASSOCIATED_DATA| base64 -d)"
