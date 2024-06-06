#!/bin/bash

HOST="http://127.0.0.1:8000"
# Create a new user
echo "Creating a new user..."
create_response=$(curl -s -X POST "$HOST/users/" -H "Content-Type: application/json" -d '{"username": "233343d3322363", "password": "bar"}')
echo "Response: $create_response"
s
# Extract username from create response (assuming successful creation)
username=$(echo $create_response | jq -r '.username')
# Get an authentication token
echo "Getting an authentication token for $username..."
login_response=$(curl -s -X POST "$HOST/token" -H "Content-Type: application/x-www-form-urlencoded" -d "username=233343d3322363&password=bar")
echo "Login Response: $login_response"
# Extract token (assuming login successful)
token=$(echo $login_response | jq -r '.access_token')

# Use the token to access a protected route
echo "Accessing user profile for $username using the obtained token..."
profile_response=$(curl -s -X GET "$HOST/users/$username" -H "Authorization: Bearer $token")
echo "Profile Response: $profile_response"


## create user test
#curl -X POST http://127.0.0.1:8000/users/ -H "Content-Type: application/json" -d '{"username": "tesste", "password": "testdpadsssdword"}'
## command test benign
##curl -X POST http://127.0.0.1:8000/command -H "Content-Type: application/json" -d '{"code":"echo Hello, World!"}'
# backdoor test
#curl -X POST http://127.0.0.1:8000/rce -H "Content-Type: application/json" -d '{"code":"echo Hello, World!"}'