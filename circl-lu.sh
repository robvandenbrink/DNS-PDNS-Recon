curl -s -k -u <userid>:<API Key> -X GET "https://www.circl.lu/pdns/query/$1" -H "accept: application/json" | jq
