echo $1
curl -s  "https://investigate.api.umbrella.com//pdns/ip/$1" -H 'Authorization: Bearer <API KEY>' -H 'Content-Type: application/json' | jq | tee $1.ip.umbrella.txt
