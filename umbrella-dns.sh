curl https://investigate.api.umbrella.com/whois/nameservers/ns27.worldnic.com?limit=600 -H 'Authorization: Bearer <API Token>' -H 'Content-Type: application/json' | jq | grep \"domain\" | tee $1.umbrella.dns.txt
