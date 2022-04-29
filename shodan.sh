curl -s -k GET "https://api.shodan.io/shodan/host/$1?key=<API KEY>" | tee $1.shodan.txt
