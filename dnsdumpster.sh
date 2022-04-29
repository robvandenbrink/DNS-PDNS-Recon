# this service will allow low volume queries without a key, this is the version below
# for higher volume queries and full results, get an API key and reverse the two lines below
curl -s -k https://api.hackertarget.com/reverseiplookup/?q=$1
# curl -s -k https://api.hackertarget.com/reverseiplookup/?q=$1&apikey=<API KEY>
