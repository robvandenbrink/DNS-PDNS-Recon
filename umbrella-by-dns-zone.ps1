# for documentatin, reference isc.sans.edu blog at:
# https://isc.sans.edu/diary/DNS+Recon+Redux+Zone+Transfers+plus+a+time+machine+for+When+You+Cant+do+a+Zone+Transfer/29552

$apikey = "YOUR API KEY GOES HERE"

$headers = @{
'Authorization'="Bearer "+$apikey
}

$domain = "domainname.com"

$validArecords = @()
$validOtherRecords =@()
$notvalidrecords = @()
$dnsrecords =@()

# set the countval to 20 so that the loop will start
$loopcount = 0
$countval = 20

while($countval -ge 20) {
    if ($loopcount -gt 0) {
        # if this is not the first loop through, get the offset and apply it
        $offsetname = ($dnsrecords | select-object -last 1).name
        $callstring = "https://investigate.umbrella.com/subdomains/" + $domain + "?offsetName="+$offsetname
        } else {
        $callstring = "https://investigate.umbrella.com/subdomains/" + $domain
        }
    
    $retvals = invoke-webrequest -Method 'Get' -uri $callstring -headers $headers -ContentType "application/json"    
    $records = ($retvals.content | convertfrom-json) | select firstseen, name
    $countval = $records.count
    $dnsrecords += $records
    write-host "Count is " $dnsrecords.count
    $loopcount += 1
    }

# Convert all the "first seen" dates from Unix Epoch to Strings
# also test each records and assign each to the correct list

foreach ($val in $dnsrecords) {
  # First, fix the "first seen" date
  $date2 = (Get-Date 01.01.1970).AddSeconds($val.firstseen)  
  $val.firstseen = ($date2).ToString("yyyy-MM-dd")  
  #next, separate out the current A records and expired A records
     if($record = resolve-dnsname -name $val.name -type a -ErrorAction SilentlyContinue) {
        # record is valid - add the ip and update thev valid list 
        # check for other record types (SOA, NS, MX etc)              
        if($record.type -ne "A") {
              $validotherrecords += $record
            } else { 
            # these are the target valid A records  
            $tempval = $val
            $tempval | add-member -membertype noteproperty -name ipaddress -value $record.ipaddress
            $validArecords += $tempval
            }
    } else {
        # record is not valid, update the list of invalid records
        $notvalidrecords += $val
    }
}


