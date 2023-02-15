
When in the recon phase of a security assessment or penetration test, quite often you want to collect the dns names for all hosts in a scope of IP addresses.  I covered how to do that with a few different APIs in this story: (https:

On the flip-side, quite often you want to collect DNS records of all hosts in a domain.  With more folks using wildcard certificates these days, certificate transparency isn't always the goldmine that it used to be for that (https ...)

What to do?  The various OSINT repositories (and commercial intelligence repos) have an answer for you.

For DNS Dumpster, this will list what you seek:
curl -k "https://api.hackertarget.com/hostsearch/?q=sans.edu"
isc.sans.edu,45.60.31.34
www.sans.edu,45.60.31.34

That seems like a short list to me though, let's look at Cisco Umbrella (which uses OpenDNS as it's back-end database):

curl -s -k "https://investigate.umbrella.com/subdomains/sans.edu" -H "Authorization: Bearer <APIKEY>" -H "Content-Type: application/json"  | jq
[
  {
    "securityCategories": [],
    "firstSeen": "1627675727",
    "name": "_dmarc.sans.edu"
  },
  {
    "securityCategories": [],
    "firstSeen": "1627675727",
    "name": "_domainkey.sans.edu"
  },
..... and so on

Getting a count:

curl -s -k "https://investigate.umbrella.com/subdomains/sans.edu" -H "Authorization: Bearer <APIKEY>" -H "Content-Type: application/json"  | jq | grep name | wc -l
     20

This is because this API returns values 20 at a time, you use the last value returned as an offset to get the next batch.
What's that, you say?  Sounds like a script?  Great idea you!

Looking one step ahead, after this list is created, we want to collect all of them that are still valid A records, so that we have a list of target hosts to dig deeper in to.

So along the way, let's take all the records that are found and divvy them up into 3 lists:
$validARecords - this is mostly what we're looking for - valid DNS A records for hosts in the domain, which we can use for targets
$validother records - these are other DNS records (MX, NS, SOA, TXT etc).  Useful, but not usually direct (in scope) targets
$notvalidrecords - these are dns records that no longer resolve, these records did exist at one time but have since been removed

This API call also returns a "first seen" date in Unix Epoch time (seconds since 1 Jan, 1970) - since we're coding, let's convert that to readable text along the way, it might be useful in subsequent phases of your gig.

Putting this all into code:


$apikey = "YOUR API KEY GOES HERE"

$headers = @{
'Authorization'="Bearer "+$apikey
}

$domain = "sans.edu"

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



So, what's in the final lists:

These list of course are the primary targets (in your customer's domain of course):

 $validarecords

firstSeen  name                     ipaddress
---------  ----                     ---------
2021-01-25 email.sans.edu           136.147.129.27
2022-09-28 localhost.email.sans.edu 127.0.0.1
2017-03-13 isc.sans.edu             {45.60.31.34, 45.60.103.34}
2014-08-03 www.sans.edu             45.60.31.34

These are also valid records, the CNAME records in particular will be of interest (for instance for multiple websites on the same host):

$validotherrecords | select name,querytype

Name                                                      QueryType
----                                                      ---------
sans.edu                                                        SOA
sans.edu                                                        SOA
autodiscover.alumni.sans.edu                                  CNAME
autodiscover.outlook.com                                      CNAME
autod.ha-autod.office.com                                     CNAME
autod.ms-acdc-autod.office.com                                    A
autod.ms-acdc-autod.office.com                                    A
autod.ms-acdc-autod.office.com                                    A
autod.ms-acdc-autod.office.com                                    A
enterpriseenrollment.alumni.sans.edu                          CNAME
enterpriseenrollment.manage.microsoft.com                     CNAME
manage-pe.trafficmanager.net                                  CNAME
pexsucpna01.westus.cloudapp.azure.com                             A
enterpriseregistration.alumni.sans.edu                        CNAME
enterpriseregistration.windows.net                            CNAME
adrs.privatelink.msidentity.com                               CNAME
www.tm.prd.adrs.trafficmanager.net                                A
lyncdiscover.alumni.sans.edu                                  CNAME
webdir.online.lync.com                                            A
msoid.alumni.sans.edu                                         CNAME
clientconfig.microsoftonline-p.net                            CNAME
a.privatelink.msidentity.com                                  CNAME
prda.aadg.msidentity.com                                      CNAME
www.tm.a.prd.aadg.trafficmanager.net                              A
www.tm.a.prd.aadg.trafficmanager.net                              A
www.tm.a.prd.aadg.trafficmanager.net                              A
www.tm.a.prd.aadg.trafficmanager.net                              A
www.tm.a.prd.aadg.trafficmanager.net                              A
www.tm.a.prd.aadg.trafficmanager.net                              A
www.tm.a.prd.aadg.trafficmanager.net                              A
www.tm.a.prd.aadg.trafficmanager.net                              A
sip.alumni.sans.edu                                           CNAME
sipdir.online.lync.com                                            A
application.sans.edu                                          CNAME
cluster.technolutions.net                                         A
autodiscover.sans.edu                                         CNAME
autodiscover.outlook.com                                      CNAME
autod.ha-autod.office.com                                     CNAME
autod.ms-acdc-autod.office.com                                    A
autod.ms-acdc-autod.office.com                                    A
autod.ms-acdc-autod.office.com                                    A
autod.ms-acdc-autod.office.com                                    A
canvas.sans.edu                                               CNAME
sans-vanity.instructure.com                                   CNAME
canvas-iad-prod-c92-449975756.us-east-1.elb.amazonaws.com         A
canvas-iad-prod-c92-449975756.us-east-1.elb.amazonaws.com         A
canvas-iad-prod-c92-449975756.us-east-1.elb.amazonaws.com         A
email.sans.edu                                                  SOA
email.sans.edu                                                  SOA
email.sans.edu                                                  SOA
email.sans.edu                                                  SOA
email.sans.edu                                                  SOA
enterpriseenrollment.sans.edu                                 CNAME
enterpriseenrollment.manage.microsoft.com                     CNAME
manage-pe.trafficmanager.net                                  CNAME
pexsucpna02.eastus.cloudapp.azure.com                             A
enterpriseregistration.sans.edu                               CNAME
enterpriseregistration.windows.net                            CNAME
adrs.privatelink.msidentity.com                               CNAME
www.tm.prd.adrs.akadns.net                                        A
handlers.sans.edu                                             CNAME
handlers.dshield.org                                              A
isctv.sans.edu                                                CNAME
ee7zbpo.x.incapdns.net                                            A
lyncdiscover.sans.edu                                         CNAME
webdir.online.lync.com                                            A
mp3.sans.edu                                                  CNAME
web-server.libsyn.com                                             A
msoid.sans.edu                                                CNAME
clientconfig.microsoftonline-p.net                            CNAME
a.privatelink.msidentity.com                                  CNAME
prda.aadg.msidentity.com                                      CNAME
www.tm.a.prd.aadg.akadns.net                                      A
www.tm.a.prd.aadg.akadns.net                                      A
www.tm.a.prd.aadg.akadns.net                                      A
www.tm.a.prd.aadg.akadns.net                                      A
www.tm.a.prd.aadg.akadns.net                                      A
www.tm.a.prd.aadg.akadns.net                                      A
www.tm.a.prd.aadg.akadns.net                                      A
www.tm.a.prd.aadg.akadns.net                                      A
sip.sans.edu                                                  CNAME
sipdir.online.lync.com                                            A
slate-mx.sans.edu                                             CNAME
sg.technolutions.net                                          CNAME
wl.sendgrid.net                                                 SOA
sans.edu                                                        SOA
sans.edu                                                        SOA
autodiscover.student.sans.edu                                 CNAME
autodiscover.outlook.com                                      CNAME
autod.ha-autod.office.com                                     CNAME
autod.ms-acdc-autod.office.com                                    A
autod.ms-acdc-autod.office.com                                    A
autod.ms-acdc-autod.office.com                                    A
autod.ms-acdc-autod.office.com                                    A
enterpriseenrollment.student.sans.edu                         CNAME
enterpriseenrollment.manage.microsoft.com                     CNAME
manage-pe.trafficmanager.net                                  CNAME
pexsucpna01.westus.cloudapp.azure.com                             A
enterpriseregistration.student.sans.edu                       CNAME
enterpriseregistration.windows.net                            CNAME
adrs.privatelink.msidentity.com                               CNAME
www.tm.prd.adrs.trafficmanager.net                                A
lyncdiscover.student.sans.edu                                 CNAME
webdir.online.lync.com                                            A
msoid.student.sans.edu                                        CNAME
clientconfig.microsoftonline-p.net                            CNAME
a.privatelink.msidentity.com                                  CNAME
prda.aadg.msidentity.com                                      CNAME
www.tm.a.prd.aadg.akadns.net                                      A
www.tm.a.prd.aadg.akadns.net                                      A
www.tm.a.prd.aadg.akadns.net                                      A
www.tm.a.prd.aadg.akadns.net                                      A
www.tm.a.prd.aadg.akadns.net                                      A
www.tm.a.prd.aadg.akadns.net                                      A
www.tm.a.prd.aadg.akadns.net                                      A
www.tm.a.prd.aadg.akadns.net                                      A
sip.student.sans.edu                                          CNAME
sipdir.online.lync.com                                            A

Finally, the invalid list - records that have been removed:

$notvalidrecords

firstSeen  name
---------  ----
2021-07-30 _dmarc.sans.edu
2021-07-30 _domainkey.sans.edu
2020-09-15 eiqu3eingae1ha9ja4phepaivahqu9xo._domainkey.sans.edu
2020-11-01 isc._domainkey.sans.edu
2020-10-12 phoa1ohmail7shai9aisheih1no3phap._domainkey.sans.edu
2021-04-30 pp1._domainkey.sans.edu
2020-03-11 s1._domainkey.sans.edu
2020-11-13 scph0718._domainkey.sans.edu
2019-04-01 selector1._domainkey.sans.edu
2019-05-29 selector2._domainkey.sans.edu
2020-09-17 slt._domainkey.sans.edu
2021-10-12 slt2._domainkey.sans.edu
2017-02-03 apply.sans.edu
2021-07-03 dev-isc3.sans.edu
2021-07-03 dev-isc32.sans.edu
2020-03-11 em5068.sans.edu
2021-08-30 _domainkey.isc.sans.edu
2020-09-03 isc._domainkey.isc.sans.edu
2021-07-03 isc3.sans.edu
2014-09-03 isc31.sans.edu
2014-07-10 isc32.sans.edu
2014-06-24 iscold.sans.edu
2015-06-21 mastersprogram.sans.edu
2019-05-16 pre-isc3.sans.edu
2016-10-28 pre-isc31.sans.edu
2015-05-19 pre-www.sans.edu
2021-02-26 preview.sans.edu
2021-07-03 s1-www.sans.edu
2021-07-03 s1-www31.sans.edu
2021-09-20 s10-www.sans.edu
2021-07-03 s10-www31.sans.edu
2021-07-03 s11-www31.sans.edu
2021-06-03 s12-www.sans.edu
2021-07-03 s12-www31.sans.edu
2021-07-03 s12-www32.sans.edu
2018-09-14 s120-www.sans.edu
2021-07-03 s121-www.sans.edu
2021-07-03 s123-www.sans.edu
2021-07-03 s124-www.sans.edu
2021-07-03 s126-www.sans.edu
2021-07-03 s127-www.sans.edu
2021-07-03 s128-www.sans.edu
2021-07-03 s129-www.sans.edu
2021-07-03 s13-www31.sans.edu
2021-07-03 s14-www.sans.edu
2021-07-03 s14-www32.sans.edu
2021-06-03 s15-www.sans.edu
2021-07-03 s15-www31.sans.edu
2021-07-03 s16-www.sans.edu
2021-07-03 s16-www31.sans.edu
2021-07-03 s17-www.sans.edu
2021-07-03 s17-www31.sans.edu
2015-08-29 s18-www.sans.edu
2021-07-03 s18-www32.sans.edu
2021-07-03 s19-www31.sans.edu
2021-07-03 s19-www32.sans.edu
2021-07-03 s2-www.sans.edu
2021-07-03 s2-www32.sans.edu
2021-07-03 s21-www.sans.edu
2021-11-30 s22-www32.sans.edu
2021-06-03 s23-www.sans.edu
2021-07-03 s23-www31.sans.edu
2021-07-03 s24-www.sans.edu
2021-06-03 s27-www.sans.edu
2021-07-03 s27-www31.sans.edu
2021-07-03 s3-www31.sans.edu
2021-07-03 s4-www31.sans.edu
2021-07-03 s4-www32.sans.edu
2021-06-03 s42-www.sans.edu
2021-07-03 s42-www31.sans.edu
2021-07-03 s5-www.sans.edu
2017-01-26 s51-www.sans.edu
2021-07-03 s51-www31.sans.edu
2021-07-03 s52-www.sans.edu
2021-07-03 s52-www32.sans.edu
2021-07-03 s53-www31.sans.edu
2021-07-03 s54-www31.sans.edu
2016-05-09 s55-www.sans.edu
2021-07-03 s55-www31.sans.edu
2021-07-03 s55-www32.sans.edu
2021-07-03 s56-www.sans.edu
2021-07-03 s57-www.sans.edu
2021-07-03 s57-www31.sans.edu
2021-07-03 s57-www32.sans.edu
2021-07-03 s58-www31.sans.edu
2021-07-03 s58-www32.sans.edu
2021-07-03 s6-www.sans.edu
2022-01-09 s6-www31.sans.edu
2021-07-03 s6-www32.sans.edu
2021-07-03 s7-www.sans.edu
2017-07-16 s70-www.sans.edu
2021-07-03 s72-www.sans.edu
2021-07-03 s75-www.sans.edu
2020-07-13 s79-www.sans.edu
2017-01-20 s8-www.sans.edu
2020-02-12 s81-www.sans.edu
2021-07-03 s83-www.sans.edu
2021-11-15 s85-www.sans.edu
2019-03-07 s87-www.sans.edu
2021-09-29 s89-www.sans.edu
2021-07-03 s9-www.sans.edu
2015-05-26 search.sans.edu
2020-07-13 vex.sans.edu
2015-04-15 www2.sans.edu
2015-02-26 www3.sans.edu