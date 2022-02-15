# HawkScan

[![PyPI version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=py&type=6&v=2.1&x2=0)](https://pypi.org/project/hawkscan)
[![PyPI Statistics](https://img.shields.io/pypi/dm/hawkscan.svg)](https://pypistats.org/packages/hawkscan)
[![Twitter](https://img.shields.io/twitter/follow/c0dejump?label=c0dejump&style=social)](https://twitter.com/intent/follow?screen_name=c0dejump)


![alt tag](https://github.com/c0dejump/HawkScan/blob/master/static/logo_hawkscan.jpeg)

Security Tool for Reconnaissance and Information Gathering on a website. (python 3.x)

- [News](https://github.com/c0dejump/HawkScan/#News)
- [Installation](https://github.com/c0dejump/HawkScan/#Installation)
- [Special features](https://github.com/c0dejump/HawkScan/#Special-features)
- [TODO](https://github.com/c0dejump/HawkScan/#todo)
- [Usage](https://github.com/c0dejump/HawkScan/#usage)
- [Exemples](https://github.com/c0dejump/HawkScan/#exemples)
- [Thanks](https://github.com/c0dejump/HawkScan/#thanks)
- [Donations](https://github.com/c0dejump/HawkScan/#donations)
- [Tools used](https://github.com/c0dejump/HawkScan/#tools-used)
- [Wiki](https://github.com/c0dejump/HawkScan/wiki)

# News v2.x
    - Redefining priorities/tasks
    - Let's debug certificate subdomains results
    - Display the current bypass number during scan ("CB:")
    - Easter egg for xmas :)
    - Option -nfs (not first step) to pass the first recon steps
    - Google CSE before scan
    - Creation of WIKI
*(for more details go on CHANGELOG.md)* 
 
# Installation
``` 

       - git clone https://github.com/c0dejump/HawkScan.git && sudo python3 HawkScan/setup.py install
       
       - pip(3) install -r requirements.txt 
    
       - python3 -m pip install -r requirements.txt

``` 

# Special features

### Before scan
 - [x] Check header information
 - [x] Check DNS information
 - [x] Check Github
 - [x] CMS detection + version and vulns
 - [x] Check in waybackmachine
 - [x] Check if DataBase firebaseio existe and accessible
 - [x] Testing if it's possible scanning with "localhost" host
 - [x] Check Google Dork 
 - [x] Check Host IP
 - [x] Check backup domain name (ex: www.domain.com/domain.zip)
 - [x] Check socketio connection
 - [x] cse google search (buckets...)

### During - After scan
 - [x] Test backup/old file on all the files found (index.php.bak, index.php~ ...)
 - [x] Backup system (if the script stopped, it take again in same place)
 - [x] WAF detection and Response error to WAF + Testing bypass it
 - [x] Option --exclude to exclude page, code error, bytes
 - [x] Option rate-limit if app is unstable (--timesleep)
 - [x] Search S3 buckets in source code page
 - [x] Try differents bypass for 403/401 code error
 - [x] JS parsing and analysis (option --js)
 - [x] Auto resize relative to window
 - [x] Notify when scan completed (Only work on Linux)
 - [x] Multiple output format. Available formats: json, csv, txt
 - [x] Multiple website scanning
 - [x] Prefix filename (old_, copy of...)
 
# TODO 
**P1 is the most important**

 [WIP] Multiple exclude like: --exclude 403,1337b [P1] [In progress] (see [Exemples](https://github.com/c0dejump/HawkScan/#exemples))
 - [ ] asyncio instead of threading ? [PX]
 - [ ] Add crt.sh to check potential hidden subdomain (with letdebug module ?) [P1]
 - [ ] Re-build resport scan [P1]
 - [ ] Push results into DB [P2]
 - [ ] If re-scan a website with an existing folder, just doing a diff btw the scan to the folder (like) // interesting ? [P2]
 - [ ] Pre-run to check the waf sensitive (by proxy with 40 threads for exemple) // add proxy funtion [P2]
 - [ ] Check HTTP headers/ssl security: securityheaders; digicert ? [P3]
 - [ ] Anonymous routing through some proxy (http/s proxy list) [P3]
 - [ ] Check source code and verify leak or sensitive data in the Github // Other tool ? [P3]
 - [ ] Analyse html code webpage [P3] => really necessary ?
 - [ ] Scan API endpoints/informations leaks [P3]

# Usage
  
```
     
    usage: hawkscan.py [-h] [-u URL] [-f FILE_URL] [-t THREAD] [--exclude EXCLUDE [EXCLUDE ...]] [--auto] [--update] [-w WORDLIST] [-b [BACKUP ...]] [-p PREFIX] [-H HEADER_] [-a USER_AGENT] [--redirect] [--auth AUTH] [--timesleep TS] [--proxie PROXIE] [-r] [-s SUBDOMAINS] [--js] [--nfs] [--ffs] [--notify] [-o OUTPUT] [-of OUTPUT_TYPE]    
 
```

``` 
> General:
    -u URL                URL to scan [required]
    -f FILE_URL           file with multiple URLs to scan
    -t THREAD             Number of threads to use for URL Fuzzing. Default: 30
    --exclude EXCLUDE [EXCLUDE ...] Exclude page, response code, response size. (Exemples: --exclude 500,337b)   
    --auto                Automatic threads depending response to website. Max: 30
    --update              For automatic update

> Wordlist Settings:
    -w WORDLIST           Wordlist used for Fuzzing the desired webite. Default: dichawk.txt     
    -b                    Adding prefix/suffix backup extensions during the scan. (Exemples: exemple.com/~ex/, exemple.com/ex.php.bak...) beware, take more longer
    -p PREFIX             Add prefix in wordlist to scan

> Request Settings:             
    -H HEADER_            Modify header. (Exemple: -H "cookie: test")    
    -a USER_AGENT         Choice user-agent. Default: Random    
    --redirect            For scan with redirect response (301/302)      
    --auth AUTH           HTTP authentification. (Exemples: --auth admin:admin)               
    --timesleep TS        To define a timesleep/rate-limit if app is unstable during scan.

> Tips:            
    -r                    Recursive dir/files      
    -s SUBDOMAINS         Subdomain tester         
    --js                  For try to found keys or token in the javascript page
    --nfs                 Not the first step of scan during the first running (waf, vhosts, wayback etc...)    
    --ffs                 Force the first step of scan during the first running (waf, vhosts, wayback etc...)              
    --notify              For receveid notify when the scan finished (only work on linux)

> Export Settings:                    
    -o OUTPUT             Output to site_scan.txt (default in website directory)     
    -of OUTPUT_TYPE       Output file format. Available formats: json, csv, txt           
```

# Exemples

```
    //Basic
     python hawkscan.py -u https://www.exemple.com/

    //With specific dico
     python hawkscan.py -u https://www.exemple.com/ -w dico_extra.txt

    //with 30 threads
     python hawkscan.py -u https://www.exemple.com/ -t 30

    //With backup files scan
     python hawkscan.py -u https://www.exemple.com/ -b

    //With an exclude page
     python hawkscan.py -u https://www.exemple.com/ --exclude https://www.exemple.com/profile.php?id=1

    //With an exclude response code
     python hawkscan.py -u https://www.exemple.com/ --exclude 403

    //With an exclude bytes number
     python hawkscan.py -u https://www.exemple.com/ --exclude 1337b 

    //With two excludes
     python hawkscan.py -u https://www.exemple.com/ --exclude 1337b,403

```

# Thanks
Layno (https://github.com/Clayno/) [Technical helper]      
Sanguinarius (https://twitter.com/sanguinarius_Bt) [Technical helper]  
Jamb0n69 (https://twitter.com/jamb0n69) [Technical helper]           
Cyber_Ph4ntoM (https://twitter.com/__PH4NTOM__) [Beta tester & Logo Graphist]


# Donations

https://www.paypal.me/c0dejump

Or if you want to offer me a coffee :)

https://ko-fi.com/c0dejump

## Tools used

This script use "WafW00f" to detect the WAF in the first step (https://github.com/EnableSecurity/wafw00f)

This script use "Sublist3r" to scan subdomains (https://github.com/aboul3la/Sublist3r)
