# HawkScan

![alt tag](https://github.com/c0dejump/HawkScan/blob/master/static/hawkscan_logo.jpeg)

Security Tool for Reconnaissance and Information Gathering on a website. (python 3.x)

- [News](https://github.com/c0dejump/HawkScan/#News)
- [Installation](https://github.com/c0dejump/HawkScan/#Installation)
- [Special features](https://github.com/c0dejump/HawkScan/#Special-features)
- [TODO](https://github.com/c0dejump/HawkScan/#todo)
- [Usage](https://github.com/c0dejump/HawkScan/#usage)
- [Exemples](https://github.com/c0dejump/HawkScan/#exemples)
- [Thanks](https://github.com/c0dejump/HawkScan/#thanks)
- [Donations](https://github.com/c0dejump/HawkScan/#paypal)
- [Tools used](https://github.com/c0dejump/HawkScan/#tools-used)

# News
**!** Updated: New logo made by Cyber_Ph4ntoM   
**!** Updated: Code review        
*(for more details go on CHANGELOG.md)*   
 
# Installation
``` 

       git clone https://github.com/c0dejump/HawkScan.git && sudo python3 HawkScan/setup.py install

       pip(3) install -r requirements.txt 
    Or:    
       sudo python3 -m pip install -r requirements.txt

``` 

# Special features
 - [x] Test backup/old file on all the files found (index.php.bak, index.php~ ...)
 - [x] Check header information
 - [x] Check DNS information
 - [x] Check email in the website and in same time if emails leaked (report)
 - [x] CMS detection + version and vulns
 - [x] Backup system (if the script stopped, it take again in same place)
 - [x] WAF detection and Response error to WAF + Testing bypass it
 - [x] Check Github
 - [x] Option --exclude to exclude page, code error, bytes
 - [x] Option rate-limit if app is unstable (--timesleep)
 - [x] Check in waybackmachine
 - [x] Check if DataBase firebaseio existe and accessible
 - [x] Search S3 buckets in source code page
 - [x] Testing if it's possible scanning with "localhost" host
 - [x] Try differents bypass for 403 code error
 - [x] JS parsing and analysis (option --js)
 - [x] Check Google Dork 
 - [x] Check Host IP
 - [x] Auto resize relative to window
 - [x] Check backup domain name (ex: www.domain.com/domain.zip)
 - [x] Check socketio connection
 - [x] Notify when scan completed (Only work on Linux)
 
# TODO 
**P1 is the most important**

 - [~] Multiple exclude like: --exclude 403,1337b [P1]
 - [ ] Multiple output (csv, json...) [P1]
 - [ ] Push results into DB [P1]
 - [ ] Pre-run to chck the waf sensitive (by proxy with 40 threads for exemple) [P2]
 - [ ] cse google search (buckets...) [P2]
 - [ ] On-the-fly writing report [P2]
 - [ ] Prefix filename (old_, copy of...) [P2]
 - [ ] Multiple website scanning [P2]
 - [ ] Check HTTP headers/ssl security [P3]
 - [ ] Anonymous routing through some proxy (http/s proxy list) [P3]
 - [ ] Check source code and verify leak or sensitive data in the Github [P3]
 - [ ] Analyse html code webpage [P3] => really necessary?
 - [ ] Check phpmyadmin version [P3]
 - [ ] Scan API endpoints/informations leaks [ASAP]
 - [ ] Active JS on website 2.0 (full js) + Webengine for MacOS [ASAP]

# Usage
  
```
     
    usage: hawkscan.py [-h] [-u URL] [-w WORDLIST] [-s SUBDOMAINS] [-t THREAD] [-a USER_AGENT] [--redirect] [-r] [-p PREFIX] [-o OUTPUT] [--cookie COOKIE_] [--exclude EXCLUDE] [--timesleep TS] [--auto] [--js] [--auth AUTH] [-ffs] [--notify]  
 
```

``` 
> General:
    -u URL                URL to scan [required]
    -t THREAD             Number of threads to use for URL Fuzzing. Default: 20
    --exclude EXCLUDE [EXCLUDE ...] Exclude page, response code, response size. (Exemples: --exclude 500,337b)   
    --auto                Automatic threads depending response to website. Max: 30
    --update              For automatic update

> Wordlist Settings:
    -w WORDLIST           Wordlist used for Fuzzing the desired webite. Default: dico.txt     
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
    --ffs                 Force the first step of scan during the first running (waf, vhosts, wayback etc...)              
    --notify              For receveid notify when the scan finished (only work on linux)

> Export Settings:                    
    -o OUTPUT             Output to site_scan.txt (default in website directory)            
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

    //With two exclude
     python hawkscan.py -u https://www.exemple.com/ --exclude 1337b,403

```

# Thanks
Layno (https://github.com/Clayno/) [Technical helper]      
Sanguinarius (https://twitter.com/sanguinarius_Bt) [Technical helper]  
Jamb0n69 (https://twitter.com/jamb0n69) [Technical helper]           
Cyber_Ph4ntoM (https://twitter.com/__PH4NTOM__) [Beta tester]


# Paypal

https://www.paypal.me/c0dejump

## Tools used

This script use "WafW00f" to detect the WAF in the first step (https://github.com/EnableSecurity/wafw00f)

This script use "Sublist3r" to scan subdomains (https://github.com/aboul3la/Sublist3r)

This script use "waybacktool" to check in waybackmachine (https://github.com/Rhynorater/waybacktool)

This script use "degoogle" to check google dork queries (https://github.com/deepseagirl/degoogle)
