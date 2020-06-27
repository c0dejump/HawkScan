# HawkScan

![alt tag](https://user-images.githubusercontent.com/29504335/43905037-75a2a9ea-9bf0-11e8-8d6b-2de51318be98.jpg)

Security Tool for Reconnaissance and Information Gathering on a website. (python 2.x & 3.x)

This script use "WafW00f" to detect the WAF in the first step (https://github.com/EnableSecurity/wafw00f)

This script use "Sublist3r" to scan subdomains (https://github.com/aboul3la/Sublist3r)

This script use "waybacktool" to check in waybackmachine (https://github.com/Rhynorater/waybacktool)

# News
**!** V 1.2 !   
**!** Adding news words in dico.txt (old dico_extra.txt)  
**!** Adding extensions in backup check test function, option -b (.json, .xml, .bkp...) => very long  
**!** Test bypass of waf rate limited in real time (X-Originating-IP...)    
**!** Exclude response http code (--exclude 403)  
**!** Filter on response http code in report   

# Features
 - [x] URL fuzzing and dir/file detection
 - [x] Test backup/old file on all the files found (index.php.bak, index.php~ ...)
 - [x] Check header information
 - [x] Check DNS information
 - [x] Check whois information
 - [x] User-agent random or personal
 - [x] Extract files
 - [x] Keep a trace of the scan
 - [x] Check @mail in the website and check if @mails leaked
 - [x] CMS detection + version and vulns
 - [x] Subdomain Checker
 - [x] Backup system (if the script stopped, it take again in same place)
 - [x] WAF detection
 - [x] Add personal prefix
 - [x] Auto update script
 - [x] Auto or personal output of scan (scan.txt)
 - [x] Check Github
 - [x] Recursif dir/file
 - [x] Scan with an authenfication cookie
 - [x] Option --profil to pass profil page during the scan
 - [x] HTML report
 - [x] Work it with py2 and py3
 - [x] Add option rate-limit if app is unstable (--timesleep)
 - [x] Check in waybackmachine
 - [x] Response error to WAF
 - [x] Check if DataBase firebaseio existe and accessible
 - [x] Automatic threads depending response to website (and reconfig if WAF detected too many times). Max: 10
 - [x] Search S3 buckets in source code page
 - [x] Testing bypass of waf if detected
 
# TODO 
**P1 is the most important**

 - [ ] JS parsing and analysis [P1]
 - [ ] Scan API endpoints/informations leaks [P1]
 - [ ] On-the-fly writing report [P1]
 - [ ] Check HTTP headers/ssl security [P2]
 - [ ] Check phpmyadmin version [P2]
 - [ ] Fuzzing amazonaws S3 Buckets [P2]
 - [ ] Anonymous routing through some proxy (http/s proxy list) [P2]
 - [ ] Check pastebin [P2]
 - [ ] Access token [P2]
 - [ ] Check source code and verify leak or sentsitive data in the Github [P2]
 - [ ] Testing website paramaters (attack, so no passive scan) [P3]
 - [ ] Detect famous honeypot [P3]
 
 # Usage
 > 
 
       pip(3) install -r requirements.txt 
    If problem with pip3:    
       sudo python3 -m pip install -r requirements.txt
 > 
  
 >
     
    usage: hawkscan.py [-h] [-u URL] [-w WORDLIST] [-s SUBDOMAINS] [-t THREAD] [-a USER_AGENT] [--redirect] [-r] [-p PREFIX] [-o OUTPUT] [--cookie COOKIE_] [--exclude EXCLUDE] [--timesleep TS] [--auto]
 
 > 
 
    optional arguments: 
      -h, --help     show this help message and exit                                                                     
      -u URL         URL to scan [required]                                                                              
      -w WORDLIST    Wordlist used for URL Fuzzing [required]                                                            
      -s SUBDOMAINS  subdomain tester                                                                                    
      -t THREAD      Number of threads to use for URL Fuzzing. Default: 20  
      -a USER_AGENT  choice user-agent     
      --redirect     For scan with redirect response like 301,302      
      -p PREFIX      add prefix in wordlist to scan    
      -o OUTPUT      output to site_scan.txt (default in website directory)      
      -b             Add a backup file scan like 'exemple.com/ex.php.bak...' but longer      
      -r             recursive dir/files       
      --cookie COOKIE  Scan with an authentification cookie   
      --exclude EXCLUDE  To define a page type to exclude during scan    
      --timesleep TS     To define a timesleep/rate-limit if app is unstable during scan 
      --auto          Automatic threads depending response to website. Max: 10    
      --update           For automatic update

 >

# Examples

 >
    //Basic
    python hawkscan.py -u https://www.exemple.com -w dico.txt

    //With redirect
    python hawkscan.py -u https://www.exemple.com -w dico.txt -t 5 --redirect

    //With backup files scan
    python hawkscan.py -u https://www.exemple.com -w dico.txt -t 5 -b

    //With an exclude page
    python hawkscan.py -u https://www.exemple.com -w dico.txt -t 5 --exclude https://www.exemple.com/profile.php?id=1
    
    //With an exclude http code
    python hawkscan.py -u https://www.exemple.com -w dico.txt --exclude 403
 >

# Thanks
Layno   
Sanguinarius   
Cyber_Ph4ntoM   
