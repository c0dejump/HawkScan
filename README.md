# HawkScan

![alt tag](https://user-images.githubusercontent.com/29504335/43905037-75a2a9ea-9bf0-11e8-8d6b-2de51318be98.jpg)

Security Tool for Reconnaissance and Information Gathering on a website. (python 2.7)

This script use "WafW00f" to detect the WAF (https://github.com/EnableSecurity/wafw00f)

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

# TODO
 - [ ] Testing website paramaters (attack, so no passive scan)
 - [ ] Get certificate (crypto keys...)
 - [ ] Recursif dir/file
 - [ ] Anonymous routing through some proxy (http/s proxy list)
 - [ ] Check github & pastebin
 - [ ] Mutli website subdomain scan
 - [ ] Spider link in website
 - [ ] Best subdomain found and analyze
 - [ ] Check if it's an user or a page
 - [ ] Backup file csv of scan
 - [ ] Work it with py2 and py3
 - [ ] add option "-o" to backup file in directory of your choice
 
 # Usage
 > pip install -r requirements.txt
 
 > usage: hawkscan.py [-h] [-u URL] [-w WORDLIST] [-s SUBDOMAINS] [-t THREAD] [-a USER_AGENT] [--redirect] [-p PREFIX]
 
 > optional arguments: 
  > -h, --help     show this help message and exit                                                                     
  > -u URL         URL to scan [required]                                                                              
  > -w WORDLIST    Wordlist used for URL Fuzzing [required]                                                            
  > -s SUBDOMAINS  subdomain tester                                                                                    
  > -t THREAD      Number of threads to use for URL Fuzzing. Default: 5  
  > -a USER_AGENT  choice user-agent     
  > --redirect     For scan with redirect response like 301,302      
  > -p PREFIX      add prefix in wordlist to scan
