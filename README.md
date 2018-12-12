# HawkScan

![alt tag](https://user-images.githubusercontent.com/29504335/43905037-75a2a9ea-9bf0-11e8-8d6b-2de51318be98.jpg)

Security Tool for Reconnaissance and Information Gathering on a website. (python 2.7)

This script use the sublist3r lib to check subdomains.

# Features
 - [x] URL fuzzing and dir/file detection
 - [x] Check header information
 - [x] Check DNS information
 - [x] Check whois information
 - [x] User-agent random or personal
 - [x] Extract robots.txt & sitemap.xml
 - [x] Keep a trace of the scan
 - [x] Check @mail in the website and check if @mails leaked
 - [x] CMS detection + version and vulns
 - [x] Subdomain Checker

# TODO
 - [ ] Automatic virtual environement to execute the script
 - [ ] Best backup files analyse
 - [ ] Testing params of website
 - [ ] Get certificate (crypto keys...)
 - [ ] Recursif dir/file
 - [ ] Anonymous routing through Tor
 - [ ] backup system (if the script stopped, it take again in same place)
 - [ ] check github & pastebin
 - [ ] mutli website scan
 
 # Usage
 > usage: hawkscan.py [-h] [-u URL] [-w WORDLIST] [-s SUBDOMAINS] [-t THREAD] [-a USER_AGENT]
 
 > optional arguments: 
  > -h, --help     show this help message and exit                                                                     
  > -u URL         URL to scan [required]                                                                              
  > -w WORDLIST    Wordlist used for URL Fuzzing [required]                                                            
  > -s SUBDOMAINS  subdomain tester                                                                                    
  > -t THREAD      Number of threads to use for URL Fuzzing. Default: 5                                                
  > -a USER_AGENT  choice user-agent 
