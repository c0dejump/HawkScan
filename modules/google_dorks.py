#! /usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import requests
from config import WARNING, INFO, LINE, INFO_MOD, LESS, PLUS
import time
import traceback
from googlesearch import search 
import json

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def timer(length):
    #timer to wait
    start = time.time()
    running = True
    while running:
        if time.time() - start >= length:
            running = False
        else:
            sys.stdout.write(""+ str(length - (time.time() - start)) + " secondes...\r")
            sys.stdout.flush()
    print("\n")
  

def query_dork(domain, directory):
    """
    query_dork: function to search google dork
    """
    key_break = False
    found = False
    answer_yes = False
    print("\033[36m GOOGLE DORK \033[0m")
    print(LINE)
    if 'www' in domain:
        direct = domain.split('.')
        director = direct[1]
        domain = "{}.{}".format(direct[1], direct[2].replace("/",""))
    else:
        direct = domain.split('/')
        director = direct[2]
        domain = director
    ext = domain.split(".")[1]
    bill = 'facture site:{} filetype:pdf'.format(domain) if "fr" in ext else 'bill site:{} filetype:pdf'.format(domain) #FR/EN
    #Didn't hesitate to add your queries
    queries = [
    bill,
    'budget site:{} filetype:pdf'.format(domain),
    'site:{} ext:action OR ext:adr OR ext:ascx OR ext:asmx OR ext:axd OR ext:backup OR ext:bak OR ext:bkf OR ext:bkp OR ext:bok OR ext:achee OR ext:cfg OR ext:cfm OR ext:cgi OR ext:cnf OR ext:conf OR ext:config OR ext:crt OR ext:csr OR ext:csv OR ext:dat OR ext:doc OR ext:docx OR ext:eml OR ext:env OR ext:exe OR ext:gz OR ext:ica OR ext:inf OR ext:ini OR ext:java'.format(domain),
    'site:{} ext:json OR ext:key OR ext:log OR ext:lst OR ext:mai OR ext:mbox OR ext:mbx OR ext:md OR ext:mdb OR ext:nsf OR ext:old OR ext:oraext: OR ext:pac OR ext:passwd OR ext:pcf OR ext:pem OR ext:pgp OR ext:pl OR ext:plist OR ext:pwd OR ext:rdp OR ext:reg OR ext:rtf OR ext:skr OR ext:sql OR ext:swf OR ext:tpl'.format(domain),
    'site:{} ext:txt OR ext:url OR ext:wml OR ext:xls OR ext:xlsx OR ext:xml OR ext:xsd OR ext:yml OR ext:NEW OR ext:save'.format(domain),
    'site:{} intitle:"index of"'.format(domain),
    'site:{} intitle:"index of" .env'.format(domain),
    'intitle:"Dashboard [Jenkins]" {}'.format(domain),
    '"{}" inurl:gitlab OR site:pastebin.com OR site:github.com'.format(domain),
    #'site:http://prezi.com "{}"'.format(domain),
    'site:http://codeshare.io "{}"'.format(domain),
    'site:http://sharecode.io "{}"'.format(domain),
    'site:http://bitbucket.org "{}"'.format(domain),
    'site:*.atlassian.net "{}"'.format(domain),
    '"{}" language:bash pwd'.format(domain),
    'site:http://box.com "{}"'.format(domain)
    ]
    for query in queries:
        print("  {}{}   (Tape ctrl+c to pass)\n".format(INFO_MOD, query))
        try:
            for j in search(query, tld="com", num=5, stop=5, pause=2.6):
                try:
                    req_url_found = requests.get(j, verify=False, timeout=4)
                    if req_url_found.status_code not in [404, 408, 503, 405, 428, 412, 429, 403, 401]:
                        print(" \033[32m[{}]\033[0m {}".format(req_url_found.status_code, j))
                        try:
                            with open(directory+"/site/{}/google_dorks.txt".format(directory), "a+") as raw:
                                raw.write("{}\n".format(j))
                        except:
                            pass
                            #traceback.print_exc() #DEBUG
                    elif req_url_found.status_code in [403, 401]:
                        print(" \033[31m[{}]\033[0m {}".format(req_url_found.status_code, j))
                    else:
                        print(" \033[31m[{}]\033[0m {}".format(req_url_found.status_code, j))
                except:
                    #traceback.print_exc() #DEBUG
                    print("  {}Error with URL {}".format(WARNING, j))
            print("")
        except:
            print("  {} Google captcha seem to be activated, try it later...\n".format(WARNING))
            break
    print(LINE)


def query_cse(domain, directory):
    if 'www' in domain:
        direct = domain.split('.')
        director = direct[1]
        domain = "{}.{}".format(direct[1], direct[2].replace("/",""))
    else:
        direct = domain.split('/')
        director = direct[2]
        domain = director
    print("\033[36m CSE \033[0m")
    print(LINE)
    url_cse = "https://cse.google.com/cse/element/v1?rsz=filtered_cse&num=10&hl=en&source=gcsc&gss=.com&cselibv=ff97a008b4153450&cx=002972716746423218710:veac6ui3rio&q={}&safe=off&cse_tok=AJvRUv3XH0l4xPTPMKG2vDufyCnn:1642524958919&sort=&exp=csqr,cc&oq={}&gs_l=partner-generic.12...0.0.4.4958.0.0.0.0.0.0.0.0..0.0.csems,nrl=13...0.0jj1....34.partner-generic..0.0.0.&cseclient=hosted-page-client&callback=google.search.cse.api1886".format(domain, domain)
    req_cse = requests.get(url_cse, verify=False)
    text = req_cse.text
    cse_json = text.replace("google.search.cse.api1886(","").replace(")", "").replace("/*O_o*/", "").replace(";","").strip()
    if "we can't process" in cse_json:
        print("{} Blocked by the google WAF".format(WARNING))
    else:
        cse_result_decod = json.loads(cse_json)
        try: 
            crd = cse_result_decod["cursor"]["resultCount"]
            print(" {}{} Result found, go on https://cse.google.com/cse?cx=002972716746423218710:veac6ui3rio#gsc.q={}".format(PLUS, crd, domain))
        except:
            print(" {}No result found".format(LESS))       
    print(LINE)

"""if __name__ == '__main__':
    domain = "login-securite.com" #DEBUG
    directory = "test"
    query_cse(domain, "test")"""