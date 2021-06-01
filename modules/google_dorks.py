#! /usr/bin/env python
# -*- coding: utf-8 -*-
try:
    from degoogle import dg
except:
    from modules.degoogle import dg
import sys
import requests
from config import WARNING, INFO, LINE
import time
import traceback

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
    print(INFO + "GOOGLE DORK")
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
    degoogler = dg()
    for query in queries:
        print("{}{}\n".format(INFO, query))
        degoogler.query = query
        results = degoogler.run()
        try:
            for result in results:
                try:
                    req_url_found = requests.get(result['url'], verify=False, timeout=3)
                    if req_url_found.status_code not in [404, 408, 503, 405, 428, 412, 429]:
                        print(" \033[32m[{}]\033[0m {}".format(req_url_found.status_code, result['url']))
                        with open(directory+"/site/{}/google_dorks.txt".format(directory), "a+") as raw:
                            raw.write("{}\n".format(result['url']))
                    elif req_url_found.status_code in [403, 401]:
                        print(" \033[31m[{}]\033[0m {}".format(req_url_found.status_code, result['url']))
                    else:
                        print(" \033[31m[{}]\033[0m {}".format(req_url_found.status_code, result['url']))
                except:
                    print("{}Error with URL {}".format(WARNING, result['url']))
        except:
            #traceback.print_exc()
            pass
        print("")
    print(LINE)


"""def query_cse(domain, directory):
    https://cse.google.com/cse?cx=002972716746423218710:veac6ui3rio#gsc.q=domain
    url_cse = "https://cse.google.com/cse?cx=002972716746423218710:veac6ui3rio#gsc.q={}".format(domain)
    print(INFO + "CSE")
    print(LINE)

    print(LINE)"""#TODO

"""if __name__ == '__main__':
    domain = "https://www..fr/" #DEBUG
    query_dork(domain)"""