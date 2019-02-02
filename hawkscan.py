#! /usr/bin/env python
# -*- coding: utf-8 -*-

#system libs
import requests
import sys, os, re
import time
import ssl, OpenSSL
import socket
import pprint
import whois
import argparse
from bs4 import BeautifulSoup
import json
#personal libs
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK
from Queue import Queue
from threading import Thread
from fake_useragent import UserAgent
from sublist import sublist


def banner():
    print("""
  _    _                _     _____                 
 | |  | |              | |   / ____|                
 | |__| | __ ___      _| | _| (___   ___ __ _ _ __  
 |  __  |/ _` \ \ /\ / / |/ /\___ \ / __/ _` | '_ \ 
 | |  | | (_| |\ V  V /|   < ____) | (_| (_| | | | |
 |_|  |_|\__,_| \_/\_/ |_|\_\_____/ \___\__,_|_| |_|
                                                    

https://github.com/c0dejump/HawkScan
-------------------------------------------------------------------
    """)


enclosure_queue = Queue()

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

#check mail
def mail(req, directory, all_mail):
    mails = req.text
    # for all @mail
    reg = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    search = re.findall(reg, mails)
    for mail in search:
        #check if email pwned
        if mail:
            datas = { "act" : mail, "accounthide" : "test", "submit" : "Submit" }
            req_ino = requests.post("https://www.inoitsu.com/", data=datas)
            if "DETECTED" in req_ino.text:
                pwnd = "{} pwned ! ".format(mail)
                if pwnd not in all_mail:
                    all_mail.append(pwnd)
            else:
                no_pwned = "{} no pwned ".format(mail)
                if no_pwned not in all_mail:
                    all_mail.append(no_pwned)
    with open(directory + '/mail.txt', 'a+') as file:
        if all_mail is not None and all_mail != [] and all_mail not in file:
            file.write(str(all_mail))

#check subdomains
def subdomain(directory, subdomains):
    print "search subdomains:\n"
    sub_wordlist = "sublist/names.txt"
    sub = sublist.main(subdomains, sub_wordlist, directory)
    with open(directory + "/subdomains.txt", "w+") as file:
        file.write(str(sub))
    print LINE

#sitemap.xml
def sitemap(req, directory):
    soup = BeautifulSoup(req.text, "html.parser")
    with open(directory + '/sitemap.xml', 'w+') as file:
        file.write(str(soup).replace(' ','\n'))

#cms detect use whatcms
def detect_cms(url):
    print INFO + "CMS"
    print LINE
    req = requests.get("https://whatcms.org/APIEndpoint/Detect?key=1481ff2f874c4942a734d9c499c22b6d8533007dd1f7005c586ea04efab2a3277cc8f2&url={}".format(url))
    if "Not Found" in req.text:
        print "{} this website does not seem to use a CMS \n".format(LESS)
        print LINE
    else:
        reqt = json.loads(req.text)
        result = reqt["result"].get("name")
        v = reqt["result"].get("version")
        if v:
            print "{} This website use \033[32m{} {} \033[0m\n".format(PLUS, result, v)
            cve_cms(result, v)
            print LINE + "\n"
        else:
            print "{} This website use \033[32m{}\033[0m but nothing version found \n".format(PLUS, result)
            print LINE

#CVE CMS
def cve_cms(result, v):
    url_comp = "https://www.cvedetails.com/version-search.php?vendor={}&product=&version={}".format(result, v)
    req = requests.get(url_comp, allow_redirects=True, verify=False)
    if not "matches" in req.text:
        print "{}CVE found ! \n{}{}\n".format(WARNING, WARNING, url_comp)
        if 'WordPress' in req.text:
            version =  v.replace('.','')
            site = "https://wpvulndb.com/wordpresses/{}".format(version)
            req = requests.get(site)
            soup = BeautifulSoup(req.text, "html.parser")
            search = soup.find_all('tr')
            if search:
                for p in search:
                    dates = p.find("td").text.strip()
                    detail = p.find("a").text.strip()
                    print "{}{} : {}".format(WARNING, dates, detail)
            else:
                print "{} Nothing wpvunldb found \n".format(LESS)
    elif 'WordPress' in req.text:
        version =  v.replace('.','')
        site = "https://wpvulndb.com/wordpresses/{}".format(version)
        req = requests.get(site)
        soup = BeautifulSoup(req.text, "html.parser")
        search = soup.find_all('tr')
        if search:
            print "{}CVE found ! \n{}{}\n".format(WARNING, WARNING, site)
            for p in search:
                dates = p.find("td").text.strip()
                detail = p.find("a").text.strip()
                print "{}{} : {}".format(WARNING, dates, detail)
        else:
            print "{} Nothing wpvunldb found \n".format(LESS)
    else:
        print "{} Nothing CVE found \n".format(LESS)

#header
def get_header(url, directory):
    head = r.headers
    print INFO + "HEADER"
    print LINE
    print " {} \n".format(head).replace(',','\n')
    print LINE
    with open(directory + '/header.csv', 'w+') as file:
        file.write(str(head).replace(',','\n'))

#whois
def who_is(url, directory):
    print INFO + "WHOIS"
    print LINE
    try:
        who_is = whois.whois(url)
        #pprint.pprint(who_is) + "\n"
        for k, w in who_is.iteritems():
            is_who = "{} : {}-".format(k, w)
            print is_who
            with open(directory + '/whois.csv', 'a+') as file:
                file.write(is_who.replace("-","\n"))
    except:
        erreur = sys.exc_info()
        typerr = u"%s" % (erreur[0])
        typerr = typerr[typerr.find("'")+1:typerr.rfind("'")]
        print typerr
        msgerr = u"%s" % (erreur[1])
        print msgerr
    print "\n" + LINE

#satut of URL
def status(stat, directory, u_agent):
    check_b = check_backup(directory)
    #check backup before start scan
    if check_b == True:
        with open(directory + "/backup.txt", "r") as word:
            for ligne in word.readlines():
                print "{}{}{}".format(BACK, url, ligne.replace("\n",""))
                lignes = ligne.split("\n")
                #take the last line in file
                last_line = lignes[-2]
            with open(wordlist, "r") as f:
                for nLine, line in enumerate(f):
                    line = line.replace("\n","")
                    if line == last_line:
                        print LINE
                        forced = False
                        check_words(url, wordlist, directory, u_agent, forced, nLine)
    elif check_b == False:
        os.remove(directory + "/backup.txt")
        print "restart scan..."
        print LINE
    if stat == 200:
        check_words(url, wordlist, directory, u_agent)
    elif stat == 301:
        print PLUS + " 301 Moved Permanently\n"
        check_words(url, wordlist, directory, u_agent)
    elif stat == 302:
        print PLUS + " 302 Moved Temporarily\n"
        check_words(url, wordlist, directory, u_agent)
    elif stat == 304:
        pass
    elif stat == 404:
        a = raw_input("{} not found/ forced ?(y:n)".format(LESS))
        if a == "y":
            check_words(url, wordlist, directory, u_agent)
        else:
            sys.exit()
    elif stat == 403:
        a = raw_input(FORBI + " forbidden/ forced ?(y:n)")
        if a == "y":
            forced = True
            check_words(url, wordlist, directory, u_agent, forced)
        else:
            sys.exit()
    else:
        a = raw_input("{} not found/ forced ?(y:n)".format(LESS))
        if a == "y":
            check_words(url, wordlist, directory, u_agent)
        else:
            sys.exit()

# information DNS
def get_dns(url, directory):
    try:
        if "https" in url:
            url = url.replace('https://','').replace('/','')
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=url)
            conn.connect((url, 443))
            cert = conn.getpeercert()
            print INFO + "DNS information"
            print LINE
            pprint.pprint(str(cert['subject']).replace(',','').replace('((','').replace('))',''))
            pprint.pprint(cert['subjectAltName'])
            print ''
            conn.close()
            print LINE
            with open(directory + '/dns_info.csv', 'w+') as file:
                file.write(str(cert).replace(',','\n').replace('((','').replace('))',''))
        else:
            pass
    except:
        print INFO + "DNS information"
        print LINE
        erreur = sys.exc_info()
        typerr = u"%s" % (erreur[0])
        typerr = typerr[typerr.find("'")+1:typerr.rfind("'")]
        print typerr
        msgerr = u"%s" % (erreur[1])
        print msgerr + "\n"
        print LINE

#check if the backup file exist
def check_backup(directory):
    if os.path.exists(directory + "/backup.txt"):
        bp = raw_input("A backup file exist, do you want to continue or restart ? (C:R)\n")
        if bp == 'C' or bp == 'c':
            print "restart from last save in backup.txt ..."
            print LINE
            return True
        else:
            print LINE
            return False
    else:
        pass

#creat backup file
def backup(res, directory, forbi):
    with open(directory + "/backup.txt", "a+") as words:
        #delete url to keep just file or dir
        anti_sl = res.split("/")
        rep = anti_sl[3:]
        result = str(rep)
        result = result.replace("['","").replace("']","").replace("',", "/").replace(" '","")
        if forbi:
            words.write(result + " Forbidden\n")
        else:
            words.write(result + "\n")

# download files and calcul size
def dl(res, req, directory):
    soup = BeautifulSoup(req.text, "html.parser")
    extensions = ['.txt', '.html', '.jsp', '.xml', '.php', '.log', '.aspx', '.zip', '.old', '.bak', '.sql', '.js', '.asp', '.ini', '.log', '.rar', '.dat', '.log', '.backup', '.dll', '.save', '.BAK', '.inc']
    d_files = directory + "/files/"
    if not os.path.exists(d_files):
        os.makedirs(d_files)
    anti_sl = res.split("/")
    rep = anti_sl[3:]
    result = rep[-1]
    p_file = d_files + result
    texte = req.text
    for exts in extensions:
        if exts in result:
            with open(p_file, 'w+') as fichier:
                fichier.write(str(soup))
            # get size of file (in bytes)
            size_bytes = os.path.getsize(p_file)
            return size_bytes

#check all backup files
def file_backup(res, directory):
    ext_b = ['.bak', '.old', '.backup', '.BAK', '.save', '.zip', '.rar', '~', '_old', '_backup', '_bak']
    d_files = directory + "/files/"
    for exton in ext_b:
        res_b = res + exton
        anti_sl = res_b.split("/")
        rep = anti_sl[3:]
        result = rep[-1]
        r_files = d_files + result
        req_b = requests.get(res_b)
        soup = BeautifulSoup(req_b.text, "html.parser")
        if req_b.status_code == 200:
            with open(r_files, 'w+') as fichier_bak:
                fichier_bak.write(str(soup))
            size_bytes = os.path.getsize(r_files)
            return res_b, size_bytes
        else:
            pass
#bf wordlist
def tryUrl(i, q, directory, u_agent, forced=False):
    all_mail = []
    while True:
        try:
            if u_agent:
                user_agent = {'User-agent': u_agent}
            else:
                ua = UserAgent()
                user_agent = {'User-agent': ua.random} #for a user-agent random
            res = q.get()
            try:
                forbi = False
                req = requests.get(res, headers=user_agent, allow_redirects=False, verify=False, timeout=5)
                status_link = req.status_code
                sys.stdout.write("...\r")
                sys.stdout.flush()
                if status_link == 200:
                    #check backup
                    backup(res, directory, forbi)
                    # dl files and calcul size
                    size = dl(res, req, directory)
                    if size:
                        print "{}{} ({} bytes)".format(PLUS, res, size)
                    else:
                        print "{}{}".format(PLUS, res)
                    #check backup files
                    f_bak, size_bytes = file_backup(res, directory)
                    if f_bak:
                        print "{}{} ({} bytes)".format(PLUS, f_bak, size_bytes)
                    else:
                        print "{}{}".format(PLUS, res)
                    #get mail
                    mail(req, directory, all_mail)
                    if 'sitemap.xml' in res:
                        sitemap(req, directory)
                if status_link == 403:
                    if not forced:
                        forbi = True
                        print FORBI + res + "\033[31m Forbidden \033[0m"
                        backup(res, directory, forbi)
                    else:
                        pass
                elif status_link == 404:
                    pass
                elif status_link == 301:
                    pass
                    #print "\033[33m[+] \033[0m" + res + "\033[33m 301 Moved Permanently \033[0m"
                elif status_link == 304:
                    pass
                elif status_link == 302:
                    pass
                    #print "\033[33m[+] \033[0m" + res + "\033[33m 302 Moved Temporarily \033[0m"
                elif status_link == 400:
                    pass
                    #print "bad request"
            except requests.exceptions.Timeout as e:
                pass
                #print "{}{} on {}".format(INFO, e, res)
            q.task_done()
        except:
            #print "{} error threads".format(INFO)
            pass
    os.remove(directory + "/backup.txt")

#multi threading
def check_words(url, wordlist, directory, u_agent, forced=False, nLine=False):
    link_url = []
    if nLine:
        with open(wordlist, "r") as payload:
            links = payload.read().splitlines()
        for i in range(thread):
            worker = Thread(target=tryUrl, args=(i, enclosure_queue, directory, u_agent, forced))
            worker.setDaemon(True)
            worker.start()
        for link in links[nLine:]:
            link_url = url + link
            enclosure_queue.put(link_url)
        enclosure_queue.join()
    else:
        with open(wordlist, "r") as payload:
            links = payload.read().splitlines()
        for i in range(thread):
            worker = Thread(target=tryUrl, args=(i, enclosure_queue, directory, u_agent, forced))
            worker.setDaemon(True)
            worker.start()
        for link in links:
            link_url = url + link
            enclosure_queue.put(link_url)
        enclosure_queue.join()

# create all files
def create_file(url, stat, u_agent, thread, subdomains):
    if 'www' in url:
        direct = url.split('.')
        directory = direct[1]
        directory = "sites/" + directory
    else:
        direct = url.split('/')
        directory = direct[2]
        directory = "sites/" + directory
    # if the directory don't exist, create it
    if not os.path.exists(directory):
        os.makedirs(directory) # creat the dir
        if subdomains:
            subdomain(directory, subdomains)
        get_header(url, directory)
        get_dns(url, directory)
        who_is(url, directory)
        detect_cms(url)
        status(stat, directory, u_agent)
    # or else ask the question
    else:
        new_file = raw_input('this file exist, do you want to create another file ? (y:n)\n')
        if new_file == 'y':
            print LINE
            directory = directory + '_2'
            os.makedirs(directory)
            if subdomains:
                subdomain(directory, subdomains)
            get_header(url, directory)
            get_dns(url, directory)
            who_is(url, directory)
            detect_cms(url)
            status(stat, directory, u_agent)
        else:
            status(stat, directory, u_agent)

if __name__ == '__main__':
    #arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", help="URL to scan [required]", dest='url')
    parser.add_argument("-w", help="Wordlist used for URL Fuzzing [required]", dest='wordlist')
    parser.add_argument("-s", help="Subdomain tester", dest='subdomains', required=False)
    parser.add_argument("-t", help="Number of threads to use for URL Fuzzing. Default: 5", dest='thread', type=int, default=5)
    parser.add_argument("-a", help="Choice user-agent", dest='user_agent', required=False)
    parser.add_argument("-r", help="Number of recursive dir. ex: -r 2: two under directory", required=False, dest="recursif", type=int)
    results = parser.parse_args()
                                     
    url = results.url
    wordlist = results.wordlist
    thread = results.thread
    u_agent = results.user_agent
    subdomains = results.subdomains 
    recur = results.recursif
    # TODO implement recursive scan

    banner()
    r = requests.get(url, allow_redirects=False, verify=False)
    stat = r.status_code
    print "\n \033[32m url " + url + " found \033[0m\n"
    print LINE
    create_file(url, stat, u_agent, thread, subdomains)
