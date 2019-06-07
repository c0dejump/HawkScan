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
import traceback
import csv
#personal libs
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK
from Queue import Queue
from threading import Thread
from fake_useragent import UserAgent
import wafw00f
try:
    from Sublist3r import sublist3r
except Exception:
    traceback.print_exc()


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

#list to append url and then recursif scan
rec_list = []

"""
auto_update: for update the tool
"""
def auto_update():
    au = raw_input("Do you want update it ? (y/n): ")
    if au == "y":
        os.system("git status && git pull origin master")
    else:
        pass
"""
Github: check github informations
Pastebin: check pastebin information #TODO
"""
def gitpast(url):
    print("{}Check in Github".format(INFO))
    print(LINE)
    if "www" in url:
        url = url.split(".")[1]
    else:
        url = url.split("/")[2]
    url = "{}".format(url)
    print("search: {}\n".format(url))
    types = ["Commits", "Issues", "Code", "Repositories", "Marketplace", "Topics", "Wikis", "Users"]
    for t in types:
        github = "https://github.com/search?q={}&type={}".format(url, t)
        req = requests.get(github, verify=False)
        soup = BeautifulSoup(req.text, "html.parser")
        search = soup.find('a', {"class":"menu-item selected"})
        if search:
            for s in search.find("span"):
                print("{}{}: {}".format(INFO, t, s))
        else:
            print("{}{}: not found".format(INFO, t))
    print(LINE)
"""
Mail:
get mail adresse in web page during the scan and check if the mail leaked
"""
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
                pwnd = "{}: pwned ! ".format(mail)
                if pwnd not in all_mail:
                    all_mail.append(pwnd)
            else:
                no_pwned = "{}: no pwned ".format(mail)
                if no_pwned not in all_mail:
                    all_mail.append(no_pwned)
    with open(directory + '/mail.csv', 'a+') as file:
        if all_mail is not None and all_mail != []:
            writer = csv.writer(file)
            for r in all_mail:
                r = r.split(":")
                writer.writerow(r)
"""
Subdomains:
Check subdomains with the option -s (-s google.fr)
script use sublit3r to scan subdomain (it's a basic scan)
"""
def subdomain(subdomains):
    print("search subdomains:\n")
    sub_file = "sublist/" + subdomains + ".txt"
    sub = sublist3r.main(subdomains, 40, sub_file, ports= None, silent=False, verbose= False, enable_bruteforce= False, engines=None)
    print(LINE)
    time.sleep(2)

""" Get sitemap.xml of website"""
def sitemap(req, directory):
    soup = BeautifulSoup(req.text, "html.parser")
    with open(directory + '/sitemap.xml', 'w+') as file:
        file.write(str(soup).replace(' ','\n'))

"""
WAF:
Detect if the website use a WAF with tools "wafw00f"
"""
def detect_waf(url, directory):
    detect = False
    message = ""
    os.system("wafw00f {} > {}/waf.txt".format(url, directory))
    with open(directory + "/waf.txt", "r+") as waf:
        for w in waf:
            if "behind" in w:
                detect = True
                message = w
            else:
                pass
        print(INFO + "WAF")
        print(LINE)
        if detect == True:
            print("{}{}".format(WARNING, message))
            print(LINE)
        else:
            print("{}This website dos not use WAF".format(LESS))
            print(LINE)

"""
CMS:
Detect if the website use a CMS
"""
def detect_cms(url):
    print(INFO + "CMS")
    print(LINE)
    req = requests.get("https://whatcms.org/APIEndpoint/Detect?key=1481ff2f874c4942a734d9c499c22b6d8533007dd1f7005c586ea04efab2a3277cc8f2&url={}".format(url))
    if "Not Found" in req.text:
        print("{} this website does not seem to use a CMS \n".format(LESS))
        print(LINE)
    else:
        reqt = json.loads(req.text)
        result = reqt["result"].get("name")
        v = reqt["result"].get("version")
        if v:
            print("{} This website use \033[32m{} {} \033[0m\n".format(PLUS, result, v))
            cve_cms(result, v)
            print(LINE)
        else:
            print("{} This website use \033[32m{}\033[0m but nothing version found \n".format(PLUS, result))
            print(LINE)

"""
CVE_CMS:
Check CVE with cms and version detected by the function 'detect_cms'.
"""
def cve_cms(result, v):
    url_comp = "https://www.cvedetails.com/version-search.php?vendor={}&product=&version={}".format(result, v)
    req = requests.get(url_comp, allow_redirects=True, verify=False)
    if not "matches" in req.text:
        print("{}CVE found ! \n{}{}\n".format(WARNING, WARNING, url_comp))
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
                    print("{}{} : {}".format(WARNING, dates, detail))
            else:
                print("{} Nothing wpvunldb found \n".format(LESS))
    elif 'WordPress' in req.text:
        version =  v.replace('.','')
        site = "https://wpvulndb.com/wordpresses/{}".format(version)
        req = requests.get(site)
        soup = BeautifulSoup(req.text, "html.parser")
        search = soup.find_all('tr')
        if search:
            print("{}CVE found ! \n{}{}\n".format(WARNING, WARNING, site))
            for p in search:
                dates = p.find("td").text.strip()
                detail = p.find("a").text.strip()
                print("{}{} : {}".format(WARNING, dates, detail))
        else:
            print("{} Nothing wpvunldb found \n".format(LESS))
    else:
        print("{} Nothing CVE found \n".format(LESS))

"""Get header of website (cookie, link, etc...)"""
def get_header(url, directory):
    head = r.headers
    print(INFO + "HEADER")
    print(LINE)
    print(" {} \n".format(head).replace(',','\n'))
    print(LINE)
    with open(directory + '/header.csv', 'w+') as file:
        file.write(str(head).replace(',','\n'))

"""Get whois of website"""
def who_is(url, directory):
    print(INFO + "WHOIS")
    print(LINE)
    try:
        who_is = whois.whois(url)
        #pprint.pprint(who_is + "\n")
        for k, w in who_is.iteritems():
            is_who = "{} : {}-".format(k, w)
            print(is_who)
            with open(directory + '/whois.csv', 'a+') as file:
                file.write(is_who.replace("-","\n"))
    except:
        erreur = sys.exc_info()
        typerr = u"%s" % (erreur[0])
        typerr = typerr[typerr.find("'")+1:typerr.rfind("'")]
        print(typerr)
        msgerr = u"%s" % (erreur[1])
        print(msgerr)
    print("\n" + LINE)

"""
Status:
 - Get response status of the website (200, 302, 404...).
 - Check if a backup exist before to start the scan.
 If exist it restart scan from to the last line of backup.
"""
def status(stat, directory, u_agent):
    check_b = check_backup(directory)
    #check backup before start scan
    if check_b == True:
        with open(directory + "/backup.txt", "r") as word:
            for ligne in word.readlines():
                print("{}{}{}".format(BACK, url, ligne.replace("\n","")))
                lignes = ligne.split("\n")
                #take the last line in file
                last_line = lignes[-2]
            with open(wordlist, "r") as f:
                for nLine, line in enumerate(f):
                    line = line.replace("\n","")
                    if line == last_line:
                        print(LINE)
                        forced = False
                        check_words(url, wordlist, directory, u_agent, forced, nLine)
    elif check_b == False:
        os.remove(directory + "/backup.txt")
        print("restarting scan...")
        print(LINE)
    if stat == 200:
        check_words(url, wordlist, directory, u_agent)
    elif stat == 301:
        print(PLUS + " 301 Moved Permanently\n")
        check_words(url, wordlist, directory, u_agent)
    elif stat == 302:
        print(PLUS + " 302 Moved Temporarily\n")
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

"""Check if a backup file exist from function 'Status' """
def check_backup(directory):
    if os.path.exists(directory + "/backup.txt"):
        bp = raw_input("A backup file exist, do you want to continue or restart ? (C:R)\n")
        if bp == 'C' or bp == 'c':
            print("restart from last save in backup.txt ...")
            print(LINE)
            return True
        else:
            print(LINE)
            return False
    else:
        pass

"""Get DNS informations"""
def get_dns(url, directory):
    try:
        if "https" in url:
            url = url.replace('https://','').replace('/','')
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=url)
            conn.connect((url, 443))
            cert = conn.getpeercert()
            print(INFO + "DNS information")
            print(LINE)
            pprint.pprint(str(cert['subject']).replace(',','').replace('((','').replace('))',''))
            pprint.pprint(cert['subjectAltName'])
            print('')
            conn.close()
            print(LINE)
            with open(directory + '/dns_info.csv', 'w+') as file:
                file.write(str(cert).replace(',','\n').replace('((','').replace('))',''))
        else:
            pass
    except:
        print(INFO + "DNS information")
        print(LINE)
        erreur = sys.exc_info()
        typerr = u"%s" % (erreur[0])
        typerr = typerr[typerr.find("'")+1:typerr.rfind("'")]
        print(typerr)
        msgerr = u"%s" % (erreur[1])
        print(msgerr + "\n")
        print(LINE)


"""Create backup file"""
def backup(res, directory, forbi):
    with open(directory + "/backup.txt", "a+") as words:
        #delete url to keep just file or dir
        anti_sl = res.split("/")
        rep = anti_sl[3:]
        result = str(rep)
        result = result.replace("['","").replace("']","").replace("',", "/").replace(" '","")
        words.write(result + "\n")

""" Download files and calcul size """
def dl(res, req, directory):
    soup = BeautifulSoup(req.text, "html.parser")
    extensions = ['.txt', '.html', '.jsp', '.xml', '.php', '.log', '.aspx', '.zip', '.old', '.bak', '.sql', '.js', '.asp', '.ini', '.log', '.rar', '.dat', '.log', '.backup', '.dll', '.save', '.BAK', '.inc', '.php?-s']
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

"""
file_backup:
During the scan, check if a backup file or dir exist.
"""
def file_backup(res, directory):
    ext_b = ['.save', '.old', '.backup', '.BAK', '.bak', '.zip', '.rar', '~', '_old', '_backup', '_bak', '?-s']
    d_files = directory + "/files/"
    for exton in ext_b:
        res_b = res + exton
        #print(res_b)
        anti_sl = res_b.split("/")
        rep = anti_sl[3:]
        result = rep[-1]
        r_files = d_files + result
        #time.sleep(1)
        req_b = requests.get(res_b, allow_redirects=False, verify=False)
        soup = BeautifulSoup(req_b.text, "html.parser")
        if req_b.status_code == 200:
            with open(r_files, 'w+') as fichier_bak:
                fichier_bak.write(str(soup))
            size_bytes = os.path.getsize(r_files)
            if size_bytes:
                print("{}{}  ({} bytes)".format(PLUS, res_b, size_bytes))
                outpt(directory, res_b, forb=False)
            else:
                print("{}{}".format(PLUS, res_b))
                outpt(directory, res_b, forb=False)
        else:
            pass

"""
hidden_dir:
Like the function 'file_backup' but check if the type backup dir like '~articles/' exist.
"""
def hidden_dir(res, user_agent):
    pars = res.split("/")
    hidd_d = "{}~{}/".format(url, pars[3])
    hidd_f = "{}~{}".format(url, pars[3])
    req_d = requests.get(hidd_d, headers=user_agent, allow_redirects=False, verify=False, timeout=5)
    req_f = requests.get(hidd_f, headers=user_agent, allow_redirects=False, verify=False, timeout=5)
    sk_d = req_d.status_code
    sk_f = req_f.status_code
    if sk_d == 200:
        print("{}{}".format(PLUS, hidd_d))
        outpt(directory, hidd_d, forb=False)
    elif sk_f == 200:
        print("{}{}".format(PLUS, hidd_f))
        outpt(directory, hidd_f, forb=False)

"""
outpt:
Output to scan
"""
def outpt(directory, res, forb):
    if output:
        with open(output + "/scan.txt", "a+") as op:
            if forb == True:
                op.write(str("[x] " + res + " Forbidden\n"))
            else:
                op.write(str("[+] " + res + "\n"))
    else:
        with open(directory + "/scan.txt", "a+") as op:
            if forb == True:
                op.write(str("[x] " + res + " Forbidden\n"))
            else:
                op.write(str("[+] " + res + "\n"))


"""
tryUrl:
Test all URL contains in the dictionnary with multi-threading.
This script run functions:
- backup()
- dl()
- file_backup()
- mail()
"""
def tryUrl(i, q, directory, u_agent, forced=False):
    all_mail = []
    for t in range(len_w):
        res = q.get()
        try:
            if u_agent:
                user_agent = {'User-agent': u_agent}
            else:
                ua = UserAgent()
                user_agent = {'User-agent': ua.random} #for a user-agent random
            try:
                forbi = False
                #time.sleep(1)
                req = requests.get(res, headers=user_agent, allow_redirects=False, verify=False, timeout=5)
                hidden_dir(res, user_agent)
                status_link = req.status_code
                if status_link == 200:
                    #add directory for recursif scan
                    if res[-1] == "/" and recur:
                        if ".git" in res:
                            pass
                        else:
                            spl = res.split("/")[3:]
                            result = "/".join(spl)
                            rec_list.append(result)
                    #check backup
                    backup(res, directory, forbi)
                    # dl files and calcul size
                    size = dl(res, req, directory)
                    if size:
                        print("{}{} ({} bytes)".format(PLUS, res, size))
                        outpt(directory, res, forb=False)
                    else:
                        print("{}{}".format(PLUS, res))
                        outpt(directory, res, forb=False)
                    #check backup files
                    file_backup(res, directory)
                    #get mail
                    mail(req, directory, all_mail)
                    if 'sitemap.xml' in res:
                        sitemap(req, directory)
                if status_link == 403:
                    #pass
                    if res[-1] == "/" and recur:
                        if ".htaccess" in res or ".htpasswd" in res or ".git" in res or "wp" in res:
                            pass
                        else:
                            spl = res.split("/")[3:]
                            result = "/".join(spl)
                            rec_list.append(result)
                    if not forced:
                        forbi = True
                        print(FORBI + res + "\033[31m Forbidden \033[0m")
                        backup(res, directory, forbi)
                        outpt(directory, res, forb=True)
                    else:
                        #print(FORBI + res + "\033[31m Forbidden \033[0m")
                        pass
                elif status_link == 404:
                    pass
                elif status_link == 301:
                    if redirect:
                        print("\033[33m[+] \033[0m" + res + "\033[33m 301 Moved Permanently \033[0m")
                        outpt(directory, res, forb=False)
                    else:
                        pass
                elif status_link == 304:
                    pass
                elif status_link == 302:
                    if redirect:
                        print("\033[33m[+] \033[0m" + res + "\033[33m 302 Moved Temporarily \033[0m")
                        outpt(directory, res, forb=False)
                    else:
                        pass
                elif status_link == 400:
                    if "Server Error" in req.text:
                        print("{}{} \033[31m400 Server Error\033[0m").format(WARNING, res)
                    else:
                        pass
                        #print("{}{} \033[33m400 bad request\033[0m").format(LESS, res)
                elif status_link == 422 or status_link == 423 or status_link == 424 or status_link == 425:
                    print("{}{} \033[33mError WebDAV\033[0m").format(LESS, res)
                elif status_link == 401:
                    print("{}{} \033[33m401 Unauthorized\033[0m").format(LESS, res)
            except Exception:
                pass
                #traceback.print_exc()
            q.task_done()
        except Exception:
            #traceback.print_exc()
            pass
        sys.stdout.write("\033[34m[i] [scan... %d/%d]\033[0m\r" % (t*thread, len_w))
        sys.stdout.flush()


"""
check_words:
Functions wich manage multi-threading
"""
def check_words(url, wordlist, directory, u_agent, forced=False, nLine=False):
    link_url = []
    hiddend = []
    if nLine:
        with open(wordlist, "r") as payload:
            links = payload.read().splitlines()
        for i in range(thread):
            worker = Thread(target=tryUrl, args=(i, enclosure_queue, directory, u_agent, forced))
            worker.setDaemon(True)
            worker.start()
        for link in links[nLine:]:
            if prefix:
                link_url = url + prefix + link
            else:
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
            if prefix:
                link_url = url + prefix + link
            else:
                link_url = url + link
            enclosure_queue.put(link_url)
        enclosure_queue.join()
    """
        Recursif: For recursif scan
    """
    if rec_list != []:
        print(LINE)
        size_rec_list = len(rec_list)
        i_r = 0
        forced = True
        while i_r < size_rec_list:
            url_rec = url + rec_list[i_r]
            print("{}Entering in directory: {}".format(INFO, rec_list[i_r]))
            print(LINE)
            with open(wordlist, "r") as payload:
                links = payload.read().splitlines()
                for i in range(thread):
                    worker = Thread(target=tryUrl, args=(i, enclosure_queue, directory, u_agent, forced))
                    worker.setDaemon(True)
                    worker.start()
                for link in links:
                    if prefix:
                        link_url = url_rec + prefix + link
                    else:
                        link_url = url_rec + link
                    enclosure_queue.put(link_url)
                enclosure_queue.join()
                i_r = i_r + 1
            print(LINE)
    else:
        print("{}not other directory to scan".format(INFO))
    try:
        os.remove(directory + "/backup.txt")
    except:
        print("backup.txt not found")

"""
create_file:
Create directory with the website name to keep a scan backup. 
"""
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
            subdomain(subdomains)
        get_header(url, directory)
        get_dns(url, directory)
        who_is(url, directory)
        detect_cms(url)
        detect_waf(url, directory)
        gitpast(url)
        status(stat, directory, u_agent)
    # or else ask the question
    else:
        new_file = raw_input('this directory exist, do you want to create another file ? (y:n)\n')
        if new_file == 'y':
            print(LINE)
            directory = directory + '_2'
            os.makedirs(directory)
            if subdomains:
                subdomain(subdomains)
            get_header(url, directory)
            get_dns(url, directory)
            who_is(url, directory)
            detect_cms(url)
            status(stat, directory, u_agent)
        else:
            if subdomains:
                subdomain(subdomains)
            status(stat, directory, u_agent)

if __name__ == '__main__':
    #arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", help="URL to scan [required]", dest='url')
    parser.add_argument("-w", help="Wordlist used for URL Fuzzing [required]", dest='wordlist')
    parser.add_argument("-s", help="Subdomain tester", dest='subdomains', required=False)
    parser.add_argument("-t", help="Number of threads to use for URL Fuzzing. Default: 5", dest='thread', type=int, default=5)
    parser.add_argument("-a", help="Choice user-agent", dest='user_agent', required=False)
    parser.add_argument("--redirect", help="For scan with redirect response (301/302)", dest='redirect', required=False, action='store_true')
    parser.add_argument("-r", help="recursive dir/files", required=False, dest="recursif", action='store_true')
    parser.add_argument("-p", help="add prefix in wordlist to scan", required=False, dest="prefix")
    parser.add_argument("-o", help="output to site_scan.txt (default in website directory)", required=False, dest="output")
    results = parser.parse_args()
                                     
    url = results.url
    wordlist = results.wordlist
    thread = results.thread
    u_agent = results.user_agent
    subdomains = results.subdomains
    redirect = results.redirect
    prefix = results.prefix
    output = results.output
    recur = results.recursif
    # TODO implement recursive scan

    banner()
    len_w = 0
    #calcul wordlist size
    auto_update()
    with open(wordlist, 'r') as words:
        for l in words:
            len_w += 1
    r = requests.get(url, allow_redirects=False, verify=False)
    stat = r.status_code
    print("\n \033[32m url " + url + " found \033[0m\n")
    print(LINE)
    create_file(url, stat, u_agent, thread, subdomains)
    
