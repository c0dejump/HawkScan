#! /usr/bin/env python
# -*- coding: utf-8 -*-

#system libs
import requests
import sys, os, re
import time
from time import strftime
import ssl, OpenSSL
import argparse
from bs4 import BeautifulSoup
import json
import traceback
import csv

# external modules
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK
try:
    from Queue import Queue
except:
    import queue as Queue
from threading import Thread
import threading
from fake_useragent import UserAgent
import wafw00f
try:
    from tools.Sublist3r import sublist3r
except Exception:
    if sys.version > '3':
        print("\n{}subbrute doesn't work with this script on py3 version for the moment sorry".format(INFO))
    pass    
from modules.creat_report import create_report
from modules.detect_waf import verify_waf
from modules.mini_scans import mini_scans


def banner():
    print("""
  _    _                _     _____                 
 | |  | |              | |   / ____|                
 | |__| | __ ___      _| | _| (___   ___ __ _ _ __  
 |  __  |/ _` \ \ /\ / / |/ /\___ \ / __/ _` | '_ \ 
 | |  | | (_| |\ V  V /|   < ____) | (_| (_| | | | |
 |_|  |_|\__,_| \_/\_/ |_|\_\_____/ \___\__,_|_| |_|
                                                    

https://github.com/c0dejump/HawkScan
\033[35mBeta version \033[0m
-------------------------------------------------------------------
    """)

try:
    enclosure_queue = Queue()
except:
    enclosure_queue = Queue.Queue()

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

rec_list = []
#list to append url and then recursif scan

req_p = u""
#for exclude option

class ThreadManager:
    """
    Class ThreadManager:
        To manage threads (add_thread())
        To stop thread (stop_thread())
    """
    workers = []

    def __init__(self, queue):
        self.queue = queue
 
    def add_thread(self, i, threads, manager):
        """
        add thread from function definded_thread()
        """
        #print(self.workers[0])
        t_event = threading.Event()
        worker = threading.Thread(target=thread_wrapper, args=(i, self.queue, threads, manager, t_event))
        worker.setDaemon(True)
        worker.start()
        self.workers.append((worker, t_event))

    def stop_thread(self):
        t, e = self.workers[0]
        e = e.set() # put event to set True for stop thread
        

def auto_update():
    """
    auto_update: for update the tool
    """
    update = 0
    print("{}Checking update...".format(INFO))
    os.system("git pull origin master > /dev/null 2>&1 > git_status.txt")
    with open("git_status.txt", "r") as gs:
        for s in gs:
            if "Already up to date" not in s:
                update = 1
    if update == 1:
        print("{}A new version was be donwload\n".format(INFO))
        os.system("rm -rf git_status.txt")
    else:
        print("{}Nothing update found".format(INFO))
        os.system("rm -rf git_status.txt")


def status(stat, directory, u_agent, thread):
    """
    Status:
     - Get response status of the website (200, 302, 404...).
     - Check if a backup exist before to start the scan.
     If exist it restart scan from to the last line of backup.
    """
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
                        check_words(url, wordlist, directory, u_agent, thread, forced, nLine)
    elif check_b == False:
        os.remove(directory + "/backup.txt")
        print("restarting scan...")
        print(LINE)
    if stat == 200:
        check_words(url, wordlist, directory, u_agent, thread)
    elif stat == 301:
        print(PLUS + " 301 Moved Permanently\n")
        check_words(url, wordlist, directory, u_agent, thread)
    elif stat == 302:
        print(PLUS + " 302 Moved Temporarily\n")
        check_words(url, wordlist, directory, u_agent, thread)
    elif stat == 304:
        pass
    elif stat == 404:
        try:
            a = raw_input("{} not found/ forced ?(y:n)".format(LESS))
        except:
            a = input("{} not found/ forced ?(y:n)".format(LESS))
        if a == "y":
            check_words(url, wordlist, directory, u_agent, thread)
        else:
            sys.exit()
    elif stat == 403:
        try:
            a = raw_input(FORBI + " forbidden/ forced ?(y:n)")
        except:
            a = input(FORBI + " forbidden/ forced ?(y:n)")
        if a == "y":
            forced = True
            check_words(url, wordlist, directory, u_agent, forced, thread)
        else:
            sys.exit()
    else:
        try:
            a = raw_input("{} not found/ forced ?(y:n)".format(LESS))
        except:
            a = input("{} not found/ forced ?(y:n)".format(LESS))
        if a == "y":
            check_words(url, wordlist, directory, u_agent, thread)
        else:
            sys.exit()
                

def mail(req, directory, all_mail):
    """
    Mail:
    get mail adresse in web page during the scan and check if the mail leaked
    """
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

def subdomain(subdomains):
    """
    Subdomains:
    Check subdomains with the option -s (-s google.fr)
    script use sublit3r to scan subdomain (it's a basic scan)
    """
    print("search subdomains:\n")
    sub_file = "sublist/" + subdomains + ".txt"
    sub = sublist3r.main(subdomains, 40, sub_file, ports= None, silent=False, verbose= False, enable_bruteforce= False, engines=None)
    print(LINE)
    time.sleep(2)


def sitemap(req, directory):
    """ Get sitemap.xml of website"""
    soup = BeautifulSoup(req.text, "html.parser")
    with open(directory + '/sitemap.xml', 'w+') as file:
        file.write(str(soup).replace(' ','\n'))


def detect_waf(url, directory):
    """
    WAF:
    Detect if the website use a WAF with tools "wafw00f"
    """
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


def detect_cms(url, directory):
    """
    CMS:
    Detect if the website use a CMS
    """
    print(INFO + "CMS")
    print(LINE)
    req = requests.get("https://whatcms.org/APIEndpoint/Detect?key=1481ff2f874c4942a734d9c499c22b6d8533007dd1f7005c586ea04efab2a3277cc8f2&url={}".format(url))
    if "Not Found" in req.text:
        with open(directory + "/cms.txt", "w+") as cms_write:
            cms_write.write("this website does not seem to use a CMS")
        print("{} this website does not seem to use a CMS \n".format(LESS))
        print(LINE)
    else:
        reqt = json.loads(req.text)
        result = reqt["result"].get("name")
        v = reqt["result"].get("version")
        if v:
            with open(directory + "/cms.txt", "w+") as cms_write:
                cms_write.write("This website use {} {}".format(result, v))
            print("{} This website use \033[32m{} {} \033[0m\n".format(PLUS, result, v))
            cve_cms(result, v)
            print(LINE)
        else:
            with open(directory + "/cms.txt", "w+") as cms_write:
                cms_write.write("This website use {} but nothing version found".format(result))
            print("{} This website use \033[32m{}\033[0m but nothing version found \n".format(PLUS, result))
            print(LINE)


def cve_cms(result, v):
    """
    CVE_CMS:
    Check CVE with cms and version detected by the function 'detect_cms'.
    """
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


def wayback_check(url, directory):
    """
    Wayback_check:
    Check in a wayback machine to found old file on the website or other things...
    Use "waybacktool"
    """
    print("{}Wayback Check".format(INFO))
    print(LINE)
    print(url + "\n")
    os.system('python tools/waybacktool/waybacktool.py pull --host {} | python tools/waybacktool/waybacktool.py check > {}/wayback.txt'.format(url, directory))
    statinfo = os.path.getsize(directory + "/wayback.txt")
    if statinfo < 1:
        print("{}Nothing wayback found".format(INFO))
    with open(directory + "/wayback.txt", "r+") as wayback:
        wb_read = wayback.read().splitlines()
        for wb in wb_read:
            wb_res = list(wb.split(","))
            try:
                if wb_res[1] == " 200":
                    print("{}{}{}".format(PLUS, wb_res[0], wb_res[1]))
                elif wb_res[1] == " 301" or wb_res[1] == " 302":
                    print("{}{}{}".format(LESS, wb_res[0], wb_res[1]))
                elif wb_res[1] == " 404" or wb_res[1] == " 403":
                    pass
                else:
                    print("{}{}{}".format(INFO, wb_res[0], wb_res[1]))
            except:
                pass
    print(LINE)


def check_backup(directory):
    """Check if a backup file exist from function 'Status' """
    if os.path.exists(directory + "/backup.txt"):
        try:
            bp = raw_input("A backup file exist, do you want to continue or restart ? (C:R)\n")
        except:
            bp = input("A backup file exist, do you want to continue or restart ? (C:R)\n")
        if bp == 'C' or bp == 'c':
            print("restart from last save in backup.txt ...")
            print(LINE)
            return True
        else:
            print(LINE)
            return False
    else:
        pass


def backup(res, directory, forbi):
    """Create backup file"""
    with open(directory + "/backup.txt", "a+") as words:
        #delete url to keep just file or dir
        anti_sl = res.split("/")
        rep = anti_sl[3:]
        result = str(rep)
        result = result.replace("['","").replace("']","").replace("',", "/").replace(" '","")
        words.write(result + "\n")


def dl(res, req, directory):
    """ Download files and calcul size """
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


def file_backup(res, directory, HOUR):
    """
    file_backup:
    During the scan, check if a backup file or dir exist.
    """
    ext_b = ['.save', '.old', '.backup', '.BAK', '.bak', '.zip', '.rar', '~', '_old', '_backup', '_bak']
    d_files = directory + "/files/"
    for exton in ext_b:
        res_b = res + exton
        #print(res_b)
        anti_sl = res_b.split("/")
        rep = anti_sl[3:]
        result = rep[-1]
        r_files = d_files + result
        if ts:
            time.sleep(ts)
        if cookie_auth:
            req_b = requests.get(res_b, allow_redirects=False, verify=False, cookies=cookie_auth)
        else:
            req_b = requests.get(res_b, allow_redirects=False, verify=False)
        soup = BeautifulSoup(req_b.text, "html.parser")
        if req_b.status_code == 200:
            with open(r_files, 'w+') as fichier_bak:
                fichier_bak.write(str(soup))
            size_bytes = os.path.getsize(r_files)
            if size_bytes:
                print("{}{}{} ({} bytes)".format(HOUR, PLUS, res_b, size_bytes))
                outpt(directory, res_b, 200)
            else:
                print("{}{}{}".format(HOUR, PLUS, res_b))
                outpt(directory, res_b, 200)
        else:
            pass


def hidden_dir(res, user_agent, directory, forbi, HOUR):
    """
    hidden_dir:
    Like the function 'file_backup' but check if the type backup dir like '~articles/' exist.
    """
    pars = res.split("/")
    hidd_d = "{}~{}/".format(url, pars[3])
    hidd_f = "{}~{}".format(url, pars[3])
    if cookie_auth:
        req_d = requests.get(hidd_d, headers=user_agent, allow_redirects=False, verify=False, timeout=5, cookies=cookie_auth)
        req_f = requests.get(hidd_f, headers=user_agent, allow_redirects=False, verify=False, timeout=5, cookies=cookie_auth)
    else:
        req_d = requests.get(hidd_d, headers=user_agent, allow_redirects=False, verify=False, timeout=5)
        req_f = requests.get(hidd_f, headers=user_agent, allow_redirects=False, verify=False, timeout=5)
    sk_d = req_d.status_code
    sk_f = req_f.status_code
    if sk_d == 200:
        if exclude:
            check_exclude_page(req_d, res, directory, forbi, HOUR)
        else:
            print("{}{}{}".format(HOUR, PLUS, hidd_d))
            outpt(directory, hidd_d, 200)
    elif sk_f == 200:
        if exclude:
            check_exclude_page(req_f, res, directory, forbi, HOUR)
        else:
            print("{}{}{}".format(HOUR, PLUS, hidd_f))
            outpt(directory, hidd_f, 200)


def outpt(directory, res, stats):
    """
    outpt:
    Output to scan
    """
    if output:
        with open(output + "/scan.txt", "a+") as op:
            if stats == 403:
                op.write(str("[x] " + res + " Forbidden\n"))
            else:
                op.write(str("[+] " + res + "\n"))
    else:
        with open(directory + "/scan.txt", "a+") as op:
            if stats == 403:
                op.write(str("[x] " + res + " Forbidden\n"))
            elif stats == 301:
                op.write(str("[+] " + res + " 301\n"))
            elif stats == 302:
                op.write(str("[+] " + res + " 302\n"))
            elif stats == 401:
                op.write(str("[-] " + res + " 401\n"))
            elif stats == 400:
                op.write(str("[!] " + res + " 400\n"))
            elif stats == 500:
                op.write(str("[!] " + res + " 500\n"))
            else:
                op.write(str("[+] " + res + "\n"))


def check_exclude_page(req, res, directory, forbi, HOUR):
    """
    Check_exclude_page: 
    If scan blog, or social network etc.. you can activate this option to pass profil/false positive pages.
    for use this option you do defined a profil/false positive page base, ex: 
        --exclude url.com/profil/codejump
    """
    scoring = 0
    words = req_p
    for w in words.split("\n"):
        if w in req.text:
            scoring += 1
        else:
            pass
    len_w = [lines for lines in words.split("\n")] #to avoid to do line per line
    perc = round(100 * float(scoring) / len(len_w)) #to do a percentage for check look like page
    #print(perc)
    #print(res)
    if perc >= 80:
        pass
    elif perc >= 50 and perc < 80:
        print("{}{}{} potential exclude page".format(HOUR, LESS, res))
    else:
        print("{}{}{}".format(HOUR, PLUS, res))
        #check backup
        backup(res, directory, forbi)
        #check backup files
        file_backup(res, directory, HOUR)
        #output scan.txt
        outpt(directory, res, stats=0)
        if res[-1] == "/" and recur:
            if ".git" in res:
                pass
            else:
                spl = res.split("/")[3:]
                result = "/".join(spl)
                rec_list.append(result)
                outpt(directory, res, stats=0)


def get_links(req, directory):
    """
    Get_links: get all links on webpage during the scan
    """
    soup = BeautifulSoup(req.text, "html.parser")
    search = soup.find_all('a')
    if search:
        for s in search:
            link = s.get("href")
            if "http" in link or "https" in link:
                with open(directory + "/links.txt", "a+") as links:
                    links.write(str(link+"\n"))
            else:
                pass


def defined_thread(thread, i, score_next):
    """
    Defined_thread: to defined the threads number
    """
    #print("score: {}".format(score_next))
    thread_count = threading.active_count()
    res_time = 0
    try:
        start = time.time()
        req = requests.get(url, verify=False)
        end = time.time()
        res_time = end - start
    except Exception:
        pass
    #print("threads: {}".format(thread))
    #print(res_time)
    if res_time != 0 and res_time < 1 and thread_count < 11:
        score = 1
        if i == 30 and score_next == 0:
            thread = 1
            return thread, i;
        elif i == 160 and score_next == 1:
            thread = 1
            return thread, i;
        elif i == 340 and score_next == 2:
            thread = 1
            return thread, i;
        else:
            return 0, score;
    else:
        return 0, 0;


def len_page_flush(len_p):
    """
    Len_page_flush: to defined the word size for then "flush" it
    """
    if len_p <= 10:
        return 10
    elif len_p > 10 and len_p <= 20:
        return 25
    elif len_p > 20 and len_p <= 30:
        return 35
    elif len_p > 30 and len_p <= 40:
        return 45
    elif len_p > 40 and len_p <= 50:
        return 55
    elif len_p > 50 and len_p <= 70:
        return 75
    else:
        return len_p + 5


def thread_wrapper(i, q, threads, manager, t_event, directory=False, forced=False, u_agent=False):
    while not q.empty() and not t_event.isSet():
        #print("AAAAAAAAAAAA: {}".format(t_event.isSet()))
        tryUrl(i, q, threads, manager, directory, forced, u_agent)


def tryUrl(i, q, threads, manager=False, directory=False, forced=False, u_agent=False):
    """
    tryUrl:
    Test all URL contains in the dictionnary with multi-threading.
    This script run functions:
    - backup()
    - dl()
    - file_backup()
    - mail()
    """
    thread_score = 0
    score_next = 0
    all_mail = []
    waf_score = 0
    percentage = lambda x, y: float(x) / float(y) * 100
    for numbers in range(len_w):
        now = time.localtime(time.time())
        hour_t = time.strftime("%H:%M:%S", now)
        HOUR = "\033[35m[{}] \033[0m".format(hour_t)
        res = q.get()
        page = res.split("/")[-1]
        #print(threading.active_count())
        if auto:
            thrds, scores = defined_thread(threads, thread_score, score_next)
                #print(thrds)
                #print(threads)
            if scores == 1:
                thread_score += 1
            if thrds == 1:
                manager.add_thread(i, threads, manager)
                threads += 1
                score_next += 1
            #print("{}: {}".format(threading.currentThread().getName() ,thread_score))
        try:
            if u_agent:
                user_agent = {'User-agent': u_agent}
            else:
                ua = UserAgent()
                user_agent = {'User-agent': ua.random} #for a random user-agent
            try:
                forbi = False
                if ts:
                    time.sleep(ts)
                if cookie_auth:
                    if redirect:
                        req = requests.get(res, headers=user_agent, allow_redirects=True, verify=False, timeout=5, cookies=cookie_auth)
                    else:
                        req = requests.get(res, headers=user_agent, allow_redirects=False, verify=False, timeout=5, cookies=cookie_auth)
                else:
                    if redirect:
                        req = requests.get(res, headers=user_agent, allow_redirects=True, verify=False, timeout=5)
                    else:
                        req = requests.get(res, headers=user_agent, allow_redirects=False, verify=False, timeout=5)
                tests = 0
                if "robots.txt" in res.split("/")[3:] and req.status_code == 200:
                    print("{}{}{}".format(HOUR, PLUS, res))
                    for r in req.text.split("\n"):
                        print("\t- {}".format(r))
                if not "git" in res:
                    waf = verify_waf(req, res, user_agent, tests)
                #print(waf)
                #print("timesleep:{}".format(ts))
                #print(waf_score)
                if waf == True:
                    waf_score += 1
                    if waf_score == 4:
                        print("{} Auto-reconfig scan to prevent the WAF".format(INFO))
                        waf_score = 0
                        if thread_count != 1:
                            manager.stop_thread()
                        '''TODO: auto reconfigure scan to prevent waf repop
                            use TOR (apt install tor, pip install torrequest)'''
                    pass
                hidden_dir(res, user_agent, directory, forbi, HOUR)
                status_link = req.status_code
                redirect_link = req.history
                if status_link == 200:
                    if exclude:
                        check_exclude_page(req, res, directory, forbi, HOUR)
                    else:
                        # dl files and calcul size
                        size = dl(res, req, directory)
                        if size:
                            print("{}{}{} ({} bytes)".format(HOUR, PLUS, res, size))
                            outpt(directory, res, stats=0)
                        else:
                            print("{}{}{}".format(HOUR, PLUS, res))
                            outpt(directory, res, stats=0)
                        #check backup
                        backup(res, directory, forbi)
                        #test backup files
                        file_backup(res, directory, HOUR)
                        #add directory for recursif scan
                        get_links(req, directory)
                        #scrape all link
                        if res[-1] == "/" and recur:
                            if ".git" in res:
                                pass
                            else:
                                spl = res.split("/")[3:]
                                result = "/".join(spl)
                                rec_list.append(result)
                    mail(req, directory, all_mail)
                    #get mail
                    if 'sitemap.xml' in res:
                        sitemap(req, directory)
                if status_link == 403:
                    #pass
                    if res[-1] == "/" and recur:
                        if ".htaccess" in res or ".htpasswd" in res or ".git" in res or "wp" in res:
                            outpt(directory, res, stats=403)
                        else:
                            spl = res.split("/")[3:]
                            result = "/".join(spl)
                            rec_list.append(result)
                            outpt(directory, res, stats=403)
                    if not forced:
                        forbi = True
                        print("{}{} {} \033[31m Forbidden \033[0m".format(HOUR, FORBI, res))
                        backup(res, directory, forbi)
                        outpt(directory, res, stats=403)
                    else:
                        #print("{}{} {} \033[31m Forbidden \033[0m".format(HOUR, FORBI, res))
                        pass
                elif status_link == 404:
                    pass
                elif status_link == 405:
                    print("{}{}{}").format(HOUR, INFO, res)
                elif status_link == 301:
                    if redirect:
                        if redirect_link != 404 or redirect_link != 403:
                            print("{}\033[33m[+] \033[0m {} \033[33m 301 Moved Permanently \033[0m".format(HOUR, res))
                            outpt(directory, res, stats=301)
                    else:
                        pass
                elif status_link == 304:
                    if redirect:
                        if redirect_link != 404 or redirect_link != 403:
                            print("{}\033[33m[+] \033[0m {} \033[33m 304 Not modified \033[0m".format(HOUR, res))
                    else:
                        print("{}\033[33m[+] \033[0m {} \033[33m 304 Not modified \033[0m".format(HOUR, res))
                elif status_link == 302:
                    if redirect:
                        if redirect_link != 404 or redirect_link != 403:
                            print("{}\033[33m[+] \033[0m {} \033[33m 302 Moved Temporarily \033[0m".format(HOUR, res))
                            outpt(directory, res, stats=302)
                    else:
                        pass
                elif status_link == 400 or status_link == 500:
                    if "Server Error" in req.text or "Erreur du serveur dans l'application" in req.text:
                        if status_link == 400:
                            print("{}{}{} \033[31m400 Server Error\033[0m".format(HOUR, WARNING, res))
                            outpt(directory, res, stats=400)
                        elif status_link == 500:
                            print("{}{}{} \033[31m500 Server Error\033[0m".format(HOUR, WARNING, res))
                            outpt(directory, res, stats=500)
                    else:
                        pass
                        #print("{}{} \033[33m400 Server Error\033[0m").format(LESS, res)
                elif status_link == 422 or status_link == 423 or status_link == 424 or status_link == 425:
                    print("{}{}{} \033[33mError WebDAV\033[0m".format(HOUR, LESS, res))
                elif status_link == 401:
                    print("{}{}{} \033[33m401 Unauthorized\033[0m".format(HOUR,LESS, res))
                    outpt(directory, res, stats=401)
                    #pass
                elif status_link == 405:
                    print("{}{}{}".format(HOUR, PLUS, res))
                    outpt(directory, res, stats=405)
                elif status_link == 503:
                    req_test_index = requests.get(url, verify=False) # take origin page url (index) to check if it's really unavailable
                    if req_test_index.status_code == 503:
                        manager.stop_thread()
                        print("{}{} Service potential Unavailable".format(HOUR, WARNING))
                        try:
                            good_service = raw_input("The site web seem unavailable pls tape anything if it's ok:\n")
                        except:
                            good_service = input("The site web seem unavailable pls tape anything if it's ok:\n")
                        if good_service:
                            pass
                    else:
                        pass
            except Exception:
                pass
                #traceback.print_exc()
            q.task_done()
        except Exception:
            #traceback.print_exc()
            pass
        len_p = len(page)
        len_flush = len_page_flush(len_p) 
        #for flush display
        sys.stdout.write("\033[34m[i] {0:.2f}% - {1}/{2} | Threads: {3} | {4:{5}}\033[0m\r".format(percentage(numbers, len_w)*threading.active_count(), numbers*threading.active_count(), len_w, threading.active_count() - 1, page, len_flush))
        sys.stdout.flush()


def check_words(url, wordlist, directory, u_agent, thread, forced=False, nLine=False):
    """
    check_words:
    Functions wich manage multi-threading
    """
    if thread:
        threads = thread
    if auto:
        threads = 3
    link_url = []
    hiddend = []
    with open(wordlist, "r") as payload:
        links = payload.read().splitlines()
    state = links[nLine:] if nLine else links
    for link in state:
        if prefix:
            link_url = url + prefix + link
        else:
            link_url = url + link
        enclosure_queue.put(link_url)
    manager = ThreadManager(enclosure_queue)
    for i in range(threads):
        worker = Thread(target=tryUrl, args=(i, enclosure_queue, threads, manager, directory, forced, u_agent))
        worker.setDaemon(True)
        worker.start()
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
                for i in range(threads):
                    worker = Thread(target=tryUrl, args=(i, enclosure_queue, threads, directory, forced, u_agent))
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


def create_file(url, stat, u_agent, thread, subdomains):
    """
    create_file:
    Create directory with the website name to keep a scan backup.
    """
    ms = mini_scans()
    dire = ''
    if 'www' in url:
        direct = url.split('.')
        director = direct[1]
        dire = "{}.{}".format(direct[1], direct[2].replace("/",""))
        directory = "sites/" + director
    else:
        direct = url.split('/')
        director = direct[2]
        dire = director
        directory = "sites/" + director
    # if the directory don't exist, create it
    if not os.path.exists(directory):
        os.makedirs(directory) # creat the dir
        if subdomains:
            subdomain(subdomains)
        ms.get_header(url, directory)
        ms.get_dns(url, directory)
        ms.who_is(url, directory)
        detect_cms(url, directory)
        detect_waf(url, directory)
        wayback_check(dire, directory)
        ms.gitpast(url)
        ms.firebaseio(director)
        status(stat, directory, u_agent, thread)
        create_report(directory, cookie_)
    # or else ask the question
    else:
        try:
            new_file = raw_input('this directory exist, do you want to create another directory ? (y:n)\n')
        except:
            new_file = input('this directory exist, do you want to create another directory ? (y:n)\n')
        if new_file == 'y':
            print(LINE)
            directory = directory + '_2'
            os.makedirs(directory)
            if subdomains:
                subdomain(subdomains)
            ms.get_header(url, directory)
            ms.get_dns(url, directory)
            ms.who_is(url, directory)
            detect_cms(url, directory)
            detect_waf(url, directory)
            wayback_check(dire, directory)
            ms.gitpast(url)
            ms.firebaseio(dire)
            status(stat, directory, u_agent, thread)
            create_report(directory, cookie_)
        else:
            if subdomains:
                subdomain(subdomains)
            status(stat, directory, u_agent, thread)
            create_report(directory, cookie_)


if __name__ == '__main__':
    #arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", help="URL to scan [required]", dest='url')
    parser.add_argument("-w", help="Wordlist used for URL Fuzzing [required]", dest='wordlist')
    parser.add_argument("-s", help="Subdomain tester", dest='subdomains', required=False)
    parser.add_argument("-t", help="Number of threads to use for URL Fuzzing. Default: 5", dest='thread', type=int, default=5, required=False)
    parser.add_argument("-a", help="Choice user-agent", dest='user_agent', required=False)
    parser.add_argument("--redirect", help="For sacn with redirect response (301/302)", dest='redirect', required=False, action='store_true')
    parser.add_argument("-r", help="Recursive dir/files", required=False, dest="recursif", action='store_true')
    parser.add_argument("-p", help="Add prefix in wordlist to scan", required=False, dest="prefix")
    parser.add_argument("-o", help="Output to site_scan.txt (default in website directory)", required=False, dest="output")
    parser.add_argument("--cookie", help="Scan with an authentification cookie", required=False, dest="cookie_", type=str)
    parser.add_argument("--exclude", help="To define a page type to exclude during scan", required=False, dest="exclude")
    parser.add_argument("--timesleep", help="To define a timesleep/rate-limit if app is unstable during scan", required=False, dest="ts", type=int, default=0)
    parser.add_argument("--auto", help="Automatic threads depending response to website. Max: 10", required=False, dest="auto", action='store_true')
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
    cookie_ = results.cookie_
    exclude = results.exclude 
    ts = results.ts
    auto = results.auto

    banner()
    auto_update()
    len_w = 0 #calcul wordlist size
    cookie_auth = {}
    if url.split("/")[-1] != "":
        url = url + "/"
    if cookie_:
        s = cookie_.split(";")
        for c in s:
            c = c.split("=", 1)
            cookie_auth.update([(c[0],c[1])])
    with open(wordlist, 'r') as words:
        for l in words:
            len_w += 1
    if exclude:
        req_exclude = requests.get(exclude, verify=False)
        req_p = req_exclude.text
    r = requests.get(url, allow_redirects=False, verify=False)
    stat = r.status_code
    print("\n \033[32m url " + url + " found \033[0m\n")
    print(LINE)
    create_file(url, stat, u_agent, thread, subdomains)
