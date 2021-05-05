#! /usr/bin/env python
# -*- coding: utf-8 -*-

#modules in standard library
import requests
import sys, os, re
import time
from datetime import datetime
from time import strftime
import argparse
from bs4 import BeautifulSoup
import json
import traceback
from requests.exceptions import Timeout
from requests.auth import HTTPBasicAuth
import signal

# external modules
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK, EXCL, SERV_ERR, BYP, WAF, EXT_B
try:
    from Queue import Queue
except:
    import queue as Queue
import threading
from threading import Thread
from fake_useragent import UserAgent
import wafw00f   
from report.creat_report import create_report
#from report.creat_report_test import create_report_test
from modules.detect_waf import verify_waf
from modules.before_run import before_start
from modules.parsing_html import parsing_html
from modules.check_cms import check_cms
from modules.bypass_waf import bypass_waf
from modules.manage_dir import manage_dir
from modules.bypass_forbidden import bypass_forbidden
from modules.google_dorks import query_dork
from modules.banner import banner
from modules.check_subdomain import subdomain
from modules.terminal_size import terminal_size
from modules.output import multiple_outputs
from modules.resume import resume_scan
from modules.check_socketio import check_socketio
from modules.send_notify import notify_scan_completed


try:
    enclosure_queue = Queue()
except:
    enclosure_queue = Queue.Queue()

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

rec_list = []
#list to append url and then recursif scan

req_p = u""
#for exclude option

stat = 0

tw, th = terminal_size() # determine terminal size

header_parsed = {}

class ThreadManager:
    """
    Class ThreadManager:
        To manage threads (add_thread())
        To stop thread (stop_thread())
    """
    workers = []

    errors_score = 0

    lock = threading.Lock()

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
        """ for stop thread => #TODO to remake"""
        t, e = self.workers[0]
        e = e.set() # put event to set True for stop thread
        del self.workers[0]

    def error_check(self):
        #TODO
        with lock:
            errors_score += 1
            return errors_score


class filterManager:
    """
    Class filterManager:
    Filter page or response status code for remove false positif
    functions:
    - check_exclude_code
    - check_exclude_page
    """
    def check_multiple(self, req, res, directory, forbi, HOUR, parsing=False, size_bytes=False):
        """
        Check_multiple: check multiple exclude, ex:
        --exclude 500,1337b,https://www.exemple.com
        --exclude 500,403
        """
        filterM = filterManager()
        list_exclude = {}
        for l_exclude in req_p:
            list_exclude[l_exclude] = False
        #print(list_exclude) #Debug
        for m_exclude in req_p:
            try:
                if int(m_exclude):
                    #print(m_exclude)
                    check_code = filterM.check_exclude_code(res, req, directory, HOUR, parsing, multiple=True)
                    if check_code:
                        list_exclude[m_exclude] = True
            except:
                check_page = filterM.check_exclude_page(req, res, directory, forbi, HOUR, parsing, size_bytes, multiple=m_exclude)
                if check_page:
                    list_exclude[m_exclude] = True
        #print(list_exclude)
        if False not in list_exclude.values():
            if req.status_code in [403, 401]:
                print("{} {} {} ({} bytes)".format(HOUR, FORBI, res, len(req.content)))
                bypass_forbidden(res)
            else:
                print("{} {} {} ({} bytes) [{}]".format(HOUR, PLUS, res, len(req.content), req.status_code))
            for l_exclude in req_p:
                list_exclude[l_exclude] = False



    def check_exclude_code(self, res, req, directory, HOUR, parsing=False, multiple=False):
        """
        check_exclude_code:
        You can activate this option to pass the response status code, ex:
        --exclude 500
        """
        req_st = str(req.status_code) if multiple else req.status_code
        if multiple and req_st in req_p:
            return False
        elif req_st == req_p:
            pass
        elif req_st in [403, 401]:
            bypass_forbidden(res)
            pass
        elif req_st in [500, 400, 422, 423, 424, 425]:
            print("{} {} {} ({} bytes) \033[33m{} Server Error\033[0m".format(HOUR, SERV_ERR, res, len(req.content), req.status_code))
            if js:
                parsing.get_javascript(res, req)
        else:
            if multiple:
                return True
            else:
                print("{} {} {} ({} bytes)".format(HOUR, PLUS, res, len(req.content)))
                if js:
                    parsing.get_javascript(res, req)
                output_scan(directory, res, len(req.content), stats=200)


    def check_exclude_page(self, req, res, directory, forbi, HOUR, parsing=False, size_bytes=False, multiple=False):
        """
        Check_exclude_page: 
        If scan blog, or social network etc.. you can activate this option to pass profil/false positive pages or response status code.
        for use this option you do defined a profil/false positive page base, ex: 
            --exclude url.com/profil/codejump
        OR
            --exclude 240b for just number of bytes
        """
        scoring = 0
        multiple = multiple if multiple else "0b"
        if multiple and "http" in multiple:
            print("\n\033[34mHi ! Sorry but multiple excludes with an url doesn't work for the moment, please put a number or bytes number\n(ex: --exclude 404,1337b)\033[0m")
            pid = os.getpid()
            os.killpg(pid, signal.SIGSTOP)

        if "b" in exclude[0][-1] and int(exclude[0][0]) or multiple[-1] == "b" and int(multiple[0]):
            #For exclude bytes number
            multiple = False if multiple == "0b" else multiple
            req_len = int(exclude[0][0:-1]) if not multiple else int(multiple.split('b')[0])
            req_bytes = len(req.content)
            if multiple and req_bytes == req_len:
                return False
            elif multiple and req_bytes != req_len:
                return True
            if not multiple:
                if req_bytes == req_len:
                    pass
                elif req_bytes != req_len and req.status_code == 403:
                    print("{} {} {} ({} bytes)".format(HOUR, FORBI, res, len(req.content)))
                elif req_bytes != req_len and req.status_code in [500, 502, 400, 422, 423, 424, 425]:
                    print("{} {} {} ({} bytes) \033[33m{} Server Error\033[0m".format(HOUR, SERV_ERR, res, len(req.content), req.status_code))
                elif req_bytes != req_len and req.status_code == 200:
                    print("{} {} {} ({} bytes)".format(HOUR, PLUS, res, len(req.content)))
                    if js:
                        parsing.get_javascript(res, req)
                elif req_bytes != req_len and req.status_code in [301, 302]:
                    if js:
                        parsing.get_javascript(res, req)
        else:
            multiple = False if multiple == "0b" else multiple
            if redirect or stat == 301 or stat == 302:
                req = requests.get(req.url, verify=False)
            words = req_p
            for w in words.split("\n"):
                if w in req.text:
                    scoring += 1
                else:
                    pass
            len_wd = [lines for lines in words.split("\n")] #to avoid to do line per line
            perc = round(100 * float(scoring) / len(len_wd)) #to do a percentage for check look like page
            #print(req.text)
            #print(perc) #DEBUG percentage
            #print(multiple)
            if perc >= 80:
                pass
            elif perc > 50 and perc < 80:
                print("{} {} {} Potential exclude page {}%".format(HOUR, EXCL, res, perc))
            else:
                if req.status_code in [403, 401, 429]:
                    bypass_forbidden(res)
                    pass
                elif req.status_code in [500, 400, 422, 423, 424, 425]:
                    if multiple:
                        return True
                    else:
                        print("{} {} {} ({} bytes) \033[33m{} Server Error\033[0m".format(HOUR, SERV_ERR, res, len(req.content), req.status_code))
                else:
                    if multiple:
                        return True
                    else:
                        if js:
                            parsing.get_javascript(res, req)
                        print("{} {} {} ({} bytes)".format(HOUR, PLUS, res, len(req.content)))
                #check backup
                create_backup(res, directory, forbi)
                #output scan.txt
                output_scan(directory, res, len(req.content), stats=200)
                if res[-1] == "/" and recur:
                    if ".git" in res:
                        pass
                    else:
                        spl = res.split("/")[3:]
                        result = "/".join(spl)
                        rec_list.append(result)
                        output_scan(directory, res, len(req.content), stats=200)


def auto_update():
    """
    auto_update: for update the tool
    """
    updt = 0
    print("{}Checking update...".format(INFO))
    os.system("git pull origin master > /dev/null 2>&1 > git_status.txt")
    with open("git_status.txt", "r") as gs:
        for s in gs:
            if "Already up to date" not in s:
                updt = 1
    if updt == 1:
        print("{}A new version was be donwload\n".format(INFO))
        os.system("cd ../ && rm -rf HawkScan && git clone https://github.com/c0dejump/HawkScan.git")
    else:
        print("{}Nothing update found".format(INFO))
        os.system("rm -rf git_status.txt")


def status(r, stat, directory, u_agent, thread, manageDir):
    """
    Status:
     - Get response status of the website (200, 302, 404...).
     - Check if a backup exist before to start the scan.
     If exist it restart scan from to the last line of backup.
    """
    check_b = manageDir.check_backup(directory)
    #check backup before start scan
    last_line = ''
    if check_b == True:
        with open(directory + "/backup.txt", "r") as word:
            for ligne in word.readlines():
                print("{}{}{}".format(BACK, url, ligne.strip()))
                lignes = ligne.split("\n")
                #take the last line in file
                last_line = lignes[-2]
        with open(wordlist, "r") as f:
            for nLine, line in enumerate(f):
                if line.strip() == last_line:
                    print(LINE)
                    forced = False
                    check_words(url, wordlist, directory, u_agent, thread, forced, nLine)
    elif not check_b:
        try:
            os.remove(directory + "/backup.txt")
            print("{} Restarting scan...".format(INFO))
        except:
            pass
        print(LINE)

    if auth:
        r = requests.get(url, allow_redirects=False, verify=False, auth=(auth.split(":")[0], auth.split(":")[1]))
        if r.status_code in [200, 302, 301]:
            print("{} Authentification successfull\n".format(PLUS))
            stat = r.status_code
        else:
            print("{} Authentification error".format(LESS))
            try:
                continue_error = raw_input("The authentification seems bad, continue ? [y/N]")
            except:
                continue_error = input("The authentification seems bad, continue ? [y/N]")
            if continue_error not in ["y", "Y"]:
                sys.exit()

    if stat == 200:
        check_words(url, wordlist, directory, u_agent, thread)
    elif stat == 301:
        req_red = requests.get(url, verify=False)
        try:
            follow = raw_input("{} 301 Moved Permanently => {}\nDo you want follow redirection ? [y/N]".format(PLUS, req_red.url))
            print("")
        except:
            follow = input("{} 301 Moved Permanently => {}\nDo you want follow redirection ? [y/N]".format(PLUS, req_red.url))
            print("")
        stat = 301 if follow == "y" or follow == "Y" else 0
        check_words(url, wordlist, directory, u_agent, thread)
    elif stat == 302:
        req_red = requests.get(url, verify=False)
        try:
            follow = raw_input("{} 302 Moved Temporarily => {}\nDo you want follow redirection ? [y/N]".format(PLUS, req_red.url))
            print("")
        except:
            follow = input("{} 302 Moved Temporarily => {}\nDo you want follow redirection ? [y/N]".format(PLUS, req_red.url))
            print("")
        stat = 302 if follow == "y" or follow == "Y" else 0
        check_words(url, wordlist, directory, u_agent, thread)
    elif stat == 304:
        pass
    elif stat == 404:
        try:
            not_found = raw_input("{} not found/ forced ? [y/N]: ".format(LESS))
        except:
            not_found = input("{} not found/ forced ? [y/N]: ".format(LESS))
        if not_found == "y" or not_found == "Y":
            forced = True
            check_words(url, wordlist, directory, u_agent, thread, forced)
        else:
            sys.exit()
    elif stat == 403:
        try:
            fht = raw_input(FORBI + " forbidden/ forced ? [y/N]: ")
        except:
            fht = input(FORBI + " forbidden/ forced ? [y/N]: ")
        if fht == "y" or fht == "Y":
            forced = True
            check_words(url, wordlist, directory, u_agent, thread, forced)
        else:
            sys.exit()
    else:
        try:
            not_found = raw_input("{} not found/ forced ? [y/N]: ".format(LESS))
        except:
            not_found = input("{} not found/ forced ? [y/N]: ".format(LESS))
        if not_found == "y" or not_found == "Y":
            forced = True
            check_words(url, wordlist, directory, u_agent, thread, forced)
        else:
            sys.exit()


def detect_wafw00f(url, directory, thread):
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
                message = w.replace("[+]","").replace("[*]","")
            else:
                pass
        print(INFO + "WAF")
        print(LINE)
        if detect:
            print(" {}{}".format(WARNING, message))
            if thread >= 20:
                try:
                    confirm_thread = raw_input(" {} This website have a waf, are you sure to use {} threads ? [y:n] ".format(WARNING, thread))
                except:
                    confirm_thread = input(" {} This website have a waf, are you sure to use {} threads ? [y:n] ".format(WARNING, thread))
                if confirm_thread == "y" or confirm_thread == "Y":
                    print(LINE)
                    pass
                else:
                    try:
                        enter_thread = raw_input("{}Enter the number of threads: ".format(INFO))
                    except:
                        enter_thread = input("{}Enter the number of threads: ".format(INFO))
                    if int(enter_thread) > 0:
                        print(LINE)
                        return int(enter_thread)
                    else:
                        print("If you enter 0 or less that's will doesn't work :)")
                        sys.exit()
            else:
                print(LINE)
        else:
            print(" {} This website doesn't seem use WAF".format(LESS))
            print(LINE)


def create_backup(res, directory, forbi):
    """Create backup file"""
    with open(directory + "/backup.txt", "a+") as words:
        #delete url to keep just file or dir
        anti_sl = res.split("/")
        rep = anti_sl[3:]
        result = str(rep)
        result = result.replace("['","").replace("']","").replace("',", "/").replace(" '","")
        words.write(result + "\n")


def dl(res, req, directory):
    """ Download files """
    req_size = len(req.content)
    if req_size > 1:
        extensions = ['.json', '.txt', '.html', '.jsp', '.xml', '.aspx', '.zip', '.old', '.bak', 
        '.sql', '.js', '.asp', '.ini', '.rar', '.dat', '.log', '.backup', '.dll', '.save', '.BAK', '.inc', '.md']
        d_files = directory + "/files/"
        if not os.path.exists(d_files):
            os.makedirs(d_files)
        anti_sl = res.split("/")
        rep = anti_sl[3:]
        result = rep[-1]
        p_file = d_files + result
        for exts in extensions:
            if exts in result:
                with open(p_file, 'w+') as fichier:
                    try:
                        fichier.write(str(req.text))
                    except:
                        pass


def output_scan(directory, res, size_res, stats):
    """
    output_scan:
    Output to scan
    """
    mo = multiple_outputs()
    directory = output if output else directory
    mo.raw_output(directory, res, stats, size_res)



def backup_ext(s, res, page, directory, forbi, HOUR, parsing, filterM):
    """
    backup_ext:
    During the scan, check if a backup file or dir exist.
    You can modify this in "config.py"
    """
    size_check = 0
    
    d_files = directory + "/files/" #directory to download backup file if exist

    authent = (auth.split(":")[0], auth.split(":")[1]) if auth else False

    bckp = EXT_B if backup == [] else [bck.replace(",","") for bck in backup]
    for exton in bckp:
        res_b = res + exton
        page_b = page + exton
        #print(res_b) #DEBUG
        anti_sl = res_b.split("/")
        rep = anti_sl[3:]
        result = rep[-1]
        r_files = d_files + result
        if ts:
            time.sleep(ts)
        if header_parsed:
            req_b = s.get(res_b, allow_redirects=False, verify=False, headers=header_parsed)
        else:
            if redirect:
                req_check = s.get(res_b, allow_redirects=True, verify=False)
                req_b = s.get(req_check.url, verify=False)
            else:
                req_b = s.get(res_b, allow_redirects=False, verify=False, timeout=10, auth=authent)
        soup = BeautifulSoup(req_b.text, "html.parser")
        req_b_status = req_b.status_code
        size_bytes = len(req_b.content)
        if req_b_status == 200:
            ranges = range(size_check - 50, size_check + 50) if size_check < 100000 else range(size_check - 1000, size_check + 1000)
            if size_bytes == size_check or size_bytes in ranges:
                #if the number of bytes of the page equal to size_check variable and not bigger than size_check +5 and not smaller than size_check -5
                pass
            elif size_bytes != size_check:
                if js:
                    parsing.get_javascript(res, req_b)
                if exclude:
                    if len(exclude) > 1:
                        filterM.check_multiple(req_b, res_b, directory, forbi, HOUR, parsing, size_bytes=size_bytes)
                    elif type(req_p) == int:
                        filterM.check_exclude_code(res_b, req_b, directory, HOUR, parsing)
                    else:
                        filterM.check_exclude_page(req_b, res_b, directory, forbi, HOUR, parsing)
                        with open(r_files, 'w+') as fichier_bak:
                            fichier_bak.write(str(soup))
                        #print("{} {} {} ({} bytes)".format(HOUR, PLUS, res_b, size_bytes))
                else:
                    print("{} {} {} ({} bytes)".format(HOUR, PLUS, res_b if tw > 120 else page_b, size_bytes))
                    with open(r_files, 'w+') as fichier_bak:
                        fichier_bak.write(str(soup))
                    output_scan(directory, res_b, size_bytes, 200)
                size_check = size_bytes
            else:
                if exclude:
                    if len(exclude) > 1:
                        filterM.check_multiple(req_b, res_b, directory, forbi, HOUR, parsing, size_bytes=size_bytes)
                    elif type(req_p) == int:
                        filterM.check_exclude_code(res, req_b, directory, HOUR, parsing)
                    else:
                        filterM.check_exclude_page(req_b, res_b, directory, forbi, HOUR, parsing) 
                else:
                    print("{} {} {}".format(HOUR, PLUS, res_b))
                    output_scan(directory, res_b, size_bytes, 200)
        elif req_b_status in [404, 406, 429, 503, 502, 500, 400]:
            pass
        elif req_b_status in [301, 302, 303, 307, 308]:
            if redirect:
                print("{} {} {} => {}".format(HOUR, LESS, res_b if tw > 120 else page_b, req_check.url))
        elif req_b_status in [403, 401]:
            #pass
            if exclude:
                if len(exclude) > 1:
                    filterM.check_multiple(req_b, res_b, directory, forbi, HOUR, parsing, size_bytes=size_bytes)
                elif type(req_p) == int:
                    filterM.check_exclude_code(res, req_b, directory, HOUR, parsing)
                else:
                    filterM.check_exclude_page(req_b, res_b, directory, forbi, HOUR, parsing) 
            else:
                bypass_forbidden(res)
                """print("{}{}{}".format(HOUR, FORBI, res_b))
                output_scan(directory, res_b, 403)"""
        else:
            if exclude:
                if len(exclude) > 1:
                    filterM.check_multiple(req_b, res_b, directory, forbi, HOUR, parsing, size_bytes=size_bytes)
                elif type(req_p) == int:
                    filterM.check_exclude_code(res, req_b, directory, HOUR, parsing)
                else:
                    filterM.check_exclude_page(req_b, res_b, directory, forbi, HOUR, parsing)
            else:
                print("{}{} {}".format(HOUR, res_b if tw > 120 else page_b, req_b.status_code))
        #sys.stdout.write(" \033[34m\t\t\t\t\t  | B: {} {}\033[0m\r".format(result, exton))
        #sys.stdout.flush()


def hidden_dir(res, user_agent, directory, forbi, HOUR, filterM):
    """
    hidden_dir:
    Like the function 'backup_ext' but check if the type backup dir like '~articles/' exist.
    """
    pars = res.split("/")
    hidd_tild = "{}~{}/".format(url, pars[3]) if pars[-1] == "" else "{}~{}".format(url, pars[3])
    if header_parsed:
        user_agent.update(header_parsed)
        req_tild = requests.get(hidd_tild, headers=user_agent, allow_redirects=False, verify=False, timeout=10)
    else:
        req_tild = requests.get(hidd_tild, headers=user_agent, allow_redirects=False, verify=False, timeout=10)
    status_tild = req_tild.status_code
    if status_tild not in [404, 403, 500, 400, 301, 302]:
        if exclude:
            if len(exclude) > 1:
                filterM.check_multiple(req_tild, res_b, directory, forbi, HOUR, parsing, size_bytes=len(req_tild.content))
            elif type(req_p) == int:
                filterM.check_exclude_code(res, req_tild, directory, HOUR, parsing)
            else:
                filterM.check_exclude_page(req_tild, res, directory, forbi, HOUR)
        else:
            print("{} {} {} ({} bytes)".format(HOUR, PLUS, hidd_tild, len(req_tild.content)))
            output_scan(directory, hidd_tild, len(req_tild.content), 200)


def scan_error(directory, forbi):
    """
    scan_error: Checking the links who was in error during scan
    """
    filterM = filterManager()
    error_count = 0
    errors_stat = False
    print(LINE)
    print("{} Error check".format(INFO))
    print(LINE)
    path_error = directory + "/errors.txt"
    if os.path.exists(path_error):
        with open(path_error) as read_links:
            for ec in read_links.read().splitlines():
                error_count += 1
        with open(path_error) as read_links:
            print("{}[{}] Errors detected".format(INFO, error_count))
            for error_link in read_links.read().splitlines():
                try:
                    req = requests.get(error_link, verify=False) if not auth else requests.get(error_link, verify=False, auth=(auth.split(":")[0], auth.split(":")[1]))
                    len_req_error = len(req.content)
                    if exclude:
                        if type(req_p) == int:
                            pass
                        else:
                            cep = filterM.check_exclude_page(req, error_link, directory, forbi, HOUR=False)
                        if cep:
                            error_status = req.status_code
                            if error_status in [404, 406]:
                                pass
                            else:
                                print("{}[{}] {} ({} bytes)".format(INFO, req.status_code, error_link, len_req_error))
                                output_scan(directory, error_link, len_req_error, req.status_code)
                                errors_stat = True
                    else: 
                        error_status = req.status_code
                        if error_status in [404, 406]:
                            pass
                        else:
                            print("{}[{}] {}".format(INFO, req.status_code, error_link))
                            output_scan(directory, error_link, len_req_error, req.status_code)
                            errors_stat = True
                except Exception:
                    pass
                    #traceback.print_exc()
                sys.stdout.write("\033[34m[i] {}\033[0m\r".format(error_link))
                sys.stdout.flush()
            if errors_stat == False:
                print("{} Nothing error error need to be fixed".format(PLUS))
        os.system("rm {}".format(path_error))
    else:
        print("{} Nothing errors need to be fixed".format(PLUS))


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
    if res_time != 0 and res_time < 1 and thread_count < 30:
        #automaticly 30 threads MAX
        score = 1
        if i == 40 and score_next == 0:
            return 1, i;
        elif i == 160 and score_next == 1:
            return 1, i;
        elif i == 340 and score_next == 2:
            return 1, i;
        else:
            return 0, score;
    else:
        return 0, 0;


def defined_connect(s, res, user_agent=False, header_parsed=False):
    allow_redirection = True if stat == 301 or stat == 302 or redirect else False
    authent = (auth.split(":")[0], auth.split(":")[1]) if auth else False

    header = header_parsed if header_parsed else user_agent

    JS_error = ["You need to enable JavaScript to run this app", "JavaScript Required", "without JavaScript enabled",
    "This website requires JavaScript", "Please enable JavaScript", "Loading"]

    req = s.get(res, headers=header, allow_redirects=allow_redirection, verify=False, timeout=10, auth=authent)
    if any(js_e in req.text for js_e in JS_error):
        #print("{} This URL need to active JS: {}".format(INFO, res)) #TODO
        return False
    else:
        return req

def thread_wrapper(i, q, threads, manager, t_event, directory=False, forced=False, u_agent=False):
    while not q.empty() and not t_event.isSet():
        #print("DEBUG: {}".format(t_event.isSet())) #DEBUG
        tryUrl(i, q, threads, manager, directory, forced, u_agent)

def get_date():
    now = time.localtime(time.time())
    hour_t = time.strftime("%H:%M:%S", now)
    HOUR = "\033[35m[{}] \033[0m".format(hour_t)
    return HOUR

def tryUrl(i, q, threads, manager=False, directory=False, forced=False, u_agent=False, nLine=False):
    """
    tryUrl:
    Test all URL contains in the dictionnary with multi-threading.
    This script run functions:
    - create_backup()
    - dl()
    - backup_ext()
    - mail()
    """
    filterM = filterManager()
    s = requests.session()
    s.verify=False
    parsing = parsing_html()
    thread_score = 0
    score_next = 0
    waf_score = 0
    percentage = lambda x, y: float(x) / float(y) * 100
    thread_i = 0
    stop_add_thread = False
    time_i = 120
    time_bool = False
    waf = False
    error_bool = False
    tested_bypass = False
    len_flush = 1
    for numbers in range(len_w):
        thread_count = threading.active_count()
        thread_all = thread_count - 1
        res = q.get()
        page = "/".join(res.split("/")[3:])
        #print("{} :: {}".format(res.split("/"), "/".join(res.split("/")[3:]))) #DEBUG

        if auto and not stop_add_thread:
            thrds, scores = defined_thread(threads, thread_score, score_next)
            if scores == 1:
                thread_score += 1
            if thrds == 1:
                threads += 1
                score_next += 1
                manager.add_thread(i, threads, manager)
            #print("{}: {}".format(threading.currentThread().getName() ,thread_score))#DEBUG
        try:
            user_agent = {'User-agent': u_agent} if u_agent else {'User-agent': UserAgent().random} #for a random user-agent
            try:
                forbi = False
                if ts: #if --timesleep option defined
                    time.sleep(ts)
                req = defined_connect(s, res, user_agent, header_parsed)

                waf = verify_waf(req, res, user_agent) if not forced else False
                #verfiy_waf function, to check if waf detected, True: detected # False: not detected

                if waf:
                    if not tested_bypass:
                        try_bypass_waf = bypass_waf(req, res)
                        #print(try_bypass_waf) #DEBUG
                        #print(user_agent) #DEBUG
                        if try_bypass_waf == False: # if not worked not repeat
                            print("{}\033[31m[-]\033[0m Our tests not bypass it, sorry".format(BYP))
                            tested_bypass = True
                        elif try_bypass_waf and type(try_bypass_waf) is not bool:
                            user_agent.update(try_bypass_waf)
                    waf_score += 1
                    time_bool = True
                    if waf_score == 2:
                        waf_score = 0
                        if thread_count != 1:
                            thread_count += 1
                            stop_add_thread = True
                            print("{}Auto-reconfig scan to prevent the WAF".format(WAF))
                            manager.stop_thread()
                        #TODO: potentialy use TOR (apt install tor, pip install torrequest) for next requests after that.
                    #pass
                if backup:
                    hidden_dir(res, user_agent, directory, forbi, get_date(), filterM)
                if redirect and req.history:
                    status_link = [histo.status_code for histo in req.history]
                else:
                    status_link = req.status_code if req != False else False
                redirect_link = req.url if req != False else False
                len_req = len(req.content) if req != False else False

                display_res = res if tw > 110 else page
                if len(page) > 50:
                    len_flush = len(res) + 5 if tw > 120 else len(page[:10]) + 5
                else:
                    len_flush = len(res) + 5 if tw > 120 else len(page) + 5

                #print(status_link) #DEBUG status response
                if status_link == 200:
                    if exclude:
                        if type(req_p) == list and len(req_p) > 1:
                            #print(len_req)
                            filterM.check_multiple(req, res, directory, forbi, get_date(), parsing, size_bytes=len_req)
                        elif type(req_p) == int:
                            filterM.check_exclude_code(res, req, directory, get_date(), parsing)
                        else:
                            #print(req)
                            filterM.check_exclude_page(req, res, directory, forbi, get_date(), parsing, size_bytes=len_req)
                    else:            
                        if "robots.txt" in res.split("/")[3:]:
                            print("{} {} {}".format(get_date(), PLUS, res))
                            for r in req.text.split("\n"):
                                print("\t- {}".format(r))
                        if js:
                            #try to found js keyword
                            parsing.get_javascript(res, req)
                        # dl files and calcul size
                        download_file = dl(res, req, directory)
                        print("{} {} {} ({} bytes)".format(get_date(), PLUS, display_res, len_req))
                        output_scan(directory, res, len_req, stats=200)
                        #check backup
                        create_backup(res, directory, forbi)
                        #add directory for recursif scan
                        parsing.get_links(req, directory)
                        #scrape all link
                        if res[-1] == "/" and recur:
                            if ".git" in res:
                                pass
                            else:
                                spl = res.split("/")[3:]
                                result = "/".join(spl)
                                rec_list.append(result)
                        #report.create_report_url(status_link, res, directory)
                    if 'sitemap.xml' in res:
                        parsing.sitemap(req, directory)
                    parsing.search_s3(res, req, directory)
                elif status_link in [401, 403] and not forced:
                    #pass
                    if type(req_p) == list and len(req_p) > 1:
                        filterM.check_multiple(req, res, directory, forbi, get_date(), parsing)
                    elif type(req_p) == int:
                        filterM.check_exclude_code(res, req, directory, get_date(), parsing)
                    else:            
                        bypass_forbidden(res)
                        if res[-1] == "/" and recur:
                            if ".htaccess" in res or ".htpasswd" in res or ".git" in res or "wp" in res:
                                output_scan(directory, res, len_req, stats=403)
                            else:
                                spl = res.split("/")[3:]
                                result = "/".join(spl)
                                rec_list.append(result)
                                output_scan(directory, res, len_req, stats=403)
                            #report.create_report_url(status_link, res, directory)
                        if not forced:
                            forbi = True
                            print("{} {} {} ({} bytes) \033[31m{} Forbidden \033[0m".format(get_date(), FORBI, display_res, len_req, status_link))
                            create_backup(res, directory, forbi)
                            output_scan(directory, res, len_req, stats=403)
                            #report.create_report_url(status_link, res, directory)
                        elif not forced and recur:
                            pass
                        else:
                            print("{} {} {} ({} bytes) \033[31m{} Forbidden \033[0m".format(get_date(), FORBI, display_res, len_req, status_link))
                            output_scan(directory, res, len_req, stats=403)
                            #pass
                elif status_link == 404:
                    pass
                elif status_link == 405:
                    if exclude:
                        if type(req_p) == list and len(req_p) > 1:
                            #print(len_req)
                            filterM.check_multiple(req, res, directory, forbi, get_date(), parsing, size_bytes=len_req)
                        elif type(req_p) == int:
                            filterM.check_exclude_code(res, req, directory, get_date(), parsing)
                        else:
                            #print(req)
                            filterM.check_exclude_page(req, res, directory, forbi, get_date(), parsing, size_bytes=len_req)
                    else:
                        print("{} {} {} ({} bytes) [405]".format(get_date(), INFO, display_res, len_req))
                    #report.create_report_url(status_link, res, directory)
                elif status_link == 301:
                    if redirect:
                        if exclude:
                            if type(req_p) == list and len(req_p) > 1:
                                filterM.check_multiple(req, res, directory, forbi, get_date(), parsing, size_bytes=len_req)
                            elif type(req_p) == int:
                                filterM.check_exclude_code(res, req, directory, get_date(), parsing)
                            else:
                                filterM.check_exclude_page(req, res, directory, forbi, get_date(), parsing, size_bytes=len_req)
                        else:                
                            print("{} {} {}\033[33m => {}\033[0m 301 Moved Permanently".format(get_date(), LESS, display_res, redirect_link))
                            parsing.search_s3(res, req, directory)
                            output_scan(directory, res, len_req, stats=301)
                            #report.create_report_url(status_link, res, directory) #TODO
                elif status_link == 302:
                    if redirect:
                        if exclude:
                            if type(req_p) == list and len(req_p) > 1:
                                filterM.check_multiple(req, res, directory, forbi, get_date(), parsing, size_bytes=len_req)
                            elif type(req_p) == int:
                                filterM.check_exclude_code(res, req, directory, get_date(), parsing)
                            else:
                                filterM.check_exclude_page(req, res, directory, forbi, get_date(), parsing, size_bytes=len_req)
                        else:                
                            print("{} {} {}\033[33m => {}\033[0m 302 Moved Temporarily".format(get_date(), LESS, display_res, redirect_link))
                            parsing.search_s3(res, req, directory)
                            output_scan(directory, res, len_req, stats=302)
                            #report.create_report_url(status_link, res, directory) #TODO
                elif status_link == 304:
                    print("{}\033[33m[+] \033[0m {}\033[33m 304 Not modified \033[0m".format(get_date(), display_res))
                    parsing.search_s3(res, req, directory)
                    #report.create_report_url(status_link, res, directory) #TODO                
                elif status_link in [307, 308]:
                    pass
                elif status_link in [400, 500]:
                    #pass
                    if exclude:
                        if type(req_p) == list and len(req_p) > 1:
                            filterM.check_multiple(req, res, directory, forbi, get_date(), parsing, size_bytes=len_req)
                        elif type(req_p) == int:
                            filterM.check_exclude_code(res, req, directory, get_date(), parsing)
                        else:
                            filterM.check_exclude_page(req, res, directory, forbi, get_date(), parsing, size_bytes=len_req)
                    else:                
                        server_error = "400" if status_link == 400 else "500"
                        print("{} {} {} ({} bytes) \033[33m{} Server Error\033[0m".format(get_date(), SERV_ERR, display_res, len_req, server_error))
                        output_scan(directory, res, len_req, stats=status_link)
                elif status_link in [422, 423, 424, 425]:
                    print("{} {} {} \033[33mError WebDAV\033[0m".format(get_date(), LESS, res if tw > 110 else page))
                    #report.create_report_url(status_link, res, directory) #TODO
                elif status_link == 405:
                    print("{} {} {}".format(get_date(), PLUS, display_res))
                    #output_scan(directory, res, stats=405)
                elif status_link == 503:
                    req_test_index = requests.get(url, verify=False) # take origin page url (index) to check if it's really unavailable
                    if req_test_index.status_code == 503:
                        manager.stop_thread()
                        print("{}{} Service potentialy Unavailable, The site web seem unavailable please wait...\n".format(get_date(), WARNING))
                        time_bool = True
                    else:
                        pass
                elif status_link in [429, 522]:
                    req_test_many = requests.get(url, verify=False)
                    if req_test_many in [429, 522]:
                        print("{} {} Too many requests, web service seem to be offline".format(get_date(), WARNING))
                        print("STOP so many requests, we should wait a little...")
                        time_bool = True
                    else:
                        pass
                        #print("{}{}{} 429".format(HOUR, LESS, res))
                if backup != None:
                    fbackp = backup_ext(s, res, page, directory, forbi, get_date(), parsing, filterM)
                        #errors = manager.error_check() #TODO
                        #error_bool = True
            except Timeout:
                #traceback.print_exc() #DEBUG
                with open(directory + "/errors.txt", "a+") as write_error:
                    write_error.write(res+"\n")
                #errors = manager.error_check() #TODO
                #error_bool = True
            except Exception:
                #traceback.print_exc() #DEBUG
                with open(directory + "/errors.txt", "a+") as write_error:
                    write_error.write(res+"\n")
                #errors = manager.error_check()#TODO
                #error_bool = True
            q.task_done()
        except Exception:
            #traceback.print_exc() #DEBUG
            pass
        if time_bool: #if a waf detected, stop for any seconds
            while time_i != 0:
                time_i -= 1
                time.sleep(1)
                #for flush display
                sys.stdout.write("\033[34m {0:.2f}% - {1}/{2} | T:{3:} - stop 60s | {4:{5}}\033[0m\r".format(percentage(numbers+nLine, len_w)*thread_all, numbers*thread_all+nLine, len_w, thread_all, page, len_flush))
                sys.stdout.flush()
            time_i = 60
            time_bool = False
        else:
            if tw < 110:
                sys.stdout.write("\033[34m {0}/{1} | {2:{3}}\033[0m\r".format(numbers*thread_all+nLine, len_w, page if len(page) < 50 else page[:10], len_flush))
                sys.stdout.flush()
            else:
                sys.stdout.write("\033[34m {0:.2f}% - {1}/{2} | T:{3:} | {4:{5}}\033[0m\r".format(percentage(numbers+nLine, len_w)*thread_all, numbers*thread_all+nLine, len_w, thread_all, page if len(page) < 50 else page[:10], len_flush))
                sys.stdout.flush()


def check_words(url, wordlist, directory, u_agent, thread, forced=False, nLine=False):
    """
    check_words:
    Functions wich manage multi-threading
    """
    #report = create_report_test()
    #report.create_report_base(directory, header_)
    threads = 3 if auto else thread
    link_url = []
    hiddend = []
    with open(wordlist, "r") as payload:
        links = payload.read().splitlines()
    state = links[nLine:] if nLine else links
    for link in state:
        link_url = url + prefix + link if prefix else url + link
        enclosure_queue.put(link_url)
    manager = ThreadManager(enclosure_queue)
    for i in range(threads):
        worker = Thread(target=tryUrl, args=(i, enclosure_queue, threads, manager, directory, forced, u_agent, nLine))
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
                    link_url = url + prefix + link if prefix else url + link
                    enclosure_queue.put(link_url)
                enclosure_queue.join()
                i_r = i_r + 1
            print(LINE)
    else:
        print("\n{}not other directory to scan".format(INFO))
    try:
        os.remove(directory + "/backup.txt")
    except:
        pass
        print("{}backup.txt not found".format(INFO))
    if notify:
        notify_scan_completed()
        

def start_scan(subdomains, r, stat, directory, u_agent, thread, manageDir, header_, forbi):
    if subdomains:
        subdomain(subdomains)
    status(r, stat, directory, u_agent, thread, manageDir)
    scan_error(directory, forbi)
    print(LINE)
    try:
        create_report(directory, header_)
        print("{} The report has been created".format(PLUS))
    except:
        print("{} An error occurred, the report cannot be created".format(WARNING))


def create_dir_and_file(r, url, stat, u_agent, thread, subdomains, beforeStart):
    """
    create_dir_and_file:
    Create directory with the website name to keep a scan backup.
    """
    checkCms = check_cms()
    manageDir = manage_dir()
    checkSocketio = check_socketio()

    now = datetime.now()
    today = now.strftime("_%Y-%m-%d")

    backup_exist = False
    found_dire = False
    creat_other = True
    dire_exists = []

    today_hour = now.strftime("_%Y-%m-%d_%H-%M")

    dire = ''
    forbi = False
    url = url if len(url.split('/')) == 4 else '/'.join(url.split('/')[:-2]) + '/'
    if 'www' in url:
        direct = url.split('.')
        director = direct[1]
        dire = "{}.{}".format(direct[1], direct[2].replace("/",""))
        directory = "sites/{}{}".format(dire, today)
    else:
        direct = url.split('/')
        director = direct[2]
        dire = director
        directory = "sites/" + dire

    listdir = os.listdir("sites/")
    for ld in listdir:
        if dire in ld:
            found_dire = True
            dire_exists.append(ld)

    if not found_dire or force_first_step:
        creat_other = False
        directory = directory if not force_first_step else "sites/{}{}".format(dire, today_hour)
        os.makedirs(directory) if not force_first_step else os.makedirs(directory) # creat the dir
        os.makedirs(directory+"/output/") if not force_first_step else os.makedirs("sites/{}{}/output/".format(dire, today_hour))
        beforeStart.get_header(url, directory)
        beforeStart.get_dns(url, directory)
        result, v = checkCms.detect_cms(url, directory)
        if result:
            checkCms.cve_cms(result, v)
        dw = detect_wafw00f(url, directory, thread)
        if dw:
            thread = dw
        beforeStart.wayback_check(dire, directory)
        beforeStart.gitpast(url)
        beforeStart.firebaseio(url)
        query_dork(url, directory)
        beforeStart.check_localhost(url)
        beforeStart.check_vhost(dire, url)
        beforeStart.check_backup_domain(dire, url)
        checkSocketio.run_socketio(url, directory)
        start_scan(subdomains, r, stat, directory, u_agent, thread, manageDir, header_, forbi)
    else:
        for de in dire_exists:
            if os.path.exists("sites/{}/backup.txt".format(de)):
                backup_exist = True
                de = "sites/{}".format(de)
                start_scan(subdomains, r, stat, de, u_agent, thread, manageDir, header_, forbi) 

    #print("creat_other: {} // bck_exst: {}".format(creat_other, backup_exist)) #DEBUG
    if not backup_exist and creat_other:
        new_directory = "sites/{}{}".format(dire, today_hour)
        os.makedirs(new_directory)
        os.makedirs("{}/output/".format(new_directory))
        start_scan(subdomains, r, stat, new_directory, u_agent, thread, manageDir, header_, forbi)


if __name__ == '__main__':
    #arguments
    parser = argparse.ArgumentParser(add_help = True)
    parser = argparse.ArgumentParser(description='\033[32m Version 1.8 | Contact: codejumpgame@gmail.com\033')

    group = parser.add_argument_group('\033[34m> General\033[0m')
    group.add_argument("-u", help="URL to scan \033[31m[required]\033[0m", dest='url')
    group.add_argument("-t", help="Number of threads to use for URL Fuzzing. \033[32mDefault: 20\033[0m", dest='thread', type=int, default=20, required=False)
    group.add_argument("--exclude", help="Exclude page, response code, response size. \033[33m(Exemples: --exclude 500,337b)\033[0m", required=False, dest="exclude", nargs="+")
    group.add_argument("--auto", help="Automatic threads depending response to website. Max: 30", required=False, dest="auto", action='store_true')
    group.add_argument("--update", help="For automatic update", required=False, dest="update", action='store_true')

    group = parser.add_argument_group('\033[34m> Wordlist Settings\033[0m')
    group.add_argument("-w", help="Wordlist used for Fuzzing the desired webite. \033[32mDefault: dichawk.txt\033[0m", dest='wordlist', default="dichawk.txt", required=False)
    group.add_argument("-b", help="Adding prefix/suffix backup extensions during the scan. \033[33m(Exemples: exemple.com/~ex/, exemple.com/ex.php.bak...)\033[0m beware, take more longer", required=False, dest="backup", nargs="*", action="store")
    group.add_argument("-p", help="Add prefix in wordlist to scan", required=False, dest="prefix")

    group = parser.add_argument_group('\033[34m> Request Settings\033[0m')
    group.add_argument("-H", help="Modify header. \033[33m(Exemple: -H \"cookie: test\")\033[0m", required=False, dest="header_", type=str)
    group.add_argument("-a", help="Choice user-agent. \033[32mDefault: Random\033[0m", dest='user_agent', required=False)
    group.add_argument("--redirect", help="For scan with redirect response (301/302)", dest='redirect', required=False, action='store_true')
    group.add_argument("--auth", help="HTTP authentification. \033[33m(Exemples: --auth admin:admin)\033[0m", required=False, dest="auth")
    group.add_argument("--timesleep", help="To define a timesleep/rate-limit if app is unstable during scan.", required=False, dest="ts", type=float, default=0)

    group = parser.add_argument_group('\033[34m> Tips\033[0m')
    group.add_argument("-r", help="Recursive dir/files", required=False, dest="recursif", action='store_true')
    group.add_argument("-s", help="Subdomain tester", dest='subdomains', required=False)
    group.add_argument("--js", help="For try to found keys or token in the javascript page", required=False, dest="javascript", action='store_true')
    group.add_argument("--ffs", help="Force the first step of scan during the first running (waf, vhosts, wayback etc...)", required=False, dest="force_first_step", action='store_true')
    group.add_argument("--notify", help="For receveid notify when the scan finished (work only on linux)", required=False, dest="notify", action='store_true')

    group = parser.add_argument_group('\033[34m> Export Settings\033[0m')
    group.add_argument("-o", help="Output to site_scan.txt (default in website directory)", required=False, dest="output")

    results = parser.parse_args()
                                     
    url = results.url
    wordlist = results.wordlist
    subdomains = results.subdomains
    thread = results.thread
    u_agent = results.user_agent
    redirect = results.redirect
    recur = results.recursif
    prefix = results.prefix
    output = results.output
    backup = results.backup
    header_ = results.header_
    exclude = results.exclude 
    ts = results.ts
    auto = results.auto
    update = results.update
    js = results.javascript
    auth = results.auth
    force_first_step = results.force_first_step
    notify = results.notify

    if len(sys.argv) < 2:
        print("{}URL target is missing, try using -u <url> or -h for help".format(INFO))
        parser.print_help()
        sys.exit()

    banner()

    if update:
        auto_update()


    len_w = 0 #calcul wordlist size
    url = url + "/" if url.split("/")[-1] != "" else url
    if header_:
        s = header_.split(";")
        for c in s:
            if ":" in c:
                c = c.split(":", 1)
            elif "=" in c:
                c = c.split("=", 1)
            header_parsed.update([(c[0],c[1])])
    with open(wordlist, 'r') as words:
        for l in words:
            len_w += 1
    if exclude:
        exclude = exclude[0].split(",")
        if len(exclude) > 1:
            req_p = exclude
            #TODO
        elif "b" in exclude[0][-1] and int(exclude[0][0]):
            req_p = exclude
        elif len(exclude[0]) < 5: #Defined if it's int for response http code or strings for url
            req_p = int(exclude[0])
        else:
            req_exclude = requests.get(exclude[0], verify=False)
            req_p = req_exclude.text
    beforeStart = before_start()        
    beforeStart.test_timeout(url)
    r = requests.get(url, allow_redirects=False, verify=False, timeout=6)
    stat = r.status_code
    if backup is not None:
        bckp = EXT_B if backup == [] else [bck.replace(",","") for bck in backup]
    resume_scan(url, thread, wordlist, recur, redirect, js, backup=False if backup == None else bckp)
    print(LINE)
    create_dir_and_file(r, url, stat, u_agent, thread, subdomains, beforeStart)
