#! /usr/bin/env python3
# -*- coding: utf-8 -*-

__version__ = '2.3'
__program__ = 'HawkScan'
__author__ = 'codejump'
__twitter__ = 'https://twitter.com/c0dejump'
__projects__ = 'https://github.com/c0dejump'


#modules in standard library
import requests
import sys, os, re
import time
from datetime import datetime
import argparse
import json
import traceback
from requests.exceptions import Timeout
import signal
import random
import builtins
from urllib.parse import urljoin, urlsplit

# external modules
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK, EXCL, SERV_ERR, BYP, EXT_B, MINI_B, ARCH
from queue import Queue
import threading
from threading import Thread

from fake_useragent import UserAgent
try:
    UserAgent = UserAgent()
except Exception:
    UserAgent = ["Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko", "c0dejump", "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"]

from static.banner import banner

from report.creat_report import create_report

from modules.waf.detect_waf import verify_waf
from modules.waf.bypass_waf import bypass_waf

from modules.before_fuzzing.before_run import before_start
from modules.before_fuzzing.check_subdomain import subdomain

from modules.during_fuzzing.parsing_html import parsing_html
import modules.during_fuzzing.parsing_html as parsing_module
from modules.during_fuzzing.bypass_forbidden import bypass_forbidden
from modules.during_fuzzing.check_backup import scan_backup, vim_backup
from modules.during_fuzzing.calibration import Calibration, raw_request
from concurrent.futures import ThreadPoolExecutor

from modules.manage_dir import manage_dir

from modules.terminal_size import terminal_size
from modules.output import multiple_outputs
from modules.resume import resume_options

from modules.after_fuzzing.scan_errors import scan_error
try:
    from modules.after_fuzzing.send_notify import notify_scan_completed
except:
    notify = False


from modules.auto_update import auto_update
from modules.multi_scan import scan_multiple
from report.html_report import build_report
from run_modules import check_modules


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

_session_request = requests.Session.request
def _request_with_timeout(self, method, url, **kwargs):
    # a request without timeout can freeze a thread forever
    kwargs.setdefault("timeout", 15)
    return _session_request(self, method, url, **kwargs)
requests.Session.request = _request_with_timeout

rate = 0 # --rate: max requests per second (all threads)
proxy_list = [] # --proxy: one proxy (Burp...) or a file of proxies
rate_lock = threading.Lock()
rate_state = {"next": 0.0}

_session_send = requests.Session.send
def _send_limited(self, request, **kwargs):
    # every request goes here (fuzzing, calibration, bypass, backups, JS...): rate limit + proxy
    if rate:
        with rate_lock:
            now = time.time()
            wait = rate_state["next"] - now
            rate_state["next"] = max(now, rate_state["next"]) + 1.0 / rate
        if wait > 0:
            time.sleep(wait)
    if proxy_list:
        p = random.choice(proxy_list)
        kwargs["proxies"] = {"http": p, "https": p}
    return _session_send(self, request, **kwargs)
requests.Session.send = _send_limited
#requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':ADH-AES128-SHA256'
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

rec_list = []
#list to append url and then recursif scan

req_p = u""
#for exclude option

stat = 0

tw, th = terminal_size() # determine terminal size

header_parsed = {}

basic_user_agent = {"User-agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko"}

calib = None # Calibration (soft-404 / wildcard filter), created in check_words

authent = False

bp_current = 0
bypass_pool = ThreadPoolExecutor(max_workers=4) # 403 bypass tests run in background, fuzzing threads don't wait
bypass_jobs = []
bypass_seen = set()

rec_seen = set()
retries = {}
discovery = {"q": None, "root": "", "seen": set(), "count": 0}
counter_lock = threading.Lock()

waf_state = {"last": 0}
WAF_STATUS = (403, 406, 429, 430, 493, 503, 999)
NO_CALIB_STATUS = (404, 307, 308, 429, 503, 522)
BACKUP_STATUS = (200, 301, 302, 401, 403, 500)


class ThreadManager:
    """
    Class ThreadManager:
        To manage threads (add_thread())
    """
    lock = threading.Lock()

    def __init__(self, queue):
        self.queue = queue
 
    def add_thread(self, worker_func, args):
        """
        add thread from function definded_thread() (--auto)
        """
        worker = threading.Thread(target=worker_func, args=args)
        worker.daemon = True
        worker.start()


class filterManager:
    """
    Class filterManager:
        Filter page or response status code for remove false positif
        functions:
            - check_exclude_code
            - check_exclude_page
    """

    def exclude_type(self, req_p, s, req, res, directory, forbi, get_date, bp_current, parsing, len_req):
        if type(req_p) == list and len(req_p) > 1:
            #print(len_req)
            self.check_multiple(s, req, res, directory, forbi, get_date, bp_current, parsing, size_bytes=len_req)
        elif type(req_p) == int:
            self.check_exclude_code(s, res, req, directory, get_date, bp_current, parsing)
        else:
            #print(req)
            self.check_exclude_page(s, req, res, directory, forbi, get_date, bp_current, parsing, size_bytes=len_req)


    def check_multiple(self, s, req, res, directory, forbi, HOUR, bp_current, parsing=False, size_bytes=False):
        """
        Check_multiple: check multiple exclude, ex:
        --exclude 500,1337b,https://www.exemple.com
        --exclude 500,403
        """
        req_bytes = len(req.content)
        exclude_bytes = "[{}b]".format(req_bytes)
        list_exclude = {}
        for l_exclude in req_p:
            list_exclude[l_exclude] = False
        #print(list_exclude) #Debug
        for m_exclude in req_p:
            try:
                if int(m_exclude):
                    #print(m_exclude)
                    check_code = self.check_exclude_code(s, res, req, directory, HOUR, bp_current, parsing, multiple=True)
                    if check_code:
                        list_exclude[m_exclude] = True
            except:
                check_page = self.check_exclude_page(s, req, res, directory, forbi, HOUR, parsing, size_bytes, multiple=m_exclude)
                if check_page:
                    list_exclude[m_exclude] = True
        #print(list_exclude)
        if False not in list_exclude.values():
            if req.status_code in [403, 401]:
                #print("{} {} {:<13}{:<10} ".format(HOUR, FORBI, exclude_bytes, res))
                #bp_current += 1
                #bypass_forbidden(res, exclude[:-1] if "b" in exclude else False)
                #bp_current -= 1
                pass
            elif req.status_code in [400, 500]:
                print("{} {} {:<13}{:<10}  [{}]".format(HOUR, SERV_ERR, exclude_bytes, res, req.status_code))
            elif req.status_code in [301, 302]:
                redirect_link = ""
                for rh in req.headers:
                    if "location" in rh or "Location" in rh:
                        loc = req.headers[rh]
                        redirect_link = loc if "http" in loc.split("/")[0] else "{}{}".format(url, loc)
                        req_loc = s.get(loc, verify=False, allow_redirects=False, headers=basic_user_agent)
                        if "/".join(res.split("/")[1:]) == "/".join(loc.split("/")[1:-1]) and len(req_loc.content) != index_len and not "." in loc:
                            print(" \033[33m[<>]\033[0m {} redirect to \033[33m{}\033[0m [\033[33mPotential Hidden Directory\033[0m]".format(res, loc))
                    else:
                        req_loc = s.get(res, verify=False, allow_redirects=True, headers=basic_user_agent)
                        redirect_link = req_loc.url
                print("{} {} {:<13}{:<10}\033[33m → {}\033[0m {}\r".format(HOUR, LESS, exclude_bytes, res, redirect_link, req.status_code))
            elif req.status_code == 404:
                pass
            else:
                if len(req.content) != 0:
                    print("{} {} {:<13}{:<10}  [{}]".format(HOUR, PLUS, exclude_bytes, res, req.status_code))
            for l_exclude in req_p:
                list_exclude[l_exclude] = False



    def check_exclude_code(self, s, res, req, directory, HOUR, bp_current, parsing=False, multiple=False):
        """
        check_exclude_code: 
        You can activate this option to pass the  bp_current,response status code, ex:
        --exclude 500
        """
        req_bytes = len(req.content)
        exclude_bytes = "[{}b]".format(req_bytes)
        req_st = str(req.status_code) if multiple else req.status_code
        if multiple and req_st in req_p:
            return False
        elif req_st == req_p:
            pass
        elif req_st == 404:
            pass
        elif req_st in [403, 401]:
            #print("{} {} {:<13}{:<10} ".format(HOUR, FORBI, exclude_bytes, res))
            #bp_current += 1
            #bypass_forbidden(res)
            #bp_current -= 1
            pass
        elif req_st in [500, 400, 422, 423, 424, 425]:
            print("{} {} {:<13}{:<10} \033[33m{} Server Error\033[0m".format(HOUR, SERV_ERR, exclude_bytes, res, req.status_code))
            if js and req_bytes > 0:
                parsing.get_javascript(res, req, directory)
        elif req_st in [301, 302]:
            redirect_link = ""
            for rh in req.headers:
                if "location" in rh or "Location" in rh:
                    loc = req.headers[rh]
                    redirect_link = loc if "http" in loc.split("/")[0] else "{}{}".format(url, loc)
                    req_loc = s.get(redirect_link, verify=False, allow_redirects=False, headers=basic_user_agent)
                    if "/".join(res.split("/")[1:]) == "/".join(loc.split("/")[1:-1]) and len(req_loc.content) != index_len and not "." in loc:
                        print(" \033[33m[<>]\033[0m {} redirect to \033[33m{}\033[0m [\033[33mPotential Hidden Directory\033[0m]".format(res, loc))
                else:
                    req_loc = s.get(res, verify=False, allow_redirects=True, headers=basic_user_agent)
                    redirect_link = req_loc.url
            print("{} {} {:<13}{:<10}\033[33m → {}\033[0m {}\r".format(HOUR, LESS, exclude_bytes, res, redirect_link, req.status_code))
            if js and req_bytes > 0:
                parsing.get_javascript(res, req, directory)
        else:
            if multiple:
                return True
            else:
                if req_bytes > 0:
                    print("{} {} {:<13}{:<10}".format(HOUR, PLUS, exclude_bytes, res))
                if req_bytes > 0:
                    html_actions(directory, res, req, parsing)
                output_scan(directory, res, req_bytes, 200)


    def check_exclude_page(self, s, req, res, directory, forbi, HOUR, bp_current, parsing=False, size_bytes=False, multiple=False):
        """
        Check_exclude_page:  
        If scan blog, or social network etc.. you can activate this option to pass profil/false positive pages or response status code.
        Do a percentage btw pages.
        for use this option you do defined a profil/false positive page base, ex: 
            --exclude url.com/profil/codejump
        OR
            --exclude 240b for just number of bytes
        """
        scoring = 0
        multiple = multiple if multiple else "0b"
        req_bytes = len(req.content)

        if multiple and "." in multiple:
            print("\n\033[34mHi ! Sorry but multiple excludes with an url doesn't work for the moment, please put a number or bytes number\n(ex: --exclude 404,1337b)\033[0m")
            pid = os.getpid()
            os.killpg(pid, signal.SIGSTOP)

        if "b" in exclude[0][-1] and int(exclude[0][0]) or multiple[-1] == "b" and int(multiple[0]):
            #For exclude bytes number
            multiple = False if multiple == "0b" else multiple
            req_len = int(exclude[0][0:-1]) if not multiple else int(multiple.split('b')[0])
            exclude_bytes = "[{}b]".format(req_bytes)
            if multiple and req_bytes == req_len:
                return False
            elif multiple and req_bytes != req_len:
                return True
            if not multiple:
                if req_bytes == req_len:
                    pass
                elif req_bytes != req_len and req.status_code == 200 and len(req.content) != 0:
                    print("{} {} {:<13}{:<10}".format(HOUR, PLUS, exclude_bytes, res))
                    if req_bytes > 0:
                        html_actions(directory, res, req, parsing)
                elif req_bytes != req_len and req.status_code in [401, 403]:
                    print("{} {} {:<13}{:<10}".format(HOUR, FORBI, exclude_bytes, res))
                elif req_bytes != req_len and req.status_code in [500, 502, 400, 422, 423, 424, 425]:
                    print("{} {} {:<13}{:<10} \033[33m{} Server Error\033[0m".format(HOUR, SERV_ERR, exclude_bytes, res, req.status_code))
                elif req_bytes != req_len and req.status_code in [301, 302]:
                    redirect_link = req.url
                    print("{} {} {:<13}{:<10}\033[33m → {}\033[0m {}\r".format(HOUR, LESS, exclude_bytes, res, redirect_link, req.status_code))
                    if js and req_bytes > 0:
                        parsing.get_javascript(res, req, directory)
        else:
            ### Exclude page ###
            ## TODO
            multiple = False if multiple == "0b" else multiple
            if stat == 301 or stat == 302:
                req = requests.get(req.url, verify=False, headers=basic_user_agent)
            words = req_p
            for w in words.split("\n"):
                if w in req.text:
                    scoring += 1
                else:
                    pass
            len_wd = [lines for lines in words.split("\n")] #to avoid to do line per line
            perc = round(float(scoring) / len(len_wd) * 100)#to do a percentage for check look like page
            #print(req.text)
            #print(perc) #DEBUG percentage
            #print(multiple)
            if perc >= 80 or perc == 78:
                pass
            elif perc > 50 and perc < 80:
                print("{} {} {} [Potential exclude page with {}%]".format(HOUR, EXCL, res, perc))
            else:
                exclude_bytes = "[{}b]".format(len(req.content))
                if req.status_code in [403, 401]:
                    #bp_current += 1
                    #print("{} {} {:<13}{:<10} \033[31m{} Forbidden \033[0m".format(HOUR, FORBI, exclude_bytes, res, req.status_code))
                    #bypass_forbidden(res, exclude[:-1] if "b" in exclude else False)
                    #bp_current -= 1
                    pass
                elif req.status_code in [500, 400, 422, 423, 424, 425]:
                    if multiple:
                        return True
                    else:
                        print("{} {} {:<13}{:<10} \033[33m{} Server Error\033[0m".format(HOUR, SERV_ERR, exclude_bytes, res, req.status_code))
                else:
                    if multiple:
                        return True
                    else:
                        if req_bytes > 0:
                            html_actions(directory, res, req, parsing)
                        print("{} {} {:<13}{:<10}".format(HOUR, PLUS, exclude_bytes, res))
                #check backup
                create_backup(res, directory, forbi)
                #output scan.txt
                output_scan(directory, res, len(req.content), stats=200)
                if res[-1] == "/" and recur:
                    add_recursion(res)


class runFuzzing:
    """
    Class runFuzzing:
    Run fuzzing of webpage
    functions:
    - tryUrl
    """
    def light_mode(self, uri, directory, s, forced=False, u_agent=False):
        filterM = filterManager()
        parsing = parsing_html()

        global bp_current
        bp_current = 0

        global n_error
        n_error = 0

        time_i = 60

        res = uri
        page = "/".join(res.split("/")[3:])
        #print("{} :: {}".format(res.split("/"), "/".join(res.split("/")[3:]))) #DEBUG  
        try:
            user_agent_r = random.choice(UserAgent) if type(UserAgent) == list else UserAgent.random
            user_agent = {'User-agent': u_agent} if u_agent else {'User-agent': user_agent_r} #for a random user-agent
            try:
                forbi = False

                req = requests.get(res, verify=False, timeout=10, headers=user_agent)

                if ts: #if --timesleep option defined
                    time.sleep(ts)
                if req == 404:
                    status_link = req
                elif req != 404 and req.history:
                    status_link = [histo.status_code for histo in req.history]
                else:
                    status_link = req.status_code

                len_req = len(req.content) if req != 404 else False   
                bytes_len = "[{}b]".format(len_req)    
                display_res = res if tw > 110 else page 
                #print(status_link) #DEBUG status response

                if status_link == 200:
                    if exclude:
                        filterM.exclude_type(req_p, s, req, res, directory, forbi, get_date(), bp_current, parsing, len_req)
                    else:            
                        if len(req.content) > 0:
                            html_actions(directory, res, req, parsing)
                        print("{} {} {:<13}{:<10}".format(get_date(), PLUS, bytes_len, display_res))
                        output_scan(directory, res, len_req, stats=200) #check backup
                        create_backup(res, directory, forbi) #add directory for recursif scan
                elif status_link in [401, 403]:
                    if exclude:
                        filterM.exclude_type(req_p, s, req, res, directory, forbi, get_date(), bp_current, parsing, len_req)
                    else:
                        two_verify = requests.get(url, verify=False, headers=basic_user_agent)
                        if "Generated by cloudfront" in req.text and "Request blocked" in req.text and two_verify.status_code in [403, 401]:
                            print("{} {} Cloudflare protection activated on {}, wait 60s please".format(get_date(), WARNING, req.url))
                            time_wait(time_i)
                        if not forced:
                            forbi = True
                            print("{} {} {:<13}{:<10} \033[31m{} Forbidden \033[0m".format(get_date(), FORBI, bytes_len, display_res, status_link))
                        elif not forced and recur:
                            pass
                        else:
                            """print("{} {} {:<13}{:<10} \033[31m{} Forbidden \033[0m".format(get_date(), FORBI, bytes_len, display_res, status_link))
                            output_scan(directory, res, len_req, stats=403)"""
                            pass
                elif status_link == 404:
                    pass
                elif status_link == 405:
                    if exclude:
                        filterM.exclude_type(req_p, s, req, res, directory, forbi, get_date(), bp_current, parsing, len_req)
                    else:
                        print("{} {} {:<13}{:<10} [405]".format(get_date(), INFO, bytes_len, display_res))
                        if len(req.content) > 0:
                            html_actions(directory, res, req, parsing)
                    #report.create_report_url(status_link, res, directory)
                elif status_link in [301, 302]:
                    if exclude:
                        filterM.exclude_type(req_p, s, req, res, directory, forbi, get_date(), bp_current, parsing, len_req)
                    else:
                        redirect_link = ""
                        for rh in req.headers:
                            if "location" in rh or "Location" in rh:
                                loc = req.headers[rh]
                                redirect_link = loc if "http" in loc.split("/")[0] else "{}{}".format(url, loc)
                                req_loc = requests.get(redirect_link, verify=False, allow_redirects=False, headers=basic_user_agent)
                                if "/".join(res.split("/")[1:]) == "/".join(loc.split("/")[1:-1]) and len(req_loc.content) != index_len and not "." in loc:
                                    print(" \033[33m[<>]\033[0m {} redirect to \033[33m{}\033[0m [\033[33mPotential Hidden Directory\033[0m]".format(res, loc))
                            else:
                                req_loc = requests.get(res, verify=False, allow_redirects=True, headers=basic_user_agent)
                                redirect_link = req_loc.url
                        print("{} {} {:<13}{:<10}\033[33m → {}\033[0m {}\r".format(get_date(), LESS, bytes_len, display_res, redirect_link, status_link))
                        if len(req.content) > 0:
                            html_actions(directory, res, req, parsing)
                        output_scan(directory, res, len_req, stats=301)
                        #report.create_report_url(status_link, res, directory) #TODO
                elif status_link == 304:
                    print("{}\033[33m[+] \033[0m {}\033[33m 304 Not modified \033[0m".format(get_date(), display_res))
                    if len(req.content) > 0:
                        html_actions(directory, res, req, parsing)
                    #report.create_report_url(status_link, res, directory) #TODO                
                elif status_link in [307, 308]:
                    pass
                elif status_link in [400, 500]:
                    #pass
                    if exclude:
                        filterM.exclude_type(req_p, s, req, res, directory, forbi, get_date(), bp_current, parsing, len_req)
                    else:
                        if len(req.content) > 0:
                            html_actions(directory, res, req, parsing)          
                        print("{} {} {:<13}{:<10} \033[33m{} Server Error\033[0m".format(get_date(), SERV_ERR, bytes_len, display_res, status_link))
                        output_scan(directory, res, len_req, stats=status_link)
                elif status_link in [422, 423, 424, 425]:
                    print("{} {} {} \033[33mError WebDAV\033[0m\r".format(get_date(), LESS, res if tw > 110 else page))
                    if len(req.content) > 0:
                        html_actions(directory, res, req, parsing)
                    #report.create_report_url(status_link, res, directory) #TODO
                elif status_link == 405:
                    print("{} {} {}".format(get_date(), PLUS, display_res))
                    #output_scan(directory, res, stats=405)
                elif status_link == 503:
                    req_test_index = requests.get(url, verify=False, headers=basic_user_agent) # take origin page url (index) to check if it's really unavailable
                    if req_test_index.status_code == 503 and not forced:
                        #manager.stop_thread() #TODO
                        print("{}{} Service potentialy Unavailable, The site web seem unavailable please wait...\n".format(get_date(), WARNING))
                        time_wait(time_i)
                    else:
                        pass
                elif status_link in [429, 522]:
                    if "Just a moment" in req.text:
                        print("{} {} Cloudflare protection activated, wait 60s please".format(get_date(), WARNING))
                        time_wait(time_i)
                    else:
                        pass
            except Timeout:
                n_error += 1
                #traceback.print_exc() #DEBUG
                with open(directory + "/errors.txt", "a+") as write_error:
                    write_error.write(res+"\n")
                #pass
            except Exception:
                n_error += 1
                if print_error:
                    traceback.print_exc() #DEBUG
                with open(directory + "/errors.txt", "a+") as write_error:
                    write_error.write(res+"\n")
        except Exception:
            n_error += 1
            if print_error:
                traceback.print_exc() #DEBUG


    def tryUrl(self, i, q, threads, manager=False, directory=False, forced=False, u_agent=False, nLine=False):
        """
        tryUrl:
        Test all URL contains in the dictionnary with multi-threading.
        This script run functions:
        - create_backup()
        - dl()
        - suffix_backup()
        - mail()
        """
        global n
        n = 0 if not nLine else nLine

        global n_error
        n_error = 0

        filterM = filterManager()
        parsing = parsing_html()

        s = requests.session()
        s.verify=False

        thread_score = 0
        score_next = 0
        #waf_score = 0
        percentage = lambda x, y: float(x) / float(y) * 100.00
        stop_add_thread = False
        time_i = 60
        waf = False
        tested_bypass = False
        # same user-agent for the whole scan: stable responses (calibration) and the WAF bypass header is kept
        user_agent = {'User-agent': u_agent} if u_agent else dict(scan_user_agent)

        while True:
            res = q.get()
            if res is None: # end of scan
                q.task_done()
                break
            n += 1
            thread_count = threading.active_count() - 1
            page = "/".join(res.split("/")[3:])
            #print("{} :: {}".format(res.split("/"), "/".join(res.split("/")[3:]))) #DEBUG  

            if auto and not stop_add_thread:
                thrds, scores = defined_thread(threads, thread_score, score_next)
                if scores == 1:
                    thread_score += 1
                if thrds == 1:
                    threads += 1
                    score_next += 1
                    manager.add_thread(self.tryUrl, (i, q, threads, manager, directory, forced, u_agent, nLine))
                #print("{}: {}".format(threading.currentThread().getName() ,thread_score))#DEBUG
            try:
                try:
                    forbi = False
                    if ts: #if --timesleep option defined
                        time.sleep(ts)

                    req = defined_connect(s, res, user_agent, header_parsed)    

                    waf = verify_waf(s, req, res, user_agent) if not forced and waf_suspect(req) else False
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
                        time_wait(time_i)
                        requeue(q, res)
                        #TODO: if waf_score == X: manager.stop_thread() & re-create with the bypass or potentialy use TOR (apt install tor, pip install torrequest) for next requests after that.
                    if req.history:
                        status_link = [histo.status_code for histo in req.history]
                    else:
                        status_link = req.status_code
                    len_req = len(req.content)

                    bytes_len = "[{}b]".format(len_req)    

                    display_res = res if tw > 110 else page

                    if waf:
                        status_link = 0 # blocked response, the word was requeued
                    elif req.status_code == 400 and (not req.content or re.search(r"\.\.|\\|%[0-9a-fA-F]{2}|[<>'\"]", page)):
                        status_link = 404 # malformed path (raw payload refused by the server)
                    elif req.status_code not in NO_CALIB_STATUS and calib and calib.is_noise(s, res, req):
                        status_link = 404 # wildcard / soft-404 / catch-all / WAF page: same as not found

                    #print(status_link) #DEBUG status response
                    if status_link == 200:
                        if exclude:
                            filterM.exclude_type(req_p, s, req, res, directory, forbi, get_date(), bp_current, parsing, len_req)
                        else:            
                            if "robots.txt" in res.split("/")[3:]:
                                print("{} {} {}".format(get_date(), PLUS, res))
                                for r in req.text.split("\n"):
                                    print("\t├ {}".format(r))
                                    rule = re.match(r"\s*(dis)?allow\s*:\s*(/\S*)", r, re.I)
                                    if rule:
                                        discover(rule.group(2).rstrip("$"), "robots.txt")

                            if len(req.content) > 0:
                                html_actions(directory, res, req, parsing)

                            print("{} {} {:<13}{:<10}".format(get_date(), PLUS, bytes_len, display_res))
                            output_scan(directory, res, len_req, stats=200) #check backup
                            create_backup(res, directory, forbi) #add directory for recursif scan
                            if res[-1] == "/" and recur:
                                add_recursion(res)
                            #report.create_report_url(status_link, res, directory) #TODO
                    elif status_link in [401, 403]:
                        if "Generated by cloudfront" in req.text and "Request blocked" in req.text:
                            two_verify = s.get(url, verify=False, headers=basic_user_agent)
                            if two_verify.status_code in [403, 401]:
                                print("{} {} Cloudflare protection activated on {}, wait 60s please".format(get_date(), WARNING, req.url))
                                time_wait(time_i)

                        if exclude:
                            filterM.exclude_type(req_p, s, req, res, directory, forbi, get_date(), bp_current, parsing, len_req)
                        else:
                            is_dir = res[-1] == "/" and recur
                            # forced scan (root 403/404) too: generic 403 are already removed by the calibration
                            forbi = True
                            print("{} {} {:<13}{:<10} \033[31m{} Forbidden \033[0m".format(get_date(), FORBI, bytes_len, display_res, status_link))
                            launch_bypass(res, directory, user_agent)
                            create_backup(res, directory, forbi)
                            output_scan(directory, res, len_req, stats=403)
                            #report.create_report_url(status_link, res, directory)
                            if is_dir and not any(d in page for d in [".htaccess", ".htpasswd", ".git", "wp"]):
                                add_recursion(res)
                    elif status_link == 404:
                        pass
                    elif status_link == 405:
                        if exclude:
                            filterM.exclude_type(req_p, s, req, res, directory, forbi, get_date(), bp_current, parsing, len_req)
                        else:
                            print("{} {} {:<13}{:<10} [405]".format(get_date(), INFO, bytes_len, display_res))
                            if len(req.content) > 0:
                                html_actions(directory, res, req, parsing)
                        #report.create_report_url(status_link, res, directory)
                    elif status_link in [301, 302]:
                        if exclude:
                            filterM.exclude_type(req_p, s, req, res, directory, forbi, get_date(), bp_current, parsing, len_req)
                        else:
                            loc = req.headers.get("Location", "")
                            redirect_link = urljoin(res, loc) if loc else ""
                            if redirect_link == res + "/": # admin -> admin/ : directory, is it different from the index ?
                                req_loc = s.get(redirect_link, verify=False, allow_redirects=False, headers=basic_user_agent)
                                if len(req_loc.content) != index_len:
                                    print(" \033[33m[<>]\033[0m {} redirect to \033[33m{}\033[0m [\033[33mPotential Hidden Directory\033[0m]".format(res, loc))
                            print("{} {} {:<13}{:<10}\033[33m → {}\033[0m {}\r".format(get_date(), LESS, bytes_len, display_res, redirect_link, status_link))
                            if len(req.content) > 0:
                                html_actions(directory, res, req, parsing)
                            output_scan(directory, res, len_req, stats=req.status_code, detail="-> {}".format(redirect_link) if redirect_link else None)
                            #report.create_report_url(status_link, res, directory) #TODO
                    elif status_link == 304:
                        print("{}\033[33m[+] \033[0m {}\033[33m 304 Not modified \033[0m".format(get_date(), display_res))
                        if len(req.content) > 0:
                            html_actions(directory, res, req, parsing)
                        #report.create_report_url(status_link, res, directory) #TODO                
                    elif status_link in [307, 308]:
                        pass
                    elif status_link in [400, 500]:
                        #pass
                        if exclude:
                            filterM.exclude_type(req_p, s, req, res, directory, forbi, get_date(), bp_current, parsing, len_req)
                        else:
                            if len(req.content) > 0:
                                html_actions(directory, res, req, parsing)          
                            print("{} {} {:<13}{:<10} \033[33m{} Server Error\033[0m".format(get_date(), SERV_ERR, bytes_len, display_res, status_link))
                            output_scan(directory, res, len_req, stats=status_link)
                    elif status_link in [422, 423, 424, 425]:
                        print("{} {} {} \033[33mError WebDAV\033[0m\r".format(get_date(), LESS, res if tw > 110 else page))
                        if len(req.content) > 0:
                            html_actions(directory, res, req, parsing)
                        #report.create_report_url(status_link, res, directory) #TODO
                    elif status_link == 503:
                        req_test_index = requests.get(url, verify=False, headers=basic_user_agent) # take origin page url (index) to check if it's really unavailable
                        if req_test_index.status_code == 503 and not forced:
                            #manager.stop_thread() #TODO
                            print("{}{} Service potentialy Unavailable, The site web seem unavailable please wait...\n".format(get_date(), WARNING))
                            time_wait(time_i)
                            requeue(q, res)
                        else:
                            pass
                    elif status_link in [429, 522]:
                        if "Just a moment" in req.text:
                            print("{} {} Cloudflare protection activated, wait 60s please".format(get_date(), WARNING))
                            time_wait(time_i)
                        else:
                            req_test_many = s.get(url, verify=False, timeout=10, allow_redirects=False, headers=basic_user_agent)
                            if req_test_many.status_code in [429, 522]:
                                print("{} {} Too many requests, web service seem to be offline".format(get_date(), WARNING))
                                print("{} {} STOP so many requests, we should wait a little...".format(get_date(), WARNING))
                                time_wait(time_i)
                        requeue(q, res) # rate limited: the word is retried instead of lost

                    if backup != None and status_link in BACKUP_STATUS:
                        # backups only around real hits (was: around every word of the wordlist)
                        vim_backup(s, url, res, user_agent, exclude, get_date(), calib, directory, original=req)
                        scan_backup(s, url, len_req, res, js, req_p, bp_current, exclude, backup, header_parsed, user_agent, directory, forbi, filterM, page, tw, parsing, authent, get_date=get_date(), calib=calib, original=req)
                except Timeout:
                    n_error += 1
                    #traceback.print_exc() #DEBUG
                    with open(directory + "/errors.txt", "a+") as write_error:
                        write_error.write(res+"\n")
                    #pass
                except Exception:
                    n_error += 1
                    if print_error:
                        traceback.print_exc() #DEBUG
                    with open(directory + "/errors.txt", "a+") as write_error:
                        write_error.write(res+"\n")
                q.task_done()
            except Exception:
                n_error += 1
                if print_error:
                    traceback.print_exc() #DEBUG
                q.task_done()
            Progress(len_w, thread_count, nLine, page, percentage, tw, bp_current)


UNSAFE_PATH = ("logout", "logoff", "signout", "sign-out", "log-out", "delete", "remove", "destroy", "unsubscribe", "revoke", "disable", "reset")


def discover(path, source=""):
    """Path found in robots.txt / JS: fuzzed like a word (GET, same host, 300 max, nothing like logout/delete)"""
    global len_w
    q = discovery["q"]
    if q is None or not path or not path.startswith("/") or path.startswith("//") or len(path) > 150:
        return
    path = path.split("#")[0]
    if any(w in path.lower() for w in UNSAFE_PATH) or any(c in path for c in "{}$*<>\\ "):
        return
    with counter_lock:
        if path in discovery["seen"] or discovery["count"] >= 300:
            return
        discovery["seen"].add(path)
        discovery["count"] += 1
        len_w += 1
    q.put(discovery["root"] + path.lstrip("/"))


def target_words(url):
    """Backups named like the target: shop.zip, target.sql.gz, shop.target.com.tar.gz..."""
    host = (urlsplit(url).hostname or "").lower()
    if not host or re.match(r"^[0-9.]+$", host) or ":" in host:
        return []
    parts = host.split(".")
    names = {host, parts[0], host.replace(".", "_"), host.replace(".", "-")}
    if len(parts) >= 2:
        names.update([parts[-2], ".".join(parts[-2:])])
    if parts[0] == "www" and len(parts) > 2:
        names.add(parts[1])
    names.discard("www")
    exts = [".zip", ".tar.gz", ".tgz", ".rar", ".7z", ".tar", ".sql", ".sql.gz", ".sql.zip", ".bak", ".gz", ".db"]
    return [n + e for n in sorted(names) for e in exts]


STACK_EXTENSIONS = [
    (("phpsessid", "laravel_session", "ci_session", "x-powered-by: php", "symfony", "wordpress", "wp-content"), ["php"]),
    (("asp.net", "aspnet", ".aspxauth", "x-aspnet-version", "microsoft-iis", "__viewstate"), ["aspx", "asp", "ashx"]),
    (("jsessionid", "servlet", "jsp", "tomcat", "jetty", "weblogic", "websphere", "jboss", "wildfly"), ["jsp", "do", "action"]),
    (("cfid", "cftoken", "coldfusion"), ["cfm"]),
]


def scan_extensions(index_req):
    """-e php,aspx or -e auto (from the cookies / headers / home page)"""
    if not extensions:
        return []
    if extensions.lower() != "auto":
        return [e.strip().lstrip(".") for e in extensions.split(",") if e.strip()]
    hay = " ".join("{}: {}".format(k, v) for k, v in index_req.headers.items()).lower() + index_req.text[:20000].lower()
    found = []
    for markers, exts in STACK_EXTENSIONS:
        if any(m in hay for m in markers):
            found += [e for e in exts if e not in found]
    if not found:
        print("{} -e auto: no stack detected (routes without extension), no extension added".format(INFO))
    return found


def requeue(q, res):
    """Put back a word lost because of rate-limit / unavailability (2 retries max)"""
    with counter_lock:
        retries[res] = retries.get(res, 0) + 1
        if retries[res] > 2:
            return
    q.put(res)


def waf_suspect(req):
    """verify_waf costs 2 requests on the index: only on blocking status codes, max once every 30s"""
    if req.status_code not in WAF_STATUS:
        return False
    with counter_lock:
        if time.time() - waf_state["last"] < 30:
            return False
        waf_state["last"] = time.time()
    return True


def launch_bypass(res, directory, user_agent):
    """Forbidden bypass in background (once per URL) so fuzzing threads keep going"""
    global bp_current
    with counter_lock:
        if res.rstrip("/") in bypass_seen: # admin & admin/ : tested once
            return
        bypass_seen.add(res.rstrip("/"))
        bp_current += 1
    headers = build_headers(user_agent)

    def job():
        global bp_current
        try:
            bypass_forbidden(res, headers=headers, auth=authent, directory=directory)
        except Exception:
            if print_error:
                traceback.print_exc()
        finally:
            with counter_lock:
                bp_current -= 1
    bypass_jobs.append(bypass_pool.submit(job))


def add_recursion(res):
    """Queue a found directory for the recursive scan (once, max depth 3)"""
    path = "/".join(res.split("/")[3:])
    if ".git" in path or path.count("/") > 3:
        return
    with counter_lock:
        if path in rec_seen:
            return
        rec_seen.add(path)
        rec_list.append(path)


def time_wait(time_i):
    while time_i != 0:
        time_i -= 1
        time.sleep(1)
        sys.stdout.write(" Time Remaining for thread: {}\r".format(time_i))


def html_actions(directory, res, req, parsing):
    dl(res, req, directory) # dl files and calcul size
    if not parsing_module.is_text(req):
        return
    parsing.html_recon(res, req, directory) #try to found S3 buckets
    parsing.get_links(req, directory) #scrape all link
    if js:
        parsing.get_javascript(res, req, directory) #try to found js keyword



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
                lignes = ligne.split("\n") #take the last line in file
                last_line = lignes[-2]
        with open(wordlist, "r") as f:
            for nLine, line in enumerate(f):
                if line.strip() == last_line:
                    print(LINE)
                    forced = False
                    check_words(url, wordlist, directory, u_agent, thread, forced, nLine)
                    return # resumed: don't rescan the whole wordlist after
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
            continue_error = input("The authentification seems bad, continue ? [y/N]")
            if continue_error not in ["y", "Y"]:
                sys.exit()

    if stat == 200:
        check_words(url, wordlist, directory, u_agent, thread)
    elif stat in [301, 302]:
        req_red = requests.get(url, verify=False, headers=basic_user_agent)
        message_type = "Permanently" if stat == 301 else "Temporarily"
        follow = input("{} {} Moved {} → {}\nDo you want follow redirection ? [y/N]".format(PLUS, stat, message_type, req_red.url))
        print("")
        stat = stat if follow == "y" or follow == "Y" else 0
        check_words(url, wordlist, directory, u_agent, thread)
    elif stat == 304:
        pass
    elif stat == 404:
        not_found = input("{} URL return 404 response / forced ? [y/N]: ".format(LESS))
        if not_found == "y" or not_found == "Y":
            forced = True
            check_words(url, wordlist, directory, u_agent, thread, forced)
        else:
            sys.exit()
    elif stat in [403, 401]:
        fht = input(FORBI + " URL return {} response / forced ? [y/N]: ".format(stat))
        if fht == "y" or fht == "Y":
            forced = True
            check_words(url, wordlist, directory, u_agent, thread, forced)
        else:
            sys.exit()
    else:
        not_found = input("{} URL return {} response / forced ? [y/N]: ".format(LESS, stat))
        if not_found == "y" or not_found == "Y":
            forced = True
            check_words(url, wordlist, directory, u_agent, thread, forced)
        else:
            sys.exit()


def create_backup(res, directory, forbi):
    """Create backup file"""
    with open(directory + "/backup.txt", "a+") as words:
        #delete url to keep just file or dir
        anti_sl = res.split("/")
        rep = str(anti_sl[3:])
        result = rep.replace("['","").replace("']","").replace("',", "/").replace(" '","")
        words.write(result + "\n")


def dl(res, req, directory):
    """ Download files """
    #extensions = ['.json', '.txt', '.html', '.jsp', '.xml', '.aspx', '.zip', '.old', '.bak', 
    #'.sql', '.js', '.asp', '.ini', '.rar', '.dat', '.log', '.backup', '.dll', '.save', '.BAK', '.inc', '.md', ".info"]
    d_files = directory + "/files/"
    if not os.path.exists(d_files):
        try:
            os.makedirs(d_files)
        except:
            pass
    anti_sl = res.split("/")
    rep = anti_sl[3:]
    result = rep[-1]
    p_file = d_files + result
    if "." in result:
        with open(p_file, 'wb') as fichier: # binary: archives/dumps stay intact
            try:
                fichier.write(req.content)
            except:
                pass


def output_scan(directory, res, size_res, stats, detail=None):
    """
    output_scan:
    Output to scan
    """
    mo = multiple_outputs()
    directory = output if output else directory
    if output_type == "csv":
        mo.csv_output(directory, res, stats, size_res)
        mo.raw_output(directory, res, stats, size_res, detail=detail)
    elif output_type == "json":
        mo.json_output(directory, res, stats, size_res)
        mo.raw_output(directory, res, stats, size_res, detail=detail)
    else:
        mo.raw_output(directory, res, stats, size_res, detail=detail)


def defined_thread(thread, i, score_next):
    """
    Defined_thread: to defined the threads number
    """
    #print("score: {}".format(score_next))
    thread_count = threading.active_count()
    res_time = 0
    try:
        start = time.time()
        requests.get(url, verify=False)
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


def build_headers(user_agent=False):
    """User-agent + all the -H headers (keep-alive: no more "Connection: close")"""
    header = {"Cache-Control": "no-cache", "Pragma": "no-cache"}
    if user_agent:
        header.update(user_agent)
    if header_parsed:
        header.update(header_parsed)
    return header


def defined_connect(s, res, user_agent=False, header_parsed=False):
    allow_redirection = True if stat == 301 or stat == 302 else False
    global authent
    authent = tuple(auth.split(":", 1)) if auth else False
    header = build_headers(user_agent)

    # raw: payloads like "..;/", "%2e/" or "/./" are sent as written in the wordlist
    # (JS-only pages are no more dropped as 404: the calibration filters the SPA catch-all)
    return raw_request(s, "GET", res, headers=header, auth=authent, timeout=15, allow_redirects=allow_redirection)


def get_date():
    now = time.localtime(time.time())
    hour_t = time.strftime("%H:%M:%S", now)
    HOUR = "\033[36m[{}] \033[0m".format(hour_t)
    return HOUR


def Progress(len_w, thread_count, nLine, page, percentage, tw, bp_current):
    """
    Progress: just a function to print the scan progress
    """
    if batch:
        return
    progress_print = "\033[36m {0}/{1} | T:{2} | Err: {3} | Cb: {4} | {5}\033[0m\r".format(n+nLine, len_w, thread_count, n_error, bp_current, page if len(page) < 55 else page.split("/")[-3:-1])
    little_progress_print = "\033[36m {0}/{1} | Err: {2} | Cb: {3} | {4}\033[0m\r".format(n, len_w, n_error, bp_current, page if len(page) < 70 else page.split("/")[-3:-1])
    if tw < 110:
        sys.stdout.write(little_progress_print)
        if len(little_progress_print) > 36: sys.stdout.write("\033[K") #clear line
    else:
        per = percentage(n+nLine, len_w)
        sys.stdout.write("\033[36m {0:.2f}% - {1}/{2} | T:{3} | Err: {4} | Cb: {5} | {6}\033[0m\r".format(per, n+nLine, len_w, thread_count, n_error, bp_current, page if len(page) < 55 else page.split("/")[-3:-1]))
        if len(progress_print) > 55: sys.stdout.write("\033[K") #clear line 


def check_words(url, wordlist, directory, u_agent, thread, forced=False, nLine=False):
    """
    check_words:
    Functions wich manage multi-threading
    """
    #report = create_report_test()
    #report.create_report_base(directory, header_)
    global n, calib, index_len, len_w
    runFuzz = runFuzzing()
    threads = 3 if auto else thread
    q = Queue() # one queue per scan: workers of a previous site (-f) can't mix results
    discovery.update({"q": q, "root": "/".join(url.split("/")[:3]) + "/"}) # paths found in robots.txt / JS are fuzzed too
    parsing_module.discover_hook = discover
    parsing_module.request_headers = build_headers(scan_user_agent)

    try:
        index_req = defined_connect(requests.session(), url, scan_user_agent, header_parsed) # with the -H headers (cookies)
    except Exception:
        index_req = requests.get(url, verify=False, allow_redirects=False, headers=basic_user_agent)
    index_len = len(index_req.content)
    if index_req.content and not nLine:
        try:
            html_actions(directory, url, index_req, parsing_html()) # home page: links, S3 buckets, JS secrets (--js)
        except Exception:
            if print_error:
                traceback.print_exc()

    calib = Calibration(lambda s, u: defined_connect(s, u, scan_user_agent, header_parsed), enabled=not no_calib, flood_limit=flood, directory=output if output else directory)

    with open(wordlist, "r", errors="ignore") as payload:
        links = payload.read().splitlines()
    exts = scan_extensions(index_req)
    if exts:
        print("{} Extensions added to the words without extension: {}".format(INFO, ", ".join(exts)))
        links = links + [w + "." + e for e in exts for w in links if w and not w.endswith("/") and "." not in w.split("/")[-1] and "?" not in w]
    state = links[nLine:] if nLine else target_words(url) + links # For restart from the last line found in the dico
    len_w = len(state) + (nLine or 0)
    manager = ThreadManager(q)
    for i in range(threads):
        worker = Thread(target=runFuzz.tryUrl, args=(i, q, threads, manager, directory, forced, u_agent, nLine))
        worker.daemon = True
        worker.start()
    try:
        for link in state:
            link_url = "{}{}{}".format(url, prefix, link) if prefix else "{}{}".format(url, link) #url/prefix-words or url/words
            q.put(link_url)
        q.join()
        """
            Recursif: For recursif scan (rec_list grows during the scan, depth limited in add_recursion)
        """
        root = "/".join(url.split("/")[:3]) + "/"
        i_r = 0
        if rec_list:
            print(LINE)
        while i_r < len(rec_list):
            url_rec = "{}{}".format(root, rec_list[i_r])
            print("{} Entering in directory: {}".format(INFO, rec_list[i_r]))
            print(LINE)
            n = 0
            for link in links:
                link_url = "{}{}{}".format(url_rec, prefix, link) if prefix else "{}{}".format(url_rec, link)
                q.put(link_url)
            q.join()
            i_r = i_r + 1
            print(LINE)
        if not rec_list:
            print("\n{}not other directory to scan".format(INFO))
        if discovery["count"]:
            print("\033[K{} {} paths found in robots.txt / JS were tested too".format(INFO, discovery["count"]))
        pending = [job for job in bypass_jobs if not job.done()]
        if pending:
            print("\033[K{} Waiting for {} forbidden bypass test(s)...".format(INFO, len(pending)))
            for job in pending:
                job.result()
    except KeyboardInterrupt:
        with q.mutex:
            q.queue.clear()
        for job in bypass_jobs:
            job.cancel()
        if not file_url:
            print(" {}Canceled by keyboard interrupt (Ctrl-C) ".format(INFO))
            sys.exit()
        else:
            print(" {}Canceled by keyboard interrupt (Ctrl-C), next site ".format(INFO))
    for i in range(threads):
        q.put(None) # stop the workers
    try:
        os.remove(directory + "/backup.txt")
    except:
        print("{}backup.txt not found".format(INFO))
    if notify:
        notify_scan_completed()
        

def write_run_info(directory, state):
    """--run-info: where this scan writes its results (read by the multi-site scan)"""
    if run_info:
        with open(run_info, "w") as f:
            json.dump({"url": url, "directory": output if output else directory, "status": state}, f)


def start_scan(subdomains, r, stat, directory, u_agent, thread, manageDir, header_, forbi):
    write_run_info(directory, "running")
    if subdomains:
        subdomain(subdomains)
    if light_mode:
        runFuzz = runFuzzing()

        s = requests.session()
        s.verify=False

        c = 0
        with open(wordlist, "r") as payload:
            links = payload.read().splitlines()
        for l in links:
            uri = "{}{}".format(url, l)
            runFuzz.light_mode(uri, directory, s)
            c+=1
            sys.stdout.write(" {}/{} - {} \r".format(c, len(links), l))
            sys.stdout.write("\033[K")
    else:
        status(r, stat, directory, u_agent, thread, manageDir)
    scan_error(directory, build_headers(scan_user_agent), authent, calib)
    print(LINE)
    if not html and not run_info: # old per-site report, replaced by the global one with --html / -f
        try:
            create_report(directory, header_)
            print("\n{} The report has been created".format(PLUS))
        except:
            print("\n{} An error occurred, the report cannot be created".format(WARNING))
    if html and not run_info:
        dirs = [directory] + ([output] if output and output != directory else [])
        site = {"url": url, "status": "done", "duration": time.time() - scan_started, "directories": dirs}
        path = build_report([site], os.path.join(directory, "hawkscan_report.html"), report_meta())
        print("{} HTML report: {}".format(PLUS, os.path.abspath(path)))
    write_run_info(directory, "done")
    print(LINE)


def report_meta():
    """Options shown in the HTML report (no credential / header value)"""
    return {
        "wordlist": os.path.basename(wordlist),
        "threads": thread,
        "parallel": (parallel or 3) if file_url or resume else None,
        "backups": " ".join(backup) if backup else ("default" if backup == [] else None),
        "recursive": recur,
        "js analysis": js,
        "calibration": not no_calib,
        "authenticated": bool(auth or header_),
    }


BATCH_ANSWERS = [("follow redirection", "n"), ("[c:r]", "c"), ("Do you want continue", "n"), ("Enter the number of threads", "10")]


def batch_input(prompt=""):
    """--batch: no question, sensible answer (force 403/404 targets, resume backups, keep threads...)"""
    answer = next((a for k, a in BATCH_ANSWERS if k in prompt), "y")
    print("{}{} (batch)".format(prompt, answer))
    return answer



def make_scan_dir(path):
    """Create the scan directory, path_2, path_3... if it already exists (same host scanned in the same minute)"""
    candidate, i = path, 1
    while True:
        try:
            os.makedirs(candidate)
            break
        except FileExistsError:
            i += 1
            candidate = "{}_{}".format(path, i)
    os.makedirs(candidate + "/output/", exist_ok=True)
    return candidate


def create_structure_scan(r, url, stat, u_agent, thread, subdomains, beforeStart):
    """
    create_structure_scan:
    Create directory with the website name to keep a scan backup.
    """
    ram = check_modules()
    manageDir = manage_dir()

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

    if not found_dire or force_first_step and not not_first_step:
        creat_other = False
        dire_date = "{}{}".format(dire, today_hour)
        directory = directory if not force_first_step else "sites/{}".format(dire_date)
        directory = make_scan_dir(directory) # creat the dir

        if not file_url and not not_first_step:
            mods = ram.run_all_modules(beforeStart, url, directory, dire, thread) # Run all modules
            if mods:
                thread = mods

        start_scan(subdomains, r, stat, directory, u_agent, thread, manageDir, header_, forbi)
    else:
        for de in dire_exists:
            if os.path.exists("sites/{}/backup.txt".format(de)):
                backup_exist = True
                de = "sites/{}".format(de)
                start_scan(subdomains, r, stat, de, u_agent, thread, manageDir, header_, forbi) 

    #print("creat_other: {} // bck_exst: {}".format(creat_other, backup_exist)) #DEBUG
    if not backup_exist and creat_other:
        new_directory = make_scan_dir("sites/{}{}".format(dire, today_hour))
        start_scan(subdomains, r, stat, new_directory, u_agent, thread, manageDir, header_, forbi)


def main(url):
    beforeStart = before_start()
    beforeStart.test_timeout(url, first=True)
    user_agent_r = random.choice(UserAgent) if type(UserAgent) == list else UserAgent.random
    r = requests.get(url, allow_redirects=False, verify=False, timeout=15, headers=dict({'User-agent': user_agent_r}, **header_parsed))
    stat = r.status_code
    if backup is not None:
        if len(backup) > 0 and backup[0] == "min":
            bckp = MINI_B
        elif len(backup) > 0 and backup[0] == "arc":
            bckp = ARCH
        else:
            bckp = EXT_B if backup == [] else [bck.replace(",","") for bck in backup]
    resume_options(url, thread if not light_mode else 0, wordlist, recur, js, exclude, proxy, header=False if not header_ else " | ".join(header_), backup=False if backup == None else bckp)
    print(LINE)
    create_structure_scan(r, url, stat, u_agent, thread, subdomains, beforeStart)



if __name__ == '__main__':
    #arguments
    parser = argparse.ArgumentParser(add_help = True)
    parser = argparse.ArgumentParser(description='\033[32m Version 2.3 | contact: https://twitter.com/c0dejump\033[0m')

    group = parser.add_argument_group('\033[34m> General\033[0m')
    group.add_argument("-u", help="URL to scan \033[31m[required]\033[0m", dest='url')
    group.add_argument("-f", help="file with multiple URLs to scan", dest='file_url', required=False)
    group.add_argument("-t", help="Number of threads to use for URL Fuzzing. \033[32mDefault: 30\033[0m", dest='thread', type=int, default=30, required=False)
    group.add_argument("--exclude", help="Exclude page, response code, response size. \033[33mEx: --exclude 500,337b\033[0m", required=False, dest="exclude", nargs="+")
    group.add_argument("--auto", help="Automatic threads depending response to website. Max: 30 \033[33m(In progress...)\033[0m", required=False, dest="auto", action='store_true')
    group.add_argument("--update", help="For automatic update", required=False, dest="update", action='store_true')
    group.add_argument("--lightmode", help="For a just simple fuzzing 1 request per second & a new session for each request", required=False, dest="light_mode", action='store_true')
    group.add_argument("--no-calib", help="Disable the auto-calibration (soft-404 / wildcard false positives filter)", required=False, dest="no_calib", action='store_true')
    group.add_argument("--parallel", help="With -f: number of websites scanned at the same time (each one with -t threads). \033[32mDefault: 3\033[0m", required=False, dest="parallel", type=int)
    group.add_argument("--resume", help="Resume a stopped -f scan: done websites are skipped, interrupted ones continue. \033[33mEx: --resume sites/_multi_2026-10-29_09-31-21\033[0m", required=False, dest="resume")
    group.add_argument("--batch", help=argparse.SUPPRESS, required=False, dest="batch", action='store_true') # no question (used by -f)
    group.add_argument("--run-info", help=argparse.SUPPRESS, required=False, dest="run_info") # used by -f
    group.add_argument("--flood", help="Mute a response seen more than N times on different paths (catch-all / WAF rule / error page). 0 to disable. \033[32mDefault: 5\033[0m", required=False, dest="flood", type=int, default=5)

    group = parser.add_argument_group('\033[34m> Wordlist Settings\033[0m')
    group.add_argument("-w", help="Wordlist used for Fuzzing the desired webite. \033[32mDefault: dichawk.txt\033[0m", dest='wordlist', default="dichawk.txt", required=False)
    group.add_argument("-b", help="Adding prefix/suffix backup extensions during the scan. \033[33mEx: -b .bak, .old | OR 'min' for default minimum backup\033[0m. \033[32mDefault: all extension in config.py\033[0m", required=False, dest="backup", nargs="*", action="store")
    group.add_argument("-p", help="Add prefix in wordlist to scan", required=False, dest="prefix")
    group.add_argument("-e", help="Extensions added to the words without extension, or 'auto' (detected stack: php, aspx, jsp...). \033[33mEx: -e php,bak | -e auto\033[0m", required=False, dest="extensions")

    group = parser.add_argument_group('\033[34m> Request Settings\033[0m')
    group.add_argument("-H", help="Add a header, several -H allowed. \033[33mEx: -H \"Cookie: a=1; b=2\" -H \"Authorization: Bearer x\"\033[0m", required=False, dest="header_", action="append")
    group.add_argument("-a", help="Choice user-agent. \033[32mDefault: Random\033[0m", dest='_user_agent', required=False)
    group.add_argument("--auth", help="HTTP authentification. \033[33mEx: --auth admin:admin)\033[0m", required=False, dest="auth")
    group.add_argument("--timesleep", help="To define a timesleep/rate-limit if app is unstable during scan.", required=False, dest="ts", type=float, default=0)
    group.add_argument("--proxy", help="Proxy for all requests (Burp...) or a file of proxies (random per request). \033[33mEx: --proxy http://127.0.0.1:8080\033[0m", required=False, dest="proxy")
    group.add_argument("--rate", help="Max requests per second for a website, all threads included (respect the program rules). \033[33mEx: --rate 20\033[0m", required=False, dest="rate", type=float, default=0)
    group.add_argument("--error", help="print errors", required=False, dest="print_error", action='store_true')

    group = parser.add_argument_group('\033[34m> Tips\033[0m')
    group.add_argument("-r", help="Recursive dir/files", required=False, dest="recursif", action='store_true')
    group.add_argument("-s", help="Subdomain tester", dest='subdomains', required=False)
    group.add_argument("--js", help="For try to found keys or token in the javascript page", required=False, dest="javascript", action='store_true')
    group.add_argument("--nfs", help="Not the first step of scan during the first running (waf, vhosts, wayback etc...)", required=False, dest="not_first_step", action='store_true')
    group.add_argument("--ffs", help="Force the first step of scan during the first running (waf, vhosts, wayback etc...)", required=False, dest="force_first_step", action='store_true')
    group.add_argument("--notify", help="For receveid notify when the scan finished (work only on linux)", required=False, dest="notify", action='store_true')

    group = parser.add_argument_group('\033[34m> Export Settings\033[0m')
    group.add_argument("-o", help="Output different path (default in website directory). \033[33mEx: -o /tmp/toto.com will create a directory in /tmp/toto.com/output/raw.txt\033[0m", required=False, dest="output")
    group.add_argument("-of", help="Output file format. Available formats: json, csv, txt ", required=False, dest="output_type")
    group.add_argument("--html", help="Global HTML report (one or several websites with -f): findings, bypasses, secrets, backups, filters & export", required=False, dest="html", action='store_true')

    results = parser.parse_args()
                                     
    url = results.url
    file_url = results.file_url
    light_mode = results.light_mode
    wordlist = results.wordlist
    subdomains = results.subdomains
    thread = results.thread
    u_agent = results._user_agent
    recur = results.recursif
    prefix = results.prefix
    output = results.output
    output_type = results.output_type
    backup = results.backup
    header_ = results.header_
    exclude = results.exclude 
    ts = results.ts
    auto = results.auto
    update = results.update
    js = results.javascript
    auth = results.auth
    not_first_step = results.not_first_step
    force_first_step = results.force_first_step
    notify = results.notify
    proxy = results.proxy
    extensions = results.extensions
    rate = results.rate
    if proxy:
        if os.path.isfile(proxy):
            with open(proxy) as f_proxy:
                proxy_list = [l.strip() for l in f_proxy if l.strip() and not l.startswith("#")]
        else:
            proxy_list = [proxy]
        proxy_list = [p if "://" in p else "http://" + p for p in proxy_list]
    print_error = results.print_error
    no_calib = results.no_calib
    flood = results.flood
    parallel = results.parallel
    resume = results.resume
    batch = results.batch
    run_info = results.run_info
    html = results.html
    scan_started = time.time()

    if batch:
        builtins.input = batch_input

    if len(sys.argv) < 2:
        print("{}URL target is missing, try using -u <url> \n".format(INFO))
        parser.print_help()
        sys.exit()

    banner()

    if file_url or resume:
        #For scan multiple website to one time: one process per website, --parallel at the same time
        if resume and not os.path.isdir(resume):
            print("{} {} doesn't exist".format(WARNING, resume))
            sys.exit()
        urls = []
        with open(file_url if file_url else os.devnull, "r") as f_url:
            for f in f_url.read().splitlines():
                f = f.strip()
                if not f or f.startswith("#"):
                    continue
                f = f if "://" in f else "https://" + f
                urls.append(f + "/" if f.split("/")[-1] != "" else f)
        scan_multiple(list(dict.fromkeys(urls)), sys.argv[1:], parallel, True, os.path.abspath(__file__), report_meta(), resume_dir=resume) # always one global report
        sys.exit()

    # one user-agent for the whole scan (random UA per request = unstable responses = false positives)
    scan_user_agent = {'User-agent': u_agent if u_agent else (random.choice(UserAgent) if type(UserAgent) == list else UserAgent.random)}

    if update:
        auto_update

    len_w = 0 #calcul wordlist size

    with open(wordlist, 'r') as words:
        for l in words:
            len_w += 1

    if header_:
        for h in header_:
            name, sep, value = h.partition(":")
            segments = [c for c in h.split(";") if c.strip()]
            if sep and re.match(r"^[A-Za-z0-9_-]+$", name.strip()) and (name.strip().lower() == "cookie" or len(segments) == 1 or
                    not all(re.match(r"^\s*[A-Za-z0-9_-]+\s*[:=]", c) for c in segments)):
                header_parsed[name.strip()] = value.strip() # "Name: value", value can contain ";" (cookies)
            else:
                for c in segments: # legacy: -H "a:1;b=2"
                    c = c.split(":", 1) if ":" in c else c.split("=", 1)
                    if len(c) == 2:
                        header_parsed[c[0].strip()] = c[1].strip()

    if exclude:
        exclude = exclude[0].split(",")
        if len(exclude) > 1:
            req_p = exclude
        elif "b" in exclude[0][-1] and int(exclude[0][0]):
            req_p = exclude
        elif len(exclude[0]) < 5: #Defined if it's int for response http code or strings for url
            if exclude[0] == "0b":
                req_p = 0
            else:
                req_p = int(exclude[0])
        else:
            page_url = "{}{}".format(url + "/" if url.split("/")[-1] != "" else url, exclude[0])
            req_exclude = requests.get(page_url, verify=False)
            req_p = req_exclude.text

    if not file_url:
        url = url + "/" if url.split("/")[-1] != "" else url
        main(url)
