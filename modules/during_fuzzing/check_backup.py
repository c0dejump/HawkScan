#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK, EXCL, SERV_ERR, BYP, WAF, EXT_B, MINI_B, ARCH
from bs4 import BeautifulSoup
from modules.output import multiple_outputs


def scan_backup(s, url, len_req, res, js, req_p, bp_current, exclude, backup, header_parsed, user_agent, directory, forbi, filterM, page, tw, parsing, authent, get_date):


    if len(backup) > 0 and backup[0] == "min":
        bckp = MINI_B
    elif len(backup) > 0 and backup[0] == "arc":
        bckp = ARCH  
    else:
        if len(backup) == 1:
            for bck in backup:
                bckp = bck.split(",")
        else:
            bckp = EXT_B if backup == [] else [bck.replace(",","") for bck in backup]

    size_check = len_req

    other_backup = ["old_", "~", "Copy of "]
    for ob in other_backup:
        size_bckp = prefix_backup(s, url, res, req_p, bp_current, js, header_parsed, exclude, tw, user_agent, directory, forbi, get_date, filterM, parsing, ob)

    for exton in bckp:
        size_bckp = suffix_backup(s, url, res, req_p, bp_current, js, header_parsed, exclude, tw, page, exton, size_check, directory, forbi, get_date, parsing, filterM, authent)


def prefix_backup(s, url, res, req_p, bp_current, js, header_parsed, exclude, tw, user_agent, directory, forbi, HOUR, filterM, parsing, ob):
    """
    prefix_backup:
    Like the function 'suffix_backup' but check if the type backup dir like '~articles/' exist.
    """
    mo = multiple_outputs()
    pars = res.split("/")
    hidd_tild = "{}{}{}/".format(url, ob, pars[3]) if pars[-1] == "" else "{}{}{}".format(url, ob, pars[3])
    if header_parsed:
        user_agent.update(header_parsed)
        req_tild = requests.get(hidd_tild, headers=user_agent, allow_redirects=False, verify=False, timeout=10)
    else:
        req_tild = requests.get(hidd_tild, headers=user_agent, allow_redirects=False, verify=False, timeout=10)
    status_tild = req_tild.status_code
    if status_tild not in [404, 403, 500, 400, 301, 302]:
        if exclude:
            filterM.exclude_type(req_p, s, req_tild, res, directory, forbi, HOUR, bp_current, parsing, len(req_tild.content))
        else:
            h_bytes_len = "[{}b]".format(len(req_tild.content))
            print("{} {} {:<13}{:<10}".format(HOUR, PLUS, h_bytes_len, hidd_tild))
            mo.raw_output(directory, hidd_tild, 200, len(req_tild.content))



def suffix_backup(s, url, res, req_p, bp_current, js, header_parsed, exclude, tw, page, exton, size_check, directory, forbi, HOUR, parsing, filterM, authent):
    """
    suffix_backup:
    During the scan, check if a backup file or dir exist.
    You can modify this in "config.py"
    """

    mo = multiple_outputs()
    
    d_files = directory + "/files/" #directory to download backup file if exist

    res_b = res + exton
    page_b = page + exton
    #print(res_b) #DEBUG
    anti_sl = res_b.split("/")
    rep = anti_sl[3:]
    result = rep[-1]
    r_files = d_files + result

    if header_parsed:
        req_b = s.get(res_b, allow_redirects=False, verify=False, headers=header_parsed)
    else:
        req_b = s.get(res_b, allow_redirects=False, verify=False, timeout=10, auth=authent)

    soup = BeautifulSoup(req_b.text, "html.parser")
    req_b_status = req_b.status_code

    size_bytes = len(req_b.content)
    size_bytes_b = "[{}b]".format(size_bytes)

    if req_b_status == 200:
        ranges = range(size_check - 50, size_check + 50) if size_check < 10000 else range(size_check - 1000, size_check + 1000)
        if size_bytes == size_check or size_bytes in ranges:
            #if the number of bytes of the page equal to size_check variable and not bigger than size_check +5 and not smaller than size_check -5
            pass
        elif size_bytes != size_check:
            if js and size_bytes > 0:
                parsing.get_javascript(res, req_b, directory)
            if exclude:
                filterM.exclude_type(req_p, s, req_b, res_b, directory, forbi, HOUR, bp_current, parsing, size_bytes)
            else:
                print("{} {} {:<13}{:<10}".format(BACK, PLUS, size_bytes_b, res_b if tw > 120 else page_b))
                try:
                    with open(r_files, 'w+') as fichier_bak:
                        fichier_bak.write(str(soup))
                    mo.raw_output(directory, res_b, 200, size_bytes)
                except:
                    pass
            return size_bytes
    elif req_b_status in [404, 406, 429, 503, 502, 500, 400]:
        pass
    elif req_b_status in [301, 302, 303, 307, 308]:
        """redirect_link = ""
        for rh in req_b.headers:
            if "location" in rh or "Location" in rh:
                loc = req_b.headers[rh]
                redirect_link = loc if "http" in loc else "{}{}".format(url, loc)
                req_loc = s.get(redirect_link, verify=False, allow_redirects=False)
                if "/".join(res.split("/")[1:]) == "/".join(loc.split("/")[1:-1]) and len(req_loc.content) != index_len and not "." in loc:
                    print(" \033[33m[<>]\033[0m {} redirect to \033[33m{}\033[0m [\033[33mPotential Hidden Directory\033[0m]".format(res, loc))
            else:
                req_loc = s.get(res, verify=False, allow_redirects=True)
                redirect_link = req_loc.url
        print("{} {} {} → {}".format(HOUR, LESS, res_b if tw > 120 else page_b, redirect_link))"""
        pass
    elif req_b_status in [403, 401]:
        ranges = range(size_check - 50, size_check + 50) if size_check < 10000 else range(size_check - 1000, size_check + 1000)
        if size_bytes == size_check or size_bytes in ranges:
            #if the number of bytes of the page equal to size_check variable and not bigger than size_check +5 and not smaller than size_check -5
            pass
        else:
            print("{} {} [{}] {}".format(HOUR, FORBI, size_bytes, res_b))
            #bypass_forbidden(res_b)
            mo.raw_output(directory, res_b, req_b_status, size_bytes)
            #pass
    else:
        if exclude:
            filterM.exclude_type(req_p, s, req_b, res_b, directory, forbi, HOUR, bp_current, parsing, size_bytes)
        else:
            print("{}{} {}".format(HOUR, res_b if tw > 120 else page_b, req_b.status_code))


def vim_backup(s, url, res, user_agent, exclude):
    """
    vim_backup: Testing backup vim like ".plop.swp"
    """
    if "." in res:
        pars = res.split("/")
        vb = ".{}.swp".format(pars[-1])
        vim_b = "{}{}/".format(url, vb) if pars[-1] == "" else "{}{}".format(url, vb)
        req_vb = s.get(vim_b, headers=user_agent, allow_redirects=False, verify=False, timeout=10)
        if req_vb.status_code not in [404, 403, 401, 500, 406] and len(req_vb.content) != len(req_vb.content):
            if exclude:
                if exclude != len(req_vb.text) and len(req_vb.text) != 0:
                    print("{} {} [{}b] Potential backup vim found {:<15}".format(get_date, PLUS, len(req_vb.text), vim_b))
            else:
                if len(req_vb.text) != 0:
                    print("{} {} [{}b] Potential backup vim found {:<15}".format(get_date, PLUS, len(req_vb.text), vim_b))