#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from config import PLUS, INFO, FORBI, BACK, EXT_B, MINI_B, ARCH
from modules.output import multiple_outputs, record_finding
from modules.during_fuzzing.bypass_forbidden import same_page
from modules.during_fuzzing.calibration import rand_token

# not backups but formats: /api/users.json, /feed.atom, /login.action = the same route (content negotiation)
FORMAT_SUFFIXES = {".json", ".xml", ".atom", ".txt", ".md", ".yml", ".yaml", ".action", ".cgi", ".xsd", ".wml",
                   "?stats=1", "/authorize/", "%01", ".1", ".html", ".htm"}


def not_a_backup(s, url, resp, original, calib, suffix_ctrl=None):
    """The answer is the page we already have (suffix ignored), the route itself (any suffix), or the home page (fallback)"""
    if original is not None and same_page(resp, original):
        return True
    if suffix_ctrl is not None and same_page(resp, suffix_ctrl):
        return True
    root = "/".join(url.split("/")[:3]) + "/"
    return bool(calib) and resp.status_code == 200 and calib.same_as_index(s, root, resp)



def scan_backup(s, url, len_req, res, js, req_p, bp_current, exclude, backup, header_parsed, user_agent, directory, forbi, filterM, page, tw, parsing, authent, get_date, calib=None, original=None):


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

    # admin/ -> admin.zip, admin.tar.gz... (not admin/.zip)
    res_base = res[:-1] if res.endswith("/") else res
    page_base = page[:-1] if page.endswith("/") else page
    last = res.rstrip("/").rsplit("/", 1)[-1]
    route = not res.endswith("/") and "." not in last # /api/users, /login: a route, not a file

    if route and original is not None and original.status_code == 200 and "html" in original.headers.get("Content-Type", "").lower():
        return # a CMS page (/de/sqladm): page.bak, page_old... are not files

    found = []
    other_backup = ["old_", "~", "Copy of ", "backup_", "copy_", "_"]
    for ob in ([] if route else other_backup): # old_config.php, old_admin/ (not copy_login)
        prefix_backup(s, url, res, req_p, bp_current, js, header_parsed, exclude, tw, user_agent, directory, forbi, get_date, filterM, parsing, ob, calib, original, found)
    # control: a route that answers whatever the suffix (Spring suffix pattern, rewrites): /api/users.<random> = /api/users.zip
    suffix_ctrl = None
    try:
        headers = dict(user_agent or {})
        headers.update(header_parsed or {})
        ctrl = s.get("{}.{}".format(res_base, rand_token(6)), headers=headers, allow_redirects=False, verify=False, timeout=10, auth=authent)
        if 200 <= ctrl.status_code < 300 and ctrl.content:
            suffix_ctrl = ctrl
    except Exception:
        pass
    for exton in bckp:
        if route and exton.lower() in FORMAT_SUFFIXES:
            continue
        suffix_backup(s, url, res_base, req_p, bp_current, js, header_parsed, exclude, tw, page_base, exton, size_check, directory, forbi, get_date, parsing, filterM, authent, calib, original, suffix_ctrl, found)
    # 3+ backup names giving the same page: the server answers that page for those extensions, not backups
    groups = []
    for item in found:
        for g in groups:
            if same_page(item[2], g[0][2]):
                g.append(item)
                break
        else:
            groups.append([item])
    for g in groups:
        if len(g) >= 3:
            print("\033[K{} {} backup names of {} give the same page ({}...): ignored".format(INFO, len(g), page_base, ", ".join(i[0].split("/")[-1] for i in g[:3])))
            continue
        for res_b, page_b, req_b in g:
            report_backup(res_b, page_b, req_b, directory, get_date, tw)


def report_backup(res_b, page_b, req_b, directory, HOUR, tw):
    print("{} {} {:<13}{:<10}".format(HOUR, BACK, "[{}b]".format(len(req_b.content)), res_b if tw > 120 else page_b))
    try:
        with open(directory + "/files/" + res_b.split("/")[-1], 'wb') as fichier_bak:
            fichier_bak.write(req_b.content)
    except Exception:
        pass
    multiple_outputs().raw_output(directory, res_b, 200, len(req_b.content), kind="backup")


def prefix_backup(s, url, res, req_p, bp_current, js, header_parsed, exclude, tw, user_agent, directory, forbi, HOUR, filterM, parsing, ob, calib=None, original=None, found=None):
    """
    prefix_backup:
    Like the function 'suffix_backup' but check if the type backup dir like '~articles/' exist.
    """
    mo = multiple_outputs()
    # prefix the last segment, in the same directory: a/b/config.php -> a/b/old_config.php
    trail = "/" if res.endswith("/") else ""
    parent, _, last = res.rstrip("/").rpartition("/")
    if not last or len(parent.split("/")) < 3:
        return
    hidd_tild = "{}/{}{}{}".format(parent, ob, last, trail)
    headers = dict(user_agent)
    if header_parsed:
        headers.update(header_parsed)
    req_tild = s.get(hidd_tild, headers=headers, allow_redirects=False, verify=False, timeout=10)
    status_tild = req_tild.status_code
    if status_tild not in [404, 403, 500, 400, 301, 302] and len(req_tild.content) > 0 and not (calib and calib.is_noise(s, hidd_tild, req_tild)) \
            and not not_a_backup(s, url, req_tild, original, calib):
        if exclude:
            filterM.exclude_type(req_p, s, req_tild, res, directory, forbi, HOUR, bp_current, parsing, len(req_tild.content))
        else:
            h_bytes_len = "[{}b]".format(len(req_tild.content))
            if found is not None:
                found.append((hidd_tild, "/".join(hidd_tild.split("/")[3:]), req_tild)) # compared with the other names first
            else:
                print("{} {} {:<13}{:<10}".format(HOUR, PLUS, h_bytes_len, hidd_tild))
                mo.raw_output(directory, hidd_tild, 200, len(req_tild.content), kind="backup", detail="prefix {}".format(ob))



def suffix_backup(s, url, res, req_p, bp_current, js, header_parsed, exclude, tw, page, exton, size_check, directory, forbi, HOUR, parsing, filterM, authent, calib=None, original=None, suffix_ctrl=None, found=None):
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
        req_b = s.get(res_b, allow_redirects=False, verify=False, timeout=10, headers=header_parsed, auth=authent)
    else:
        req_b = s.get(res_b, allow_redirects=False, verify=False, timeout=10, auth=authent)

    req_b_status = req_b.status_code
    if req_b_status != 404 and calib and calib.is_noise(s, res_b, req_b):
        return
    if req_b_status != 404 and not_a_backup(s, url, req_b, original, calib, suffix_ctrl):
        return

    size_bytes = len(req_b.content)
    size_bytes_b = "[{}b]".format(size_bytes)


    if req_b_status == 200:
        # same page served again (ex: suffix ignored)? small files (empty php output, configs) need an exact size
        if size_bytes == size_check or abs(size_bytes - size_check) <= same_page_tolerance(size_check):
            #if the number of bytes of the page equal to size_check variable and not bigger than size_check +5 and not smaller than size_check -5
            pass
        elif size_bytes != size_check:
            if js and size_bytes > 0:
                parsing.get_javascript(res, req_b, directory)
            if exclude:
                filterM.exclude_type(req_p, s, req_b, res_b, directory, forbi, HOUR, bp_current, parsing, size_bytes)
            elif found is not None:
                found.append((res_b, page_b, req_b)) # reported by scan_backup, after the comparison of all the names
            else:
                print("{} {} {:<13}{:<10}".format(HOUR, BACK, size_bytes_b, res_b if tw > 120 else page_b))
                try:
                    with open(r_files, 'wb') as fichier_bak:
                        fichier_bak.write(req_b.content)
                    mo.raw_output(directory, res_b, 200, size_bytes, kind="backup")
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
        # same page served again (ex: suffix ignored)? small files (empty php output, configs) need an exact size
        if size_bytes == size_check or abs(size_bytes - size_check) <= same_page_tolerance(size_check):
            #if the number of bytes of the page equal to size_check variable and not bigger than size_check +5 and not smaller than size_check -5
            pass
        else:
            if exclude:
                filterM.exclude_type(req_p, s, req_b, res_b, directory, forbi, HOUR, bp_current, parsing, size_bytes)
            else:
                print("{} {} [{}] {}".format(HOUR, FORBI, size_bytes, res_b))
                #bypass_forbidden(res_b)
                mo.raw_output(directory, res_b, req_b_status, size_bytes, kind="forbidden", detail="backup name, forbidden")
                #pass
    else:
        if exclude:
            filterM.exclude_type(req_p, s, req_b, res_b, directory, forbi, HOUR, bp_current, parsing, size_bytes)
        else:
            print("{}{} {}".format(HOUR, res_b if tw > 120 else page_b, req_b.status_code))


def same_page_tolerance(size):
    if size < 1000:
        return 0
    return 60 if size < 10000 else 1000


def vim_backup(s, url, res, user_agent, exclude, get_date="", calib=None, directory=None, original=None):
    """
    vim_backup: Testing backup vim like ".plop.swp"
    """
    parent, _, last = res.rpartition("/")
    if not last or "." not in last or len(parent.split("/")) < 3:
        return
    for ext in [".swp", ".swo"]:
        vim_b = "{}/.{}{}".format(parent, last, ext)
        req_vb = s.get(vim_b, headers=user_agent, allow_redirects=False, verify=False, timeout=10)
        if req_vb.status_code == 200 and len(req_vb.content) != 0 and not (calib and calib.is_noise(s, vim_b, req_vb)) \
                and not not_a_backup(s, url, req_vb, original, calib):
            exclude_len = exclude[0][:-1] if exclude and exclude[0].endswith("b") else False
            if not exclude_len or exclude_len != str(len(req_vb.content)):
                print("{} {} [{}b] Potential backup vim found {:<15}".format(get_date, PLUS, len(req_vb.content), vim_b))
                record_finding(directory, "backup", vim_b, 200, len(req_vb.content), "vim swap file")
