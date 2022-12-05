#! /usr/bin/env python3
# -*- coding: utf-8 -*-

#modules in standard library
import requests
import sys, os, re
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK, EXCL, SERV_ERR, BYP, WAF, EXT_B, MINI_B

def scan_error(directory, forbi, filterManager):
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
                    req = requests.get(error_link, verify=False, timeout=10) if not auth else requests.get(error_link, verify=False, auth=(auth.split(":")[0], auth.split(":")[1]), timeout=10)
                    len_req_error = len(req.content)
                    if exclude:
                        if type(req_p) == int:
                            pass
                        else:
                            cep = filterM.check_exclude_page(s, req, error_link, directory, forbi, HOUR, bp_current)
                        if cep:
                            error_status = req.status_code
                            if error_status in [404, 406]:
                                pass
                            else:
                                print("{}[{}] [{}b] {}".format(INFO, req.status_code, len_req_error, error_link))
                                output_scan(directory, error_link, len_req_error, req.status_code)
                                errors_stat = True
                    else: 
                        error_status = req.status_code
                        if error_status in [404, 406]:
                            pass
                        else:
                            print("{}[{}] [{}b] {}".format(INFO, req.status_code, len_req_error, error_link))
                            output_scan(directory, error_link, len_req_error, req.status_code)
                            errors_stat = True
                except Exception:
                    pass
                    #traceback.print_exc()
                sys.stdout.write("\033[34m[i] {}\033[0m\r".format(error_link))
                sys.stdout.write("\033[K")
            if errors_stat == False:
                print("{} Nothing error error need to be fixed".format(PLUS))
        os.system("rm {}".format(path_error))
    else:
        print("{} Nothing errors need to be fixed".format(PLUS))