#! /usr/bin/env python3
# -*- coding: utf-8 -*-

#modules in standard library
import requests
import sys, os
from modules.output import multiple_outputs
from modules.during_fuzzing.calibration import raw_request
from config import PLUS, INFO, LINE

def scan_error(directory, headers=None, auth=None, calib=None):
    """
    scan_error: Checking the links who was in error during scan
    """
    errors_stat = False
    print(LINE)
    print("{} Error check".format(INFO))
    print(LINE)
    path_error = directory + "/errors.txt"
    if not os.path.exists(path_error):
        print("{} Nothing errors need to be fixed".format(PLUS))
        return
    with open(path_error) as read_links:
        error_links = list(dict.fromkeys(read_links.read().splitlines()))
    print("{}[{}] Errors detected".format(INFO, len(error_links)))
    s = requests.session()
    s.verify = False
    mo = multiple_outputs()
    for error_link in error_links:
        try:
            req = raw_request(s, "GET", error_link, headers=headers, auth=auth, timeout=20)
            len_req_error = len(req.content)
            if req.status_code not in [404, 406] and not (calib and calib.is_noise(s, error_link, req)):
                print("\033[K{}[{}] [{}b] {}".format(INFO, req.status_code, len_req_error, error_link))
                mo.raw_output(directory, error_link, req.status_code, len_req_error)
                errors_stat = True
        except Exception:
            pass
            #traceback.print_exc()
        sys.stdout.write("\033[34m[i] {}\033[0m\r".format(error_link))
        sys.stdout.write("\033[K")
    if errors_stat == False:
        print("{} Nothing error error need to be fixed".format(PLUS))
    os.remove(path_error)
