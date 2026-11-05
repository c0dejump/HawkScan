#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import csv
import time
import threading

findings_lock = threading.Lock()

STATUS_KIND = {200: "hit", 301: "redirect", 302: "redirect", 401: "forbidden", 403: "forbidden"}


def record_finding(directory, kind, url, status=None, size=None, detail=None):
    """output/findings.jsonl: one finding per line, used by the HTML report (--html)"""
    if not directory:
        return
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        pass
    line = json.dumps({"time": time.strftime("%H:%M:%S"), "type": kind, "url": url, "status": status, "size": size, "detail": detail})
    try:
        with findings_lock:
            if not os.path.exists(directory + "/output/"):
                os.makedirs(directory + "/output/")
            with open(directory + "/output/findings.jsonl", "a+") as f:
                f.write(line + "\n")
    except Exception:
        pass

class multiple_outputs:
    """
    multiple_outputs:
    To export in multiple file format.
    Available: txt, json, csv
    TODO: other format
    """

    def raw_output(self, directory, res, stats, size_res, kind=None, detail=None):
        if not os.path.exists(directory+"/output/"):
            os.makedirs(directory+"/output/")
        with open(directory+"/output/raw.txt", "a+") as raw:
            raw.write("url, {}, {}, {}b\n".format(res, stats, size_res))
        try:
            code = int(stats)
        except (TypeError, ValueError):
            code = 0
        record_finding(directory, kind or STATUS_KIND.get(code, "error" if code >= 400 else "hit"), res, stats, size_res, detail)

    def json_output(self, directory, res, stats, size_res):
        if not os.path.exists(directory+"/output/"):
            os.makedirs(directory+"/output/")
        data = {
            'url': '{}'.format(res),
            'response_status': '{}'.format(stats),
            'size_bytes': '{}'.format(size_res)
        }
        with open(directory+"/output/json_output.txt", "a+") as raw_json:
            json.dump(data, raw_json)

    def csv_output(self, directory, res, stats, size_res):
        data = ['{}'.format(res), '{}'.format(stats), '{}'.format(size_res)]

        with open(directory+"/output/csv_ouput.csv", 'a+') as f:
            writer = csv.writer(f)
            writer.writerow(data)