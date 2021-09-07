#! /usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import csv

class multiple_outputs:
    """
    multiple_outputs:
    To export in multiple file format.
    Available: txt, json, csv
    TODO: other format
    """

    def raw_output(self, directory, res, stats, size_res):
        if not os.path.exists(directory+"/output/"):
            os.makedirs(directory+"/output/")
        with open(directory+"/output/raw.txt", "a+") as raw:
            raw.write("url, {}, {}, {}b\n".format(res, stats, size_res))

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