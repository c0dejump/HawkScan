#! /usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json

class multiple_outputs:

	def raw_output(self, directory, res, stats, size_res):
		if not os.path.exists(directory+"/output/"):
 			os.makedirs(directory+"/output/")
		with open(directory+"/output/raw.txt", "a+") as raw:
			raw.write("url, {}, {}, {}b\n".format(res, stats, size_res))

	def json_output(self, directory, res, stats, size_res):
		if not os.path.exists(directory+"/output/"):
 			os.makedirs(directory+"/output/")
		with open(directory+"/output/json_output.txt", "a+") as raw:
			raw.write("""
			{{
				url: {},
				{{
					url: {},
				 	response_status: {}, 
				 	size_bytes: {}
				}},
			""".format(res, res, stats, size_res))
"""
	def csv_output(self):
		#TODO
"""