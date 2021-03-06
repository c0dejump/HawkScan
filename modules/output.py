#! /usr/bin/env python
# -*- coding: utf-8 -*-

import os

class multiple_outputs:

	def raw_output(self, directory, res, stats, size_res):
		if not os.path.exists(directory+"/output/"):
 			os.makedirs(directory+"/output/")
		with open(directory+"/output/raw.txt", "a+") as raw:
			raw.write("url, {}, {}, {}b\n".format(res, stats, size_res))
