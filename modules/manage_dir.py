#! /usr/bin/env python
# -*- coding: utf-8 -*-

import os
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK

class manage_dir:

    def check_backup(self, directory):
        """Check if a backup file exist from function 'Status'"""
        if os.path.exists(directory + "/backup.txt"):
            bp = input("A backup file exists, do you want to Continue with it or Restart ? [c:r]: ")
            if bp == 'C' or bp == 'c':
                print("restart from last save of backup.txt ...")
                print(LINE)
                return True
            else:
                try:
                    os.remove(directory+'/output/raw.txt')
                except:
                    pass
                print(LINE)
                return False
        else:
            pass