from bs4 import BeautifulSoup
import requests
import csv
import sys, re, os
from config import S3
import traceback

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

urls_s3 = []

class parsing_html:
    """
    Parsing_html: class with all function who parse html
    """
    def get_links(self, req, directory):
        """
        Get_links: get all links on webpage during the scan
        """
        soup = BeautifulSoup(req.text, "html.parser")
        search = soup.find_all('a')
        if search:
            for s in search:
                link = s.get("href")
                try:
                    if "http" in link or "https" in link:
                        with open(directory + "/links.txt", "a+") as links:
                            links.write(str(link+"\n"))
                    else:
                        pass
                except:
                    pass


    def search_s3(self, res, req, directory):
        """
        search_s3: Check on source page if a potentialy "s3 amazon bucket" is there
        """
        s3_keyword = ["S3://", "s3-", "amazonaws"]
        for s3_f in s3_keyword:
            reqtext = req.text.split(" ")
            for req_key in reqtext:
                req_value = req_key.split('"')
                for r in req_value:
                    if s3_f in r:
                        if not os.path.exists(directory + "/s3_links.txt"):
                            with open(directory + "/s3_links.txt", "a+") as s3_links:
                                s3_links.write(str(r+"\n"))
                        else:
                            with open(directory + "/s3_links.txt", "a+") as read_links:
                                for rl in read_links.readlines():
                                    if r == rl:
                                        pass
                                    else:
                                        try:
                                            req_s3 = requests.get(r, verify=False)
                                            if req_s3.status_code == 200:
                                                print("{} Potentialy s3 buckets found with reponse 200: {}".format(S3, r))
                                                read_links.write(r)
                                        except:
                                            pass


    def mail(self, req, directory, all_mail):
        """
        Mail:
        get mail adresse in web page during the scan and check if the mail leaked
        """
        mails = req.text
        # for all @mail
        reg = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
        search = re.findall(reg, mails)
        for mail in search:
            #check if email pwned
            if mail and not "png" in mail or not "jpg" in mail:
                datas = { "act" : mail, "accounthide" : "test", "submit" : "Submit" }
                req_ino = requests.post("https://www.inoitsu.com/", data=datas)
                if "DETECTED" in req_ino.text:
                    pwnd = "{}: pwned ! ".format(mail)
                    if pwnd not in all_mail and not "png" in mail or not "jpg" in mail:
                        all_mail.append(pwnd)
                else:
                    no_pwned = "{}: no pwned ".format(mail)
                    if no_pwned not in all_mail and not "png" in mail or not "jpg" in mail:
                        all_mail.append(no_pwned)
        with open(directory + '/mail.csv', 'a+') as file:
            if all_mail is not None and all_mail != []:
                writer = csv.writer(file)
                for r in all_mail:
                    r = r.split(":")
                    writer.writerow(r)

    def sitemap(self, req, directory):
        """ Get sitemap.xml of website"""
        soup = BeautifulSoup(req.text, "html.parser")
        with open(directory + '/sitemap.xml', 'w+') as file:
            file.write(str(soup).replace(' ','\n'))