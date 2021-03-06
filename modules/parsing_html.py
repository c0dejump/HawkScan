# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
import requests
import csv
import sys, re, os
from config import S3, JS
import traceback

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


class parsing_html:
    """
    Parsing_html: class with all function who parse html
    """
    def get_links(self, req, directory):
        """
        Get_links: get all links on webpage during the scan
        """
        if len(req.content) > 0:
            #print("{}:{}".format(req, req.url)) #DEBUG
            req_text = req.text
            soup = BeautifulSoup(req_text, "html.parser")
            search = soup.find_all('a')
            if search:
                for s in search:
                    link = s.get("href")
                    try:
                        if re.match(r'http(s)', link):
                            with open(directory + "/links.txt", "a+") as links:
                                links.write(str(link+"\n"))
                        else:
                            pass
                    except:
                        pass
        else:
            pass


    def search_s3(self, res, req, directory):
        """
        search_s3: Check on source page if a potentialy "s3 amazon bucket" is there
        """
        s3_keyword = ["S3://", "s3-", "amazonaws", "aws."]
        for s3_f in s3_keyword:
            reqtext = req.text.split(" ")
            for req_key in reqtext:
                req_value = req_key.split('"')
                for rv in req_value:
                    if s3_f in rv:
                        if not os.path.exists(directory + "/s3_links.txt"):
                            with open(directory + "/s3_links.txt", "a+") as s3_links:
                                s3_links.write(str(rv+"\n"))
                        else:
                            with open(directory + "/s3_links.txt", "a+") as read_links:
                                if any(rl.strip() == rv.strip() for rl in read_links.readlines()):
                                    pass
                                else:
                                    try:
                                        req_s3 = requests.get(rv, verify=False)
                                        if req_s3.status_code == 200:
                                            print("{}[200] Potentialy s3 buckets found: {}".format(S3, rv))
                                            read_links.write(rv + "\n")
                                    except:
                                        pass
                                        #traceback.print_exc()


    def mail(self, req, directory):
        """
        Mail:
        get mail adresse in web page during the scan and check if the mail leaked
        """
        write_mail = True
        mails = req.text
        # for all @mail
        reg = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
        search = re.findall(reg, mails)
        for mail in search:
            #check if email pwned
            if mail and not "png" in mail or not "jpg" in mail or not "jpeg" in mail:
                datas = { "act" : mail, "accounthide" : "test", "submit" : "Submit" }
                req_ino = requests.post("https://www.inoitsu.com/", data=datas, verify=False)
                res_pwned = "{}: pwned ! ".format(mail) if "DETECTED" in req_ino.text else "{}: no pwned ".format(mail)
                if os.path.exists(directory + '/mail.csv'):
                    with open(directory + '/mail.csv', 'r+') as read_csv_file:
                        read_file = csv.reader(read_csv_file)
                        for r_mail in read_file:
                            if res_pwned.split(":")[0] == r_mail[0]:
                                write_mail = False
                if write_mail == True:
                    with open(directory + '/mail.csv', 'a+') as write_csv_file:
                        writer = csv.writer(write_csv_file)
                        writer.writerow(res_pwned.split(":"))
                        write_mail = False


    def sitemap(self, req, directory):
        """Get sitemap.xml of website"""
        soup = BeautifulSoup(req.text, "html.parser")
        with open(directory + '/sitemap.xml', 'w+') as file:
            file.write(str(soup).replace(' ','\n'))
            

    def get_javascript(self, url, req):
        """search potentialy sensitive keyword in javascript"""
        REGEX_ = {
            "AMAZON_URL_1":r"[a-z0-9.-]+\.s3-[a-z0-9-]\\.amazonaws\.com",
            "AMAZON_URL_2":r"[a-z0-9.-]+\.s3-website[.-](eu|ap|us|ca|sa|cn)",
            "AMAZON_URL_3":r"s3\\.amazonaws\.com/[a-z0-9._-]+",
            "AMAZON_URL_4":r"s3-[a-z0-9-]+\.amazonaws\\.com/[a-z0-9._-]+",
            "AMAZON_KEY":r"([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}",
            "Authorization":r"^Bearer\s[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
            "accessToken":r"^acesstoken=[0-9]{13,17}",
            "vtex-key":r"vtex-api-(appkey|apptoken)",
            "google_api":r"AIza[0-9A-Za-z-_]{35}",
            "firebase":r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
            "paypal_braintree_access_token":r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
            "github_access_token":r"[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*",
            "json_web_token":r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$",
            "SSH_privKey":r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
        }

        url_index = url.split("/")[0:3] if "http" in url else url
        url_index = "/".join(url_index)
        UNINTERESTING_EXTENSIONS = ['css', 'svg', 'png', 'jpeg', 'jpg', 'mp4', 'gif']
        UNINTERESTING_JS_FILES = ['bootstrap', 'jquery']
        """
        'api:', 'api=', 'apis:', 'apis=', 'token=', 'token:', 'key:', 'key=', 'keys:', 'keys=', 'password=', "password:"
         => interesting ? false positive ?
        """
        INTERESTING_KEY = ['ApiKey', 'appKey', '_public_key', '_TOKEN', '_PASSWORD', '_DATABASE', 
        'SECRET_KEY', 'client_secret', '_secret', 'api_key', 'APPKey', 'apiSettings', 'sourceMappingURL']
        text = req.content
        regex = r'''((https?:)?[/]{1,2}[^'\"> ]{5,})|(\.(get|post|ajax|load)\s*\(\s*['\"](https?:)?[/]{1,2}[^'\"> ]{5,})'''
        if ".js" in url:
            for keyword_match in INTERESTING_KEY:
                if keyword_match in text.decode('utf-8'):
                    print(b"{}Potentialy keyword found \033[33m[{}] \033[0min {}".format(JS, keyword_match, url))
        else:
            matches = re.findall(regex, text.decode('utf-8'))
            for match in matches:
                #print(match[0]) #DEBUG
                if not any('{}'.format(ext) in match[0] for ext in UNINTERESTING_EXTENSIONS) and url_index in match[0] and ".js" in match[0]:
                    req_js = requests.get(match[0], verify=False)
                    #print(match[0]) #DEBUG
                    for keyword_match in INTERESTING_KEY:
                        if keyword_match in req_js.text:
                            print("{}Potentialy keyword found \033[33m[{}] \033[0min {}".format(JS, keyword_match, match[0]))
        for k, v in REGEX_.items():
            values_found = re.findall(v, text.decode('utf-8'))
            if values_found:
                for v in values_found:
                    print("{} keyword found \033[33m[{}] \033[0min {} with value \033[32m[{}] \033[0".format(JS, k, url, v))


                        
"""if __name__ == '__main__':
    ph = parsing_html()
    url = "https://www..fr/"
    req = requests.get(url)
    ph.get_javascript(url, req)""" #DEBUG