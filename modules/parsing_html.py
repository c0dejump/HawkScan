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
                    if s3_f in rv: #TODO → and "dmoain" in rv
                        if not os.path.exists(directory + "/s3_links.txt"):
                            with open(directory + "/s3_links.txt", "a+") as s3_links:
                                s3_links.write(str(rv+"\n"))
                        else:
                            with open(directory + "/s3_links.txt", "r+") as read_links:
                                if any(rl.strip() == rv.strip() for rl in read_links.readlines()):
                                    pass
                                else:
                                    try:
                                        req_s3 = requests.get(rv, verify=False)
                                        if req_s3.status_code == 200:
                                            print("{}[200] Potentialy s3 buckets found: {} in {}".format(S3, rv, res))
                                            read_links.write(rv + "\n")
                                    except:
                                        #print("{} Error with the URL {}".format(S3, rv))
                                        pass
                                        #traceback.print_exc()


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
        'api:', 'api=', 'apis:', 'apis=', 'token=', 'token:', 'key:', 'key=', 'keys:', 'keys=', 'password=', 'password:', 'blob'
         => interesting ? false positive ?
        """
        INTERESTING_KEY = ['ApiKey', 'appKey', '_public_key', '_TOKEN', '_PASSWORD', '_DATABASE', 
        'SECRET_KEY', '_secret', 'api_key', 'APPKey', 'apiSettings', 'sourceMappingURL', 'private_key', 'JWT_SECRET', 'api_secret_key']
        SOCKET_END = ["socket.io", "socketio", "socket", "websocket", "app.module.ts", "ws://", "wss://"]
        text = req.content
        url = req.url
        regex = r'''((https?:)?[/]{1,2}[^'\"> ]{5,})|(\.(get|post|ajax|load)\s*\(\s*['\"](https?:)?[/]{1,2}[^'\"> ]{5,})'''
        if ".js" in url:
            for keyword_match in INTERESTING_KEY:
                if keyword_match in text.decode('utf-8', errors="ignore"):
                    print("{}Potentialy keyword found \033[33m[{}] \033[0min {}".format(JS, keyword_match, url))
            for socketio_ in SOCKET_END:
                if socketio_ in text.decode('utf-8', errors="ignore"):
                    print("{}Potentialy socketio endpoint found \033[33m[{}] \033[0min {}".format(JS, socketio_, url))
        else:
            matches = re.findall(regex, text.decode('utf-8', errors="ignore"))
            for match in matches:
                #print(match[0]) #DEBUG
                if not any('{}'.format(ext) in match[0] for ext in UNINTERESTING_EXTENSIONS) and url_index in match[0] and ".js" in match[0]:
                    req_js = requests.get(match[0], verify=False)
                    #print(match[0]) #DEBUG
                    for keyword_match in INTERESTING_KEY:
                        if keyword_match in req_js.text:
                            print("{}Potentialy keyword found \033[33m[{}] \033[0min {}".format(JS, keyword_match, match[0]))
        for k, v in REGEX_.items():
            values_found = re.findall(v, text.decode('utf-8', errors="ignore"))
            if values_found:
                for v in values_found:
                    print("{}Keyword found \033[33m[{}] \033[0min {} with value \033[32m[{}] \033[0".format(JS, k, url, v))


                        
"""if __name__ == '__main__':
    ph = parsing_html()
    url = "https://www..fr/"
    req = requests.get(url)
    ph.get_javascript(url, req)""" #DEBUG