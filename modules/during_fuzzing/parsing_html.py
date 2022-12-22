# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
import requests
import csv
import sys, re, os
from config import S3, JS, WARNING
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


    def html_recon(self, res, req, directory):
        """
        Check if S3 buckets and path disclosure are in html page
        """
        path_disclosure = ["file://", "tmp/", "var/www", "/usr/", "var/lib", "srv/www", "srv/data", "var/opt", "file:///", "var/run", "firebase"]
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
        for pad in path_disclosure:
            #regex
            m = re.search(r"{}[a-zA-z/]+".format(pad), req.text)
            if m:
                print(" {}Possible path disclosure \033[34m{}\033[0m in {}".format(WARNING, m.group(0), res))


    def sitemap(self, req, directory):
        """Get sitemap.xml of website"""
        soup = BeautifulSoup(req.text, "html.parser")
        with open(directory + '/sitemap.xml', 'w+') as file:
            file.write(str(soup).replace(' ','\n'))
            

    def get_javascript(self, url, req, directory):
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
        'SECRET_KEY', '_secret', 'api_key', 'APPKey', 'apiSettings', 'sourceMappingURL', 'private_key', 'JWT_SECRET',
        'api_secret_key', 'access_key', 'access_token', 'admin_pass', 'admin_user', 'algolia_admin_key', 'algolia_api_key', 
        'alias_pass', 'alicloud_access_key', 'amazon_secret_access_key', 'amazonaws', 'ansible_vault_password', 'aos_key',
        'api_key', 'api_key_secret', 'api_key_sid', 'api_secret', 'api.googlemaps AIza', 'apidocs', 'apikey', 'apiSecret',
        'app_debug', 'app_id', 'app_key', 'app_log_level', 'app_secret', 'appkey', 'appkeysecret', 'application_key', 
        'appsecret', 'appspot', 'auth_token', 'authorizationToken', 'authsecret', 'aws_access', 'aws_access_key_id', 'aws_bucket', 'aws_key', 
        'aws_secret', 'aws_secret_key', 'aws_token', 'AWSSecretKey', 'b2_app_key', 'bashrc password', 'bintray_apikey', 'bintray_gpg_password', 
        'bintray_key', 'bintraykey', 'bluemix_api_key', 'bluemix_pass', 'browserstack_access_key', 'bucket_password', 'bucketeer_aws_access_key_id', 
        'bucketeer_aws_secret_access_key', 'built_branch_deploy_key', 'bx_password', 'cache_driver', 'cache_s3_secret_key', 'cattle_access_key', 
        'cattle_secret_key', 'certificate_password', 'ci_deploy_password', 'client_secret', 'client_zpk_secret_key', 'clojars_password', 'cloud_api_key', 
        'cloud_watch_aws_access_key', 'cloudant_password', 'cloudflare_api_key', 'cloudflare_auth_key', 'cloudinary_api_secret', 'cloudinary_name', 'codecov_token', 
        'conn.login', 'connectionstring', 'consumer_key', 'consumer_secret', 'credentials', 'cypress_record_key', 'database_password', 'database_schema_test', 
        'datadog_api_key', 'datadog_app_key', 'db_password', 'db_server', 'db_username', 'dbpasswd', 'dbpassword', 'dbuser', 'deploy_password', 'digitalocean_ssh_key_body', 
        'digitalocean_ssh_key_ids', 'docker_hub_password', 'docker_key', 'docker_pass', 'docker_passwd', 'docker_password', 'dockerhub_password', 'dockerhubpassword', 
        'dot-files', 'dotfiles', 'droplet_travis_password', 'dynamoaccesskeyid', 'dynamosecretaccesskey', 'elastica_host', 'elastica_port', 'elasticsearch_password', 
        'encryption_key', 'encryption_password', 'env.heroku_api_key', 'env.sonatype_password', 'eureka.awssecretkey', 'apex', 'aura', 'firebase']

        SOCKET_END = ["socket.io", "socketio", "socket", "websocket", "app.module.ts", "ws://", "wss://"]
        text = req.content
        url = req.url
        regex = r'''((https?:)?[/]{1,2}[^'\"> ]{5,})|(\.(get|post|ajax|load)\s*\(\s*['\"](https?:)?[/]{1,2}[^'\"> ]{5,})'''
        if ".js" in url:
            for keyword_match in INTERESTING_KEY:
                if keyword_match in text.decode('utf-8', errors="ignore"):
                    try:
                        with open("{}/js.txt".format(directory), 'w+') as js_write:
                            js_link = open("{}/js.txt".format(directory), 'r')
                            if "{}::{}".format(url, keyword_match) not in js_link.read():
                                print("{}Potentialy keyword found \033[33m[{}] \033[0min {}".format(JS, keyword_match, url))
                                js_write.write("{}::{}\n".format(url, keyword_match))
                            js_link.close()
                    except:
                        traceback.print_exc()
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
                            #print("{}Potentialy keyword found \033[33m[{}] \033[0min {}".format(JS, keyword_match, match[0]))
                            try:
                                with open("{}/js.txt".format(directory), 'a+') as js_write:
                                    js_link = open("{}/js.txt".format(directory), 'r')
                                    #print(js_link.read())
                                    if "{}::{}".format(match[0], keyword_match) not in js_link.read():
                                        print("{}Potentialy keyword found \033[33m[{}] \033[0min {}".format(JS, keyword_match, match[0]))
                                        js_write.write("{}::{}\n".format(match[0], keyword_match))
                                    js_link.close()
                            except:
                                traceback.print_exc()

        for k, v in REGEX_.items():
            values_found = re.findall(v, text.decode('utf-8', errors="ignore"))
            if values_found:
                for v in values_found:
                    try:
                        with open("{}/js.txt".format(directory), 'a+') as js_write:
                            js_link = open("{}/js.txt".format(directory), 'r')
                            if "{}::{}::{}".format(k, url, v) not in js_link.read():
                                print("{}Keyword found \033[33m[{}] \033[0min {} with value \033[32m[{}] \033[0".format(JS, k, url, v))
                                js_write.write("{}::{}::{}\n".format(url, k, v))
                            js_link.close()
                    except:
                        traceback.print_exc()


                        
"""if __name__ == '__main__':
    ph = parsing_html()
    url = "https://www..fr/"
    req = requests.get(url)
    ph.get_javascript(url, req)""" #DEBUG