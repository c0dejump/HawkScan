import requests
from bs4 import BeautifulSoup
import json
import sys, re, os
import ssl
import socket
import traceback
from requests.exceptions import Timeout
import time
# External
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK, INFO_MOD

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class before_start:
    

    def get_header(self, url, directory):
        """Get header of website (cookie, link, etc...)"""
        r = requests.get(url, allow_redirects=False, verify=False)
        print("\033[36m HEADER\033[0m")
        print(LINE)
        print("  {} \n".format(r.headers).replace(',','\n'))
        print(LINE)
        with open(directory + '/header.csv', 'w+') as file:
            file.write(str(r.headers).replace(',','\n'))


    def gitpast(self, url):
        """
        Github: check github informations
        """
        print("\033[36m Check in Github \033[0m")
        print(LINE)
        url = url.split(".")[1] if "www" in url else url.split("/")[2]
        url = "{}".format(url)
        print("search: {}\n".format(url))
        types = ["Commits", "Issues", "Repositories", "Topics", "Wikis", "Users", "Code"]
        try:
            for t in types:
                github = "https://github.com/search?q={}&type={}".format(url, t)
                req = requests.get(github, verify=False)
                soup = BeautifulSoup(req.text, "html.parser")
                search = soup.find('a', {"class":"menu-item selected"})
                if search:
                    for s in search.find("span"):
                        print("  {}{}: {}".format(INFO_MOD, t, s))
                else:
                    print("  {}{}: not found".format(INFO_MOD, t))
        except:
            print("{}You need connection to check the github".format(WARNING))
        print("\n" + LINE)


    def get_dns(self, url, directory):
        """Get DNS informations"""
        port = 0
        print("\033[36m DNS information \033[0m")
        print(LINE)
        try:
            if "https" in url:
                url = url.replace('https://','').replace('/','')
                port = 443
            else:
                url = url.replace('http://','').replace('/','')
                port = 80
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=url)
            conn.connect((url, port))
            cert = conn.getpeercert()
            print(" \u251c Organization: {}".format(cert['subject']))
            print(" \u251c DNS: {}".format(cert['subjectAltName']))
            print(" \u251c SerialNumber: {}".format(cert['serialNumber']))
            conn.close()
            with open(directory + '/dns_info.csv', 'w+') as file:
                file.write(str(cert).replace(',','\n').replace('((','').replace('))',''))
        except:
            erreur = sys.exc_info()
            typerr = u"%s" % (erreur[0])
            typerr = typerr[typerr.find("'")+1:typerr.rfind("'")]
            print(typerr)
            msgerr = u"%s" % (erreur[1])
            print(msgerr + "\n")
        print(LINE)


    def letsdebug(self, url):
        """
        letsdebug: Get certificate of the website and potentialy found old certificate with old subdomain
        """
        print("\033[36m Let's Debug information \033[0m")
        print(LINE)
        wait_finish = True
        list_result = []
        string_result = ""
        domain = ".".join(url.split("/")[2].split(".")[1:]) if len(url.split("/")[2].split(".")) == 3 else ".".join(url.split("/")[2].split(".")[0:])
        url_ld = "https://letsdebug.net/"
        print(" {} {}".format(INFO_MOD, domain))
        datas = {"domain":domain,"method":"http-01"}
        req = requests.post(url_ld, data=datas, allow_redirects=True, verify=False)
        url_debug = "{}?debug=y".format(req.url)
        while wait_finish:
            res = requests.get(url_debug, verify=False)
            if "please wait" in res.text:
                time.sleep(1)
            else:
                wait_finish = False
        soup = BeautifulSoup(res.text, "html.parser")
        search = soup.find('div', {"id":"RateLimit-Debug"})
        if search:
            for s in search:
                    if s != None and s != "\n":
                        string_result += str(s)
            result = re.findall(r'\[.*?\]', string_result)
            for r in result:
                r = r.replace("[","").replace("]","")
                if r not in list_result:
                    list_result.append(r)
            for rl in list_result:
                print(" {} {}".format(INFO_MOD, rl))
        else:
            print(" {} Nothing certificate subdomain found".format(INFO_MOD))
        print(LINE)


    def firebaseio(self, url):
        """
        Firebaseio: To check db firebaseio
        ex: --firebase facebook
        """
        get_domain = url.split("/")[2]
        parse_domain = get_domain.split(".")
        if not "www" in get_domain:
            dire = "{}-{}".format(parse_domain[0], parse_domain[1]) if len(parse_domain) > 2 else "{}".format(parse_domain[0])
        else:
            dire = "{}".format(parse_domain[1])
        print("\033[36m Firebaseio Check \033[0m")
        print(LINE)
        url = 'https://{}.firebaseio.com/.json'.format(dire.split(".")[0])
        print(" Target: {}\n".format(url))
        try:
            r = requests.get(url, verify=False).json()
            if 'error' in r.keys():
                if r['error'] == 'Permission denied':
                    print(" {}{} seems to be protected".format(FORBI, url)) #successfully protected
                elif r['error'] == '404 Not Found':
                    print(" {}{} not found".format(LESS, url)) #doesn't exist
                elif "Firebase error." in r['error']:
                    print(" {}{} Firebase error. Please ensure that you spelled the name of your Firebase correctly ".format(WARNING, url))
            else:
                print(" {}{} seems to be vulnerable !".format(PLUS, url)) #vulnerable
        except AttributeError:
            '''
            Some DBs may just return null
            '''
            print("{} null return".format(INFO))
        except:
            print("Error with the requests, please do a manual check")
            pass
        print(LINE)
        

    def wayback_check(self, url, directory):
        """
        Wayback_check:
        Check in a wayback machine to found old file on the website or other things...
        Use "waybacktool"
        """
        print("\033[36m Wayback Check \033[0m")
        print(LINE)
        print(url + "\n")
        try:
            os.system('python3 tools/waybacktool/waybacktool.py pull --host {} | python3 tools/waybacktool/waybacktool.py check > {}/wayback.txt'.format(url, directory))
        except Exception:
            pass
            #traceback.print_exc()
        try:
            statinfo = os.path.getsize(directory + "/wayback.txt")
        except:
            print(" {} No wayback found ".format(LESS))
        if statinfo < 1 :
            print(" {} No wayback found".format(LESS))
        else:
            with open(directory + "/wayback.txt", "r+") as wayback:
                wb_read = wayback.read().splitlines()
                for wb in wb_read:
                    wb_res = list(wb.split(","))
                    try:
                        if wb_res[1] == " 200":
                            print("{}{}{}".format(PLUS, wb_res[0], wb_res[1]))
                        elif wb_res[1] == " 301" or wb_res[1] == " 302":
                            print("{}{}{}".format(LESS, wb_res[0], wb_res[1]))
                        elif wb_res[1] == " 404" or wb_res[1] == " 403":
                            pass
                        else:
                            print("{}{}{}".format(INFO, wb_res[0], wb_res[1]))
                    except:
                        pass
        print(LINE)


    def check_localhost(self, url):
        """
        Check_localhost: Function which try automatically if it's possible scanning with "localhost" host for discovery other files/directories
        """
        list_test = ["127.0.0.1", "localhost"]
        localhost = False
        print("\033[36m Try localhost host \033[0m")
        print(LINE)
        for lt in list_test:
            header = {"Host": lt}
            try:
                req = requests.get(url, headers=header, verify=False, timeout=10)
                if req.status_code == 200:
                    print(" \033[32m\u251c\033[0m You can potentialy try bf directories with this option '-H \"Host:{}\"' ".format(lt))
                    localhost = True
                else:
                    pass
            except:
                pass
        if not localhost:
            print(" {} Not seem possible to scan with localhost host".format(LESS))
        print(LINE)


    def check_vhost(self, domain, url):
        """
        check_ip:
        Check the host ip if this webpage is different or not
        """
        print("\033[36m Check Vhosts misconfiguration \033[0m")
        print(LINE)
        try:
            req_index = requests.get(url, verify=False, timeout=10)
            len_index = len(req_index.content)
            retrieve_ip = False
            dom = socket.gethostbyname(domain)
            ips = ["https://{}/".format(dom), "http://{}/".format(dom), "http://www2.{}/".format(domain), "http://www3.{}/".format(domain), "https://www2.{}/".format(domain),
            "https://www3.{}/".format(domain)]
            for ip in ips:
                try:
                    req_ip = requests.get(ip, verify=False, timeout=10)
                    if req_ip.status_code not in [404, 403, 425, 503, 500, 400] and len(req_ip.content) != len_index:
                        retrieve_ip = True
                        print(" \033[32m\u251c\033[0m The host IP seem to be different, check it: {} ".format(ip))
                except:
                    print(" \033[33m\u251c\033[0m The host IP have a problem, check it manualy please: {} ".format(ip))
                    pass
            if not retrieve_ip:
                print(" {} IPs do not appear to be different from the host".format(LESS))
            print(LINE)
        except:
            pass


    def check_backup_domain(self, domain, url):
        """
        check_backup_domain:
        Check the backup domain, like exemple.com/exemple.zip
        """
        print("\033[36m Check domain backup \033[0m")
        print(LINE)
        backup_dn_ext = ["zip", "rar", "iso", "tar", "gz", "tgz", "tar.gz", "7z", "jar"]
        found_bdn = False
        len_response = 0
        try:
            req_index = requests.get(url, verify=False, timeout=10)
            len_index = len(req_index.content)
            domain = domain.split('.')[1] if len(domain.split('.')) > 2 else domain.split('.')[0]
            print(" {}List of backup extension for domain {}: {}\nExemple: {}{}.zip\n".format(INFO, domain, backup_dn_ext, url, domain.split('.')[0]))
            for bdn in backup_dn_ext:
                url_dn_ext = "{}{}.{}".format(url, domain.split('.')[0], bdn)
                try:
                    req_dn_ext = requests.get(url_dn_ext, verify=False, timeout=10)
                    if req_dn_ext.status_code not in [404, 403, 401, 500, 400, 425] and len(req_dn_ext.content) not in range(len_index - 10, len_index + 10):
                        if len(req_dn_ext.content) not in range(len_response - 10, len_response + 10):
                            print(" {} {} found ({}b)".format(PLUS, url_dn_ext, len(req_dn_ext.text)))
                            len_response = len(req_dn_ext.content)
                            found_bdn = True
                except:
                    pass
        except:
            pass
        if not found_bdn:
            print(" {} No backup domain name found".format(LESS))
        print(LINE)



    def test_timeout(self, url, first=False):
        """
        Test_timeout: just a little function for test if the connection is good or not
        """
        try:
            req_timeout = requests.get(url, timeout=30, verify=False)
        except Timeout:
            print("{}Service potentialy Unavailable, The site web seem unavailable please wait...\n".format(WARNING))
            if first:
                next_step = input("Do you want continue ?: [y:N] ")
                if next_step in ["y", "Y"]:
                    pass
                else:
                    sys.exit()
            else:
                time.sleep(180)
        except requests.exceptions.ConnectionError:
            pass