import requests
from bs4 import BeautifulSoup
import whois
import json
import sys, re, os
import ssl, OpenSSL
import socket
import pprint
import traceback
from requests.exceptions import Timeout
import time
# External
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK

class before_start:
    

    def get_header(self, url, directory):
        """Get header of website (cookie, link, etc...)"""
        r = requests.get(url, allow_redirects=False, verify=False)
        print(INFO + "HEADER")
        print(LINE)
        print("  {} \n".format(r.headers).replace(',','\n'))
        print(LINE)
        with open(directory + '/header.csv', 'w+') as file:
            file.write(str(r.headers).replace(',','\n'))


    def gitpast(self, url):
        """
        Github: check github informations
        Pastebin: check pastebin information #TODO
        """
        print("{}Check in Github".format(INFO))
        print(LINE)
        url = url.split(".")[1] if "www" in url else url.split("/")[2]
        url = "{}".format(url)
        print("search: {}\n".format(url))
        types = ["Commits", "Issues", "Code", "Repositories", "Marketplace", "Topics", "Wikis", "Users"]
        try:
            for t in types:
                github = "https://github.com/search?q={}&type={}".format(url, t)
                req = requests.get(github, verify=False)
                soup = BeautifulSoup(req.text, "html.parser")
                search = soup.find('a', {"class":"menu-item selected"})
                if search:
                    for s in search.find("span"):
                        print("  {}{}: {}".format(INFO, t, s))
                else:
                    print("  {}{}: not found".format(INFO, t))
        except:
            print("{}You need connection to check the github".format(WARNING))
        print("\n" + LINE)


    def who_is(self, url, directory):
        """Get whois of website"""
        print(INFO + "WHOIS")
        print(LINE)
        try:
            who_is = whois.whois(url)
            #pprint.pprint(who_is + "\n")
            for k, w in who_is.iteritems():
                is_who = " {} : {}-".format(k, w)
                print(is_who)
                with open(directory + '/whois.csv', 'a+') as file:
                    file.write(is_who.replace("-","\n"))
        except:
            erreur = sys.exc_info()
            typerr = u"%s" % (erreur[0])
            typerr = typerr[typerr.find("'")+1:typerr.rfind("'")]
            print(typerr)
            msgerr = u"%s" % (erreur[1])
            print(msgerr)
        print("\n" + LINE)


    def get_dns(self, url, directory):
        """Get DNS informations"""
        port = 0
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
            print(INFO + "DNS information")
            print(LINE)
            pprint.pprint(str(cert['subject']).replace(',','').replace('((','').replace('))',''))
            pprint.pprint(cert['subjectAltName'])
            print('')
            conn.close()
            print(LINE)
            with open(directory + '/dns_info.csv', 'w+') as file:
                file.write(str(cert).replace(',','\n').replace('((','').replace('))',''))
        except:
            print(INFO + "DNS information")
            print(LINE)
            erreur = sys.exc_info()
            typerr = u"%s" % (erreur[0])
            typerr = typerr[typerr.find("'")+1:typerr.rfind("'")]
            print(typerr)
            msgerr = u"%s" % (erreur[1])
            print(msgerr + "\n")
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
        print("{}Firebaseio Check".format(INFO))
        print(LINE)
        url = 'https://{}.firebaseio.com/.json'.format(dire.split(".")[0])
        print(url + "\n")
        r = requests.get(url, verify=False).json()
        try:
            if 'error' in r.keys():
                if r['error'] == 'Permission denied':
                    print("\t{}{} seems to be protected".format(FORBI, url)) #successfully protected
                elif r['error'] == '404 Not Found':
                    print("\t{}{} not found".format(LESS, url)) #doesn't exist
                elif "Firebase error." in r['error']:
                    print("\t{}{} Firebase error. Please ensure that you spelled the name of your Firebase correctly ".format(WARNING, url))
            else:
                print("\t{}{} seems to be vulnerable !".format(PLUS, url)) #vulnerable
        except AttributeError:
            '''
            Some DBs may just return null
            '''
            print("{} null return".format(INFO))
        print(LINE)
        

    def wayback_check(self, url, directory):
        """
        Wayback_check:
        Check in a wayback machine to found old file on the website or other things...
        Use "waybacktool"
        """
        print("{}Wayback Check".format(INFO))
        print(LINE)
        print(url + "\n")
        try:
            os.system('python tools/waybacktool/waybacktool.py pull --host {} | python tools/waybacktool/waybacktool.py check > {}/wayback.txt'.format(url, directory))
        except Exception:
            traceback.print_exc()
        try:
            statinfo = os.path.getsize(directory + "/wayback.txt")
        except:
            print("\t{}Nothing wayback found !".format(INFO))
        if statinfo < 1 :
            print("\t{}Nothing wayback found".format(INFO))
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
        #TODO
        """
        CHeck_localhost: Function which try automatically if it's possible scanning with "localhost" host for discovery other files/directories
        """
        list_test = ["127.0.0.1", "localhost"]
        localhost = False
        print("{}Try localhost host".format(INFO))
        print(LINE)
        for lt in list_test:
            header = {"Host": lt}
            try:
                req = requests.get(url, headers=header, verify=False, timeout=10)
                if req.status_code == 200:
                    print("\t{}You can potentialy try bf directories with this option '-H \"Host:{}\"' ".format(PLUS, lt))
                    localhost = True
                else:
                    pass
            except:
                pass
        if not localhost:
            print("\t{}Not seem possible to scan with localhost host".format(LESS))
        print(LINE)


    def check_vhost(self, domain, url):
        """
        check_ip:
        Check the host ip if this webpage is different or not
        """
        print("{}Check Vhosts misconfiguration".format(INFO))
        print(LINE)
        try:
            req_index = requests.get(url, verify=False)
            len_index = len(req_index.content)
            retrieve_ip = False
            dom = socket.gethostbyname(domain)
            ips = ["https://{}/".format(dom), "http://{}/".format(dom), "http://www2.{}/".format(domain), "http://www3.{}/".format(domain)]
            for ip in ips:
                try:
                    req_ip = requests.get(ip, verify=False, timeout=6)
                    if req_ip.status_code not in [404, 403, 425, 503, 500, 400] and len(req_ip.content) != len_index:
                        retrieve_ip = True
                        print("\t{}The host IP seem to be different, check it: {} ".format(PLUS, ip))
                except:
                    pass
            if not retrieve_ip:
                print("\t{}The IP Not seem different host".format(LESS))
            print(LINE)
        except:
            pass


    def check_backup_domain(self, domain, url):
        print("{}Check domain backup".format(INFO))
        print(LINE)
        backup_dn_ext = ["zip", "rar", "iso", "tar", "gz", "tgz", "tar.gz", "7z", "jar"]
        req_index = requests.get(url, verify=False)
        len_index = len(req_index.content)
        domain = domain.split('.')[1] if len(domain.split('.')) > 2 else domain.split('.')[0]
        print("{}List of backup extension for domain {}: {}\n".format(INFO, domain, backup_dn_ext))
        found_bdn = False
        for bdn in backup_dn_ext:
            url_dn_ext = "{}{}.{}".format(url, domain.split('.')[0], bdn)
            req_dn_ext = requests.get(url_dn_ext, verify=False, timeout=6)
            if req_dn_ext.status_code not in [404, 403, 401, 500, 400, 425] and len(req_dn_ext.content) != len_index:
                print("\t{}{}".format(PLUS, url_dn_ext))
                found_bdn = True
        if not found_bdn:
            print("{}Nothing backup domain name found".format(LESS))
        print(LINE)



    def test_timeout(self, url):
        """
        Test_timeout: just a little function for test if the connection is good or not
        """
        try:
            req_timeout = requests.get(url, timeout=30)
        except Timeout:
            print("{}Service potentialy Unavailable, The site web seem unavailable please wait...\n".format(WARNING))
            time.sleep(180)
        except requests.exceptions.ConnectionError:
            pass