import requests
from bs4 import BeautifulSoup
import whois
import json
import sys, re, os
import ssl, OpenSSL
import socket
import pprint
import traceback
# External
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK

class mini_scans:

    def get_header(self, url, directory):
        """Get header of website (cookie, link, etc...)"""
        r = requests.get(url, allow_redirects=False, verify=False)
        head = r.headers
        print(INFO + "HEADER")
        print(LINE)
        print("  {} \n".format(head).replace(',','\n'))
        print(LINE)
        with open(directory + '/header.csv', 'w+') as file:
            file.write(str(head).replace(',','\n'))

    def gitpast(self, url):
        """
        Github: check github informations
        Pastebin: check pastebin information #TODO
        """
        print("{}Check in Github".format(INFO))
        print(LINE)
        if "www" in url:
            url = url.split(".")[1]
        else:
            url = url.split("/")[2]
        url = "{}".format(url)
        print("search: {}\n".format(url))
        types = ["Commits", "Issues", "Code", "Repositories", "Marketplace", "Topics", "Wikis", "Users"]
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
            if len(parse_domain) > 2:
                dire = "{}-{}".format(parse_domain[0], parse_domain[1])
            else:
                dire = "{}".format(parse_domain[0])
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
                    print("  {}{} seems to be protected".format(FORBI, url)) #successfully protected
                elif r['error'] == '404 Not Found':
                    print("  {}{} not found".format(LESS, url)) #doesn't exist
                elif "Firebase error." in r['error']:
                    print("  {}{} Firebase error. Please ensure that you spelled the name of your Firebase correctly ".format(WARNING, url))
            else:
                print("  {}{} seems to be vulnerable !".format(PLUS, url)) #vulnerable
        except AttributeError:
            '''
            Some DBs may just return null
            '''
            print("{} null return".format(INFO))
        print(LINE + "\n")

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
        statinfo = os.path.getsize(directory + "/wayback.txt")
        if statinfo < 1:
            print("  {}Nothing wayback found".format(INFO))
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
