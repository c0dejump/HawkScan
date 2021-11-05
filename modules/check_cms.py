import json
import requests
from bs4 import BeautifulSoup
from config import PLUS, WARNING, INFO, LESS, LINE

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class check_cms:

    def detect_cms(self, url, directory):
        """
        CMS:
        Detect if the website use a CMS
        """
        print("\033[36m CMS \033[0m")
        print(LINE)
        try:
            whatscms_url = "https://whatcms.org/APIEndpoint/Detect?key=1481ff2f874c4942a734d9c499c22b6d8533007dd1f7005c586ea04efab2a3277cc8f2&url={}".format(url)
            req = requests.get(whatscms_url, timeout=10, allow_redirects=False, verify=False)
            if "Not Found" in req.text or "Theme not detected" in req.text:
                with open(directory + "/cms.txt", "w+") as cms_write:
                    cms_write.write("this website does not seem to use a CMS")
                print(" {} This website does not seem to use a CMS \n".format(LESS))
                print(LINE)
                return False, False;
            else:
                reqt = json.loads(req.text)
                result = reqt["result"].get("name")
                v = reqt["result"].get("version")
                if v:
                    with open(directory + "/cms.txt", "w+") as cms_write:
                        cms_write.write("This website use {} {}".format(result, v))
                    print(" {} This website use \033[32m{} {} \033[0m\n".format(PLUS, result, v))
                    return result, v;
                else:
                    with open(directory + "/cms.txt", "w+") as cms_write:
                        cms_write.write("This website use {} but nothing version found".format(LESS, result))
                    print(" {} This website use \033[32m{}\033[0m but nothing version found \n".format(PLUS, result))
                    print(LINE)
                    return False, False;
        except:
            print(" {} You need connection to check the CMS".format(WARNING))
            print(LINE)
            return False, False;
                

    def cve_cms(self, result, v):
        """
        CVE_CMS:
        Check CVE with cms and version detected by the function 'detect_cms'.
        """
        url_comp = "https://www.cvedetails.com/version-search.php?vendor={}&product=&version={}".format(result, v)
        req = requests.get(url_comp, allow_redirects=True, verify=False, timeout=10)
        if not "matches" in req.text:
            print(" {} CVE found ! \n{}{}\n".format(WARNING, WARNING, url_comp))
            if 'WordPress' in req.text:
                version =  v.replace('.','')
                site = "https://wpvulndb.com/wordpresses/{}".format(version)
                req = requests.get(site, verify=False)
                soup = BeautifulSoup(req.text, "html.parser")
                search = soup.find_all('tr')
                if search:
                    for p in search:
                        dates = p.find("td").text.strip()
                        detail = p.find("a").text.strip()
                        print("  {}{} : {}".format(WARNING, dates, detail))
                else:
                    print(" {} Nothing wpvunldb found \n".format(LESS))
        elif 'WordPress' in req.text:
            version =  v.replace('.','')
            site = "https://wpvulndb.com/wordpresses/{}".format(version)
            req = requests.get(site, verify=False)
            soup = BeautifulSoup(req.text, "html.parser")
            search = soup.find_all('tr')
            if search:
                print(" {} CVE found ! \n{}{}\n".format(WARNING, WARNING, site))
                for p in search:
                    dates = p.find("td").text.strip()
                    detail = p.find("a").text.strip()
                    print("{}{} : {}".format(WARNING, dates, detail))
                    print(LINE)
            else:
                print(" {} Nothing wpvunldb found ".format(LESS))
                print(LINE)
        else:
            print(" {} Nothing CVE found \n".format(LESS))
            print(LINE)