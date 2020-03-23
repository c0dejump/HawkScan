from bs4 import BeautifulSoup
import requests
import csv
import sys, re


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
                if "http" in link or "https" in link:
                    with open(directory + "/links.txt", "a+") as links:
                        links.write(str(link+"\n"))
                else:
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
            if mail:
                datas = { "act" : mail, "accounthide" : "test", "submit" : "Submit" }
                req_ino = requests.post("https://www.inoitsu.com/", data=datas)
                if "DETECTED" in req_ino.text:
                    pwnd = "{}: pwned ! ".format(mail)
                    if pwnd not in all_mail:
                        all_mail.append(pwnd)
                else:
                    no_pwned = "{}: no pwned ".format(mail)
                    if no_pwned not in all_mail:
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