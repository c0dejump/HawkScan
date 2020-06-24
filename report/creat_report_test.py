from datetime import datetime
import csv
import traceback
from bs4 import BeautifulSoup


class create_report_test():

    def create_report(self, directory, url_status, waf, mails, cms, wayback, auth_stat, urls, link):
        try:
            print(url_status)
            with open("report/report_"+ directory.split("/")[-1] + ".html", "a+") as report_write:
                report_write.write('''
                    <!DOCTYPE html>
                    <html>
                        <head>
                            <meta charset="utf-8" />
                            <title>Hawkscan Report</title>
                            <link href="charte.css" rel="stylesheet">
                            <link href="page.css" rel="stylesheet">
                        </head>
                        <body>
                            
                            <header class="title w100">
                                <div class="container">
                                    <h1>Hawkscan Report</h1>
                                </div>
                            </header>
                            <main>
                                <div class="subTitle container">
                                    <div class="w100 flex flex-jsb">
                                        <div class="w1-3 centerText flex flex-dc flex-aic flex-jcc">
                                            <h2>WAF</h2>
                                            {}
                                        </div>
                                        <div class="w1-3 centerText flex flex-dc flex-aic flex-jcc">
                                            <h2>CMS</h2>
                                            {}
                                        </div>
                                        <div class="w1-3 centerText flex flex-dc flex-aic flex-jcc">
                                            <h2>Status</h2>
                                            <span class="subText">{}</span>
                                        </div>
                                    </div>
                                </div>
                                <div class="subLinkSection w100">
                                    <div class="subLinkBloc w100">
                                        <input type="radio" id="s1" name="s" checked/>
                                        <input type="radio" id="s2" name="s"/>
                                        <input type="radio" id="s3" name="s"/>
                                        <input type="radio" id="s4" name="s"/>
                                        <div class="subLink">
                                            <div class="tabs container flex flex-jsb">
                                                <label class="w1-4 centerText" for="s1">URLs</label>
                                                <label class="w1-4 centerText" for="s2">Mails</label>
                                                <label class="w1-4 centerText" for="s3">Links</label>
                                                <label class="w1-4 centerText" for="s4">Wayback</label>
                                            </div>
                                        </div>
                                        <ul class="sections container">
                                        <center class="url_var">
                                            <li class="d-flex flex-dc">
                                                <h3>URLs</h3>
                                                  <div class="tableau">
                                                    <table>
                                                       <tr>
                                                            <td>Date</td>
                                                            <td>Url</td>
                                                            <td>Status</td>
                                                              {}
                                                        </tr>
                                                    </table>
                                                </div>
                                            </li>
                                            <li class="d-flex flex-dc">
                                                <h3>MAIL</h3>
                                                <div class="tableau">
                                                    <table>
                                                        <tr>
                                                          <td>Mails</td>
                                                          <td>Status</td>
                                                            {}
                                                        </tr>
                                                      </table>
                                                </div>
                                            </li>
                                            <li class="d-flex flex-dc">
                                                <h3>Links</h3>
                                                <div class="tableau">
                                                    <table>
                                                        <tr>
                                                          {}
                                                        </tr>
                                                      </table>
                                                </div>
                                            </li>
                                            <li class="d-flex flex-dc">
                                                <h3>Wayback</h3>
                                                <div class="tableau">
                                                    <table>
                                                        <tr>
                                                          {}
                                                        </tr>
                                                      </table>
                                                </div>
                                            </li>
                                        </center>
                                        </ul>
                                    </div>
                                    <!-- <div class="w1-4 centerText">
                                        <h2>Test Subtitle</h2>
                                    </div>
                                    <div class="w1-4 centerText">
                                        <h2>Test Subtitle</h2>
                                    </div>
                                    <div class="w1-4 centerText">
                                        <h2>Test Subtitle</h2>
                                    </div>
                                    <div class="w1-4 centerText">
                                        <h2>Test Subtitle</h2>
                                    </div> -->
                                </div>
                            </main>        
                            </body>
                            </html>'''.format(waf, cms, auth_stat, urls if url_status else None mails, link, wayback))
 """           with open("yourfile.txt", "r") as f:
    lines = f.readlines()
with open("yourfile.txt", "w") as f:
    for line in lines:
        if line.strip("\n") != "nickname_to_delete":
            f.write(line)    """    
        except Exception:
            traceback.print_exc()


    def create_report_base(self, directory, cookie_):
        waf = ""
        mails = ""
        urls = False
        link = False
        """
        Create_report: make a html report with url, waf, email...
        """
        #directory = "../" + directory
        if cookie_:
            auth_stat = "Authenticated"
        else:
            auth_stat = "No Authenticated"
        try:
            with open(directory + "/waf.txt", "r") as waff:
                waf_res = ""
                for w in waff.read().splitlines():
                    if "The site" in w:
                        waf_res = w
                if waf_res:
                    waf += """
                        <span class="subText" style='color: red;'>{}</span>
                    """.format(waf_res)
        except:
            waf += """
                <span class="subText" style='color: green;'>This site dosn't seem to use a WAF</span>
            """
        try:
            with open(directory + "/mail.csv", "r") as csvFile:
                reader = csv.reader(csvFile)
                for row in reader:
                    mail = row[0]
                    stat = row[1]
                    if "no" in stat:
                        mails += """
                            <tr>
                            <td style="color: green; ">{}</td>
                            <td style="color: green; ">{}</td>
                            </tr>
                            """.format(mail, stat)
                    else:
                        mails += """
                            <tr>
                            <td style="color: red; ">{}</td>
                            <td style="color: red; ">{}</td>
                            </tr>
                            """.format(mail, stat)
        except:
            mails = "<tr><td><b> No emails found </b></td></tr>"
        try:
            wayback = ""
            with open(directory + "/wayback.txt", "r") as waybacks:
                for wb in waybacks.read().splitlines():
                    w = wb.split(",")
                    w_status = w[1]
                    wayback += """
                        <tr>
                        <td><a href="{}">{}</a></td>
                        <td>{}</td>
                        </tr>
                        """.format(w[0], w[0], w_status)
        except:
            wayback = "<tr><td><b> No wayback found </b></td></tr>"
        try:
            with open(directory + "/cms.txt","r") as cmsFile:
                cms = ""
                for cms_read in cmsFile.read().splitlines():
                    cms += """
                        <span class='subText' color: green; ">{}</span>
                        """.format(cms_read)
        except:
            cms = "<span class='subText' style='color: red;'> This site dosn't seem to use a CMS </span>"
        url_status = False    
        self.create_report(directory, url_status, waf, mails, cms, wayback, auth_stat, urls, link)


    def create_report_url(self, status_link, res, directory):
        waf = False
        mails = False
        cms = False
        wayback = False
        auth_stat = False
        urls = ""
        link = ""
        nowdate = datetime.now()
        nowdate = "{}-{}-{}".format(nowdate.day, nowdate.month, nowdate.year)
        if status_link == 301 or status_link == 302:
            urls += """
                <tr>
                <td style="color: orange; ">{}</td>
                <td style="color: orange; "><a href="{}" target="_blank" style="color: white;">{}</a></td>
                <td style="color: orange; ">{}</td>
                </tr>
                """.format(nowdate, res, res, status_link)
        elif status_link == 200:
            urls += """
                <tr>
                <td style="color: green; ">{}</td>
                <td style="color: green; "><a href="{}" target="_blank" style="color: white;">{}</td>
                <td style="color: green; ">{}</td>
                </tr>
                """.format(nowdate, res, res, status_link)
        elif status_link == 403 or status_link == 401:
            urls += """
                <tr>
                <td style="color: red; ">{}</td>
                <td style="color: red; "><a href="{}" target="_blank" style="color: white;">{}</a></td>
                <td style="color: red; ">{}</td>
                </tr>
                """.format(nowdate, res, res, status_link)
        elif status_link == 400:
            urls += """
                    <tr>
                    <td style="color: red; ">{}</td>
                    <td style="color: red; "><a href="{}" target="_blank" style="color: white;">{}</a></td>
                    <td style="color: red; ">{}</td>
                    </tr>
                """.format(nowdate, res, res, status_link)
        else:
            urls += """
                    <tr>
                    <td style="color: blue; ">{}</td>
                    <td style="color: blue; "><a href="{}" target="_blank" style="color: white;">{}</a></td>
                    <td style="color: blue; ">{}</td>
                    </tr>
                """.format(nowdate, res, res, status_link)
        try:
            with open(directory + "/links.txt", "r") as links:
                for l in links.read().splitlines():
                    link += """
                        <tr>
                        <td><a href="{}" target="_blank" style="color: white;">{}</a></td>
                        </tr>
                        """.format(l, l)
        except:
            link = "<tr><td> No links found </td></tr>"
        url_status = True
        self.create_report(directory, url_status, waf, mails, cms, wayback, auth_stat, urls, link)


"""if __name__ == '__main__':
    directory = "../sites/fr.chaturbate.com"
    cookie_ = None
    create_report(directory, cookie_)"""