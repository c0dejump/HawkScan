from datetime import datetime
import csv
import traceback

def create_report(directory, cookie_):
    """
    Create_report: make a html report with url, waf, email...
    """
    urls = ""
    waf = ""
    mails = ""
    nowdate = datetime.now()
    nowdate = "{}-{}-{}".format(nowdate.day, nowdate.month, nowdate.year)
    #directory = "../" + directory#DEBUG
    if cookie_:
        auth_stat = "Authenticated"
    else:
        auth_stat = "No Authenticated"
    with open("report/report_"+ directory.split("/")[-1] + ".html", "a+") as test:
        with open(directory + "/output/raw.txt", "r") as scan:
            for s in scan.read().splitlines():
                s = s.split(', ')
                if s[2] in ["301","302"]:
                    urls += """
                            <tr style="display:none;" class="value300">
                            <td style="color: orange; ">{}</td>
                            <td style="color: orange; "><a href="{}" target="_blank" style="color: white;">{}</a></td>
                            <td style="color: orange; ">{}</td>
                            <td style="color: white; ">{}</td>
                            </tr>
                            """.format(nowdate, s[1], s[1], s[2], s[3])

                elif s[2] in ["401","403"]:
                    urls += """
                        <tr style="display:none;" class="value403">
                        <td style="color: red;">{}</td>
                        <td style="color: red;"><a href="{}" target="_blank" style="color: white;">{}</a></td>
                        <td style="color: red;">{}</td>
                        <td style="color: white; ">{}</td>
                        </tr>
                        """.format(nowdate, s[1], s[1], s[2], s[3])
                elif s[2] in ["400", "500"]:
                    urls += """
                            <tr style="display:none;" class="value4500">
                            <td style="color: orange; ">{}</td>
                            <td style="color: orange; "><a href="{}" target="_blank" style="color: white;">{}</a></td>
                            <td style="color: orange; ">{}</td>
                            <td style="color: white; ">{}</td>
                            </tr>
                            """.format(nowdate, s[1], s[1], s[2], s[3])
                else:
                    urls += """
                        <tr style="display:none;" class="value200">
                        <td style="color: green;">{}</td>
                        <td style="color: green;"><a href="{}" target="_blank" style="color: white;">{}</td>
                        <td style="color: green;">{}</td>
                        <td style="color: white; ">{}</td>
                        </tr>
                        """.format(nowdate, s[1], s[1], s[2], s[3])
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
            with open(directory + "/google_dorks.txt", "r") as google_dork:
                reader = csv.reader(csvFile)
                for gd in google_dork:
                    gd_link += """
                        <tr>
                        <td><a href="{}" target="_blank" style="color: white;">{}</a></td>
                        </tr>
                        """.format(l, l)
        except:
            gd_link = "<tr><td><b> No google dork result found </b></td></tr>"
        try:
            link = ""
            with open(directory + "/links.txt", "r") as links:
                for l in links.read().splitlines():
                    link += """
                        <tr>
                        <td><a href="{}" target="_blank" style="color: white;">{}</a></td>
                        </tr>
                        """.format(l, l)
        except:
            link = "<tr><td> No links found </td></tr>"
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
            pass
        try:
            with open(directory + "/cms.txt","r") as cmsFile:
                cms = ""
                for cms_read in cmsFile.read().splitlines():
                    cms += """
                        <span class='subText' color: green; ">{}</span>
                        """.format(cms_read)
        except:
            cms = "<span class='subText' style='color: red;'> This site dosn't seem to use a CMS </span>"
        test.write('''
            <!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8" />
        <title>Hawkscan Report</title>
        <link href="html/fonts/charte.css" rel="stylesheet">
        <link href="html/fonts/page.css" rel="stylesheet">
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.0/jquery.min.js"></script>
        <script src="html/scripts/scripts.js"></script>
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
                            <label class="w1-4 centerText" for="s2">Google Dork</label>
                            <label class="w1-4 centerText" for="s3">Links</label>
                            <label class="w1-4 centerText" for="s4">Wayback</label>
                        </div>
                    </div>
                    <ul class="sections container">
                    <center>
                        <li class="d-flex flex-dc">
                            <h3>URLs</h3>
                            <div class="tableau">
                                <table>
                                <select id="status_code">
                                  <option value="-1">All</option>
                                  <option value="plus">200</option>
                                  <option value="redirect">301/302</option>
                                  <option value="forbi">401/403</option>
                                  <option value="serv_error">400/500</option>
                                </select>
                                <br>
                                    <tr>
                                      <td>Date</td>
                                      <td>Url</td>
                                      <td>Status</td>
                                      <td>Bytes</td>
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
                                      <td>Google Dork</td>
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
</html>'''.format(waf, cms, auth_stat, urls, gd_link, link, wayback))

"""if __name__ == '__main__':
    directory = "/sites/"
    cookie_ = None
    create_report(directory, cookie_)"""#DEBUG