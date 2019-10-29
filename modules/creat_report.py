from datetime import datetime

def create_report(directory, cookie_):
    """
    Create_report: make a html report with url, waf, email...
    """
    urls = ""
    waf = ""
    mails = ""
    nowdate = datetime.now()
    nowdate = "{}-{}-{}".format(nowdate.day, nowdate.month, nowdate.year)
    if cookie_:
        auth_stat = "Authenticated"
    else:
        auth_stat = "No Authenticated"
    with open(directory + "/report.html", "a+") as test:
        with open(directory + "/scan.txt", "r") as scan:
            for s in scan.read().splitlines():
                s = s.split(" ")
                s0 = s[0]
                s1 = s[1]
                if s0 == "[+]":
                    if "301" in s or "302" in s:
                        if s[2] == "301":
                            s0 = s0.replace("[+]", "301")
                        elif s[2] == "302":
                            s0 = s0.replace("[+]", "302")
                        urls += """
                            <tr>
                            <td style="width: 120px; color: orange; padding: 3px;">{}</td>
                            <td style="width: 230px; color: orange; padding: 3px;"><a href="{}">{}</a></td>
                            <td style="width: 20px; color: orange; padding: 3px;">{}</td>
                            </tr>
                            """.format(nowdate, s1, s1, s0)
                    else:
                        s0 = s0.replace("[+]", "200")
                        urls += """
                        <tr>
                        <td style="width: 120px; color: green; padding: 3px;">{}</td>
                        <td style="width: 230px; color: green; padding: 3px;"><a href="{}">{}</td>
                        <td style="width: 20px; color: green; padding: 3px;">{}</td>
                        </tr>
                        """.format(nowdate, s1, s1, s0)
                elif s0 == "[x]":
                    s0 = s0.replace("[x]", "403")
                    urls += """
                        <tr>
                        <td style="width: 120px; color: red; padding: 3px;">{}</td>
                        <td style="width: 230px; color: red; padding: 3px;"><a href="{}">{}</a></td>
                        <td style="width: 20px; color: red; padding: 3px;">{}</td>
                        </tr>
                        """.format(nowdate, s1, s1, s0)
                elif s0 == "[-]":
                    if "401" in s:
                        if s[2] == "401":
                            s0 = s0.replace("[-]","401")
                        urls += """
                            <tr>
                            <td style="width: 120px; color: orange; padding: 3px;">{}</td>
                            <td style="width: 230px; color: orange; padding: 3px;"><a href="{}">{}</a></td>
                            <td style="width: 20px; color: orange; padding: 3px;">{}</td>
                            </tr>
                            """.format(nowdate, s1, s1, s0)
                elif s0 == "[!]":
                    if "400" in s:
                        if s[2] == "400":
                            s0 = s0.replace("[!]","400")
                        urls += """
                            <tr>
                            <td style="width: 120px; color: red; padding: 3px;">{}</td>
                            <td style="width: 230px; color: red; padding: 3px;"><a href="{}">{}</a></td>
                            <td style="width: 20px; color: red; padding: 3px;">{}</td>
                            </tr>
                            """.format(nowdate, s1, s1, s0)
        with open(directory + "/waf.txt", "r") as waff:
            waf_res = ""
            for w in waff.read().splitlines():
                if "The site" in w:
                    waf_res = w
            if waf_res:
                waf += """
                    <tr>
                    <td style="width: 120px;">{}</td>
                    </tr>
                """.format(waf_res)
            else:
                waf += """
                    <tr>
                    <td style="width: 120px;">This site dosn't seem to use a WAF</td>
                    </tr>
                """.format(w)
        try:
            with open(directory + "/mail.csv", "r") as csvFile:
                reader = csv.reader(csvFile)
                for row in reader:
                    mail = row[0]
                    stat = row[1]
                    if "no" in stat:
                        mails += """
                            <tr>
                            <td style="width: 120px; color: green; padding: 3px;">{}</td>
                            <td style="width: 20px; color: green; padding: 3px;">{}</td>
                            </tr>
                            """.format(mail, stat)
                    else:
                        mails += """
                            <tr>
                            <td style="width: 120px; color: red; padding: 3px;">{}</td>
                            <td style="width: 20px; color: red; padding: 3px;">{}</td>
                            </tr>
                            """.format(mail, stat)
        except:
            mails = "<tr><td><b> No emails found </b></td></tr>"
        with open(directory + "/cms.txt","r") as cmsFile:
            cms = ""
            for cms_read in cmsFile.read().splitlines():
                cms += """
                    <tr>
                    <td style="width: 120px; color: blue; padding: 3px;">{}</td>
                    </tr>
                    """.format(cms_read)
        test.write('''
                <!DOCTYPE html>
                <html>
                <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
                <head>
                <style>
                body{{
                    font-family: "Arial";
                }}
                h1 {{
                    font-size: 15;
                }}
                </style>
                <title>Hawkscan Report</title>
                </head>
                <body>
                <center>
                <h1>Hawkscan Report </h1></br>
                <hr></br>
                <b>Status : <p style="color: blue;">{}</b><br>
                <hr>
                <b>WAF</b> </br>
                <p style="color: red;">{}</p>
                <br>
                <hr>
                <br>
                <b> CMS </b>
                <p style="color: blue;">{}</p>
                <br>
                <hr>
                <br>
                <b> URLS </b>
                <br>
                <table style="width: 800px; border-color: black; height: 1px;" border="1" cellspacing="0" cellpadding="0">
                <tbody>
                <tr>
                <td style="width: 120px;">Date</td>
                <td style="width: 230px;">URL</td>
                <td style="width: 20px;">Status</td>
                {}
                </tbody>
                </table>
                <br>
                <hr>
                <br>
                <b>Check Mails</b><br><br>
                <table style="width: 400px; border-color: black; height: 1px;" border="1" cellspacing="0" cellpadding="0">
                <tbody>
                <tr>
                <td style="width: 120px;"><b>Mails</b></td>
                <td style="width: 20px;"><b>Status</b></td>
                {}
                </tbody>
                </table>
                </br>
                </center>
                </body>
                </html>'''.format(auth_stat, waf, cms, urls, mails))