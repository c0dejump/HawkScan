# -*- coding: utf-8 -*-
import time
import sys, os
import requests
from config import PLUS, WARNING, LESS, LINE, FORBI, BACK, WAF, INFO
import wafw00f

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def detect_wafw00f(url, directory, thread):
    """
    WAF:
    Detect if the website use a WAF with tools "wafw00f"
    """
    detect = False
    message = ""
    os.system("wafw00f {} > {}/waf.txt".format(url, directory))
    with open(directory + "/waf.txt", "r+") as waf:
        for w in waf:
            if "behind" in w:
                detect = True
                message = w.replace("[+]","").replace("[*]","")
            else:
                pass
        print("\033[36m WAF \033[0m")
        print(LINE)
        if detect:
            print(" {}{}".format(WARNING, message))
            if thread >= 30:
                confirm_thread = input(" {} This website have a waf, are you sure to use {} threads ? [y:n] ".format(WARNING, thread))
                if confirm_thread == "y" or confirm_thread == "Y":
                    print(LINE)
                    pass
                else:
                    enter_thread = input(" {} Enter the number of threads: ".format(INFO))
                    if int(enter_thread) > 0:
                        print(LINE)
                        return int(enter_thread)
                    else:
                        print("If you enter 0 or less that's will doesn't work :)")
                        sys.exit()
            else:
                print(LINE)
        else:
            print(" {} This website doesn't seem use WAF".format(LESS))
            print(LINE)


def req_test_false_positif(s, res, headers):
    """
    req_test_false_positif:
    Function to test if the first response is a FP or not
    """
    url_base = res.split("/")[:3]
    url_send = '/'.join(url_base)+"/"
    try:
        req_test_w = s.get(url_send, allow_redirects=False, verify=False, timeout=10)
        req_test_waf = s.get(url_send, allow_redirects=True, verify=False, timeout=10)
        #print("Reponse test false positive: {}".format(req_test_waf)) #DEBUG
        if req_test_w.status_code == req_test_waf.status_code:
            return req_test_waf
    except:
        pass

#@timeit
def verify_waf(s, req, res, headers, display=True):
    """
    Function verify if there is a WAF to instable website
    """
    #360
    req_test = req_test_false_positif(s, res, headers)
    if req_test:
        req_response = req_test.text
        if req_test.status_code == 493 or "wzws-waf-cgi" in req_response or "X-Powered-By-360wzb" in req_test.headers:
            if display:
                print("{}360 Web Application Firewall waf detected : {} ".format(WAF, res))
            return True
        #aeSecure
        elif "aesecure_denied.png" in req_response or "aeSecure-code" in req_test.headers:
            if display:
                print("{}aeSecure WAF detected : {} ".format(WAF, res))
            return True
        elif "Server detected a syntax error in your request" in req_response or "AL-SESS" in req_test.headers or "AL-LB" in req_test.headers:
            if display:
                print("{}Airlock (Phion/Ergon) WAF detected : {} ".format(WAF, res))
            return True
        #Aliyundun 
        elif req_test.status_code == 405 and \
            "Sorry, your request has been blocked as it may cause potential threats to the server's security" in req_response:
            if display:
                print("{}Aliyundun WAF detected : {} ".format(WAF, res))
            return True
        #Anquando
        elif req_test.status_code == 405 and "/aqb_cc/error/|hidden_intercept_time" in req_response or "X-Powered-By-Anquanbao" in req_test.headers:
            if display:
                print("{}Anquanbao Web Application Firewall WAF detected : {} ".format(WAF, res))
            return True
        #Anyu
        elif "Sorry! your access has been intercepted by AnYu" in req_response or "AnYu- the green channel" in req_response or \
            "WZWS-RAY" in req_test.headers:
            if display:
                print("{}AnYu WAF detected : {} ".format(WAF, res))
            return True
        #Approach
        elif "Approach Web Application Firewall Framework" in req_response or \
            "Your IP address has been logged and this WAFrmation could be used by authorities to track you." in req_response:
            if display:
                print("{}Approach WAF detected : {} ".format(WAF, res))
            return True
        #Armor
        elif "This request has been blocked by website protection from Armor" in req_response:
            if display:
                print("{}Armor Protection (Armor Defense) WAF detected : {} ".format(WAF, res))
            return True
        #ArvanCloud 
        elif "ArvanCloud" in req_test.headers:
            if display:
                print("{}ArvanCloud WAF detected : {} ".format(WAF, res))
            return True
        #ASPA 
        elif "ASPA-WAF" in req_test.headers or "ASPA-Cache-Status_code" in req_test.headers:
            if display:
                print("{}ASPA WAF detected : {} ".format(WAF, res))
            return True
        #ASP.NET
        elif "X-ASPNET-Version" in req_test.headers and \
            "This generic 403 error means that the authenticated user is not authorized to use the requested resource" in req_response or \
            "Error Code 0x00000000<" in req_response: 
            if display:
                print("{}ASP.NET WAF detected : {} ".format(WAF, res))
            return True
        #ASTRA
        elif "our website protection system has detected an issue ss and wont let you proceed any further" in req_response or \
            "www.getastra.com/assets/images/" in req_response or "cz_astra_csrf_cookie" in req_test.headers:
            if display:
                print("{}ASTRA WAF detected : {} ".format(WAF, res))
            return True
        #AWS ELB 
        elif "AWSALB" in req_test.headers or "X-AMZ-ID" in req_test.headers or "X-AMZ-REQUEST-ID" in req_test.headers and "Access Denied" in req_response:
            if display:
                print ("{}AWS ELB WAF detected : {} ".format(WAF, res))
            return True
        #Barikode 
        elif "BARIKODE" in req_response:
            if display:
                print("{}BARIKODE WAF detected : {} ".format(WAF, res))
            return True
        #Barracuda
        elif "You have been blocked" in req_response or "You are unable to access this website" in req_response and \
            "barra_counter_session" in req_test.headers or "barracuda_" in req_test.headers:
            if display:
                print("{}Barracuda WAF detected : {} ".format(WAF, res))
            return True
        #Bekchy
        elif "Bekchy - Access Denied" in req_response or "https://bekchy.com/report" in req_response:
            if display:
                print("{}Bekchy WAF detected : {} ".format(WAF, res))
            return True
        #BitNinja 
        elif "Security check by BitNinja" in req_response or "your IP will be removed from BitNinja" in req_response or \
            "Visitor anti-robot validation" in req_response:
            if display:
                print("{}BitNinja WAF detected : {} ".format(WAF, res))
            return True
        #BIG-IP
        elif "BigIP" in req_test.headers or "F5" in req_test.headers:
            if display:
                print("{}BIG-IP WAF detected : {} ".format(WAF, res))
            return True
        #Bluedon
        elif "Bluedon Web Application Firewall" in req_response:
            if display:
                print("{}Bluedon WAF detected : {} ".format(WAF, res))
            return True
        #BulletProof Security Pro 
        elif "bpsMessage" in req_response or \
            "If you arrived here due to a search or clicking on a link click your Browser's back button to return to the previous page." in req_response:
            if display:
                print("{}BulletProof WAF detected : {} ".format(WAF, res))
            return True
        #CDN NS Application Gateway 
        elif "CdnNsWAF Application Gateway" in req_response:
            if display:
                print("{}CDN NS Application Gateway WAF detected : {} ".format(WAF, res))
            return True
        #ChinaCache 
        elif "Powered-By-ChinaCache" in req_test.headers:
            if display:
                print("{}ChinaCache WAF detected : {} ".format(WAF, res))
            return True
        #Cisco ACE XML Gateway
        elif "ACE XML Gateway" in req_test.headers:
            if display:
                print("{}Cisco ACE WAF detected : {} ".format(WAF, res))
            return True
        #Cloudbric Web Application Firewall
        elif "Malicious Code Detected" in req_response or "Your request was blocked by Cloudbric" in req_response or \
            "Cloudbric | ERROR!" in req_response:
            if display:
                print("{}Cloudbric WAF detected : {} ".format(WAF, res))
            return True
        #Cloudflare
        elif "Cloudflare Ray ID:" in req_response or "Attention Required! | Cloudflare" in req_response:
            if display:
                print("{}Cloudflare WAF detected : {} ".format(WAF, res))
            return True
        #CloudfloorDNS 
        elif "CloudfloorDNS - Web Application Firewall Error" in req_response:
            if display:
                print("{}CloudfloorDNS WAF detected : {} ".format(WAF, res))
            return True
        #Cloudfront 
        elif "Generated by cloudfront (CloudFront)" in req_response:
            if display:
                print("{}Cloudfront WAF detected : {} ".format(WAF, res))
            return True
        #Comodo cWatch 
        elif "Protected by COMODO WAF" in req_test.headers:
            if display:
                print("{}COMODO WAF detected : {} ".format(WAF, res))
            return True
        #CrawlProtect 
        elif "crawlprotect" in req_test.headers or "CrawlProtect" in req_response:
            if display:
                print("{}CrawlProtect WAF detected : {} ".format(WAF, res))
            return True
        #Distil Web Protection 
        elif "X-Distil-CS" in req_test.headers and "Pardon Our Interruption" in req_response or \
            "You have disabled javascript in your browser" in req_response or "Something about your browser made us think that you are a bot" in req_response:
            if display:
                print("{}Distil Web Protection WAF detected : {} ".format(WAF, res))
            return True
        #DoSArrest Internet Security 
        elif "X-DIS-Request-ID" in req_test.headers or "DOSarrest" in req_response:
            if display:
                print("{}DoSArrest WAF detected : {} ".format(WAF, res))
            return True
        #DotDefender
        elif "dotDefender Blocked Your Request" in req_response or "X-dotDefender-denied" in req_test.headers:
            if display:
                print("{}DotDefender WAF detected : {} ".format(WAF, res))
            return True
        #DynamicWeb Injection Check 
        elif "dw-inj-check" in req_test.headers:
            if display:
                print("{}DynamicWeb WAF detected : {} ".format(WAF, res))
            return True
        #e3Learning Security 
        elif "e3Learning_WAF" in req_test.headers:
            if display:
                print("{}e3Learning WAF detected : {} ".format(WAF, res))
            return True
        #EdgeCast 
        elif req_test.status_code == 400 and "ID:EdgeCast Web Application Firewall" in req_response:
            if display:
                print("{}EdgeCast WAF detected : {} ".format(WAF, res))
            return True
        #Eisoo Cloud 
        elif "(year) Eisoo Inc." in req_response:
            if display:
                print("{}Eisoo WAF detected : {} ".format(WAF, res))
            return True
        #FortiWeb 
        elif "FORTIWAFSID=" in req_test.headers and ".fgd_icon" in req_response or "Server Unavailable" in req_response:
            if display:
                print("{}FortiWeb WAF detected : {} ".format(WAF, res))
            return True
        #GoDaddy
        elif "Access Denied - GoDaddy Website Firewall" in req_response:
            if display:
                print("{}GoDaddy WAF detected : {} ".format(WAF, res))
            return True
        #GreyWizard 
        elif "Contact the website owner or Grey Wizard" in req_response or "We've detected attempted attack or non standard traffic from your IP address" in req_response:
            if display:
                print("{}GreyWizard WAF detected : {} ".format(WAF, res))
            return True
        #Huawei Cloud
        elif "account.hwclouds.com/static/error/images/404img.jpg" in req_response:
            if display:
                print("{}Huawei WAF detected : {} ".format(WAF, res))
            return True
        #Imperva Incapsula
        elif "Incapsula incident ID" in req_response or \
            "subject=WAF Block Page" in req_response:
            if display:
                print("{}Imperva Incapsula WAF detected : {} ".format(WAF, res))
            return True
        #Immunify360 
        elif "imunify360-webshield" in req_test.headers or "Powered by Imunify36" in req_response or "imunify360 preloader" in req_response or \
            "protected by Imunify360" in req_response:
            if display:
                print("{}Immunify360 WAF detected : {} ".format(WAF, res))
            return True
        #IndusGuard
        elif "further investigation and remediation of this page" in req_response:
            if display:
                print("{}Potential IndusGuard WAF detected : {} ".format(WAF, res))
            return True
        #Instart DX
        elif "X-Instart-Request-ID" in req_test.headers or "X-Instart-WL" in req_test.headers or "X-Instart-Cache" in req_test.headers:
            if display:
                print("{}Instart DX WAF detected : {} ".format(WAF, res))
            return True
        #ISA
        elif "The ISA Server denied the specified Uniform Resource Locator (URL)" in req_response:
            if display:
                print("{}ISA WAF detected : {} ".format(WAF, res))
            return True
        #Janusec Application Gateway 
        elif "JANUSEC" in req_response or "Janusec Application Gateway" in req_response:
            if display:
                print("{}Janusec WAF detected : {} ".format(WAF, res))
            return True
        #Jiasule
        elif "static.jiasule.com/static/js/http_error.js" in req_response or "jsl_tracking" in req_test.headers or "__jsluid=" in req_test.headers or \
            "jiasule-WAF" in req_test.headers or "notice-jiasule" in req_response:
            if display:
                print("{}Jiasule WAF detected : {} ".format(WAF, res))
            return True
        #KeyCDN 
        elif "KeyCDN" in req_test.headers:
            if display:
                print("{}KeyCDN WAF detected : {} ".format(WAF, res))
            return True
        #KnownSec 
        elif "ks-waf-error.png" in req_response:
            if display:
                print("{}KnowSec WAF detected : {} ".format(WAF, res))
            return True
        #KONA Site Defender (Akamai)
        elif "AkamaiGHost" in req_test.headers:
            if display:
                print("{}Akamai WAF detected : {} ".format(WAF, res))
            return True
        #LiteSpeed
        elif "LiteSpeed" in req_test.headers or "Proudly powered by LiteSpeed Web Server" in req_response or "http://www.litespeedtech.com/error-page" in req_response:
            if display:
                print("{}LiteSpeed WAF detected : {} ".format(WAF, res))
            return True
        #Malcare 
        elif "Firewall powered by MalCare" in req_response:
            if display:
                print("{}Malcare WAF detected : {} ".format(WAF, res))
            return True
        #MissionControl Application Shield 
        elif "Mission Control Application Shield" in req_test.headers:
            if display:
                print("{}Mission Control Application Shield WAF detected : {} ".format(WAF, res))
            return True
        #ModSecurity
        elif "This error was generated by Mod_Security" in req_response or "rules of the mod_security module" in req_response or \
            "mod_security rules triggered" in req_response or "/modsecurity-errorpage/" in req_response or "Mod_Security" in req_test.headers or \
            req_test.status_code == 403 and "ModSecurity Action" in req_response:
            if display:
                print("{}ModSecurity WAF detected : {} ".format(WAF, res))
            return True
        #NAXSI 
        elif "This Request Has Been Blocked By NAXSI" in req_response or "naxsi/waf" in req_test.headers or "NAXSI blocked WAFrmation" in req_response:
            if display:
                print("{}NAXSI WAF detected : {} ".format(WAF, res))
            return True
        #Netcontinuum 
        elif "NCI__SessionId=" in req_test.headers:
            if display:
                print("{}Potential Netcontinuum WAF detected : {} ".format(WAF, res))
            return True
        #NetScaler AppFirewall 
        elif "NSC_" in req_test.headers or "ns_af=" in req_test.headers:
            if display:
                print("{}NetScaler WAF detected : {} ".format(WAF, res))
            return True
        #NevisProxy
        elif "Navajo" in req_test.headers:
            if display:
                print("{}NevisProxy")
            return True
        #NewDefend
        elif "http://www.newdefend.com/feedback/misWAFrmation" in req_response or "/nd_block/" in req_response:
            if display:
                print("{}NewDefend WAF detected : {} ".format(WAF, res))
            return True
        #Nexusguard
        elif "speresources.nexusguard.com/wafpage/index.html" in req_response:
            if display:
                print("{}Nexusguard WAF detected : {} ".format(WAF, res))
            return True
        #NinjaFirewall 
        elif "NinjaFirewall: 403 Forbidden" in req_response or "NinjaFirewall" in req_response or \
            req_test.status_code == 403 and "For security reasons, it was blocked and logged" in req_response:
            if display:
                print("{}NinjaFirewall WAF detected : {} ".format(WAF, res))
            return True
        #NSFocus
        elif "NSFocus" in req_test.headers:
            if display:
                print("{}NSFocus WAF detected : {} ".format(WAF, res))
            return True
        #NullDDoS 
        elif "NullDDoS System" in req_response:
            if display:
                print("{}NullDDoS WAF detected : {} ".format(WAF, res))
            return True
        #onMessage Shield 
        elif "onMessage Shield" in req_test.headers or "Blackbaud K-12 conducts routine maintenance" in req_response or "blackbaud.com" in req_response:
            if display:
                print("{}onMessage Shield WAF detected : {} ".format(WAF, res))
            return True
        #OpenResty Lua WAF 
        elif req_test.status_code == 406 and "openresty/" in req_response or "openresty/" in req_test.headers:
            if display:
                print("{}OpenResty Lua WAF detected : {} ".format(WAF, res))
            return True
        #Palo Alto 
        elif "Palo Alto Next Generation Security Platform" in req_response:
            if display:
                print("{}Palo Alto WAF detected : {} ".format(WAF, res))
            return True
        #PentaWAF 
        elif "PentaWAF/" in req_test.headers or "PentaWAF/" in req_response:
            if display:
                print("{}PentaWAF detected : {} ".format(WAF, res))
            return True
        #PerimeterX 
        elif "perimeterx" in req_response and "whywasiblocked" in req_response:
            if display:
                print("{}PerimeterX WAF detected : {} ".format(WAF, res))
            return True
        #pkSecurityModule IDS
        elif "pkSecurityModule: Security.Alert" in req_response:
            if display:
                print("{}pkSecurityModule WAF detected : {} ".format(WAF, res))
            return True
        #PowerCDN 
        elif "powercdn" in req_test.headers:
            if display:
                print("{}PowerCDN WAF detected : {} ".format(WAF, res))
            return True
        #Profense 
        elif "Profense" in req_test.headers:
            if display:
                print("{}Profense WAF detected : {} ".format(WAF, res))
            return True
        #Proventia (IBM) 
        elif "request does not match Proventia rules" in req_response:
            if display:
                print("{}Potential Proventia (IBM) WAF detected : {} ".format(WAF, res))
            return True
        #Puhui 
        elif "PuhuiWAF" in req_test.headers:
            if display:
                print("{}Puhui WAF detected : {} ".format(WAF, res))
            return True
        #Request Validation Mode 
        elif "ASP.NET has detected data in the request that is potentially dangerous" in req_response:
            if display:
                print("{}Potential ASP.NET WAF detected : {} ".format(WAF, res))
            return True
        #RSFirewall
        elif "COM_RSFIREWALL_403_FORBIDDEN" in req_response or "COM_RSFIREWALL_EVENT" in req_response:
            if display:
                print("{}RSFirewall WAF detected : {} ".format(WAF, res))
            return True
        #Sabre 
        elif req_test.status_code == 500 and "dxsupport@sabre.com" in req_response:
            if display:
                print("{}Sabre WAF detected : {} ".format(WAF, res))
            return True
        #Safe3 
        elif "Safe3WAF" in req_test.headers or "Safe3waf" in req_response:
            if display:
                print("{}Safe3waf WAF detected : {} ".format(WAF, res))
            return True
        #SafeDog 
        elif "safedog" in req_test.headers:
            if display:
                print("{}safedog WAF detected : {} ".format(WAF, res))
            return True
        #SecKing
        elif "SECKING" in req_test.headers:
            if display:
                print("{}SecKing WAF detected : {} ".format(WAF, res))
            return True
        #SecuPress
        elif "SecuPress" in req_response or req_test.status_code == 503 and "Block ID: Bad URL Contents" in req_response:
            if display:
                print("{}SecuPress WAF detected : {} ".format(WAF, res))
            return True
        #Secure Entry 
        elif "Secure Entry Server" in req_test.headers:
            if display:
                print("{}Secure Entry WAF detected : {} ".format(WAF, res))
            return True
        #SecureIIS 
        elif "beyondtrust" in req_response or "Download SecureIIS Personal Edition" in req_response or "SecureIIS Error" in req_response:
            if display:
                print("{}SecureIIS WAF detected : {} ".format(WAF, res))
            return True
        #SEnginx 
        elif "SENGINX-ROBOT-MITIGATION" in req_response:
            if display:
                print("{}SEnginx WAF detected : {} ".format(WAF, res))
            return True
        #ShieldSecurity 
        elif "You were blocked by the Shield" in req_response:
            if display:
                print("{}ShieldSecurity WAF detected : {} ".format(WAF, res))
            return True
        #SiteLock TrueShield 
        elif "Sitelock is leader in Business Website Security Services" in req_response or "sitelock-site-verification" in req_response or \
            "sitelock_shield_logo" in req_response or "www.sitelock.com" in req_response:
            if display:
                print("{}SiteLock WAF detected : {} ".format(WAF, res))
            return True
        #SonicWall
        elif "SonicWALL" in req_test.headers or "This request is blocked by the SonicWALL" in req_response:
            if display:
                print("{}SonicWALL WAF detected : {} ".format(WAF, res))
            return True
        #Sophos UTM
        elif "Powered by UTM Web Protection" in req_response:
            if display:
                print("{}Sophos UTM WAF detected : {} ".format(WAF, res))
            return True
        #SquidProxy IDS 
        elif "Access control configuration prevents your request from being allowed at this time" in req_response:
            if display:
                print("{}SquidProxy WAF detected : {} ".format(WAF, res))
            return True
        #StackPath 
        elif "ou performed an action that triggered the service and blocked your request" in req_response or "StackPath" in req_response:
            if display:
                print("{}StackPath WAF detected : {} ".format(WAF, res))
            return True
        #Sucuri CloudProxy
        elif "Access Denied - Sucuri Website Firewall" in req_response:
            if display:
                print("{}Sucuri WAF detected : {} ".format(WAF, res))
            return True
        #Synology Cloud
        elif "opyright (c) 2019 Synology Inc. All rights reserved" in req_response:
            if display:
                print("{}Synology WAF detected : {} ".format(WAF, res))
            return True
        #Tencent Cloud 
        elif "waf.tencent-cloud.com" in req_response:
            if display:
                print("{}Tencent WAF detected : {} ".format(WAF, res))
            return True
        #TransIP 
        elif "X-TransIP" in req_test.headers:
            if display:
                print("{}TransIP WAF detected : {} ".format(WAF, res))
            return True
        #UCloud UEWaf 
        elif "ucloud.cn" in req_response or "uewaf" in req_test.headers:
            if display:
                print("{}UCloud WAF detected : {} ".format(WAF, res))
            return True
        #URLScan 
        elif "Rejected-by-URLScan" in req_response:
            if display:
                print("{}URLScan WAF detected : {} ".format(WAF, res))
            return True
        #Varnish (OWASP) 
        elif "Request rejected by xVarnish-WAF" in req_response:
            if display:
                print("{}Varnish WAF detected : {} ".format(WAF, res))
            return True
        #Varnish CacheWall 
        elif "Varnish cache Server" in req_response:
            if display:
                print("{}Varnish CacheWall WAF detected : {} ".format(WAF, res))
            return True
        #Viettel 
        elif "Viettel WAF" in req_response:
            if display:
                print("{}Viettel WAF detected : {} ".format(WAF, res))
            return True
        #VirusDie 
        elif "copy; Virusdie.ru" in req_response or "Virusdie" in req_response or 'name="FW_BLOCK"' in req_response:
            if display:
                print("{}Virusdie WAF detected : {} ".format(WAF, res))
            return True
        #WatchGuard IPS 
        elif "Request denied by WatchGuard Firewall" in req_response or "WatchGuard Technologies Inc" in req_response:
            if display:
                print("{}WatchGuard WAF detected : {} ".format(WAF, res))
            return True
        #WebARX Security 
        elif "This request has been blocked by WebARX Web Application Firewall" in req_response or "/wp-content/plugins/webarx/" in req_response:
            if display:
                print("{}WebARX WAF detected : {} ".format(WAF, res))
            return True
        #WebKnight
        elif "WebKnight" in req_test.headers or "WebKnight Application Firewall Alert" in req_response or "AQTRONIX WebKnight" in req_response or \
            req_test.status_code == 999:
            if display:
                print("{}WebKnight WAF detected : {} ".format(WAF, res))
            return True
        #WebLand 
        elif "Apache Protected By WebLand WAF" in req_test.headers:
            if display:
                print("{}WebLand WAF detected : {} ".format(WAF, res))
            return True
        #WebRay 
        elif "WebRay-WAF" in req_test.headers or "RaySrv RayEng" in req_response:
            if display:
                print("{}WebRay WAF detected : {} ".format(WAF, res))
            return True
        #WebSEAL 
        elif "WebSEAL" in req_test.headers or "This is a WebSEAL error message template file" in req_response or "WebSEAL server received an invalid HTTP request" in req_response:
            if display:
                print("{}WebSEAL WAF detected : {} ".format(WAF, res))
            return True
        #WebTotem 
        elif "The current request was blocked by WebTotem" in req_response:
            if display:
                print("{}WebTotem WAF detected : {} ".format(WAF, res))
            return True
        #West263CDN 
        elif "WT263CDN" in req_test.headers:
            if display:
                print("{}West263CDN WAF detected : {} ".format(WAF, res))
            return True
        #Wordfence 
        elif "WebKnight" in req_test.headers or "Generated by Wordfence" in req_response or "This response was generated by Wordfence" in req_response:
            if display:
                print("{}Wordfence WAF detected : {} ".format(WAF, res))
            return True
        #WTS-WAF 
        elif "WTS-WAF" in req_response:
            if display:
                print("{}WTS WAF detected : {} ".format(WAF, res))
            return True
        #XLabs Security WAF 
        elif "XLabs Security" in req_response:
            if display:
                print("{}XLabs Security WAF detected : {} ".format(WAF, res))
            return True
        #Xuanwudun WAF 
        elif "http://admin.dbappwaf.cn/index.php/Admin/ClientMisWAFrm/" in req_response:
            if display:
                print("{}Xuanwudun WAF detected : {} ".format(WAF, res))
            return True
        #Yunaq Chuangyu 
        elif "365cyd.net" in req_response or "http://help.365cyd.com/cyd-error-help.html?code=403" in req_response:
            if display:
                print("{}Yunaq Chuangyu WAF detected : {} ".format(WAF, res))
            return True
        #Yundun 
        elif "YUNDUN" in req_test.headers or "YUNDUN" in req_response or "Blocked by YUNDUN Cloud WAF" in req_response:
            if display:
                print("{}Yundun WAF detected : {} ".format(WAF, res))
            return True
        #Yunsuo 
        elif "yunsuologo" in req_response or "yunsuo_session" in req_test.headers:
            if display:
                print("{}Yunsuo WAF detected : {} ".format(WAF, res))
            return True
        #YxLink 
        elif "Yxlink-WAF" in req_test.headers:
            if display:
                print("{}YxLink WAF detected : {} ".format(WAF, res))
            return True
        #ZenEdge 
        elif "/__zenedge/assets/0" in req_response or "ZENEDGE" in req_test.headers or "X-Zen-Fury" in req_response:
            if display:
                print("{}ZenEdge WAF detected : {} ".format(WAF, res))
            return True
        #ZScaler 
        elif "ZScaler" in req_test.headers or "https://login.zscloud.net/img_logo_new1.png" in req_response or \
            "Your organization has selected Zscaler to protect you from internet threats" in req_response or "The Internet site you have attempted to access is prohibited. Accenture's webfilters indicate that the site likely contains content considered inappropriate" in req_response:
            if display:
                print("{}ZScaler WAF detected : {} ".format(WAF, res))
            return True
        #X-DirectAdmin
        elif "X-DirectAdmin" in req_test.headers and "blacklisted" in req_test.headers:
            if display:
                print("{}X-DirectAdmin WAF detected : {} ".format(WAF, res))
            return True
        elif "Access Denied" in req_response or "access denied" in req_response or "Something went wrong" in req_response or \
        "we have detected malicious traffic" in req_response or "device from your location is sending large amounts of web requests" in req_response or \
        "Sorry, there have been too many requests in a short time" in req_response or \
        "Access denied due to a large number of requests" in req_response or "has detected an attack" in req_response or "Your IP has been banned" in req_response and not forced:
            if req_test.status_code == 401 or req_test.status_code == 403 or req_test.status_code == 430 and not forced:
                if display:
                    print("{}{} Unknown WAF detected : {} ".format(WAF, req_test.status_code, res))
                return True
        else:
            return False

"""if __name__ == '__main__':
    verify_waf(req, res, user_agent)"""