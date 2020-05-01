# -*- coding: utf-8 -*-
import time
import sys
import requests
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK

def req_test_false_positif(res, user_agent):
    url_base = res.split("/")[:3]
    url_send = '/'.join(url_base)+"/"
    req_test_waf = requests.get(url_send, headers=user_agent, allow_redirects=True, verify=False)
    #print(req_test_waf.status_code)
    return req_test_waf

def verify_waf(req, res, user_agent):
    """
    Function verify if there is a WAF to instable website
    """
    #360
    req_test = req_test_false_positif(res, user_agent)
    if req_test.status_code == 493 or "wzws-waf-cgi" in req_test.text or "X-Powered-By-360wzb" in req_test.headers:
        print("{}360 Web Application Firewall waf detected : {} ".format(INFO, res))
        return True
    #aeSecure
    elif "aesecure_denied.png" in req_test.text or "aeSecure-code" in req_test.headers:
        print("{}aeSecure WAF detected : {} ".format(INFO, res))
        return True
    elif "Server detected a syntax error in your request" in req_test.text or "AL-SESS" in req_test.headers or "AL-LB" in req_test.headers:
        print("{}Airlock (Phion/Ergon) WAF detected : {} ".format(INFO, res))
        return True
    #Aliyundun 
    elif req_test.status_code == 405 and \
        "Sorry, your request has been blocked as it may cause potential threats to the server's security" in req_test.text:
        print("{}Aliyundun WAF detected : {} ".format(INFO, res))
        return True
    #Anquando
    elif req_test.status_code == 405 and "/aqb_cc/error/|hidden_intercept_time" in req_test.text or "X-Powered-By-Anquanbao" in req_test.headers:
        print("{}Anquanbao Web Application Firewall WAF detected : {} ".format(INFO, res))
        return True
    #Anyu
    elif "Sorry! your access has been intercepted by AnYu" in req_test.text or "AnYu- the green channel" in req_test.text or \
        "WZWS-RAY" in req_test.headers:
        print("{}AnYu WAF detected : {} ".format(INFO, res))
        return True
    #Approach
    elif "Approach Web Application Firewall Framework" in req_test.text or \
        "Your IP address has been logged and this information could be used by authorities to track you." in req_test.text:
        print("{}Approach WAF detected : {} ".format(INFO, res))
        return True
    #Armor
    elif "This request has been blocked by website protection from Armor" in req_test.text:
        print("{}Armor Protection (Armor Defense) WAF detected : {} ".format(INFO, res))
        return True
    #ArvanCloud 
    elif "ArvanCloud" in req_test.headers:
        print("{}ArvanCloud WAF detected : {} ".format(INFO, res))
        return True
    #ASPA 
    elif "ASPA-WAF" in req_test.headers or "ASPA-Cache-Status_code" in req_test.headers:
        print("{}ASPA WAF detected : {} ".format(INFO, res))
        return True
    #ASP.NET
    elif "X-ASPNET-Version" in req_test.headers and \
        "This generic 403 error means that the authenticated user is not authorized to use the requested resource" in req_test.text or \
        "Error Code 0x00000000<" in req_test.text: 
        print("{}ASP.NET WAF detected : {} ".format(INFO, res))
        return True
    #ASTRA
    elif "our website protection system has detected an issue ss and wont let you proceed any further" in req_test.text or \
        "www.getastra.com/assets/images/" in req_test.text or "cz_astra_csrf_cookie" in req_test.headers:
        print("{}ASTRA WAF detected : {} ".format(INFO, res))
        return True
    #AWS ELB 
    elif "Access Denied" in req_test.text and "AWSALB" in req_test.headers or "X-AMZ-ID" in req_test.headers or "X-AMZ-REQUEST-ID" in req_test.headers:
        print ("{}AWS ELB WAF detected : {} ".format(INFO, res))
        return True
    #Barikode 
    elif "BARIKODE" in req_test.text:
        print("{}BARIKODE WAF detected : {} ".format(INFO, res))
        return True
    #Barracuda
    elif "You have been blocked" in req_test.text or "You are unable to access this website" in req_test.text and \
        "barra_counter_session" in req_test.headers or "barracuda_" in req_test.headers:
        print("{}Barracuda WAF detected : {} ".format(INFO, res))
        return True
    #Bekchy
    elif "Bekchy - Access Denied" in req_test.text or "https://bekchy.com/report" in req_test.text:
        print("{}Bekchy WAF detected : {} ".format(INFO, res))
        return True
    #BitNinja 
    elif "Security check by BitNinja" in req_test.text or "your IP will be removed from BitNinja" in req_test.text or \
        "Visitor anti-robot validation" in req_test.text:
        print("{}BitNinja WAF detected : {} ".format(INFO, res))
        return True
    #BIG-IP
    elif "BigIP" in req_test.headers or "F5" in req_test.headers:
        print("{}BIG-IP WAF detected : {} ".format(INFO, res))
        return True
    #Bluedon
    elif "Bluedon Web Application Firewall" in req_test.text:
        print("{}Bluedon WAF detected : {} ".format(INFO, res))
        return True
    #BulletProof Security Pro 
    elif "bpsMessage" in req_test.text or \
        "If you arrived here due to a search or clicking on a link click your Browser's back button to return to the previous page." in req_test.text:
        print("{}BulletProof WAF detected : {} ".format(INFO, res))
        return True
    #CDN NS Application Gateway 
    elif "CdnNsWAF Application Gateway" in req_test.text:
        print("{}CDN NS Application Gateway WAF detected : {} ".format(INFO, res))
        return True
    #ChinaCache 
    elif "Powered-By-ChinaCache" in req_test.headers:
        print("{}ChinaCache WAF detected : {} ".format(INFO, res))
        return True
    #Cisco ACE XML Gateway
    elif "ACE XML Gateway" in req_test.headers:
        print("{}Cisco ACE WAF detected : {} ".format(INFO, res))
        return True
    #Cloudbric Web Application Firewall
    elif "Malicious Code Detected" in req_test.text or "Your request was blocked by Cloudbric" in req_test.text or \
        "Cloudbric | ERROR!" in req_test.text:
        print("{}Cloudbric WAF detected : {} ".format(INFO, res))
        return True
    #Cloudflare
    elif "Cloudflare Ray ID:" in req_test.text:
        print("{}Cloudflare WAF detected : {} ".format(INFO, res))
        return True
    #CloudfloorDNS 
    elif "CloudfloorDNS - Web Application Firewall Error" in req_test.text:
        print("{}CloudfloorDNS WAF detected : {} ".format(INFO, res))
        return True
    #Cloudfront 
    elif "Generated by cloudfront (CloudFront)" in req_test.text:
        print("{}Cloudfront WAF detected : {} ".format(INFO, res))
        return True
    #Comodo cWatch 
    elif "Protected by COMODO WAF" in req_test.headers:
        print("{}COMODO WAF detected : {} ".format(INFO, res))
        return True
    #CrawlProtect 
    elif "crawlprotect" in req_test.headers or "CrawlProtect" in req_test.text:
        print("{}CrawlProtect WAF detected : {} ".format(INFO, res))
        return True
    #Distil Web Protection 
    elif "X-Distil-CS" in req_test.headers and "Pardon Our Interruption" in req_test.text or \
        "You have disabled javascript in your browser" in req_test.text or "Something about your browser made us think that you are a bot" in req_test.text:
        print("{}Distil Web Protection WAF detected : {} ".format(INFO, res))
        return True
    #DoSArrest Internet Security 
    elif "X-DIS-Request-ID" in req_test.headers or "DOSarrest" in req_test.text:
        print("{}DoSArrest WAF detected : {} ".format(INFO, res))
        return True
    #DotDefender
    elif "dotDefender Blocked Your Request" in req_test.text or "X-dotDefender-denied" in req_test.headers:
        print("{}DotDefender WAF detected : {} ".format(INFO, res))
        return True
    #DynamicWeb Injection Check 
    elif "dw-inj-check" in req_test.headers:
        print("{}DynamicWeb WAF detected : {} ".format(INFO, res))
        return True
    #e3Learning Security 
    elif "e3Learning_WAF" in req_test.headers:
        print("{}e3Learning WAF detected : {} ".format(INFO, res))
        return True
    #EdgeCast 
    elif req_test.status_code == 400 and "ID:EdgeCast Web Application Firewall" in req_test.text:
        print("{}EdgeCast WAF detected : {} ".format(INFO, res))
        return True
    #Eisoo Cloud 
    elif "(year) Eisoo Inc." in req_test.text:
        print("{}Eisoo WAF detected : {} ".format(INFO, res))
        return True
    #FortiWeb 
    elif "FORTIWAFSID=" in req_test.headers and ".fgd_icon" in req_test.text or "Server Unavailable" in req_test.text:
        print("{}FortiWeb WAF detected : {} ".format(INFO, res))
        return True
    #GoDaddy
    elif "Access Denied - GoDaddy Website Firewall" in req_test.text:
        print("{}GoDaddy WAF detected : {} ".format(INFO, res))
        return True
    #GreyWizard 
    elif "Contact the website owner or Grey Wizard" in req_test.text or "We've detected attempted attack or non standard traffic from your IP address" in req_test.text:
        print("{}GreyWizard WAF detected : {} ".format(INFO, res))
        return True
    #Huawei Cloud
    elif "account.hwclouds.com/static/error/images/404img.jpg" in req_test.text:
        print("{}Huawei WAF detected : {} ".format(INFO, res))
        return True
    #Imperva Incapsula
    elif "Powered By Incapsula" in req_test.text or "Incapsula incident ID" in req_test.text or "_Incapsula_Resource" in req_test.text or \
        "subject=WAF Block Page" in req_test.text:
        print("{}Imperva Incapsula WAF detected : {} ".format(INFO, res))
        return True
    #Immunify360 
    elif "imunify360-webshield" in req_test.headers or "Powered by Imunify36" in req_test.text or "imunify360 preloader" in req_test.text or \
        "protected by Imunify360" in req_test.text:
        print("{}Immunify360 WAF detected : {} ".format(INFO, res))
        return True
    #IndusGuard
    elif "further investigation and remediation of this page" in req_test.text:
        print("{}Potential IndusGuard WAF detected : {} ".format(INFO, res))
        return True
    #Instart DX
    elif "X-Instart-Request-ID" in req_test.headers or "X-Instart-WL" in req_test.headers or "X-Instart-Cache" in req_test.headers:
        print("{}Instart DX WAF detected : {} ".format(INFO, res))
        return True
    #ISA
    elif "The ISA Server denied the specified Uniform Resource Locator (URL)" in req_test.text:
        print("{}ISA WAF detected : {} ".format(INFO, res))
        return True
    #Janusec Application Gateway 
    elif "JANUSEC" in req_test.text or "Janusec Application Gateway" in req_test.text:
        print("{}Janusec WAF detected : {} ".format(INFO, res))
        return True
    #Jiasule
    elif "static.jiasule.com/static/js/http_error.js" in req_test.text or "jsl_tracking" in req_test.headers or "__jsluid=" in req_test.headers or \
        "jiasule-WAF" in req_test.headers or "notice-jiasule" in req_test.text:
        print("{}Jiasule WAF detected : {} ".format(INFO, res))
        return True
    #KeyCDN 
    elif "KeyCDN" in req_test.headers:
        print("{}KeyCDN WAF detected : {} ".format(INFO, res))
        return True
    #KnownSec 
    elif "ks-waf-error.png" in req_test.text:
        print("{}KnowSec WAF detected : {} ".format(INFO, res))
        return True
    #KONA Site Defender (Akamai)
    elif "AkamaiGHost" in req_test.headers:
        print("{}Akamai WAF detected : {} ".format(INFO, res))
        return True
    #LiteSpeed
    elif "LiteSpeed" in req_test.headers or "Proudly powered by LiteSpeed Web Server" in req_test.text or "http://www.litespeedtech.com/error-page" in req_test.text:
        print("{}LiteSpeed WAF detected : {} ".format(INFO, res))
        return True
    #Malcare 
    elif "Firewall powered by MalCare" in req_test.text:
        print("{}Malcare WAF detected : {} ".format(INFO, res))
        return True
    #MissionControl Application Shield 
    elif "Mission Control Application Shield" in req_test.headers:
        print("{}Mission Control Application Shield WAF detected : {} ".format(INFO, res))
        return True
    #ModSecurity
    elif "This error was generated by Mod_Security" in req_test.text or "rules of the mod_security module" in req_test.text or \
        "mod_security rules triggered" in req_test.text or "/modsecurity-errorpage/" in req_test.text or "Mod_Security" in req_test.headers or \
        req_test.status_code == 403 and "ModSecurity Action" in req_test.text:
        print("{}ModSecurity WAF detected : {} ".format(INFO, res))
        return True
    #NAXSI 
    elif "This Request Has Been Blocked By NAXSI" in req_test.text or "naxsi/waf" in req_test.headers or "NAXSI blocked information" in req_test.text:
        print("{}NAXSI WAF detected : {} ".format(INFO, res))
        return True
    #Netcontinuum 
    elif "NCI__SessionId=" in req_test.headers:
        print("{}Potential Netcontinuum WAF detected : {} ".format(INFO, res))
        return True
    #NetScaler AppFirewall 
    elif "NSC_" in req_test.headers or "ns_af=" in req_test.headers:
        print("{}NetScaler WAF detected : {} ".format(INFO, res))
        return True
    #NevisProxy
    elif "Navajo" in req_test.headers:
        print("{}NevisProxy")
        return True
    #NewDefend
    elif "http://www.newdefend.com/feedback/misinformation" in req_test.text or "/nd_block/" in req_test.text:
        print("{}NewDefend WAF detected : {} ".format(INFO, res))
        return True
    #Nexusguard
    elif "speresources.nexusguard.com/wafpage/index.html" in req_test.text:
        print("{}Nexusguard WAF detected : {} ".format(INFO, res))
        return True
    #NinjaFirewall 
    elif "NinjaFirewall: 403 Forbidden" in req_test.text or "NinjaFirewall" in req_test.text or \
        req_test.status_code == 403 and "For security reasons, it was blocked and logged" in req_test.text:
        print("{}NinjaFirewall WAF detected : {} ".format(INFO, res))
        return True
    #NSFocus
    elif "NSFocus" in req_test.headers:
        print("{}NSFocus WAF detected : {} ".format(INFO, res))
        return True
    #NullDDoS 
    elif "NullDDoS System" in req_test.text:
        print("{}NullDDoS WAF detected : {} ".format(INFO, res))
        return True
    #onMessage Shield 
    elif "onMessage Shield" in req_test.headers or "Blackbaud K-12 conducts routine maintenance" in req_test.text or "blackbaud.com" in req_test.text:
        print("{}onMessage Shield WAF detected : {} ".format(INFO, res))
        return True
    #OpenResty Lua WAF 
    elif req_test.status_code == 406 and "openresty/" in req_test.text or "openresty/" in req_test.headers:
        print("{}OpenResty Lua WAF detected : {} ".format(INFO, res))
        return True
    #Palo Alto 
    elif "Palo Alto Next Generation Security Platform" in req_test.text:
        print("{}Palo Alto WAF detected : {} ".format(INFO, res))
        return True
    #PentaWAF 
    elif "PentaWAF/" in req_test.headers or "PentaWAF/" in req_test.text:
        print("{}PentaWAF detected : {} ".format(INFO, res))
        return True
    #PerimeterX 
    elif "https://www.perimeterx.com/whywasiblocked" in req_test.text:
        print("{}PerimeterX WAF detected : {} ".format(INFO, res))
        return True
    #pkSecurityModule IDS
    elif "pkSecurityModule: Security.Alert" in req_test.text:
        print("{}pkSecurityModule WAF detected : {} ".format(INFO, res))
        return True
    #PowerCDN 
    elif "powercdn" in req_test.headers:
        print("{}PowerCDN WAF detected : {} ".format(INFO, res))
        return True
    #Profense 
    elif "Profense" in req_test.headers:
        print("{}Profense WAF detected : {} ".format(INFO, res))
        return True
    #Proventia (IBM) 
    elif "request does not match Proventia rules" in req_test.text:
        print("{}Potential Proventia (IBM) WAF detected : {} ".format(INFO, res))
        return True
    #Puhui 
    elif "PuhuiWAF" in req_test.headers:
        print("{}Puhui WAF detected : {} ".format(INFO, res))
        return True
    #Request Validation Mode 
    elif "ASP.NET has detected data in the request that is potentially dangerous" in req_test.text:
        print("{}Potential ASP.NET WAF detected : {} ".format(INFO, res))
        return True
    #RSFirewall
    elif "COM_RSFIREWALL_403_FORBIDDEN" in req_test.text or "COM_RSFIREWALL_EVENT" in req_test.text:
        print("{}RSFirewall WAF detected : {} ".format(INFO, res))
        return True
    #Sabre 
    elif req_test.status_code == 500 and "dxsupport@sabre.com" in req_test.text:
        print("{}Sabre WAF detected : {} ".format(INFO, res))
        return True
    #Safe3 
    elif "Safe3WAF" in req_test.headers or "Safe3waf" in req_test.text:
        print("{}Safe3waf WAF detected : {} ".format(INFO, res))
        return True
    #SafeDog 
    elif "safedog" in req_test.headers:
        print("{}safedog WAF detected : {} ".format(INFO, res))
        return True
    #SecKing
    elif "SECKING" in req_test.headers:
        print("{}SecKing WAF detected : {} ".format(INFO, res))
        return True
    #SecuPress
    elif "SecuPress" in req_test.text or req_test.status_code == 503 and "Block ID: Bad URL Contents" in req_test.text:
        print("{}SecuPress WAF detected : {} ".format(INFO, res))
        return True
    #Secure Entry 
    elif "Secure Entry Server" in req_test.headers:
        print("{}Secure Entry WAF detected : {} ".format(INFO, res))
        return True
    #SecureIIS 
    elif "beyondtrust" in req_test.text or "Download SecureIIS Personal Edition" in req_test.text or "SecureIIS Error" in req_test.text:
        print("{}SecureIIS WAF detected : {} ".format(INFO, res))
        return True
    #SEnginx 
    elif "SENGINX-ROBOT-MITIGATION" in req_test.text:
        print("{}SEnginx WAF detected : {} ".format(INFO, res))
        return True
    #ShieldSecurity 
    elif "You were blocked by the Shield" in req_test.text:
        print("{}ShieldSecurity WAF detected : {} ".format(INFO, res))
        return True
    #SiteLock TrueShield 
    elif "Sitelock is leader in Business Website Security Services" in req_test.text or "sitelock-site-verification" in req_test.text or \
        "sitelock_shield_logo" in req_test.text or "www.sitelock.com" in req_test.text:
        print("{}SiteLock WAF detected : {} ".format(INFO, res))
        return True
    #SonicWall
    elif "SonicWALL" in req_test.headers or "This request is blocked by the SonicWALL" in req_test.text:
        print("{}SonicWALL WAF detected : {} ".format(INFO, res))
        return True
    #Sophos UTM
    elif "Powered by UTM Web Protection" in req_test.text:
        print("{}Sophos UTM WAF detected : {} ".format(INFO, res))
        return True
    #SquidProxy IDS 
    elif "Access control configuration prevents your request from being allowed at this time" in req_test.text:
        print("{}SquidProxy WAF detected : {} ".format(INFO, res))
        return True
    #StackPath 
    elif "ou performed an action that triggered the service and blocked your request" in req_test.text or "StackPath" in req_test.text:
        print("{}StackPath WAF detected : {} ".format(INFO, res))
        return True
    #Sucuri CloudProxy
    elif "Access Denied - Sucuri Website Firewall" in req_test.text:
        print("{}Sucuri WAF detected : {} ".format(INFO, res))
        return True
    #Synology Cloud
    elif "opyright (c) 2019 Synology Inc. All rights reserved" in req_test.text:
        print("{}Synology WAF detected : {} ".format(INFO, res))
        return True
    #Tencent Cloud 
    elif "waf.tencent-cloud.com" in req_test.text:
        print("{}Tencent WAF detected : {} ".format(INFO, res))
        return True
    #TransIP 
    elif "X-TransIP" in req_test.headers:
        print("{}TransIP WAF detected : {} ".format(INFO, res))
        return True
    #UCloud UEWaf 
    elif "ucloud.cn" in req_test.text or "uewaf" in req_test.headers:
        print("{}UCloud WAF detected : {} ".format(INFO, res))
        return True
    #URLScan 
    elif "Rejected-by-URLScan" in req_test.text:
        print("{}URLScan WAF detected : {} ".format(INFO, res))
        return True
    #Varnish (OWASP) 
    elif "Request rejected by xVarnish-WAF" in req_test.text:
        print("{}Varnish WAF detected : {} ".format(INFO, res))
        return True
    #Varnish CacheWall 
    elif "Varnish cache Server" in req_test.text:
        print("{}Varnish CacheWall WAF detected : {} ".format(INFO, res))
        return True
    #Viettel 
    elif "Viettel WAF" in req_test.text:
        print("{}Viettel WAF detected : {} ".format(INFO, res))
        return True
    #VirusDie 
    elif "copy; Virusdie.ru" in req_test.text or "Virusdie" in req_test.text or 'name="FW_BLOCK"' in req_test.text:
        print("{}Virusdie WAF detected : {} ".format(INFO, res))
        return True
    #WatchGuard IPS 
    elif "Request denied by WatchGuard Firewall" in req_test.text or "WatchGuard Technologies Inc" in req_test.text:
        print("{}WatchGuard WAF detected : {} ".format(INFO, res))
        return True
    #WebARX Security 
    elif "This request has been blocked by WebARX Web Application Firewall" in req_test.text or "/wp-content/plugins/webarx/" in req_test.text:
        print("{}WebARX WAF detected : {} ".format(INFO, res))
        return True
    #WebKnight
    elif "WebKnight" in req_test.headers or "WebKnight Application Firewall Alert" in req_test.text or "AQTRONIX WebKnight" in req_test.text or \
        req_test.status_code == 999:
        print("{}WebKnight WAF detected : {} ".format(INFO, res))
        return True
    #WebLand 
    elif "Apache Protected By WebLand WAF" in req_test.headers:
        print("{}WebLand WAF detected : {} ".format(INFO, res))
        return True
    #WebRay 
    elif "WebRay-WAF" in req_test.headers or "RaySrv RayEng" in req_test.text:
        print("{}WebRay WAF detected : {} ".format(INFO, res))
        return True
    #WebSEAL 
    elif "WebSEAL" in req_test.headers or "This is a WebSEAL error message template file" in req_test.text or "WebSEAL server received an invalid HTTP request" in req_test.text:
        print("{}WebSEAL WAF detected : {} ".format(INFO, res))
        return True
    #WebTotem 
    elif "The current request was blocked by WebTotem" in req_test.text:
        print("{}WebTotem WAF detected : {} ".format(INFO, res))
        return True
    #West263CDN 
    elif "WT263CDN" in req_test.headers:
        print("{}West263CDN WAF detected : {} ".format(INFO, res))
        return True
    #Wordfence 
    elif "WebKnight" in req_test.headers or "Generated by Wordfence" in req_test.text or "This response was generated by Wordfence" in req_test.text:
        print("{}Wordfence WAF detected : {} ".format(INFO, res))
        return True
    #WTS-WAF 
    elif "WTS-WAF" in req_test.text:
        print("{}WTS WAF detected : {} ".format(INFO, res))
        return True
    #XLabs Security WAF 
    elif "XLabs Security" in req_test.text:
        print("{}XLabs Security WAF detected : {} ".format(INFO, res))
        return True
    #Xuanwudun WAF 
    elif "http://admin.dbappwaf.cn/index.php/Admin/ClientMisinform/" in req_test.text:
        print("{}Xuanwudun WAF detected : {} ".format(INFO, res))
        return True
    #Yunaq Chuangyu 
    elif "365cyd.net" in req_test.text or "http://help.365cyd.com/cyd-error-help.html?code=403" in req_test.text:
        print("{}Yunaq Chuangyu WAF detected : {} ".format(INFO, res))
        return True
    #Yundun 
    elif "YUNDUN" in req_test.headers or "YUNDUN" in req_test.text or "Blocked by YUNDUN Cloud WAF" in req_test.text:
        print("{}Yundun WAF detected : {} ".format(INFO, res))
        return True
    #Yunsuo 
    elif "yunsuologo" in req_test.text or "yunsuo_session" in req_test.headers:
        print("{}Yunsuo WAF detected : {} ".format(INFO, res))
        return True
    #YxLink 
    elif "Yxlink-WAF" in req_test.headers:
        print("{}YxLink WAF detected : {} ".format(INFO, res))
        return True
    #ZenEdge 
    elif "/__zenedge/assets/0" in req_test.text or "ZENEDGE" in req_test.headers or "X-Zen-Fury" in req_test.text:
        print("{}ZenEdge WAF detected : {} ".format(INFO, res))
        return True
    #ZScaler 
    elif "ZScaler" in req_test.headers or "https://login.zscloud.net/img_logo_new1.png" in req_test.text or \
        "Your organization has selected Zscaler to protect you from internet threats" in req_test.text or "The Internet site you have attempted to access is prohibited. Accenture's webfilters indicate that the site likely contains content considered inappropriate" in req_test.text:
        print("{}ZScaler WAF detected : {} ".format(INFO, res))
        return True
    elif "Access Denied" in req_test.text or "access denied" in req_test.text or "Something went wrong" in req_test.text or \
    "we have detected malicious traffic" in req_test.text and not forced:
        if req_test.status_code == 401 or req_test.status_code == 403:
            print("{}{} Unknown WAF detected : {} ".format(INFO, req_test.status_code, res))
            return True
    else:
        return False

if __name__ == '__main__':
    verify_waf(req, res, user_agent)