# -*- coding: utf-8 -*-
import time
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK

def verify_waf(req, res, user_agent, tests):
    """
    Function verify if there is a WAF to instable website
    """
    #360
    if req.status_code == 493 or "wzws-waf-cgi" in req.text or "X-Powered-By-360wzb" in req.headers:
        print("{}360 Web Application Firewall waf detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        return True
    #aeSecure
    elif "aesecure_denied.png" in req.text or "aeSecure-code" in req.headers:
        print("{}aeSecure WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        return True
    elif "Server detected a syntax error in your request" in req.text or "AL-SESS" in req.headers or "AL-LB" in req.headers:
        print("{}Airlock (Phion/Ergon) WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        return True
    #Aliyundun 
    elif req.status_code == 405 and \
        "Sorry, your request has been blocked as it may cause potential threats to the server's security" in req.text:
        print("{}Aliyundun WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        return True
    #Anquando
    elif req.status_code == 405 and "/aqb_cc/error/|hidden_intercept_time" in req.text or "X-Powered-By-Anquanbao" in req.headers:
        print("{}Anquanbao Web Application Firewall WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        return True
    #Anyu
    elif "Sorry! your access has been intercepted by AnYu" in req.text or "AnYu- the green channel" in req.text or \
        "WZWS-RAY" in req.headers:
        print("{}AnYu WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        return True
    #Approach
    elif "Approach Web Application Firewall Framework" in req.text or \
        "Your IP address has been logged and this information could be used by authorities to track you." in req.text:
        print("{}Approach WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        return True
    #Armor
    elif "This request has been blocked by website protection from Armor" in req.text:
        print("{}Armor Protection (Armor Defense) WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        return True
    #ArvanCloud 
    elif "ArvanCloud" in req.headers:
        print("{}ArvanCloud WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        return True
    #ASPA 
    elif "ASPA-WAF" in req.headers or "ASPA-Cache-Status_code" in req.headers:
        print("{}ASPA WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        return True
    #ASP.NET
    elif "X-ASPNET-Version" in req.headers and \
        "This generic 403 error means that the authenticated user is not authorized to use the requested resource" in req.text or \
        "Error Code 0x00000000<" in req.text: 
        print("{}ASP.NET WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        return True
    #ASTRA
    elif "our website protection system has detected an issue with your IP address and wont let you proceed any further" in req.text or \
        "www.getastra.com/assets/images/" in req.text or "cz_astra_csrf_cookie" in req.headers:
        print("{}ASTRA WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        return True
    #AWS ELB 
    elif "Access Denied" in req.text and "AWSALB" in req.headers or "X-AMZ-ID" in req.headers or "X-AMZ-REQUEST-ID" in req.headers:
        print ("AWS ELB WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        return True
    #Barikode 
    elif "BARIKODE" in req.text:
        print("{}BARIKODE WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        return True
    #Barracuda
    elif "You have been blocked" in req.text or "You are unable to access this website" in req.text and \
        "barra_counter_session" in req.headers or "barracuda_" in req.headers:
        print("{}Barracuda WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Bekchy
    elif "Bekchy - Access Denied" in req.text or "https://bekchy.com/report" in req.text:
        print("{}Bekchy WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #BitNinja 
    elif "Security check by BitNinja" in req.text or "your IP will be removed from BitNinja" in req.text or \
        "Visitor anti-robot validation" in req.text:
        print("{}BitNinja WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #BIG-IP
    elif "BigIP" in req.headers or "F5" in req.headers:
        print("{}BIG-IP WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Bluedon
    elif "Bluedon Web Application Firewall" in req.text:
        print("{}Bluedon WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #BulletProof Security Pro 
    elif "bpsMessage" in req.text or \
        "If you arrived here due to a search or clicking on a link click your Browser's back button to return to the previous page." in req.text:
        print("{}BulletProof WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #CDN NS Application Gateway 
    elif "CdnNsWAF Application Gateway" in req.text:
        print("{}CDN NS Application Gateway WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #ChinaCache 
    elif "Powered-By-ChinaCache" in req.headers:
        print("{}ChinaCache WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Cisco ACE XML Gateway
    elif "ACE XML Gateway" in req.headers:
        print("{}Cisco ACE WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Cloudbric Web Application Firewall
    elif "Malicious Code Detected" in req.text or "Your request was blocked by Cloudbric" in req.text or \
        "Cloudbric | ERROR!" in req.text:
        print("{}Cloudbric WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Cloudflare
    elif "Cloudflare Ray ID:" in req.text or "Attention Required!" in req.text and "cf-ray" in req.headers:
        print("{}Cloudflare WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #CloudfloorDNS 
    elif "CloudfloorDNS - Web Application Firewall Error" in req.text:
        print("{}CloudfloorDNS WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Cloudfront 
    elif "Generated by cloudfront (CloudFront)" in req.text:
        print("{}Cloudfront WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Comodo cWatch 
    elif "Protected by COMODO WAF" in req.headers:
        print("{}COMODO WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #CrawlProtect 
    elif "crawlprotect" in req.headers or "CrawlProtect" in req.text:
        print("{}CrawlProtect WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Distil Web Protection 
    elif "X-Distil-CS" in req.headers and "Pardon Our Interruption" in req.text or \
        "You have disabled javascript in your browser" in req.text or "Something about your browser made us think that you are a bot" in req.text:
        print("{}Distil Web Protection WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #DoSArrest Internet Security 
    elif "X-DIS-Request-ID" in req.headers or "DOSarrest" in req.text:
        print("{}DoSArrest WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #DotDefender
    elif "dotDefender Blocked Your Request" in req.text or "X-dotDefender-denied" in req.headers:
        print("{}DotDefender WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #DynamicWeb Injection Check 
    elif "dw-inj-check" in req.headers:
        print("{}DynamicWeb WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #e3Learning Security 
    elif "e3Learning_WAF" in req.headers:
        print("{}e3Learning WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #EdgeCast 
    elif req.status_code == 400 and "ID:EdgeCast Web Application Firewall" in req.text:
        print("{}EdgeCast WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Eisoo Cloud 
    elif "(year) Eisoo Inc." in req.text:
        print("{}Eisoo WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #FortiWeb 
    elif "FORTIWAFSID=" in req.headers and ".fgd_icon" in req.text or "Server Unavailable" in req.text:
        print("{}FortiWeb WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #GoDaddy
    elif "Access Denied - GoDaddy Website Firewall" in req.text:
        print("{}GoDaddy WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #GreyWizard 
    elif "Contact the website owner or Grey Wizard" in req.text or "We've detected attempted attack or non standard traffic from your IP address" in req.text:
        print("{}GreyWizard WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Huawei Cloud
    elif "account.hwclouds.com/static/error/images/404img.jpg" in req.text:
        print("{}Huawei WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Imperva Incapsula
    elif "Powered By Incapsula" in req.text or "Incapsula incident ID" in req.text or "_Incapsula_Resource" in req.text or \
        "subject=WAF Block Page" in req.text:
        print("{}Imperva Incapsula WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Immunify360 
    elif "imunify360-webshield" in req.headers or "Powered by Imunify36" in req.text or "imunify360 preloader" in req.text or \
        "protected by Imunify360" in req.text:
        print("{}Immunify360 WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #IndusGuard
    elif "further investigation and remediation with a screenshot of this page" in req.text:
        print("{}Potential IndusGuard WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Instart DX
    elif "X-Instart-Request-ID" in req.headers or "X-Instart-WL" in req.headers or "X-Instart-Cache" in req.headers:
        print("{}Instart DX WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #ISA
    elif "The ISA Server denied the specified Uniform Resource Locator (URL)" in req.text:
        print("{}ISA WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Janusec Application Gateway 
    elif "JANUSEC" in req.text or "Janusec Application Gateway" in req.text:
        print("{}Janusec WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Jiasule
    elif "static.jiasule.com/static/js/http_error.js" in req.text or "jsl_tracking" in req.headers or "__jsluid=" in req.headers or \
        "jiasule-WAF" in req.headers or "notice-jiasule" in req.text:
        print("{}Jiasule WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #KeyCDN 
    elif "KeyCDN" in req.headers:
        print("{}KeyCDN WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #KnownSec 
    elif "ks-waf-error.png" in req.text:
        print("{}KnowSec WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #KONA Site Defender (Akamai)
    elif "AkamaiGHost" in req.headers:
        print("{}Akamai WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #LiteSpeed
    elif "LiteSpeed" in req.headers or "Proudly powered by LiteSpeed Web Server" in req.text or "http://www.litespeedtech.com/error-page" in req.text:
        print("{}LiteSpeed WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Malcare 
    elif "Firewall powered by MalCare" in req.text:
        print("{}Malcare WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #MissionControl Application Shield 
    elif "Mission Control Application Shield" in req.headers:
        print("{}Mission Control Application Shield WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #ModSecurity
    elif "This error was generated by Mod_Security" in req.text or "rules of the mod_security module" in req.text or \
        "mod_security rules triggered" in req.text or "/modsecurity-errorpage/" in req.text or "Mod_Security" in req.headers or \
        req.status_code == 403 and "ModSecurity Action" in req.text:
        print("{}ModSecurity WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #NAXSI 
    elif "This Request Has Been Blocked By NAXSI" in req.text or "naxsi/waf" in req.headers or "NAXSI blocked information" in req.text:
        print("{}NAXSI WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Netcontinuum 
    elif "NCI__SessionId=" in req.headers:
        print("{}Potential Netcontinuum WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #NetScaler AppFirewall 
    elif "NSC_" in req.headers or "ns_af=" in req.headers:
        print("{}NetScaler WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #NevisProxy
    elif "Navajo" in req.headers:
        print("{}NevisProxy")
        time.sleep(180)
        return True
    #NewDefend
    elif "http://www.newdefend.com/feedback/misinformation" in req.text or "/nd_block/" in req.text:
        print("{}NewDefend WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Nexusguard
    elif "speresources.nexusguard.com/wafpage/index.html" in req.text:
        print("{}Nexusguard WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #NinjaFirewall 
    elif "NinjaFirewall: 403 Forbidden" in req.text or "NinjaFirewall" in req.text or \
        req.status_code == 403 and "For security reasons, it was blocked and logged" in req.text:
        print("{}NinjaFirewall WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #NSFocus
    elif "NSFocus" in req.headers:
        print("{}NSFocus WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #NullDDoS 
    elif "NullDDoS System" in req.text:
        print("{}NullDDoS WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #onMessage Shield 
    elif "onMessage Shield" in req.headers or "Blackbaud K-12 conducts routine maintenance" in req.text or "blackbaud.com" in req.text:
        print("{}onMessage Shield WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #OpenResty Lua WAF 
    elif req.status_code == 406 and "openresty/" in req.text or "openresty/" in req.headers:
        print("{}OpenResty Lua WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Palo Alto 
    elif "Palo Alto Next Generation Security Platform" in req.text:
        print("{}Palo Alto WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #PentaWAF 
    elif "PentaWAF/" in req.headers or "PentaWAF/" in req.text:
        print("{}PentaWAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #PerimeterX 
    elif "https://www.perimeterx.com/whywasiblocked" in req.text:
        print("{}PerimeterX WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #pkSecurityModule IDS
    elif "pkSecurityModule: Security.Alert" in req.text:
        print("{}pkSecurityModule WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #PowerCDN 
    elif "powercdn" in req.headers:
        print("{}PowerCDN WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Profense 
    elif "Profense" in req.headers:
        print("{}Profense WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Proventia (IBM) 
    elif "request does not match Proventia rules" in req.text:
        print("{}Potential Proventia (IBM) WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Puhui 
    elif "PuhuiWAF" in req.headers:
        print("{}Puhui WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Request Validation Mode 
    elif "ASP.NET has detected data in the request that is potentially dangerous" in req.text:
        print("{}Potential ASP.NET WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #RSFirewall
    elif "COM_RSFIREWALL_403_FORBIDDEN" in req.text or "COM_RSFIREWALL_EVENT" in req.text:
        print("{}RSFirewall WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Sabre 
    elif req.status_code == 500 and "dxsupport@sabre.com" in req.text:
        print("{}Sabre WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Safe3 
    elif "Safe3WAF" in req.headers or "Safe3waf" in req.text:
        print("{}Safe3waf WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #SafeDog 
    elif "safedog" in req.headers:
        print("{}safedog WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #SecKing
    elif "SECKING" in req.headers:
        print("{}SecKing WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #SecuPress
    elif "SecuPress" in req.text or req.status_code == 503 and "Block ID: Bad URL Contents" in req.text:
        print("{}SecuPress WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Secure Entry 
    elif "Secure Entry Server" in req.headers:
        print("{}Secure Entry WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #SecureIIS 
    elif "beyondtrust" in req.text or "Download SecureIIS Personal Edition" in req.text or "SecureIIS Error" in req.text:
        print("{}SecureIIS WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #SEnginx 
    elif "SENGINX-ROBOT-MITIGATION" in req.text:
        print("{}SEnginx WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #ShieldSecurity 
    elif "You were blocked by the Shield" in req.text:
        print("{}ShieldSecurity WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #SiteLock TrueShield 
    elif "Sitelock is leader in Business Website Security Services" in req.text or "sitelock-site-verification" in req.text or \
        "sitelock_shield_logo" in req.text or "www.sitelock.com" in req.text:
        print("{}SiteLock WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #SonicWall
    elif "SonicWALL" in req.headers or "This request is blocked by the SonicWALL" in req.text:
        print("{}SonicWALL WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Sophos UTM
    elif "Powered by UTM Web Protection" in req.text:
        print("{}Sophos UTM WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #SquidProxy IDS 
    elif "Access control configuration prevents your request from being allowed at this time" in req.text:
        print("{}SquidProxy WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #StackPath 
    elif "ou performed an action that triggered the service and blocked your request" in req.text or "StackPath" in req.text:
        print("{}StackPath WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Sucuri CloudProxy
    elif "Access Denied - Sucuri Website Firewall" in req.text:
        print("{}Sucuri WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Synology Cloud
    elif "opyright (c) 2019 Synology Inc. All rights reserved" in req.text:
        print("{}Synology WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Tencent Cloud 
    elif "waf.tencent-cloud.com" in req.text:
        print("{}Tencent WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #TransIP 
    elif "X-TransIP" in req.headers:
        print("{}TransIP WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #UCloud UEWaf 
    elif "ucloud.cn" in req.text or "uewaf" in req.headers:
        print("{}UCloud WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #URLScan 
    elif "Rejected-by-URLScan" in req.text:
        print("{}URLScan WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Varnish (OWASP) 
    elif "Request rejected by xVarnish-WAF" in req.text:
        print("{}Varnish WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Varnish CacheWall 
    elif "Varnish cache Server" in req.text:
        print("{}Varnish CacheWall WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Viettel 
    elif "Viettel WAF" in req.text:
        print("{}Viettel WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #VirusDie 
    elif "copy; Virusdie.ru" in req.text or "Virusdie" in req.text or 'name="FW_BLOCK"' in req.text:
        print("{}Virusdie WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #WatchGuard IPS 
    elif "Request denied by WatchGuard Firewall" in req.text or "WatchGuard Technologies Inc" in req.text:
        print("{}WatchGuard WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #WebARX Security 
    elif "This request has been blocked by WebARX Web Application Firewall" in req.text or "/wp-content/plugins/webarx/" in req.text:
        print("{}WebARX WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #WebKnight
    elif "WebKnight" in req.headers or "WebKnight Application Firewall Alert" in req.text or "AQTRONIX WebKnight" in req.text or \
        req.status_code == 999:
        print("{}WebKnight WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #WebLand 
    elif "Apache Protected By WebLand WAF" in req.headers:
        print("{}WebLand WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #WebRay 
    elif "WebRay-WAF" in req.headers or "RaySrv RayEng" in req.text:
        print("{}WebRay WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #WebSEAL 
    elif "WebSEAL" in req.headers or "This is a WebSEAL error message template file" in req.text or "WebSEAL server received an invalid HTTP request" in req.text:
        print("{}WebSEAL WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #WebTotem 
    elif "The current request was blocked by WebTotem" in req.text:
        print("{}WebTotem WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #West263CDN 
    elif "WT263CDN" in req.headers:
        print("{}West263CDN WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Wordfence 
    elif "WebKnight" in req.headers or "Generated by Wordfence" in req.text or "This response was generated by Wordfence" in req.text:
        print("{}Wordfence WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #WTS-WAF 
    elif "WTS-WAF" in req.text:
        print("{}WTS WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #XLabs Security WAF 
    elif "XLabs Security" in req.text:
        print("{}XLabs Security WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Xuanwudun WAF 
    elif "http://admin.dbappwaf.cn/index.php/Admin/ClientMisinform/" in req.text:
        print("{}Xuanwudun WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Yunaq Chuangyu 
    elif "365cyd.net" in req.text or "http://help.365cyd.com/cyd-error-help.html?code=403" in req.text:
        print("{}Yunaq Chuangyu WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Yundun 
    elif "YUNDUN" in req.headers or "YUNDUN" in req.text or "Blocked by YUNDUN Cloud WAF" in req.text:
        print("{}Yundun WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #Yunsuo 
    elif "yunsuologo" in req.text or "yunsuo_session" in req.headers:
        print("{}Yunsuo WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #YxLink 
    elif "Yxlink-WAF" in req.headers:
        print("{}YxLink WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #ZenEdge 
    elif "/__zenedge/assets/0" in req.text or "ZENEDGE" in req.headers or "X-Zen-Fury" in req.text:
        print("{}ZenEdge WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    #ZScaler 
    elif "ZScaler" in req.headers or "https://login.zscloud.net/img_logo_new1.png" in req.text or \
        "Your organization has selected Zscaler to protect you from internet threats" in req.text or "The Internet site you have attempted to access is prohibited. Accenture's webfilters indicate that the site likely contains content considered inappropriate" in req.text:
        print("{}ZScaler WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        return True
    else:
        return False
