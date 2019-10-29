# -*- coding: utf-8 -*-
import time
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI, BACK

def verify_waf(req, res, user_agent, tests):
    """
    Function verify if there is a WAF to instable website
    """
    #360
    if req.status_code == 493 or "wzws-waf-cgi" in req.text or "X-Powered-By-360wzb" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}360 Web Application Firewall waf detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #aeSecure
    elif "aesecure_denied.png" in req.text or "aeSecure-code" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}aeSecure WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    elif "Server detected a syntax error in your request" in req.text or "AL-SESS" in req.headers or "AL-LB" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Airlock (Phion/Ergon) WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Aliyundun 
    elif req.status_code == 405 and \
        "Sorry, your request has been blocked as it may cause potential threats to the server's security" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Aliyundun WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Anquando
    elif req.status_code == 405 and "/aqb_cc/error/|hidden_intercept_time" in req.text or "X-Powered-By-Anquanbao" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Anquanbao Web Application Firewall WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Anyu
    elif "Sorry! your access has been intercepted by AnYu" in req.text or "AnYu- the green channel" in req.text or \
        "WZWS-RAY" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}AnYu WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Approach
    elif "Approach Web Application Firewall Framework" in req.text or \
        "Your IP address has been logged and this information could be used by authorities to track you." in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Approach WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Armor
    elif "This request has been blocked by website protection from Armor" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Armor Protection (Armor Defense) WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #ArvanCloud 
    elif "ArvanCloud" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}ArvanCloud WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #ASPA 
    elif "ASPA-WAF" in req.headers or "ASPA-Cache-Status_code" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}ASPA WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #ASP.NET
    elif "X-ASPNET-Version" in req.headers and \
        "This generic 403 error means that the authenticated user is not authorized to use the requested resource" in req.text or \
        "Error Code 0x00000000<" in req.text: 
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}ASP.NET WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #ASTRA
    elif "our website protection system has detected an issue with your IP address and wont let you proceed any further" in req.text or \
        "www.getastra.com/assets/images/" in req.text or "cz_astra_csrf_cookie" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}ASTRA WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #AWS ELB 
    elif "Access Denied" in req.text and "AWSALB" in req.headers or "X-AMZ-ID" in req.headers or "X-AMZ-REQUEST-ID" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print ("AWS ELB WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Barikode 
    elif "BARIKODE" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}BARIKODE WAF detected with this payload : {} \nwait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Barracuda
    elif "You have been blocked" in req.text or "You are unable to access this website" in req.text and \
        "barra_counter_session" in req.headers or "barracuda_" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Barracuda WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Bekchy
    elif "Bekchy - Access Denied" in req.text or "https://bekchy.com/report" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Bekchy WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #BitNinja 
    elif "Security check by BitNinja" in req.text or "your IP will be removed from BitNinja" in req.text or \
        "Visitor anti-robot validation" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}BitNinja WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #BIG-IP
    elif "BigIP" in req.headers or "F5" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}BIG-IP WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Bluedon
    elif "Bluedon Web Application Firewall" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Bluedon WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #BulletProof Security Pro 
    elif "bpsMessage" in req.text or \
        "If you arrived here due to a search or clicking on a link click your Browser's back button to return to the previous page." in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}BulletProof WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #CDN NS Application Gateway 
    elif "CdnNsWAF Application Gateway" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}CDN NS Application Gateway WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #ChinaCache 
    elif "Powered-By-ChinaCache" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}ChinaCache WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Cisco ACE XML Gateway
    elif "ACE XML Gateway" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Cisco ACE WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Cloudbric Web Application Firewall
    elif "Malicious Code Detected" in req.text or "Your request was blocked by Cloudbric" in req.text or \
        "Cloudbric | ERROR!" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Cloudbric WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Cloudflare
    elif "Cloudflare Ray ID:" in req.text or "Attention Required!" in req.text and "cf-ray" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Cloudflare WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests + 1)
    #CloudfloorDNS 
    elif "CloudfloorDNS - Web Application Firewall Error" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}CloudfloorDNS WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Cloudfront 
    elif "Generated by cloudfront (CloudFront)" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Cloudfront WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Comodo cWatch 
    elif "Protected by COMODO WAF" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}COMODO WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #CrawlProtect 
    elif "crawlprotect" in req.headers or "CrawlProtect" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}CrawlProtect WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Distil Web Protection 
    elif "X-Distil-CS" in req.headers and "Pardon Our Interruption" in req.text or \
        "You have disabled javascript in your browser" in req.text or "Something about your browser made us think that you are a bot" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Distil Web Protection WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #DoSArrest Internet Security 
    elif "X-DIS-Request-ID" in req.headers or "DOSarrest" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}DoSArrest WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #DotDefender
    elif "dotDefender Blocked Your Request" in req.text or "X-dotDefender-denied" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}DotDefender WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #DynamicWeb Injection Check 
    elif "dw-inj-check" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}DynamicWeb WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #e3Learning Security 
    elif "e3Learning_WAF" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}e3Learning WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #EdgeCast 
    elif req.status_code == 400 and "ID:EdgeCast Web Application Firewall" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}EdgeCast WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Eisoo Cloud 
    elif "(year) Eisoo Inc." in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Eisoo WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #FortiWeb 
    elif "FORTIWAFSID=" in req.headers and ".fgd_icon" in req.text or "Server Unavailable" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}FortiWeb WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #GoDaddy
    elif "Access Denied - GoDaddy Website Firewall" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}GoDaddy WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #GreyWizard 
    elif "Contact the website owner or Grey Wizard" in req.text or "We've detected attempted attack or non standard traffic from your IP address" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}GreyWizard WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Huawei Cloud
    elif "account.hwclouds.com/static/error/images/404img.jpg" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Huawei WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Imperva Incapsula
    elif "Powered By Incapsula" in req.text or "Incapsula incident ID" in req.text or "_Incapsula_Resource" in req.text or \
        "subject=WAF Block Page" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Imperva Incapsula WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Immunify360 
    elif "imunify360-webshield" in req.headers or "Powered by Imunify36" in req.text or "imunify360 preloader" in req.text or \
        "protected by Imunify360" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Immunify360 WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #IndusGuard
    elif "further investigation and remediation with a screenshot of this page" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Potential IndusGuard WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Instart DX
    elif "X-Instart-Request-ID" in req.headers or "X-Instart-WL" in req.headers or "X-Instart-Cache" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Instart DX WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #ISA
    elif "The ISA Server denied the specified Uniform Resource Locator (URL)" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}ISA WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Janusec Application Gateway 
    elif "JANUSEC" in req.text or "Janusec Application Gateway" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Janusec WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Jiasule
    elif "static.jiasule.com/static/js/http_error.js" in req.text or "jsl_tracking" in req.headers or "__jsluid=" in req.headers or \
        "jiasule-WAF" in req.headers or "notice-jiasule" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Jiasule WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #KeyCDN 
    elif "KeyCDN" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}KeyCDN WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #KnownSec 
    elif "ks-waf-error.png" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}KnowSec WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #KONA Site Defender (Akamai)
    elif "AkamaiGHost" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Akamai WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #LiteSpeed
    elif "LiteSpeed" in req.headers or "Proudly powered by LiteSpeed Web Server" in req.text or "http://www.litespeedtech.com/error-page" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}LiteSpeed WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Malcare 
    elif "Firewall powered by MalCare" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Malcare WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #MissionControl Application Shield 
    elif "Mission Control Application Shield" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Mission Control Application Shield WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #ModSecurity
    elif "This error was generated by Mod_Security" in req.text or "rules of the mod_security module" in req.text or \
        "mod_security rules triggered" in req.text or "/modsecurity-errorpage/" in req.text or "Mod_Security" in req.headers or \
        req.status_code == 403 and "ModSecurity Action" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}ModSecurity WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #NAXSI 
    elif "This Request Has Been Blocked By NAXSI" in req.text or "naxsi/waf" in req.headers or "NAXSI blocked information" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}NAXSI WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Netcontinuum 
    elif "NCI__SessionId=" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Potential Netcontinuum WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #NetScaler AppFirewall 
    elif "NSC_" in req.headers or "ns_af=" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}NetScaler WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #NevisProxy
    elif "Navajo" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}NevisProxy")
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #NewDefend
    elif "http://www.newdefend.com/feedback/misinformation" in req.text or "/nd_block/" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}NewDefend WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Nexusguard
    elif "speresources.nexusguard.com/wafpage/index.html" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Nexusguard WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #NinjaFirewall 
    elif "NinjaFirewall: 403 Forbidden" in req.text or "NinjaFirewall" in req.text or \
        req.status_code == 403 and "For security reasons, it was blocked and logged" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}NinjaFirewall WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #NSFocus
    elif "NSFocus" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}NSFocus WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #NullDDoS 
    elif "NullDDoS System" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}NullDDoS WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #onMessage Shield 
    elif "onMessage Shield" in req.headers or "Blackbaud K-12 conducts routine maintenance" in req.text or "blackbaud.com" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}onMessage Shield WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #OpenResty Lua WAF 
    elif req.status_code == 406 and "openresty/" in req.text or "openresty/" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}OpenResty Lua WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Palo Alto 
    elif "Palo Alto Next Generation Security Platform" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Palo Alto WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #PentaWAF 
    elif "PentaWAF/" in req.headers or "PentaWAF/" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}PentaWAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #PerimeterX 
    elif "https://www.perimeterx.com/whywasiblocked" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}PerimeterX WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #pkSecurityModule IDS
    elif "pkSecurityModule: Security.Alert" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}pkSecurityModule WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #PowerCDN 
    elif "powercdn" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}PowerCDN WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Profense 
    elif "Profense" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Profense WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Proventia (IBM) 
    elif "request does not match Proventia rules" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Potential Proventia (IBM) WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Puhui 
    elif "PuhuiWAF" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Puhui WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Request Validation Mode 
    elif "ASP.NET has detected data in the request that is potentially dangerous" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Potential ASP.NET WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #RSFirewall
    elif "COM_RSFIREWALL_403_FORBIDDEN" in req.text or "COM_RSFIREWALL_EVENT" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}RSFirewall WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Sabre 
    elif req.status_code == 500 and "dxsupport@sabre.com" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Sabre WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Safe3 
    elif "Safe3WAF" in req.headers or "Safe3waf" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Safe3waf WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #SafeDog 
    elif "safedog" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}safedog WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #SecKing
    elif "SECKING" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}SecKing WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #SecuPress
    elif "SecuPress" in req.text or req.status_code == 503 and "Block ID: Bad URL Contents" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}SecuPress WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Secure Entry 
    elif "Secure Entry Server" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Secure Entry WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #SecureIIS 
    elif "beyondtrust" in req.text or "Download SecureIIS Personal Edition" in req.text or "SecureIIS Error" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}SecureIIS WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #SEnginx 
    elif "SENGINX-ROBOT-MITIGATION" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}SEnginx WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #ShieldSecurity 
    elif "You were blocked by the Shield" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}ShieldSecurity WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #SiteLock TrueShield 
    elif "Sitelock is leader in Business Website Security Services" in req.text or "sitelock-site-verification" in req.text or \
        "sitelock_shield_logo" in req.text or "www.sitelock.com" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}SiteLock WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #SonicWall
    elif "SonicWALL" in req.headers or "This request is blocked by the SonicWALL" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}SonicWALL WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Sophos UTM
    elif "Powered by UTM Web Protection" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Sophos UTM WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #SquidProxy IDS 
    elif "Access control configuration prevents your request from being allowed at this time" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}SquidProxy WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #StackPath 
    elif "ou performed an action that triggered the service and blocked your request" in req.text or "StackPath" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}StackPath WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Sucuri CloudProxy
    elif "Access Denied - Sucuri Website Firewall" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Sucuri WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Synology Cloud
    elif "opyright (c) 2019 Synology Inc. All rights reserved" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Synology WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Tencent Cloud 
    elif "waf.tencent-cloud.com" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Tencent WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #TransIP 
    elif "X-TransIP" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}TransIP WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #UCloud UEWaf 
    elif "ucloud.cn" in req.text or "uewaf" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}UCloud WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #URLScan 
    elif "Rejected-by-URLScan" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}URLScan WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Varnish (OWASP) 
    elif "Request rejected by xVarnish-WAF" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Varnish WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Varnish CacheWall 
    elif "Varnish cache Server" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Varnish CacheWall WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Viettel 
    elif "Viettel WAF" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Viettel WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #VirusDie 
    elif "copy; Virusdie.ru" in req.text or "Virusdie" in req.text or 'name="FW_BLOCK"' in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Virusdie WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #WatchGuard IPS 
    elif "Request denied by WatchGuard Firewall" in req.text or "WatchGuard Technologies Inc" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}WatchGuard WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #WebARX Security 
    elif "This request has been blocked by WebARX Web Application Firewall" in req.text or "/wp-content/plugins/webarx/" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}WebARX WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #WebKnight
    elif "WebKnight" in req.headers or "WebKnight Application Firewall Alert" in req.text or "AQTRONIX WebKnight" in req.text or \
        req.status_code == 999:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}WebKnight WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #WebLand 
    elif "Apache Protected By WebLand WAF" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}WebLand WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #WebRay 
    elif "WebRay-WAF" in req.headers or "RaySrv RayEng" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}WebRay WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #WebSEAL 
    elif "WebSEAL" in req.headers or "This is a WebSEAL error message template file" in req.text or "WebSEAL server received an invalid HTTP request" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}WebSEAL WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #WebTotem 
    elif "The current request was blocked by WebTotem" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}WebTotem WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #West263CDN 
    elif "WT263CDN" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}West263CDN WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Wordfence 
    elif "WebKnight" in req.headers or "Generated by Wordfence" in req.text or "This response was generated by Wordfence" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Wordfence WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #WTS-WAF 
    elif "WTS-WAF" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}WTS WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #XLabs Security WAF 
    elif "XLabs Security" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}XLabs Security WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Xuanwudun WAF 
    elif "http://admin.dbappwaf.cn/index.php/Admin/ClientMisinform/" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Xuanwudun WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Yunaq Chuangyu 
    elif "365cyd.net" in req.text or "http://help.365cyd.com/cyd-error-help.html?code=403" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Yunaq Chuangyu WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Yundun 
    elif "YUNDUN" in req.headers or "YUNDUN" in req.text or "Blocked by YUNDUN Cloud WAF" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Yundun WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #Yunsuo 
    elif "yunsuologo" in req.text or "yunsuo_session" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}Yunsuo WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #YxLink 
    elif "Yxlink-WAF" in req.headers:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}YxLink WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #ZenEdge 
    elif "/__zenedge/assets/0" in req.text or "ZENEDGE" in req.headers or "X-Zen-Fury" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}ZenEdge WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    #ZScaler 
    elif "ZScaler" in req.headers or "https://login.zscloud.net/img_logo_new1.png" in req.text or \
        "Your organization has selected Zscaler to protect you from internet threats" in req.text or "The Internet site you have attempted to access is prohibited. Accenture's webfilters indicate that the site likely contains content considered inappropriate" in req.text:
        if tests == 1:
            print("{}this payload seem to blocked by WAF, we go test an another payload: {}".format(INFO, res))
            return True
        else:
            pass
        print("{}ZScaler WAF detected with this payload : {} \nplease wait...".format(INFO, res))
        time.sleep(180)
        test += 1
        test_waf = verify_waf(req, res, user_agent, tests)
    else:
        return False