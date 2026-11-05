# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
import warnings
import requests
import re
from urllib.parse import urljoin
from config import S3, JS, WARNING
import traceback
import threading
from bs4 import MarkupResemblesLocatorWarning
try:
    from bs4 import XMLParsedAsHTMLWarning
    warnings.filterwarnings('ignore', category=XMLParsedAsHTMLWarning)
except ImportError:
    pass
from modules.output import record_finding


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', category=MarkupResemblesLocatorWarning)

seen_js = set() # each JS file is downloaded & analysed once per run, not on every page that includes it
seen_js_lock = threading.Lock()
seen_buckets = set()
seen_values = set() # (rule, value): the same Google key on 300 pages = 1 finding

S3_RE = re.compile(r"(?:https?:)?//([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com"
                   r"|(?:https?:)?//s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])"
                   r"|s3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])", re.I)

discover_hook = None # set by hawkscan: paths found in the JS are fuzzed too
request_headers = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'} # set by hawkscan (UA + -H)
JS_PATH_RE = re.compile(r"""["'`](/[a-zA-Z0-9_\-.~%/]{2,120}?)(?:\?[^"'`\s]{0,100})?["'`]""")
STATIC_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".webm", ".map")


BINARY_MAGIC = (b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!", b"%PDF", b"BZh", b"\x89PNG", b"GIF8", b"\xff\xd8\xff", b"\x00\x00\x00", b"SQLite format")


def is_text(req):
    """Archives, dumps, images... are downloaded, never parsed (BeautifulSoup / regexes on 10MB of binary)"""
    ctype = req.headers.get("Content-Type", "").lower()
    if any(t in ctype for t in ("image/", "audio/", "video/", "font/", "zip", "octet-stream", "pdf", "x-tar", "gzip", "x-7z", "rar", "x-sqlite")):
        return False
    head = (req.content or b"")[:8192]
    return not head.startswith(BINARY_MAGIC) and b"\x00" not in head


def extract_paths(text):
    """API routes and hidden pages referenced in a JS bundle: "/api/v2/admin/users", "/internal/export"..."""
    if not discover_hook:
        return
    for m in JS_PATH_RE.finditer(text):
        path = m.group(1)
        if not path.lower().endswith(STATIC_EXT) and "//" not in path:
            discover_hook(path, "js")


# found in JS but public by design (front-end config): reported as "token", not as a secret
PUBLIC_KEYS = {"AMAZON_URL_1", "AMAZON_URL_2", "AMAZON_URL_3", "google_api", "firebase_db", "azure_storage",
               "json_web_token", "Authorization", "accessToken", "vtex-key"}


def check_bucket(bucket, res, directory):
    """Only what matters: public listing, or a bucket that doesn't exist anymore (takeover)"""
    url = "https://s3.amazonaws.com/{}/".format(bucket) if "." in bucket else "https://{}.s3.amazonaws.com/".format(bucket)
    try:
        r = requests.get(url, verify=False, timeout=10, allow_redirects=False)
        endpoint = re.search(r"<Endpoint>([^<]+)</Endpoint>", r.text)
        if r.status_code in (301, 307) and endpoint: # other region
            url = "https://{}/".format(endpoint.group(1)) if bucket in endpoint.group(1) else "https://{}/{}/".format(endpoint.group(1), bucket)
            r = requests.get(url, verify=False, timeout=10, allow_redirects=False)
    except Exception:
        return
    if r.status_code == 200 and "<ListBucketResult" in r.text:
        print("{}[200] S3 bucket \033[31m{}\033[0m is listable ({}) found in {}".format(S3, bucket, url, res))
        record_finding(directory, "s3", url, 200, len(r.content), "public listing, bucket referenced in {}".format(res))
    elif "NoSuchBucket" in r.text:
        print("{}[404] S3 bucket \033[31m{}\033[0m doesn't exist (takeover ?) found in {}".format(S3, bucket, res))
        record_finding(directory, "s3", url, r.status_code, len(r.content), "NoSuchBucket: takeover candidate, referenced in {}".format(res))

class parsing_html:
    """
    Parsing_html: class with all function who parse html
    """
    def get_links(self, req, directory):
        """
        Get_links: get all links on webpage during the scan
        """
        #print("{}:{}".format(req, req.url)) #DEBUG
        soup = BeautifulSoup(req.text, "html.parser")
        search = soup.find_all('a')
        if search:
            for s in search:
                link = s.get("href")
                try:
                    if re.match(r'http(s)', link):
                        with open(directory + "/links.txt", "a+") as links:
                            links.write(str(link+"\n"))
                    else:
                        pass
                except:
                    pass


    def html_recon(self, res, req, directory):
        """
        Check if S3 buckets and path disclosure are in html page
        """
        path_disclosure = ["file://", "tmp/", "var/www", "/usr/", "var/lib", "srv/www", "srv/data", "var/opt", "file:///", "var/run"]
        #archive extentions
        archives = ['db', 'swp', 'yml', 'xsd', 'wml', 'bkp', 'rar', 'zip', '7z', 'bak', 'bac', 'NEW', 
        'old', 'bkf', 'bok', 'cgi', 'dat', 'ini', 'log', 'key', 'conf', 'env', '_bak', '_old', 'json', 'lock', 
        'save', 'atom', 'action', '_backup', 'backup', 'config', '/authorize/', 'md', 'gz', 'txt', '%01', 
        '(1)', 'sql.gz', 'tgz', 'tar.gz', 'gzip', 'war', 'jar', 'cab']

        # real bucket names only (not any URL containing "aws."), each bucket checked once
        for m in S3_RE.finditer(req.text):
            bucket = (m.group(1) or m.group(2) or m.group(3) or "").lower()
            with seen_js_lock:
                if not bucket or bucket in seen_buckets:
                    continue
                seen_buckets.add(bucket)
            check_bucket(bucket, res, directory)
        for pad in path_disclosure:
            #regex
            m = re.search(r"{}[a-zA-z/]+".format(pad), req.text)
            if m:
                print(" {}Possible path disclosure \033[34m{}\033[0m in {}".format(WARNING, m.group(0), res))
        for arc in archives:
            #regex
            a = re.search(r"\.{}$".format(arc), req.text)
            if a:
                print(" {}Possible archives \033[34m{}\033[0m in {}".format(WARNING, a.group(0), res))



    def get_javascript(self, url, req, directory):
        """search potentialy sensitive keyword in javascript"""
        REGEX_ = {
            "AMAZON_URL_1":r"[a-z0-9.-]{1,100}\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com",
            "AMAZON_URL_2":r"[a-z0-9.-]{1,100}\.s3-website[.-](eu|ap|us|ca|sa|cn)",
            "AMAZON_URL_3":r"s3[.-]([a-z0-9-]+\.)?amazonaws\.com/[a-z0-9._-]+",
            "AMAZON_KEY":r"\b(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
            "Authorization":r"Bearer\s[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
            "accessToken":r"acesstoken=[0-9]{13,17}",
            "vtex-key":r"vtex-api-(appkey|apptoken)",
            "google_api":r"AIza[0-9A-Za-z\-_]{35}",
            "google_oauth_secret":r"GOCSPX-[A-Za-z0-9_-]{28}",
            "firebase":r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
            "firebase_db":r"[a-z0-9.-]{1,100}\.firebaseio\.com",
            "paypal_braintree_access_token":r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
            "github_access_token":r"[a-zA-Z0-9_-]{1,100}:[a-zA-Z0-9_\-]{1,100}@github\.com",
            "github_token":r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
            "github_fine_grained_pat":r"github_pat_[A-Za-z0-9_]{82}",
            "gitlab_pat":r"glpat-[A-Za-z0-9\-_]{20}",
            "slack_token":r"xox[baprs]-[0-9A-Za-z-]{10,72}",
            "slack_webhook":r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
            "stripe_secret":r"\b[rs]k_live_[0-9a-zA-Z]{24,99}\b",
            "sendgrid":r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
            "shopify_token":r"shp(at|ca|pa|ss)_[a-fA-F0-9]{32}",
            "npm_token":r"\bnpm_[A-Za-z0-9]{36}\b",
            "openai_key":r"sk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,200}T3BlbkFJ[A-Za-z0-9_-]{20,200}",
            "anthropic_key":r"sk-ant-(api|admin)\d{2}-[A-Za-z0-9_-]{80,200}",
            "mapbox_secret":r"\bsk\.eyJ[A-Za-z0-9_-]{20,500}\.[A-Za-z0-9_-]{20,500}",
            "azure_storage":r"[a-z0-9]{3,24}\.blob\.core\.windows\.net",
            "azure_sas":r"sv=\d{4}-\d{2}-\d{2}&[^\"' ]{0,200}sig=[A-Za-z0-9%/+=]{20,}",
            "json_web_token":r"\beyJ[A-Za-z0-9_-]{10,2000}\.eyJ[A-Za-z0-9_-]{10,4000}\.[A-Za-z0-9_-]{10,1000}",
            "SSH_privKey":r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----",
        }

        url_index = url.split("/")[0:3] if "http" in url else url
        url_index = "/".join(url_index)
        
        UNINTERESTING_EXTENSIONS = ['css', 'svg', 'png', 'jpeg', 'jpg', 'mp4', 'gif']

        INTERESTING_KEY = ['_public_key', '_token', '_password', '_database', 'secret_key', '_secret', 'api_key', 'apisettings', 
        'sourcemappingurl', 'private_key', 'jwt_secret', 'api_secret_key', 'access_key', 'access_token', 'admin_pass', 'admin_user', 
        'algolia_admin_key', 'algolia_api_key', 'alias_pass', 'alicloud_access_key', 'amazon_secret_access_key', 'amazonaws', 
        'ansible_vault_password', 'aos_key', 'api_key_secret', 'api_key_sid', 'api_secret', 'api.googlemaps AIza', 'apidocs', 'apikey', 
        'apiSecret', 'app_debug', 'app_id', 'app_key', 'app_log_level', 'app_secret', 'appkey', 'appkeysecret', 'application_key', 
        'appsecret', 'appspot', 'auth_token', 'authorizationToken', 'authsecret', 'aws_access', 'aws_access_key_id', 'aws_bucket', 'aws_key', 
        'aws_secret', 'aws_secret_key', 'aws_token', 'AWSSecretKey', 'b2_app_key', 'bashrc password', 'bintray_apikey', 'bintray_gpg_password', 
        'bintray_key', 'bintraykey', 'bluemix_api_key', 'bluemix_pass', 'browserstack_access_key', 'bucket_password', 'bucketeer_aws_access_key_id', 
        'bucketeer_aws_secret_access_key', 'built_branch_deploy_key', 'bx_password', 'cache_driver', 'cache_s3_secret_key', 'cattle_access_key', 
        'cattle_secret_key', 'certificate_password', 'ci_deploy_password', 'client_secret', 'client_zpk_secret_key', 'clojars_password', 'cloud_api_key', 
        'cloud_watch_aws_access_key', 'cloudant_password', 'cloudflare_api_key', 'cloudflare_auth_key', 'cloudinary_api_secret', 'cloudinary_name', 'codecov_token', 
        'conn.login', 'connectionstring', 'consumer_key', 'consumer_secret', 'cypress_record_key', 'database_password', 'database_schema_test', 
        'datadog_api_key', 'datadog_app_key', 'db_password', 'db_server', 'db_username', 'dbpasswd', 'dbpassword', 'dbuser', 'deploy_password', 'digitalocean_ssh_key_body', 
        'digitalocean_ssh_key_ids', 'docker_hub_password', 'docker_key', 'docker_pass', 'docker_passwd', 'docker_password', 'dockerhub_password', 'dockerhubpassword', 
        'dot-files', 'dotfiles', 'droplet_travis_password', 'dynamoaccesskeyid', 'dynamosecretaccesskey', 'elastica_host', 'elastica_port', 'elasticsearch_password', 
        'encryption_key', 'encryption_password', 'env.heroku_api_key', 'env.sonatype_password', 'eureka.awssecretkey', 'apex', 'firebase', 'xoxp', 'hapikey', 'client_credentials',
        'amplitude', 'getKey', 'appcenter', 'TrackerToken', 'conversationspasskey', 'Passkey', 'accesstoken', 'verifycustomtoken', 'signInWithCustomToken', 'x-pendo-integration-key',
        'sendgrid_token', 'x-api-token', 'x-api-key', 'branch_secret', 'Idempotency-Key', 'cognito_config', 'cognito']

        SOCKET_END = ["socket.io", "socketio", "socket", "websocket", "app.module.ts", "ws://", "wss://", "xmpp-websocket"]

        text = req.content
        url = req.url
        regex = r'''((https?:)?[/]{1,2}[^'\"> ]{5,})|(\.(get|post|ajax|load)\s*\(\s*['\"](https?:)?[/]{1,2}[^'\"> ]{5,})'''
        if ".js" in url:
            extract_paths(text.decode('utf-8', errors="ignore"))
            for keyword_match in INTERESTING_KEY:
                if keyword_match.lower() in text.decode('utf-8', errors="ignore").lower():
                    try:
                        with open("{}/js.txt".format(directory), 'a+') as js_write:
                            js_link = open("{}/js.txt".format(directory), 'r')
                            if "{}::{}".format(url, keyword_match) not in js_link.read():
                                print("{}Potential keyword found \033[33m[{}] \033[0min {}".format(JS, keyword_match, url))
                                js_write.write("{}::{}\n".format(url, keyword_match))
                                record_finding(directory, "keyword", url, detail=keyword_match)
                            js_link.close()
                    except:
                        traceback.print_exc()
            for socketio_ in SOCKET_END:
                if socketio_ in text.decode('utf-8', errors="ignore"):
                    print("{}Potential socketio endpoint found \033[33m[{}] \033[0min {}".format(JS, socketio_, url))
        else:
            matches = re.findall(regex, text.decode('utf-8', errors="ignore"))
            for match in matches:
                match = (urljoin(url, match[0]),) + tuple(match[1:]) # <script src="/static/app.js"> (relative) too
                #print(match[0]) #DEBUG
                if not any('{}'.format(ext) in match[0] for ext in UNINTERESTING_EXTENSIONS) and url_index in match[0] and ".js" in match[0]:
                    with seen_js_lock:
                        if match[0] in seen_js:
                            continue
                        seen_js.add(match[0])
                    try:
                        req_js = requests.get(match[0], verify=False, timeout=10, headers=request_headers) # same host: scan headers (cookies)
                    except Exception:
                        continue
                    extract_paths(req_js.text)
                    #print(match[0]) #DEBUG
                    for keyword_match in INTERESTING_KEY:
                        if keyword_match.lower() in req_js.text.lower():
                            #print("{}Potentialy keyword found \033[33m[{}] \033[0min {}".format(JS, keyword_match, match[0]))
                            try:
                                with open("{}/js.txt".format(directory), 'a+') as js_write:
                                    js_link = open("{}/js.txt".format(directory), 'r')
                                    #print(js_link.read())
                                    if "{}::{}".format(match[0], keyword_match) not in js_link.read():
                                        print("{}Potential keyword found \033[33m[{}] \033[0min {}".format(JS, keyword_match, match[0]))
                                        js_write.write("{}::{}\n".format(match[0], keyword_match))
                                        record_finding(directory, "keyword", match[0], detail=keyword_match)
                                    js_link.close()
                            except:
                                traceback.print_exc()

        decoded = text[:3000000].decode('utf-8', errors="ignore") # regexes on a huge file = minutes
        for k, v in REGEX_.items():
            values_found = list(dict.fromkeys(m.group(0) for m in re.finditer(v, decoded)))
            with seen_js_lock:
                values_found = [x for x in values_found if (k, x) not in seen_values]
                seen_values.update((k, x) for x in values_found)
            if values_found:
                for v in values_found:
                    try:
                        with open("{}/js.txt".format(directory), 'a+') as js_write:
                            js_link = open("{}/js.txt".format(directory), 'r')
                            if "{}::{}::{}".format(url, k, v) not in js_link.read():
                                print("{}Keyword found \033[33m[{}] \033[0min {} with value \033[32m[{}] \033[0m".format(JS, k, url, v))
                                js_write.write("{}::{}::{}\n".format(url, k, v))
                                record_finding(directory, "token" if k in PUBLIC_KEYS else "secret", url, detail="{}: {}".format(k, v))
                            js_link.close()
                    except:
                        traceback.print_exc()


                        
"""if __name__ == '__main__':
    ph = parsing_html()
    url = "https://www..fr/"
    req = requests.get(url)
    ph.get_javascript(url, req)""" #DEBUG