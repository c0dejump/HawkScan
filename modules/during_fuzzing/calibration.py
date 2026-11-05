# -*- coding: utf-8 -*-
"""
Anti false-positive helpers:
  - raw_request: send a path as-is (requests/urllib3 silently rewrite "/./", "/../" and "%2e")
  - Calibration: lazy wildcard / soft-404 fingerprinting, per directory and per path shape
  - flood control: mute a response fingerprint seen too many times (catch-all, WAF page...)
"""
import os
import random
import re
import string
import threading
import time
from collections import Counter
from urllib.parse import quote, unquote, urljoin, urlsplit

import requests

from config import INFO
from modules.output import record_finding

RAW_SAFE = "!#$%&'()*+,/:;=?@[]~"
REDIRECTS = (301, 302, 303, 307, 308)


def rand_token(size=12):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(size))


MAX_BODY = 10 * 1024 * 1024 # a 2GB backup.zip must not be loaded in memory: first 10MB, enough to report it


def raw_request(s, method, url, headers=None, auth=None, timeout=10, allow_redirects=False):
    """Send url byte-for-byte: no dot-segment removal, no %xx decoding"""
    prep = s.prepare_request(requests.Request(method, url, headers=headers, auth=auth or None))
    prep.url = quote(url, safe=RAW_SAFE)
    resp = s.send(prep, allow_redirects=allow_redirects, timeout=timeout, verify=False, stream=True)
    body, size = [], 0
    resp.truncated = False
    for chunk in resp.iter_content(65536):
        body.append(chunk)
        size += len(chunk)
        if size > MAX_BODY:
            resp.truncated = True
            resp.close()
            break
    resp._content = b"".join(body)[:MAX_BODY]
    resp._content_consumed = True
    if resp.encoding is None:
        resp.encoding = "utf-8" # avoid charset detection on every .text access
    return resp


def split_url(url):
    """http://h/a/b.php?x=1 -> ('http://h/', 'a/', 'b.php', '', '?x=1')"""
    root = "/".join(url.split("/")[:3]) + "/"
    path, sep, query = url[len(root):].partition("?")
    trail = "/" if path.endswith("/") else ""
    parent, _, last = (path[:-1] if trail else path).rpartition("/")
    return root, parent + "/" if parent else "", last, trail, sep + query


def shape_of(last, trail, query):
    """
    (prefix, extension, trail) of the last segment, ex: '.env.php' -> ('.', 'php', ''), 'x.php/' -> ('', 'php', '/')
    Apache denies every .ht* file: the extension is ignored for them
    """
    if query:
        return ("?", "", "")
    low = last.lower()
    prefix = ".ht" if low.startswith(".ht") else "." if low.startswith(".") else ""
    rest = low[len(prefix):]
    ext = rest.rsplit(".", 1)[1][:12] if "." in rest and prefix != ".ht" else ""
    return (prefix, ext, trail)


def stem_of(last, trail, query, shape):
    """Part of the path that the probes replace with a random token"""
    prefix, ext, _ = shape
    if prefix == "?":
        return query[1:]
    return last[len(prefix):len(last) - (len(ext) + 1 if ext else 0)]


def probe_url(root, parent, last, trail, shape, tok):
    prefix, ext, _ = shape
    if prefix == "?":
        return root + parent + last + trail + "?" + tok
    return root + parent + prefix + tok + ("." + ext if ext else "") + trail


def redirect_noise(url, location, stem):
    """
    Redirects that say nothing about the requested path:
    - canonical URL: same path with another case, without the final / or ., http -> https (Admin -> admin)
    - home page: /anything -> /
    - "guessed" page (WordPress redirect_guess_404_permalink): /api/org -> /blog/organiser-la-transmission...
    Kept: /admin -> /admin/ (directory exists), another host, a real move (/aboutus -> /about-us)
    """
    if not location:
        return False
    target = urlsplit(urljoin(url, location))
    req = urlsplit(url)
    site = lambda u: u.netloc.lower().split(":")[0][4:] if u.netloc.lower().startswith("www.") else u.netloc.lower().split(":")[0]
    if site(target) != site(req): # example.com -> www.example.com: same site
        return False
    req_path, loc_path = unquote(req.path), unquote(target.path)
    if loc_path == req_path + "/":
        return False
    norm = lambda p: p.lower().rstrip("/.")
    if norm(loc_path) == norm(req_path) or norm(loc_path) == "":
        return True
    last = loc_path.rstrip("/").rsplit("/", 1)[-1].lower()
    stem = stem.lower()
    return len(stem) >= 2 and last != stem and last.startswith(stem) # WordPress: post_name LIKE 'stem%' 


def loc_path(location):
    """Location without the query: Cloudflare Access, SSO... add a unique token (meta=, state=, nonce=) to each redirect"""
    return location.split("?", 1)[0].split("#", 1)[0]


def fingerprint(resp, root):
    """(status, size, words, lines, location without root)"""
    body = resp.content or b""
    loc = resp.headers.get("Location", "")
    if loc.startswith(root):
        loc = "/" + loc[len(root):]
    return (resp.status_code, len(body), len(body.split()), body.count(b"\n"), loc)


# Block pages of WAF / bot managers (some answer 200). Only markers that a normal page never contains.
WAF_SIGNATURES = [
    ("Akamai", ["errors.edgesuite.net"]),
    ("Akamai", ["errors&#46;edgesuite&#46;net"]),
    ("Akamai", ["access denied", "reference&#32;&#35;"]),
    ("Cloudflare", ["cf-error-details"]),
    ("Cloudflare", ["attention required! | cloudflare"]),
    ("Cloudflare", ["sorry, you have been blocked"]),
    ("Cloudflare challenge", ["<title>just a moment...</title>"]),
    ("Imperva", ["incapsula incident id"]),
    ("Imperva", ["request unsuccessful. incapsula"]),
    ("Imperva", ["pardon our interruption"]),
    ("F5 ASM", ["the requested url was rejected"]),
    ("F5 ASM", ["your support id is"]),
    ("AWS WAF", ["request blocked", "generated by cloudfront"]),
    ("Sucuri", ["sucuri website firewall"]),
    ("ModSecurity", ["mod_security"]),
    ("ModSecurity", ["this error was generated by modsecurity"]),
    ("FortiWeb", ["fortiweb"]),
    ("Fortinet", ["web page blocked", "attack id"]),
    ("Barracuda", ["barracuda web application firewall"]),
    ("Wordfence", ["generated by wordfence"]),
    ("Wordfence", ["your access to this site has been limited"]),
    ("Radware", ["unauthorized activity has been detected"]),
    ("PerimeterX", ["px-captcha"]),
    ("DataDome", ["captcha-delivery.com"]),
    ("Vercel", ["vercel security checkpoint"]),
    ("Azure WAF", ["the request is blocked.", "azure"]),
]
WAF_HEADERS = [("Cloudflare challenge", "cf-mitigated"), ("DataDome", "x-datadome"), ("Imperva", "x-iinfo")]


def waf_block(resp):
    """Vendor name if the response is a WAF / bot-manager block page, else None"""
    if resp is None or resp.status_code in (301, 302, 303, 307, 308, 404):
        return None
    for vendor, header in WAF_HEADERS:
        if header in resp.headers and resp.status_code != 200:
            return vendor
    head = (resp.content or b"")[:30000].decode("utf-8", "ignore").lower()
    if not head:
        return None
    for vendor, markers in WAF_SIGNATURES:
        if all(m in head for m in markers):
            return vendor
    return None


TAG_RE = re.compile(rb"<([a-zA-Z][a-zA-Z0-9-]{0,15})")
TITLE_RE = re.compile(rb"<title[^>]*>(.{0,300}?)</title>", re.I | re.S)


def page_title(resp):
    m = TITLE_RE.search((resp.content or b"")[:30000])
    return b" ".join(m.group(1).lower().split()) if m else None


def other_title(a, b):
    """Same layout but another <title>: another page (an admin login is not the home page)"""
    ta, tb = page_title(a), page_title(b)
    return ta is not None and tb is not None and ta != tb


def tag_profile(body):
    return Counter(t.lower() for t in TAG_RE.findall(body[:3000000]))


def same_template(a, b, size_ratio=0.05, tag_ratio=0.97):
    """Two big dynamic HTML pages (nonces, random blocks) built from the same template: ex the home page"""
    la, lb = len(a.content or b""), len(b.content or b"")
    if a.status_code != b.status_code or not la or not lb or abs(la - lb) > size_ratio * max(la, lb) or other_title(a, b):
        return False
    ta, tb = tag_profile(a.content), tag_profile(b.content)
    union = sum((ta | tb).values())
    return union >= 30 and sum((ta & tb).values()) / union >= tag_ratio


class Calibration:
    """
    Before trusting a non-404 response, request 2 random paths with the same shape in the same
    directory (ex: admin/backup.php -> admin/<random>.php). If the target answers the same way,
    it's a wildcard / soft-404 / catch-all and the hit is dropped. Probes are sent once per
    (directory, shape) and only when a candidate shows up, so it costs nothing on clean targets.
    Reflected paths are handled by predicting the size/Location with the candidate word.
    Also dropped: WAF block pages, home page copies, responses repeated more than flood_limit times.
    """

    def __init__(self, send, enabled=True, flood_limit=5, directory=None):
        self.send = send # send(session, url) -> response, same headers/auth as the fuzzing
        self.enabled = enabled
        self.flood_limit = flood_limit
        self.directory = directory
        self.lock = threading.Lock()
        self.cache = {}
        self.fails = {}
        self.index = {}
        self.seen = {}
        self.wafs = {}

    def log(self, line):
        """output/calibration.log: what the probes got, to understand a false positive"""
        if not self.directory:
            return
        try:
            with self.lock, open(os.path.join(self.directory, "output", "calibration.log"), "a+") as f:
                f.write(time.strftime("%H:%M:%S ") + line + "\n")
        except Exception:
            pass

    def _probe(self, s, root, parent, last, trail, shape):
        probes = []
        for size in (10, 16):
            tok = rand_token(size)
            probe = probe_url(root, parent, last, trail, shape, tok)
            resp = self.send(s, probe)
            fp = fingerprint(resp, root)
            probes.append({
                "fp": fp,
                "reflected": (resp.content or b"").count(tok.encode()),
                "tok_len": size,
                "loc": loc_path(fp[4]).replace(tok, "{T}"),
            })
            self.log("probe {} -> {} {}b {}w {}l {}".format(probe, fp[0], fp[1], fp[2], fp[3], fp[4]))
        # size without the reflected token: if it moves, the page is dynamic
        adjusted = [p["fp"][1] - p["reflected"] * p["tok_len"] for p in probes]
        spread = abs(adjusted[0] - adjusted[1])
        return {
            "probes": probes,
            "tol": max(3, spread * 2),
            "reflect": any(p["reflected"] for p in probes),
            "dynamic": spread > 0 or probes[0]["fp"][2] != probes[1]["fp"][2],
        }

    def _baseline(self, s, root, parent, last, trail, shape):
        key = (root, parent + last + trail if shape[0] == "?" else parent, shape)
        with self.lock:
            entry = self.cache.get(key)
            if entry is None:
                self.cache[key] = event = threading.Event()
        if entry is None:
            try:
                base = self._probe(s, root, parent, last, trail, shape)
            except Exception as e:
                # timeout / reset: probe again on the next candidate (3 tries), never cache "no baseline"
                self.log("probe failed {} {}: {}".format(key[1], key[2], type(e).__name__))
                with self.lock:
                    self.fails[key] = self.fails.get(key, 0) + 1
                    retry = self.fails[key] < 3
                base = None if retry else False
            with self.lock:
                if base is None:
                    del self.cache[key]
                else:
                    self.cache[key] = base
            event.set()
            return base
        if isinstance(entry, threading.Event):
            entry.wait(60)
            entry = self.cache.get(key)
            return entry if isinstance(entry, dict) else False
        return entry

    @staticmethod
    def _match(fp, stem, base):
        for p in base["probes"]:
            b = p["fp"]
            if fp[0] != b[0]:
                continue
            if fp[0] in REDIRECTS:
                # servers often re-encode the path (%0a -> %0A, ' ' -> %20...)
                if loc_path(fp[4]).lower() in [p["loc"].replace("{T}", st).lower() for st in (stem, quote(stem, safe=""), unquote(stem))]:
                    return True
                continue
            expected = b[1] + p["reflected"] * (len(stem.encode()) - p["tok_len"])
            if abs(fp[1] - expected) <= base["tol"]:
                return True
            if fp[2] == b[2] and fp[3] == b[3]:
                # same structure: dynamic page (nonce, csrf, date...) even if both probes had the same size
                if base["reflect"] or base["dynamic"] or abs(fp[1] - expected) <= expected * 0.25:
                    return True
        return False

    def flood(self, fp, stem, url):
        """Same response over and over on different paths: catch-all, WAF rule or error page we didn't calibrate"""
        if not self.flood_limit:
            return False
        if fp[0] in REDIRECTS:
            # same redirect rule: /x/ -> /personal/x/, /x -> /login?next=/x...
            target = loc_path(fp[4]).lower()
            if stem: # the word as a path segment only (not inside "cloudflareaccess.com")
                target = re.sub(r"(?<=/){}(?=[/.]|$)".format(re.escape(stem.lower())), "{t}", target)
            key = (fp[0], target)
        else:
            key = (fp[0], fp[2], fp[3], fp[1] // 64)
        with self.lock:
            count = self.seen[key] = self.seen.get(key, 0) + 1
        if count == self.flood_limit + 1:
            what = "-> {}".format(key[1]) if fp[0] in REDIRECTS else "{}b".format(fp[1])
            print("\033[K{} {}+ identical responses [{} {}] -> similar ones are muted (catch-all / WAF rule ?)".format(INFO, self.flood_limit, fp[0], what))
            self.log("flood {} {} (last: {})".format(fp[0], what, url))
            record_finding(self.directory, "noise", url, fp[0], fp[1], "{}+ identical responses muted".format(self.flood_limit))
        return count > self.flood_limit

    def waf(self, url, resp):
        vendor = waf_block(resp)
        if not vendor:
            return False
        with self.lock:
            count = self.wafs[vendor] = self.wafs.get(vendor, 0) + 1
        if count == 1:
            print("\033[K{} {} block page detected ({}) -> blocked paths are ignored".format(INFO, vendor, url))
            self.log("waf {} on {}".format(vendor, url))
            record_finding(self.directory, "waf", url, resp.status_code, len(resp.content or b""), "{} block page: blocked paths ignored".format(vendor))
        return True

    def _index(self, s, root):
        """Home page, fetched twice (dynamic part), to drop copies of it (?foo, index.html, ..;/)"""
        with self.lock:
            entry = self.index.get(root)
            if entry is not None:
                return entry
        pages = []
        for _ in range(2):
            try:
                pages.append(self.send(s, root))
            except Exception:
                pass
        entry = pages if pages else None
        with self.lock:
            if entry is not None:
                self.index[root] = entry
        return entry or []

    def same_as_index(self, s, root, resp):
        for page in self._index(s, root):
            if page.status_code != resp.status_code or other_title(resp, page):
                continue
            la, lb = len(resp.content or b""), len(page.content or b"")
            if abs(la - lb) <= max(3, 0.01 * lb) or same_template(resp, page):
                return True
        return False

    def is_noise(self, s, url, resp):
        root, parent, last, trail, query = split_url(url)
        fp = fingerprint(resp, root)
        if self.waf(url, resp):
            return True
        shape = shape_of(last, trail, query)
        stem = stem_of(last, trail, query, shape)
        if fp[0] in REDIRECTS and redirect_noise(url, resp.headers.get("Location", ""), stem):
            return True
        if self.enabled:
            base = self._baseline(s, root, parent, last, trail, shape)
            if base and self._match(fp, stem, base):
                return True
            if fp[0] == 200 and url != root and self.same_as_index(s, root, resp):
                return True
        return self.flood(fp, stem, url)
