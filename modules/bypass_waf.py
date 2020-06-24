import requests
import socket
import traceback
from modules.detect_waf import verify_waf
from config import PLUS, WARNING, INFO

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def bypass_waf(req, res):
	"""
	Bypass_waf: try if the waf can be bypass, using different payloads
	"""
	win = False
	domain = res.split("/")[2]
	website_ip = socket.gethostbyname(domain) # take ip website
	header_base = [
	"X-Originating-IP", 
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Remote-IP",
	"X-Remote-Addr",
	"X-Client-IP",
	"Cookie",
	"Access-Control-Allow-Origin",
	"Origin",
	"Timing-Allow-Origin"
	]
	options = [website_ip, domain, "127.0.0.1", "*"]
	for hb in header_base:
		for o in options:
			headers = {
				hb : o
			}
			try:
				display = False
				vrfy = verify_waf(req, res, headers, display)
				#print(vrfy)
				if vrfy == False:
					#win = True
					print("{} You can bypass with: {} !".format(PLUS, headers))
					return headers
			except Exception:
				traceback.print_exc()
	if not win:
		try:
			headers = {
			"Clear-Site-Data":"*"
			}
			display = False
			vrfy = verify_waf(req, res, headers, display)
			if vrfy == False:
				#win = True
				print("{} You can bypass with: {} !".format(PLUS, headers))
				return headers
		except:
			traceback.print_exc()
		#print("\033[31m[:(]\033[0m Our tests not bypass it, sorry")
	return win

"""if __name__ == '__main__':
	req = "plop"
	user_agent = False
	res = "https://transferwise.com/"
	bypass_waf(req, res)"""