import requests
from detect_waf import verify_waf


def send(payl):
	req = requests.post("https://www.upwork.com/search/profiles/?nbs=1&q={}".format(payl))
	verify(req)

def verify(req):
	verify_waf(req)
	req_test = req

if __name__ == '__main__':
	payl = "<script>alert(1)</script>"
