import time
from config import LINE
from tools.Sublist3r import sublist3r

def subdomain(subdomains):
    """
    Subdomains:
    Check subdomains with the option -s (-s google.fr)
    script use sublit3r to scan subdomain (it's a basic scan)
    """
    print("search subdomains:\n")
    sub_file = "sublist/" + subdomains + ".txt"
    sublist3r.main(subdomains, 40, sub_file, ports=None, silent=False, verbose=False, enable_bruteforce=False, engines=None)
    print(LINE)
    time.sleep(2)