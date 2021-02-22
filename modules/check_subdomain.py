import sys
from config import INFO
try:
    from tools.Sublist3r import sublist3r
except Exception:
    if sys.version > '3':
        print("\n{}subbrute doesn't work with this script on py3 version for the moment sorry".format(INFO))
    pass

def subdomain(subdomains):
    """
    Subdomains:
    Check subdomains with the option -s (-s google.fr)
    script use sublit3r to scan subdomain (it's a basic scan)
    """
    print("search subdomains:\n")
    sub_file = "sublist/" + subdomains + ".txt"
    sub = sublist3r.main(subdomains, 40, sub_file, ports=None, silent=False, verbose=False, enable_bruteforce=False, engines=None)
    print(LINE)
    time.sleep(2)