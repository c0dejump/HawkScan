import sys, os, platform

v_python = "{}".format(sys.version)

if "3." in v_python:
	#install pip python3
	os.system("sudo pip3 install requests pyopenssl prettyprinter prettyprint queuelib fake_useragent python-whois argparse bs4 dnspython wafw00f python-whois sockets google")
elif "2." in v_python:
	os.system("sudo pip install requests pyopenssl prettyprinter prettyprint queuelib fake_useragent python-whois argparse bs4 dnspython wafw00f python-whois sockets google")