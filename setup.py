import sys, os, platform

v_python = "{}".format(sys.version)

if "3." in v_python:
	#install pip python3
	os.system("pip3 install requests pyopenssl prettyprinter prettyprint queuelib fake_useragent python-whois argparse bs4 dnspython wafw00f python-whois sockets")
elif "2." in v_python:
	os.system("pip install requests pyopenssl prettyprinter prettyprint queuelib fake_useragent python-whois argparse bs4 dnspython wafw00f python-whois sockets")
