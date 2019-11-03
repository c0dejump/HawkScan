#!/usr/bin/env python
import requests
import sys
import json
import argparse
import warnings
import sys
import urlparse
import socket
import multiprocessing
warnings.filterwarnings("ignore")

parser = argparse.ArgumentParser(description='Tool for parsing WayBack URLs.')

parser.add_argument('function', help="`pull` or `check`. `pull` will gather the urls from the WayBack API. `check` will ensure the response code is positive (200,301,302,307).")
parser.add_argument('--host', help='The host whose URLs should be retrieved.')
parser.add_argument('--threads', help='The number of threads to use (Default 5)', default=5)
parser.add_argument('--with-subs', help='`yes` or `no`. Retrieve urls from subdomains of the host.', default=True)
parser.add_argument('--loadfile', help='Location of file from which urls should be checked.')
parser.add_argument('--outputfile', help='Location of the file to which checked urls should be reported')

args = parser.parse_args()


def waybackurls(host, with_subs):
    if with_subs:
        url = 'http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=list&fl=original&collapse=urlkey' % host
    else:
        url = 'http://web.archive.org/cdx/search/cdx?url=%s/*&output=list&fl=original&collapse=urlkey' % host
    r = requests.get(url)   
    if args.outputfile:
        j = open(args.outputfile, "w")
        j.write(r.text.strip())
        j.close()
    print r.text.strip()
    

def check(url):
    global timeout
    if url == "":
        return
    url = url.replace(":80/", "/").replace(":443/", "/")
    if not url.startswith("http"):
        url = "http://"+url
    domain = urlparse.urlparse(url).netloc.split(":")[0]
    if domain in timeout:
        return
    try:
        req = requests.head(url, verify=False, timeout=.25)
    except requests.exceptions.Timeout:
        timeout.append(domain)
        return
    except requests.exceptions.ConnectionError:
        timeout.append(domain)
        return
    if str(req.status_code)[0] == "3" and url.startswith("http://") and req.headers['Location'].startswith("https://"):
        try:
            req = requests.head("https"+url[4:], verify=False, timeout=.25)
        except requests.exceptions.Timeout:
            return
    status_code = req.status_code
    if status_code == 404:
        return
    if "Content-Length" in req.headers.keys():
        cLength = req.headers["Content-Length"]
    else:
        cLength = "Unknown"
    if  "Content-Type" in req.headers.keys():
        cType = req.headers["Content-Type"]
    else:
        cType = "Unknown"
    if str(status_code)[0] == "3":
        rUrl = req.headers["Location"]
        print ", ".join([url, str(status_code), cLength, cType, rUrl])
        if args.outputfile:
            writeQueue.put(", ".join([url, str(status_code), cLength, cType, rUrl])+"\n")
    else:
        print ", ".join([url, str(status_code), cLength, cType])
        if args.outputfile:
            writeQueue.put(", ".join([url, str(status_code), cLength, cType])+"\n")

def checkValidDomain(endpoints):
    validDomains = []
    invalidDomains = []
    validEndpoints = []
    for endpoint in endpoints:
        endpoint = endpoint.strip().strip("\r").strip('"').strip("'")
        try:
            parsedUrl = urlparse.urlparse(endpoint)
            domain = parsedUrl.netloc.split(":")[0]# split is to remove hosts of the following form: example.com:80
            if domain in validDomains:
                validEndpoints.append(endpoint)
                continue
            elif domain in invalidDomains:
                continue
            try:
                socket.gethostbyname(domain)# Will throw error if name doesn't resolve
                validDomains.append(domain)
                validEndpoints.append(endpoint)
            except:
                invalidDomains.append(domain)
        except:# URL parsing error or resolving error
            continue
    return validEndpoints

def writer(fileToWrite):
    while True:
        line = writeQueue.get(True) # True allows it block until item is available
        if line == None:
            break
        fileToWrite.write(line)

manager = multiprocessing.Manager()
timeout = manager.list()
writeQueue = manager.Queue()
pool = multiprocessing.Pool(args.threads)
if args.function == "pull":
    if args.host:
        waybackurls(args.host, args.with_subs)
    elif args.loadfile:
        for line in open(args.loadfile).readlines():
            waybackurls(line.strip(), args.with_subs)

elif args.function == "check":
    if args.loadfile:
        try:
            if args.outputfile:
                outputfile = open(args.outputfile, "w", 0)
                p = multiprocessing.Process(target=writer, args=(outputfile,))
                p.start()
            endpoints = checkValidDomain(open(args.loadfile).readlines())
            pool.map(check, endpoints)
            if args.outputfile:
                writeQueue.put(None)
                p.join()
                outputfile.close()
        except IOError as e:
            print "[-] File not found!"
            sys.exit(1)
        except KeyboardInterrupt as e:
            print "[-] Killing processes..."
            pool.terminate()
            sys.exit(1)
        except Exception as e:
            print "[-] Unknown Error: "+str(e)

    elif not sys.stdin.isatty():
        try:
            if args.outputfile:
                outputfile = open(args.outputfile, "w", 0)
                p = multiprocessing.Process(target=writer, args=(outputfile,))
                p.start()
            endpoints = checkValidDomain(sys.stdin.readlines())
            pool.map(check, endpoints)
            if args.outputfile:
                writeQueue.put(None)
                p.join()
                outputfile.close()
        except IOError as e:
            print e
            print "[-] File not found!"
            sys.exit(1)
        except KeyboardInterrupt as e:
            print "[-] Killing processes..."
            pool.terminate()
            sys.exit(1)
        except Exception as e:
            print "[-] Unknown Error: "+str(e)
    else:
        print "[-] Please either specify a file using --loadfile or pipe some data in!"
        exit()
