import requests
import sys, os, re
import dns.resolver
import argparse
from Queue import Queue
from threading import Thread
from config import PLUS, WARNING, INFO, LESS, LINE, FORBI

enclosure_queue = Queue()

#search subdomains
def trySub(i, q, directory, subs):
    while True:
        try:
            res = q.get()
            try:
                req = dns.resolver.query(res, 'A')
                req
                for rdata in req:
                    print "{}{} : {}".format(PLUS, res, rdata)
                subs.append(res)
            except:
                pass
            q.task_done()
        except:
            #print "{} error threads".format(INFO)
            pass


#multi threading
def main(domain, wordlist, directory):
    subs = []
    link_url = []
    with open(wordlist, "r") as payload:
        links = payload.read().splitlines()
    for i in range(20):
        worker = Thread(target=trySub, args=(i, enclosure_queue, directory, subs))
        worker.setDaemon(True)
        worker.start()
    for link in links:
        link_url = link + "." + domain
        enclosure_queue.put(link_url)
    enclosure_queue.join()
    return subs


if __name__ == '__main__':
    main(domain, wordlist, directory)
