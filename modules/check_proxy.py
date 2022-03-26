import requests
import json
import random
import sys
import traceback

try:
    from Queue import Queue
except:
    import queue as Queue
import threading
from threading import Thread
try:
    enclosure_queue = Queue()
except:
    enclosure_queue = Queue.Queue()


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def proxy(i, q, n, url):
    session = requests.session()
    for l in range(n):
        proxie = q.get()
        try:
            proxies = {
                'http': proxie.rstrip(),
                'https': proxie.rstrip()
                }
            req = session.get(url, verify=False, timeout=10, proxies=proxies)
            list_ips.append(proxie.rstrip())
        except:
            #traceback.print_exc()
            proxies = {
                'https': '{}'.format(proxie.rstrip())
                }
            try:
                req = session.get(url, verify=False, timeout=10, proxies=proxies)
                list_ips.append(proxie.rstrip())
            except:
                #traceback.print_exc()
                pass
        q.task_done()

def check_proxy(proxy_list):
    global list_ips
    list_ips = []

    n = 0

    url = "https://httpbin.org/ip"

    with open(proxy_list, "r") as datas:
        for data in datas:
            n += 1
    print(" Proxy IPs checking, please wait...")
    try:
        with open(proxy_list, "r") as datas:
            for d in datas:
                enclosure_queue.put(d.rstrip())
        for i in range(10):
            worker = Thread(target=proxy, args=(i, enclosure_queue, n, url))
            worker.setDaemon(True)
            worker.start()
        enclosure_queue.join()
    except KeyboardInterrupt:
        print(" Canceled by keyboard interrupt (Ctrl-C)")
        sys.exit()
    except Exception:
        traceback.print_exc()
    print(list_ips)
    return(list_ips)