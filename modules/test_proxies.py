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
            print(proxies)
            req = session.get(url, verify=False, timeout=15, proxies=proxies)
            print(req)
            list_ips.append(d.rstrip())
            print("ok")
        except:
            proxies = {
                'https': '{}'.format(proxie.rstrip())
                }
            try:
                req = session.get(url, verify=False, timeout=15, proxies=proxies)
                list_ips.append(d.rstrip())
                print(req)
                print("ok2")
            except:
                pass
        q.task_done()
        sys.stdout.write(" {}/{}\r".format(l, n))

if __name__ == '__main__':
    n = 0

    global list_ips
    list_ips = []

    url = "https://httpbin.org/ip"

    with open("../../BB-TOOLS/Proxy List-1.txt", "r") as datas:
        for data in datas:
            n += 1
    print(" Proxy IPs checking, please wait...")
    try:
        with open("../../BB-TOOLS/Proxy List-1.txt", "r") as datas:
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