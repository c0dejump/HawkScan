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


logging.basicConfig(level=logging.INFO, filename="proxy_checker.log", filemode="a",
                        format="%(asctime)s - %(levelname)s - %(message)s")
    proxy_list_file = "path/to/your/proxy_list.txt"
    checked_proxies = check_proxy(proxy_list_file)
    logging.info("Checked proxies: %s", checked_proxies)


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def proxy_checker(i, q, n, url):
    session = requests.session()
    while True:
        proxie = q.get()
        try:
            proxies = {'http': proxie.rstrip(), 'https': proxie.rstrip()}
            req = session.get(url, verify=False, timeout=10, proxies=proxies)
            list_ips.append(proxie.rstrip())
        except requests.exceptions.RequestException as e:
            logging.error("Error while checking proxy: %s", e)
            handle_proxy_error(proxie)
        finally:
            q.task_done()

def handle_proxy_error(proxie):
    with list_ips_lock:
        list_ips.remove(proxie.rstrip())


def check_proxy(proxy_list, num_threads=10):
    global list_ips
    list_ips = []

    url = "https://httpbin.org/ip"

    with open(proxy_list, "r") as datas:
        proxy_data = [d.strip() for d in datas]

    logging.info("Proxy IPs checking, please wait...")
    try:
        with Queue.Queue() as enclosure_queue:
            for data in proxy_data:
                enclosure_queue.put(data)

            for i in range(num_threads):
                worker = threading.Thread(target=proxy_checker, args=(i, enclosure_queue, url))
                worker.setDaemon(True)
                worker.start()

            enclosure_queue.join()

    except KeyboardInterrupt:
        logging.warning("Canceled by keyboard interrupt (Ctrl-C)")
        sys.exit()

    return list_ips
