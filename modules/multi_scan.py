# -*- coding: utf-8 -*-
"""
Multi-site scan (-f): each website runs in its own hawkscan process (its own -t threads),
--parallel of them at the same time. Findings are shown live and gathered in one HTML report.
A process per site keeps every scan isolated (state, calibration, recursion) and uses all CPU cores.
"""
import glob
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from urllib.parse import urlsplit

from config import PLUS, INFO, WARNING, LESS, LINE, FORBI, BACK, SERV_ERR, BYP, S3
from report.html_report import build_report

# options handled by the orchestrator, not given to the per-site scans
STRIP_VALUE = {"-f", "-u", "-o", "-s", "--parallel", "--resume"}
SECRET_VALUE = {"-H", "--auth"} # never written in run.json
STRIP_FLAG = {"--html"}

TAGS = {
    "hit": PLUS, "forbidden": FORBI, "redirect": LESS, "error": SERV_ERR, "backup": BACK,
    "bypass": BYP, "secret": "\033[31m[SECRET] \033[0m", "s3": S3, "token": "\033[33m[KEY] \033[0m",
    "waf": "\033[36m[WAF] \033[0m", "noise": "\033[34m[MUTED] \033[0m",
}
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def child_args(argv):
    out, skip = [], False
    for a in argv:
        if skip:
            skip = False
            continue
        name = a.split("=", 1)[0]
        if name in STRIP_VALUE:
            skip = "=" not in a
            continue
        if name in STRIP_FLAG:
            continue
        out.append(a)
    if "--ffs" not in out and "--nfs" not in out:
        out.append("--nfs") # like before with -f: no first step (wayback, dorks...) unless --ffs
    return out


REASONS = [
    ("Connection refused", "connection refused"), ("NameResolutionError", "DNS resolution failed"),
    ("Name or service not known", "DNS resolution failed"), ("getaddrinfo failed", "DNS resolution failed"),
    ("SSLError", "SSL/TLS error"), ("ConnectTimeout", "connection timeout"), ("ReadTimeout", "read timeout"),
    ("timed out", "timeout"), ("RemoteDisconnected", "connection closed by the server"), ("ConnectionResetError", "connection reset"),
]


def log_tail(path):
    """Short reason of a failed scan, from the end of its log"""
    try:
        with open(path, errors="ignore") as f:
            text = ANSI.sub("", f.read()[-8000:]).replace("\r", "\n")
    except Exception:
        return ""
    for needle, reason in REASONS:
        if needle in text:
            return reason
    tail = [l.strip() for l in text.splitlines() if l.strip()]
    return tail[-1][:200] if tail else ""


class Job:
    def __init__(self, n, url, run_dir, script, args):
        self.url = url
        self.host = urlsplit(url).netloc or url
        name = "{:03d}_{}".format(n, re.sub(r"[^A-Za-z0-9._-]", "_", self.host))
        self.log = os.path.join(run_dir, "logs", name + ".log")
        self.info = os.path.join(run_dir, "logs", name + ".json")
        self.directory = None
        self.offset = 0
        self.counts = {}
        self.start = time.time()
        self.end = None
        self.status = "running"
        self.error = ""
        cmd = [sys.executable, script, "-u", url] + args + ["--batch", "--run-info", self.info]
        env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONWARNINGS="ignore")
        self.log_file = open(self.log, "w")
        self.proc = subprocess.Popen(cmd, stdout=self.log_file, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env)

    def read_info(self):
        try:
            with open(self.info) as f:
                return json.load(f)
        except Exception:
            return {}

    def new_findings(self):
        if not self.directory:
            self.directory = self.read_info().get("directory")
            if not self.directory:
                return []
        path = os.path.join(self.directory, "output", "findings.jsonl")
        if not os.path.exists(path):
            return []
        found = []
        with open(path, "rb") as f:
            f.seek(self.offset)
            data = f.read()
        complete = data[:data.rfind(b"\n") + 1] # a line being written is read next time
        self.offset += len(complete)
        for line in complete.decode("utf-8", "ignore").splitlines():
            try:
                found.append(json.loads(line))
            except ValueError:
                pass
        return found

    def finish(self, interrupted=False):
        self.end = time.time()
        self.log_file.close()
        info = self.read_info()
        self.directory = self.directory or info.get("directory")
        code = self.proc.returncode
        if code == 0 and info.get("status") == "done":
            self.status = "done"
        elif interrupted:
            self.status = "interrupted"
        elif not self.directory:
            self.status = "unreachable"
            self.error = log_tail(self.log)
        else:
            self.status = "error" if code else "done"
            self.error = log_tail(self.log) if code else ""

    def site(self, run_dir):
        return {
            "url": self.url,
            "status": self.status,
            "duration": (self.end or time.time()) - self.start,
            "error": self.error,
            "log": os.path.relpath(self.log, run_dir),
            "directories": [self.directory] if self.directory else [],
        }


def print_finding(job, f):
    kind = f.get("type")
    job.counts[kind] = job.counts.get(kind, 0) + 1
    if kind in ("keyword", "noise"): # low confidence / already said by the scan: report only
        return
    url = f.get("url") or ""
    path = url.split(job.host, 1)[1] if job.host in url else url
    detail = " \033[36m{}\033[0m".format(f["detail"]) if f.get("detail") else ""
    size = "[{}b]".format(f["size"]) if f.get("size") is not None else ""
    sys.stdout.write("\r\033[K\033[36m[{}]\033[0m {}{:<30.30} {:<5} {:<9} {}{}\n".format(
        f.get("time", ""), TAGS.get(kind, PLUS), job.host, f.get("status") or "", size, path, detail))


def summary(job):
    c = job.counts
    parts = ["{} {}".format(c[k], k) for k in ("bypass", "secret", "backup", "hit", "forbidden") if c.get(k)]
    took = int((job.end or time.time()) - job.start)
    if job.status == "done":
        head = "{}\033[32mdone\033[0m".format(PLUS)
    elif job.status == "interrupted":
        head = "{}\033[33minterrupted\033[0m".format(LESS)
    else:
        head = "{}\033[31m{}\033[0m".format(WARNING, job.status)
    if job.error:
        return "{} {} ({}s) \033[31m{}\033[0m".format(head, job.url, took, job.error)
    return "{} {} ({}s) {}".format(head, job.url, took, ", ".join(parts) if parts else "nothing found")


def save_run(run_dir, urls, args, parallel, meta):
    """run.json: what --resume needs (cookies / --auth are not saved, give them again)"""
    clean, skip, auth = [], False, False
    for a in args:
        if skip:
            skip = False
            continue
        if a.split("=", 1)[0] in SECRET_VALUE:
            auth, skip = True, "=" not in a
            continue
        clean.append(a)
    with open(os.path.join(run_dir, "run.json"), "w") as f:
        json.dump({"urls": urls, "args": clean, "parallel": parallel, "meta": meta, "authenticated": auth}, f, indent=1)


def args_from_meta(meta):
    """Runs made before run.json: options rebuilt from the report"""
    args = []
    if meta.get("wordlist") and meta["wordlist"] != "dichawk.txt":
        args += ["-w", meta["wordlist"]]
    if meta.get("threads"):
        args += ["-t", str(meta["threads"])]
    if meta.get("js analysis"):
        args.append("--js")
    if meta.get("recursive"):
        args.append("-r")
    if meta.get("backups"):
        args += ["-b"] + ([] if meta["backups"] == "default" else meta["backups"].split())
    if meta.get("calibration") is False:
        args.append("--no-calib")
    return args + ["--nfs"]


def load_run(run_dir):
    """Previous run: url list, options and the websites already finished (done / unreachable)"""
    info, sites, meta = {}, [], {}
    if os.path.exists(os.path.join(run_dir, "run.json")):
        with open(os.path.join(run_dir, "run.json")) as f:
            info = json.load(f)
    report = os.path.join(run_dir, "hawkscan_report.html")
    if os.path.exists(report):
        with open(report, encoding="utf-8", errors="ignore") as f:
            m = re.search(r'<script id="hs-data" type="application/json">(.*?)</script>', f.read(), re.S)
        if m:
            data = json.loads(m.group(1))
            sites, meta = data.get("sites", []), data.get("meta", {})
    urls = info.get("urls") or [s["url"] for s in sites]
    finished = {s["url"]: s for s in sites if s.get("status") in ("done", "unreachable")}
    last = 0
    for path in glob.glob(os.path.join(run_dir, "logs", "*")):
        name = os.path.basename(path)
        if name[:3].isdigit():
            last = max(last, int(name[:3]))
        if name.endswith(".json"): # a scan finished after the report (orchestrator killed)
            try:
                with open(path) as f:
                    d = json.load(f)
            except Exception:
                continue
            if d.get("status") == "done" and d.get("url") and d["url"] not in finished:
                finished[d["url"]] = {"url": d["url"], "status": "done", "directories": [d.get("directory")],
                                      "log": os.path.relpath(path[:-5] + ".log", run_dir)}
    return urls, finished, info, info.get("meta") or meta, last


def scan_multiple(urls, argv, parallel, html, script, meta=None, resume_dir=None):
    args = child_args(argv)
    finished, first = {}, 0
    if resume_dir:
        run_dir = resume_dir.rstrip("/")
        old_urls, finished, info, old_meta, first = load_run(run_dir)
        urls = urls or old_urls
        if not urls:
            print("{} Nothing to resume in {} (no run.json / report): give the list again with -f".format(WARNING, run_dir))
            return
        if args == ["--nfs"]: # no option given: the ones of the first run
            args = info.get("args") or args_from_meta(old_meta or {})
            meta = old_meta or meta
            print("{} Options of the first run: {}".format(INFO, " ".join(args)))
            if info.get("authenticated") or (old_meta or {}).get("authenticated"):
                print("{} The first run was authenticated: give -H / --auth again".format(WARNING))
        parallel = parallel or info.get("parallel")
    else:
        run_dir = os.path.join("sites", "_multi_{}".format(datetime.now().strftime("%Y-%m-%d_%H-%M-%S")))
        os.makedirs(os.path.join(run_dir, "logs"))
    parallel = max(1, parallel or 3)
    save_run(run_dir, urls, args, parallel, meta)
    pending = [u for u in urls if u not in finished]
    running, jobs = [], []
    print("{} {} websites{}, {} at the same time. Logs: {}/logs/".format(
        INFO, len(urls), " ({} already done)".format(len(urls) - len(pending)) if finished else "", parallel, run_dir))
    print(LINE)

    def poll(interrupted=False):
        for job in list(running):
            for f in job.new_findings():
                print_finding(job, f)
            if job.proc.poll() is not None:
                for f in job.new_findings():
                    print_finding(job, f)
                job.finish(interrupted)
                running.remove(job)
                sys.stdout.write("\r\033[K" + summary(job) + "\n")

    try:
        while pending or running:
            while pending and len(running) < parallel:
                job = Job(first + len(jobs) + 1, pending.pop(0), run_dir, script, args)
                running.append(job)
                jobs.append(job)
            time.sleep(1)
            poll()
            sys.stdout.write("\r\033[K\033[36m {}/{} done | running: {}\033[0m".format(
                len(urls) - len(pending) - len(running), len(urls), ", ".join(j.host for j in running)[:150]))
            sys.stdout.flush()
    except KeyboardInterrupt:
        # Ctrl+C reaches the scans too: they stop cleanly, the report is made with what was found
        print("\n{} Canceled by keyboard interrupt (Ctrl-C), stopping {} scan(s)...".format(INFO, len(running)))
        deadline = time.time() + 20
        try:
            for job in running:
                try:
                    job.proc.wait(timeout=max(1, deadline - time.time()))
                except subprocess.TimeoutExpired:
                    job.proc.kill()
                    job.proc.wait()
        except KeyboardInterrupt:
            for job in running:
                job.proc.kill()
                job.proc.wait()
        poll(interrupted=True)

    print("\r\033[K" + LINE)
    ok = len([j for j in jobs if j.status == "done"]) + len([s for s in finished.values() if s.get("status") == "done"])
    print("{} {}/{} websites scanned".format(INFO, ok, len(urls)))
    left = len(pending) + len([j for j in jobs if j.status == "interrupted"])
    if left:
        print("{} {} websites left, to continue: python3 hawkscan.py --resume {}".format(INFO, left, run_dir))
    if html:
        by_url = dict(finished)
        by_url.update({j.url: j.site(run_dir) for j in jobs})
        sites = [by_url.get(u) or {"url": u, "status": "not scanned"} for u in urls]
        path = build_report(sites, os.path.join(run_dir, "hawkscan_report.html"), meta)
        print("{} HTML report: {}".format(PLUS, os.path.abspath(path)))
    print(LINE)
