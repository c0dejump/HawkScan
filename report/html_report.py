# -*- coding: utf-8 -*-
"""
HTML report (--html): one self-contained page (no external resource) for one or several scanned sites.
Data comes from each site's output/findings.jsonl (output/raw.txt for older scans).
"""
import json
import os
import re
from datetime import datetime
from urllib.parse import urlsplit


def read_findings(directory):
    findings = []
    path = os.path.join(directory, "output", "findings.jsonl")
    if os.path.exists(path):
        with open(path, errors="ignore") as f:
            for line in f:
                try:
                    findings.append(json.loads(line))
                except ValueError:
                    pass
    else: # scans made before the findings.jsonl
        raw = os.path.join(directory, "output", "raw.txt")
        if os.path.exists(raw):
            with open(raw, errors="ignore") as f:
                for line in f:
                    m = re.match(r"url, (.+), (\d+), (\d+)b", line.strip())
                    if m:
                        status = int(m.group(2))
                        kind = {200: "hit", 301: "redirect", 302: "redirect", 401: "forbidden", 403: "forbidden"}.get(status, "error")
                        findings.append({"type": kind, "url": m.group(1), "status": status, "size": int(m.group(3))})
    return findings


# per website: low value types are capped (a catch-all missed = thousands of rows and a report too big to open)
CAPS = {"redirect": 150, "forbidden": 150, "error": 150, "keyword": 100, "noise": 50, "token": 100, "waf": 20, "hit": 500}


def build_report(sites, out_path, meta=None):
    """
    sites: [{"url", "status", "duration", "error", "directories": [...], "log"}]
    """
    rows, seen = [], set()
    for site in sites:
        host = urlsplit(site["url"]).netloc or site["url"]
        site["host"] = host
        kept, hidden = {}, {}
        for directory in site.get("directories") or []:
            if not directory:
                continue
            for f in read_findings(directory):
                key = (f.get("type"), f.get("url"), f.get("detail"))
                if key in seen:
                    continue
                seen.add(key)
                kind = f.get("type") or "hit"
                kept[kind] = kept.get(kind, 0) + 1
                if kept[kind] > CAPS.get(kind, 10 ** 9):
                    hidden[kind] = hidden.get(kind, 0) + 1
                    continue
                url = f.get("url") or ""
                rows.append({
                    "site": host,
                    "type": f.get("type") or "hit",
                    "url": url,
                    "path": url.split(host, 1)[1] if host in url else url,
                    "status": f.get("status"),
                    "size": f.get("size"),
                    "detail": f.get("detail") or "",
                    "time": f.get("time") or "",
                })
        site["hidden"] = hidden
    data = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "meta": meta or {},
        "sites": [{k: s.get(k) for k in ("url", "host", "status", "duration", "error", "log", "hidden")} for s in sites],
        "findings": rows,
    }
    blob = json.dumps(data).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    blob = blob.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(TEMPLATE.replace("__HAWKSCAN_DATA__", blob))
    return out_path


TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HawkScan report</title>
<style>
:root{
  --bg:#f5f6f8; --panel:#ffffff; --panel-2:#f0f2f5; --text:#1a1d23; --muted:#5d6876; --border:#dfe3e8;
  --accent:#2457d6; --accent-bg:#e8eefc;
  --crit:#c62a1d; --crit-bg:#fdecea; --high:#c4520a; --high-bg:#fff0e3; --med:#946200; --med-bg:#fdf4dc;
  --info:#1d7a45; --info-bg:#e5f5ec; --low:#5b6472; --low-bg:#eef0f3;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,sans-serif;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --bg:#0e1116; --panel:#161a21; --panel-2:#1c212a; --text:#e4e8ee; --muted:#8f9bab; --border:#29303a;
    --accent:#7aa7ff; --accent-bg:#1b2840;
    --crit:#ff7b6e; --crit-bg:#3b1815; --high:#ffa057; --high-bg:#3a2413; --med:#f0c75e; --med-bg:#352c12;
    --info:#4fd18b; --info-bg:#122e1f; --low:#9aa4b2; --low-bg:#222831;
  }
}
:root[data-theme="dark"]{
  --bg:#0e1116; --panel:#161a21; --panel-2:#1c212a; --text:#e4e8ee; --muted:#8f9bab; --border:#29303a;
  --accent:#7aa7ff; --accent-bg:#1b2840;
  --crit:#ff7b6e; --crit-bg:#3b1815; --high:#ffa057; --high-bg:#3a2413; --med:#f0c75e; --med-bg:#352c12;
  --info:#4fd18b; --info-bg:#122e1f; --low:#9aa4b2; --low-bg:#222831;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 var(--sans)}
.wrap{max-width:1400px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;justify-content:space-between;margin-bottom:20px}
h1{font-size:22px;margin:0;letter-spacing:-.01em}
h1 span{color:var(--accent)}
h2{font-size:15px;margin:0 0 12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.sub{color:var(--muted);font-size:13px}
.meta{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.pill{border:1px solid var(--border);background:var(--panel);border-radius:999px;padding:2px 10px;font-size:12px;color:var(--muted)}
.pill b{color:var(--text);font-weight:600}
button,select,input{font:inherit;color:var(--text)}
.btn{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:6px 12px;cursor:pointer}
.btn:hover{border-color:var(--accent)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}
.kpi{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
.kpi .v{font-size:26px;font-weight:700;line-height:1.1;font-variant-numeric:tabular-nums}
.kpi .l{color:var(--muted);font-size:12px;margin-top:4px}
.kpi.crit .v{color:var(--crit)} .kpi.high .v{color:var(--high)} .kpi.info .v{color:var(--info)}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px;margin-bottom:20px}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600;white-space:nowrap;user-select:none}
th.sortable{cursor:pointer}
th.sortable:hover{color:var(--text)}
tbody tr:hover{background:var(--panel-2)}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}
td.url{font-family:var(--mono);font-size:12.5px;word-break:break-all;min-width:240px}
td.detail{font-family:var(--mono);font-size:12px;color:var(--muted);word-break:break-all;max-width:420px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.badge{display:inline-block;border-radius:6px;padding:1px 8px;font-size:12px;font-weight:600;white-space:nowrap}
.s4{color:var(--crit);background:var(--crit-bg)} .s3{color:var(--high);background:var(--high-bg)}
.s2{color:var(--med);background:var(--med-bg)} .s1{color:var(--info);background:var(--info-bg)} .s0{color:var(--low);background:var(--low-bg)}
.st-done{color:var(--info)} .st-error,.st-unreachable{color:var(--crit)} .st-interrupted,.st-running{color:var(--high)}
.sites tbody tr{cursor:pointer}
.sites tbody tr.active{background:var(--accent-bg)}
.zero{color:var(--muted);opacity:.5}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.toolbar input[type=search]{flex:1 1 260px;min-width:0;background:var(--panel-2);border:1px solid var(--border);border-radius:8px;padding:7px 10px}
.toolbar select{background:var(--panel-2);border:1px solid var(--border);border-radius:8px;padding:7px 8px;max-width:100%}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}
.chip{border:1px solid var(--border);background:var(--panel-2);border-radius:999px;padding:3px 10px;font-size:12px;cursor:pointer;color:var(--muted)}
.chip.on{color:var(--text);border-color:var(--accent);background:var(--accent-bg)}
.chip .n{opacity:.7;margin-left:4px;font-variant-numeric:tabular-nums}
.count{color:var(--muted);font-size:12px;margin-left:auto}
.hl{list-style:none;margin:0;padding:0}
.hl li{display:flex;flex-wrap:wrap;gap:8px;align-items:baseline;padding:8px 0;border-bottom:1px solid var(--border)}
.hl li:last-child{border-bottom:0}
.hl .host{color:var(--muted);font-size:12px}
.hl .u{font-family:var(--mono);font-size:12.5px;word-break:break-all}
.hl .d{font-family:var(--mono);font-size:12px;color:var(--muted);word-break:break-all;flex-basis:100%}
.empty{color:var(--muted);padding:16px 0;text-align:center}
.hid{color:var(--muted);font-size:12px}
.err{color:var(--crit);font-size:12px;font-family:var(--mono);overflow-wrap:anywhere}
footer{color:var(--muted);font-size:12px;margin-top:24px}
@media (max-width:640px){
  .kpi .v{font-size:22px}
  .findings thead{display:none}
  .findings tbody tr{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 10px;padding:10px 0;border-bottom:1px solid var(--border)}
  .findings td{border:0;padding:0}
  .findings td.url{flex-basis:100%;min-width:0}
  .findings td.detail{flex-basis:100%;max-width:none}
  .findings td.empty{flex-basis:100%}
}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1><span>HawkScan</span> report</h1>
      <div class="sub" id="sub"></div>
      <div class="meta" id="meta"></div>
    </div>
    <button class="btn" id="theme" type="button" title="Theme">Theme: auto</button>
  </header>

  <section class="kpis" id="kpis"></section>

  <section class="card" id="hl-card">
    <h2>Highlights</h2>
    <ul class="hl" id="hl"></ul>
  </section>

  <section class="card">
    <h2>Sites</h2>
    <div class="scroll"><table class="sites"><thead><tr>
      <th>Site</th><th>Status</th><th>Duration</th><th>Bypass</th><th>Secrets</th><th>Backups</th><th>200</th><th>403</th><th>3xx</th><th>Errors</th>
    </tr></thead><tbody id="sites"></tbody></table></div>
  </section>

  <section class="card" id="findings-card">
    <h2>Findings</h2>
    <div class="toolbar">
      <input type="search" id="q" placeholder="Filter: url, detail, status, size..." aria-label="Filter findings">
      <select id="site" aria-label="Site"></select>
      <button class="btn" id="copy" type="button">Copy URLs</button>
      <button class="btn" id="csv" type="button">CSV</button>
    </div>
    <div class="chips" id="chips"></div>
    <div class="scroll"><table class="findings"><thead><tr>
      <th class="sortable" data-k="sev">Type</th><th class="sortable" data-k="site">Site</th><th class="sortable" data-k="status">Status</th>
      <th class="sortable" data-k="size">Size</th><th class="sortable" data-k="path">URL</th><th>Detail</th>
    </tr></thead><tbody id="rows"></tbody></table></div>
    <div class="toolbar" style="margin-top:10px"><span class="count" id="count"></span></div>
  </section>

  <footer id="foot"></footer>
</div>

<script id="hs-data" type="application/json">__HAWKSCAN_DATA__</script>
<script>
(function(){
  "use strict";
  var DATA = JSON.parse(document.getElementById("hs-data").textContent);
  var TYPES = {
    bypass:{label:"403 bypass", sev:4}, secret:{label:"Secret", sev:4}, backup:{label:"Backup", sev:3},
    s3:{label:"S3 bucket", sev:3}, hit:{label:"200", sev:1}, token:{label:"Public key", sev:1}, error:{label:"Error", sev:0},
    forbidden:{label:"403", sev:0}, redirect:{label:"Redirect", sev:0}, waf:{label:"WAF", sev:0},
    keyword:{label:"JS keyword", sev:0}, noise:{label:"Muted", sev:0}
  };
  var ORDER = ["bypass","secret","backup","s3","hit","token","forbidden","redirect","error","waf","keyword","noise"];
  var F = DATA.findings.map(function(f){
    var t = TYPES[f.type] || {label:f.type, sev:0};
    f.sev = t.sev; f.label = t.label; return f;
  });
  var MAX_ROWS = 2000;
  var state = {q:"", site:"", types:{}, sort:"sev", dir:-1};
  ORDER.forEach(function(t){ state.types[t] = t !== "keyword" && t !== "noise"; });

  function el(tag, cls, text){
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function link(url, text){
    if (/^https?:\/\//i.test(url)) {
      var a = el("a", null, text); a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer"; return a;
    }
    return el("span", null, text);
  }
  function badge(f){ return el("span", "badge s" + f.sev, f.label); }
  function fmtSize(n){
    if (n === null || n === undefined || n === "") return "";
    n = Number(n); if (isNaN(n)) return "";
    return n < 1024 ? n + " B" : n < 1048576 ? (n/1024).toFixed(1) + " KB" : (n/1048576).toFixed(1) + " MB";
  }
  function fmtDur(s){
    if (s === null || s === undefined) return "";
    s = Math.round(s); var m = Math.floor(s/60);
    return m ? m + "m " + (s%60) + "s" : s + "s";
  }
  function count(list, fn){ var n = 0; list.forEach(function(x){ if (fn(x)) n++; }); return n; }

  // header
  var sites = DATA.sites;
  document.getElementById("sub").textContent = "Generated " + DATA.generated + " \u00b7 " + sites.length + " site" + (sites.length > 1 ? "s" : "");
  var meta = document.getElementById("meta");
  Object.keys(DATA.meta || {}).forEach(function(k){
    var v = DATA.meta[k]; if (v === null || v === undefined || v === false || v === "") return;
    var p = el("span", "pill"); p.appendChild(document.createTextNode(k + ": "));
    p.appendChild(el("b", null, v === true ? "yes" : v)); meta.appendChild(p);
  });

  // KPIs
  var kpis = [
    ["Sites scanned", count(sites, function(s){ return s.status === "done"; }) + "/" + sites.length, ""],
    ["Findings", count(F, function(f){ return ["keyword", "noise", "waf"].indexOf(f.type) < 0; }), ""],
    ["403 bypasses", count(F, function(f){ return f.type === "bypass"; }), "crit"],
    ["Secrets", count(F, function(f){ return f.type === "secret"; }), "crit"],
    ["Backups", count(F, function(f){ return f.type === "backup"; }), "high"],
    ["200 hits", count(F, function(f){ return f.type === "hit"; }), "info"],
    ["403", count(F, function(f){ return f.type === "forbidden"; }), ""]
  ];
  var kbox = document.getElementById("kpis");
  kpis.forEach(function(k){
    var d = el("div", "kpi " + k[2]); d.appendChild(el("div", "v", k[1])); d.appendChild(el("div", "l", k[0])); kbox.appendChild(d);
  });

  // highlights
  var hl = F.filter(function(f){ return f.sev >= 2; }).sort(function(a, b){ return b.sev - a.sev; });
  var hlBox = document.getElementById("hl");
  if (!hl.length) hlBox.appendChild(el("li", "empty", "No bypass, secret, backup or S3 bucket found."));
  hl.slice(0, 60).forEach(function(f){
    var li = el("li"); li.appendChild(badge(f));
    li.appendChild(el("span", "host", f.site));
    var u = el("span", "u"); u.appendChild(link(f.url, f.path || f.url)); li.appendChild(u);
    if (f.status) li.appendChild(el("span", "host", "[" + f.status + "] " + fmtSize(f.size)));
    if (f.detail) li.appendChild(el("span", "d", f.detail));
    hlBox.appendChild(li);
  });
  if (hl.length > 60) hlBox.appendChild(el("li", "empty", (hl.length - 60) + " more in the findings table"));

  // sites table
  var sBody = document.getElementById("sites");
  sites.forEach(function(s){
    var mine = F.filter(function(f){ return f.site === s.host; });
    var tr = el("tr"); tr.dataset.host = s.host;
    var td = el("td"); td.appendChild(link(s.url, s.host));
    if (s.error) td.appendChild(el("div", "err", s.error));
    var hid = Object.keys(s.hidden || {}).map(function(k){ return s.hidden[k] + " " + ((TYPES[k] || {}).label || k); });
    if (hid.length) td.appendChild(el("div", "hid", "+ " + hid.join(", ") + " not shown (too many)"));
    tr.appendChild(td);
    tr.appendChild(el("td", "st-" + (s.status || ""), s.status || ""));
    tr.appendChild(el("td", "num", fmtDur(s.duration)));
    [["bypass"],["secret"],["backup"],["hit"],["forbidden"],["redirect"],["error"]].forEach(function(t){
      var n = count(mine, function(f){ return f.type === t[0]; });
      tr.appendChild(el("td", "num" + (n ? "" : " zero"), n));
    });
    tr.addEventListener("click", function(){
      state.site = state.site === s.host ? "" : s.host;
      document.getElementById("site").value = state.site; render();
      if (state.site) document.getElementById("findings-card").scrollIntoView({behavior:"smooth"});
    });
    sBody.appendChild(tr);
  });

  // filters
  var siteSel = document.getElementById("site");
  siteSel.appendChild(new Option("All sites", ""));
  sites.forEach(function(s){ siteSel.appendChild(new Option(s.host, s.host)); });
  siteSel.addEventListener("change", function(){ state.site = siteSel.value; render(); });
  document.getElementById("q").addEventListener("input", function(e){ state.q = e.target.value.toLowerCase(); render(); });
  var chips = document.getElementById("chips");
  ORDER.forEach(function(t){
    var n = count(F, function(f){ return f.type === t; }); if (!n) return;
    var c = el("button", "chip"); c.type = "button"; c.dataset.t = t;
    c.appendChild(document.createTextNode(TYPES[t].label)); c.appendChild(el("span", "n", n));
    c.addEventListener("click", function(){ state.types[t] = !state.types[t]; render(); });
    chips.appendChild(c);
  });
  Array.prototype.forEach.call(document.querySelectorAll("th.sortable"), function(th){
    th.addEventListener("click", function(){
      var k = th.dataset.k; state.dir = state.sort === k ? -state.dir : (k === "sev" || k === "size" ? -1 : 1); state.sort = k; render();
    });
  });

  function filtered(){
    return F.filter(function(f){
      if (!state.types[f.type] && TYPES[f.type]) return false;
      if (state.site && f.site !== state.site) return false;
      if (state.q) {
        var hay = (f.url + " " + f.detail + " " + f.status + " " + f.size + " " + f.label).toLowerCase();
        if (hay.indexOf(state.q) < 0) return false;
      }
      return true;
    }).sort(function(a, b){
      var x = a[state.sort], y = b[state.sort];
      if (state.sort === "sev" && x === y) { x = a.site + a.path; y = b.site + b.path; return x < y ? -1 : x > y ? 1 : 0; }
      if (x === y) return 0;
      if (x === null || x === undefined) return 1;
      if (y === null || y === undefined) return -1;
      return (x < y ? -1 : 1) * state.dir;
    });
  }

  var body = document.getElementById("rows");
  function render(){
    Array.prototype.forEach.call(chips.children, function(c){ c.classList.toggle("on", !!state.types[c.dataset.t]); });
    Array.prototype.forEach.call(sBody.children, function(tr){ tr.classList.toggle("active", tr.dataset.host === state.site); });
    var list = filtered();
    body.textContent = "";
    if (!list.length) { var tr0 = el("tr"); var td0 = el("td", "empty", "Nothing matches the filters."); td0.colSpan = 6; tr0.appendChild(td0); body.appendChild(tr0); }
    var frag = document.createDocumentFragment();
    list.slice(0, MAX_ROWS).forEach(function(f){
      var tr = el("tr");
      var t = el("td"); t.appendChild(badge(f)); tr.appendChild(t);
      tr.appendChild(el("td", null, f.site));
      tr.appendChild(el("td", "num", f.status === null || f.status === undefined ? "" : f.status));
      tr.appendChild(el("td", "num", fmtSize(f.size)));
      var u = el("td", "url"); u.appendChild(link(f.url, f.path || f.url)); tr.appendChild(u);
      tr.appendChild(el("td", "detail", f.detail));
      frag.appendChild(tr);
    });
    body.appendChild(frag);
    document.getElementById("count").textContent = list.length > MAX_ROWS
      ? MAX_ROWS + " of " + list.length + " shown (narrow the filters)" : list.length + " of " + F.length + " findings";
    return list;
  }
  render();

  // exports
  function download(name, text, type){
    var a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], {type:type}));
    a.download = name; document.body.appendChild(a); a.click(); setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); }, 0);
  }
  document.getElementById("copy").addEventListener("click", function(e){
    var text = filtered().map(function(f){ return f.url; }).join("\n"), btn = e.currentTarget;
    function done(){ btn.textContent = "Copied"; setTimeout(function(){ btn.textContent = "Copy URLs"; }, 1200); }
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function(){ download("urls.txt", text, "text/plain"); });
    else download("urls.txt", text, "text/plain");
  });
  document.getElementById("csv").addEventListener("click", function(){
    var q = function(v){ v = v === null || v === undefined ? "" : String(v); return '"' + v.replace(/"/g, '""') + '"'; };
    var lines = [["type","site","status","size","url","detail"].join(",")];
    filtered().forEach(function(f){ lines.push([f.type, f.site, f.status, f.size, f.url, f.detail].map(q).join(",")); });
    download("hawkscan_findings.csv", lines.join("\n"), "text/csv");
  });

  // theme
  var themes = ["auto","dark","light"], cur = "auto", tbtn = document.getElementById("theme");
  try { cur = localStorage.getItem("hawkscan-theme") || "auto"; } catch (e) {}
  function applyTheme(){
    if (cur === "auto") document.documentElement.removeAttribute("data-theme"); else document.documentElement.setAttribute("data-theme", cur);
    tbtn.textContent = "Theme: " + cur;
  }
  tbtn.addEventListener("click", function(){
    cur = themes[(themes.indexOf(cur) + 1) % themes.length];
    try { localStorage.setItem("hawkscan-theme", cur); } catch (e) {}
    applyTheme();
  });
  applyTheme();

  var foot = document.getElementById("foot");
  var logs = sites.filter(function(s){ return s.log; });
  foot.textContent = "Per-site logs and downloaded files are next to this report" + (logs.length ? " (logs/)." : " (files/, output/).");
})();
</script>
</body>
</html>
"""
